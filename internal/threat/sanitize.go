// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package threat

import (
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/nethesis/nethesis-insights/internal/model"
)

// DefaultMaxDecisions caps one request. Over-cap batches are truncated with a
// counter, never rejected (spec §5.2): a probe under active attack is exactly
// the reporter whose batch must not be thrown away whole.
const DefaultMaxDecisions = 500

// maxClockSkew bounds how far into the future a reporter's created_at may sit
// before it is clamped to the server's clock. An edge with a broken clock must
// not be able to pin a blocklist entry into the future, where the TTL would
// never expire it.
const maxClockSkew = 24 * time.Hour

// cgnat, ula and benchmark are the ranges Go's netip predicates do not cover.
var (
	cgnat     = netip.MustParsePrefix("100.64.0.0/10")
	ula       = netip.MustParsePrefix("fc00::/7")
	benchmark = netip.MustParsePrefix("198.18.0.0/15")
)

// localOrigins are the CrowdSec decision origins this server accepts.
//
// Everything else -- CAPI, "lists", the console -- is dropped, and this is
// the single most important filter in the package after the IP one:
// re-reporting CrowdSec's community blocklist would manufacture agreement
// between systems that never independently observed anything, and consensus
// computed over manufactured agreement is worthless (spec §7.2).
var localOrigins = map[string]bool{"crowdsec": true, "cscli": true}

// Options carries the per-request inputs the sanitizer cannot derive itself.
type Options struct {
	// SourceIP is the reporter's own address as the server observed it. A
	// decision naming it is dropped: a node banning its own egress address
	// is a misconfiguration, and propagating it to the fleet would be an
	// outage.
	SourceIP netip.Addr
	// MaxDecisions caps the batch; <= 0 means DefaultMaxDecisions.
	MaxDecisions int
}

// Result is one sanitized batch.
type Result struct {
	Events   []model.ThreatEvent
	Counters model.ThreatCounters
	// Unknown counts the scenarios that were dropped for having no category,
	// keyed by scenario name, so the server can show operators what its map
	// is missing.
	Unknown map[string]int
}

// dedupKey collapses decisions that describe the same observation. CrowdSec
// fires one decision per alert, so a node under a sustained brute force
// reports the same (ip, category, second) repeatedly; folding them here means
// the store's unique index is never fought at insert time.
type dedupKey struct {
	ip         string
	category   string
	observedAt int64
}

// Sanitize turns a reported batch of CrowdSec decisions into storable events.
//
// It is fail-open on content and total on input: every decision either
// becomes an event or increments exactly one counter, and no input can make
// this function fail. now is unix millis.
func Sanitize(r model.ThreatReport, opts Options, now int64) Result {
	max := opts.MaxDecisions
	if max <= 0 {
		max = DefaultMaxDecisions
	}

	res := Result{Unknown: map[string]int{}}

	decisions := r.Decisions
	if len(decisions) > max {
		res.Counters.Truncated = len(decisions) - max
		decisions = decisions[:max]
	}

	merged := make(map[dedupKey]*model.ThreatEvent, len(decisions))
	for _, d := range decisions {
		if !strings.EqualFold(d.Type, "ban") {
			res.Counters.DroppedType++
			continue
		}
		if !strings.EqualFold(d.Scope, "ip") {
			res.Counters.DroppedScope++
			continue
		}
		if !localOrigins[strings.ToLower(d.Origin)] {
			res.Counters.DroppedOrigin++
			continue
		}

		addr, err := netip.ParseAddr(strings.TrimSpace(d.Value))
		if err != nil {
			// A CIDR value lands here too, which is correct: scope Ip means a
			// single address, and a range slipping through would list far more
			// than the reporter observed.
			res.Counters.DroppedBadIP++
			continue
		}
		addr = addr.Unmap()
		if !publicUnicast(addr) || (opts.SourceIP.IsValid() && addr == opts.SourceIP.Unmap()) {
			res.Counters.DroppedPrivateIP++
			continue
		}

		category, ok := CategoryFor(d.Scenario)
		if !ok {
			res.Counters.DroppedScenario++
			res.Unknown[d.Scenario]++
			continue
		}

		observedAt, ok := observedAt(d.CreatedAt, now)
		if !ok {
			res.Counters.DroppedTime++
			continue
		}

		res.Counters.Accepted++
		key := dedupKey{ip: addr.String(), category: category, observedAt: observedAt}
		if ev, seen := merged[key]; seen {
			ev.HitCount++
			continue
		}
		merged[key] = &model.ThreatEvent{
			AttackerIP: key.ip,
			Category:   category,
			ObservedAt: observedAt,
			HitCount:   1,
			Metadata:   metadata(d),
		}
	}

	res.Events = make([]model.ThreatEvent, 0, len(merged))
	for _, ev := range merged {
		res.Events = append(res.Events, *ev)
	}
	// Deterministic output: the same batch must always produce the same rows
	// in the same order, for the same reason prompt sorts its templates.
	sort.Slice(res.Events, func(i, j int) bool {
		a, b := res.Events[i], res.Events[j]
		if a.AttackerIP != b.AttackerIP {
			return a.AttackerIP < b.AttackerIP
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		return a.ObservedAt < b.ObservedAt
	})
	return res
}

// publicUnicast reports whether addr is an address a third party could
// plausibly attack from. Everything private, local or reserved is rejected
// here, at ingest, so private addressing never reaches the store at all --
// not merely never reaches the feed (spec §5.2).
//
// The documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
// 2001:db8::/32) are deliberately NOT rejected: they are not private
// addressing, they never appear in real traffic, and both the design document
// and the manual verification steps use them as example attacker IPs.
func publicUnicast(a netip.Addr) bool {
	switch {
	case !a.IsValid(),
		a.IsUnspecified(),
		a.IsLoopback(),
		a.IsPrivate(),
		a.IsLinkLocalUnicast(),
		a.IsLinkLocalMulticast(),
		a.IsInterfaceLocalMulticast(),
		a.IsMulticast():
		return false
	}
	return !cgnat.Contains(a) && !ula.Contains(a) && !benchmark.Contains(a)
}

// observedAt parses a CrowdSec RFC3339 timestamp into unix millis, clamping a
// clock-skewed future value to now. An unparseable or empty value is dropped
// rather than defaulted to now: a decision with no credible time cannot be
// placed in a consensus window.
func observedAt(raw string, now int64) (int64, bool) {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(raw))
	if err != nil {
		return 0, false
	}
	ms := t.UnixMilli()
	if ms > now+maxClockSkew.Milliseconds() {
		return now, true
	}
	return ms, true
}

// metadata reduces a decision to a fixed, typed allowlist. Nothing free-text
// reaches the store: no usernames (a hash of "root" is trivially reversible
// and carries no analytic value), no URIs, no user agents.
func metadata(d model.Decision) map[string]any {
	m := map[string]any{"scenario": d.Scenario}
	if dur, err := time.ParseDuration(strings.TrimSpace(d.Duration)); err == nil {
		m["duration_seconds"] = int64(dur.Seconds())
	}
	return m
}
