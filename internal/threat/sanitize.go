// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package threat holds the pure half of the Threat Shield pipeline: the ingest
// sanitizer and the promotion allowlist.
//
// Same purity contract as gate, fingerprint and prompt -- no I/O, no clock
// beyond an injected now -- and for a sharper reason than those: everything
// that decides whether a third party's IP address is stored and published
// lives here, so a bug in this package is a data-protection incident rather
// than a wrong answer. That is what makes it worth being table-driven testable
// with no fixtures and no database.
//
// What this package does NOT do is judge the scenario. There is no fixed
// category set and no scenario allowlist: CrowdSec's hub grows continuously
// and nodes run third-party and local collections, so anything resembling a
// known-scenarios list would silently discard real evidence until someone
// noticed. Scenarios are bounded and stripped of control characters, then
// carried through verbatim.
package threat

import (
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode"

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
}

// dedupKey collapses decisions that describe the same observation. CrowdSec
// fires one decision per alert, so a node under a sustained brute force
// reports the same (ip, scenario, second) repeatedly; folding them here means
// the store's unique index is never fought at insert time.
type dedupKey struct {
	ip         string
	scenario   string
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

	var res Result

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

		observedAt, ok := observedAt(d.CreatedAt, now)
		if !ok {
			res.Counters.DroppedTime++
			continue
		}

		// Every scenario is accepted, whatever it says. There is deliberately
		// no allowlist: CrowdSec's hub grows continuously and nodes run
		// third-party and local collections, so a fixed set would silently
		// discard real evidence until someone noticed and shipped a release.
		// The scenario is free text from the edge, so it is bounded and
		// stripped of control characters -- it reaches an HTML page and a
		// plain-text log -- but never judged.
		scenario := cleanScenario(d.Scenario)

		res.Counters.Accepted++
		key := dedupKey{ip: addr.String(), scenario: scenario, observedAt: observedAt}
		if ev, seen := merged[key]; seen {
			ev.HitCount++
			continue
		}
		merged[key] = &model.ThreatEvent{
			AttackerIP: key.ip,
			Scenario:   scenario,
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
		if a.Scenario != b.Scenario {
			return a.Scenario < b.Scenario
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

// MaxScenarioLen bounds the scenario string. CrowdSec's own names are well
// under this; the cap exists because the value is free text from the edge that
// ends up in a rendered page, a log line and a database column.
const MaxScenarioLen = 128

// cleanScenario bounds and de-fangs a scenario name without judging it.
// Control characters are stripped so the value cannot break a log line, and
// the result is truncated by rune so a multi-byte name cannot be cut in half.
func cleanScenario(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' || unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))

	if runes := []rune(s); len(runes) > MaxScenarioLen {
		s = string(runes[:MaxScenarioLen])
	}
	return s
}

// metadata reduces a decision to a fixed, typed allowlist. Nothing free-text
// reaches the store beyond the scenario itself: no usernames (a hash of "root"
// is trivially reversible and carries no analytic value), no URIs, no user
// agents.
func metadata(d model.Decision) map[string]any {
	m := map[string]any{}
	if dur, err := time.ParseDuration(strings.TrimSpace(d.Duration)); err == nil {
		m["duration_seconds"] = int64(dur.Seconds())
	}
	return m
}
