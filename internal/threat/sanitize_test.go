// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package threat

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/nethesis/nethesis-insights/internal/model"
)

// testNow is a fixed clock for every case below; the created_at values are
// chosen relative to it.
var testNow = time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC).UnixMilli()

const testCreatedAt = "2026-08-28T09:59:00Z"

var testObservedAt = time.Date(2026, 8, 28, 9, 59, 0, 0, time.UTC).UnixMilli()

// goodDecision is a decision that passes every filter. Each table case below
// mutates exactly one field, so a failure names exactly one rule.
func goodDecision() model.Decision {
	return model.Decision{
		ID:        1,
		Value:     "203.0.113.7",
		Scope:     "Ip",
		Type:      "ban",
		Scenario:  "crowdsecurity/ssh-bf",
		Origin:    "crowdsec",
		Duration:  "3h59m59s",
		CreatedAt: testCreatedAt,
	}
}

func report(ds ...model.Decision) model.ThreatReport {
	return model.ThreatReport{SchemaVersion: model.ThreatSchemaVersion, Decisions: ds}
}

func TestSanitizeAcceptsAGoodDecision(t *testing.T) {
	res := Sanitize(report(goodDecision()), Options{}, testNow)

	if len(res.Events) != 1 {
		t.Fatalf("events: got %d, want 1 (%+v)", len(res.Events), res)
	}
	ev := res.Events[0]
	if ev.AttackerIP != "203.0.113.7" {
		t.Fatalf("attacker_ip: got %q", ev.AttackerIP)
	}
	if ev.Category != "ssh_bruteforce" {
		t.Fatalf("category: got %q", ev.Category)
	}
	if ev.ObservedAt != testObservedAt {
		t.Fatalf("observed_at: got %d, want %d", ev.ObservedAt, testObservedAt)
	}
	if ev.HitCount != 1 {
		t.Fatalf("hit_count: got %d, want 1", ev.HitCount)
	}
	if res.Counters.Accepted != 1 {
		t.Fatalf("accepted: got %d, want 1", res.Counters.Accepted)
	}
}

// The metadata allowlist is fixed and typed. Nothing free-text may reach the
// store: no usernames, no URIs, no user agents.
func TestSanitizeMetadataIsAFixedTypedAllowlist(t *testing.T) {
	res := Sanitize(report(goodDecision()), Options{}, testNow)
	md := res.Events[0].Metadata

	if len(md) != 2 {
		t.Fatalf("metadata keys: got %v, want exactly scenario and duration_seconds", md)
	}
	if md["scenario"] != "crowdsecurity/ssh-bf" {
		t.Fatalf("metadata scenario: got %v", md["scenario"])
	}
	if md["duration_seconds"] != int64(14399) {
		t.Fatalf("metadata duration_seconds: got %v (%T), want int64(14399)", md["duration_seconds"], md["duration_seconds"])
	}
}

// An unparseable duration must not lose the whole event: the duration is
// decoration, the address and the category are the evidence.
func TestSanitizeKeepsTheEventWhenDurationIsUnparseable(t *testing.T) {
	d := goodDecision()
	d.Duration = "not-a-duration"
	res := Sanitize(report(d), Options{}, testNow)

	if len(res.Events) != 1 {
		t.Fatalf("events: got %d, want 1", len(res.Events))
	}
	if _, present := res.Events[0].Metadata["duration_seconds"]; present {
		t.Fatal("duration_seconds should be absent when the duration does not parse")
	}
}

// The IP table is the deepest one here on purpose: a bug that lets a private
// or customer-internal address through is a data-protection incident, not a
// wrong answer.
func TestSanitizeDropsNonPublicAddresses(t *testing.T) {
	cases := []struct {
		name string
		ip   string
	}{
		{"RFC1918 ten", "10.0.0.5"},
		{"RFC1918 172.16", "172.16.4.9"},
		{"RFC1918 192.168", "192.168.1.1"},
		{"loopback v4", "127.0.0.1"},
		{"loopback v6", "::1"},
		{"unspecified v4", "0.0.0.0"},
		{"unspecified v6", "::"},
		{"CGNAT", "100.64.1.1"},
		{"CGNAT upper", "100.127.255.254"},
		{"link-local v4", "169.254.10.10"},
		{"IMDS", "169.254.169.254"},
		{"link-local v6", "fe80::1"},
		{"multicast v4", "224.0.0.1"},
		{"multicast v6", "ff02::1"},
		{"IPv6 ULA", "fd00::1"},
		{"benchmark", "198.18.0.1"},
		{"IPv4-mapped private v6", "::ffff:10.0.0.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := goodDecision()
			d.Value = tc.ip
			res := Sanitize(report(d), Options{}, testNow)

			if len(res.Events) != 0 {
				t.Fatalf("%s (%s) was stored: %+v", tc.name, tc.ip, res.Events)
			}
			if res.Counters.DroppedPrivateIP != 1 {
				t.Fatalf("dropped_private_ip: got %d, want 1 (%+v)", res.Counters.DroppedPrivateIP, res.Counters)
			}
		})
	}
}

// The documentation ranges are not private addressing. They never appear in
// real traffic, and the design document plus the manual verification steps
// use them as example attacker IPs, so dropping them would break both.
func TestSanitizeKeepsDocumentationRanges(t *testing.T) {
	for _, ip := range []string{"192.0.2.88", "198.51.100.44", "203.0.113.12", "2001:db8::1"} {
		d := goodDecision()
		d.Value = ip
		res := Sanitize(report(d), Options{}, testNow)
		if len(res.Events) != 1 {
			t.Fatalf("documentation address %s was dropped: %+v", ip, res.Counters)
		}
	}
}

// A node banning its own egress address is a misconfiguration; propagating it
// to the fleet would be an outage.
func TestSanitizeDropsTheReportersOwnAddress(t *testing.T) {
	d := goodDecision()
	d.Value = "198.51.100.44"
	opts := Options{SourceIP: netip.MustParseAddr("198.51.100.44")}

	res := Sanitize(report(d), opts, testNow)

	if len(res.Events) != 0 {
		t.Fatalf("the reporter's own address was stored: %+v", res.Events)
	}
	if res.Counters.DroppedPrivateIP != 1 {
		t.Fatalf("dropped_private_ip: got %d, want 1", res.Counters.DroppedPrivateIP)
	}
}

func TestSanitizeDropsUnparseableAddresses(t *testing.T) {
	// A CIDR belongs here too: scope Ip means one address, and a range
	// slipping through would list far more than the reporter observed.
	for _, v := range []string{"", "not-an-ip", "203.0.113.0/24", "203.0.113.999", "example.org"} {
		d := goodDecision()
		d.Value = v
		res := Sanitize(report(d), Options{}, testNow)

		if len(res.Events) != 0 {
			t.Fatalf("value %q was stored", v)
		}
		if res.Counters.DroppedBadIP != 1 {
			t.Fatalf("value %q: dropped_bad_ip = %d, want 1", v, res.Counters.DroppedBadIP)
		}
	}
}

// Re-reporting CrowdSec's community list would manufacture agreement between
// systems that never independently observed anything (spec §7.2).
func TestSanitizeAcceptsOnlyLocalOrigins(t *testing.T) {
	kept := []string{"crowdsec", "cscli", "CrowdSec"}
	dropped := []string{"CAPI", "capi", "lists", "console", "cscli-import", ""}

	for _, o := range kept {
		d := goodDecision()
		d.Origin = o
		if res := Sanitize(report(d), Options{}, testNow); len(res.Events) != 1 {
			t.Fatalf("origin %q was dropped, want kept", o)
		}
	}
	for _, o := range dropped {
		d := goodDecision()
		d.Origin = o
		res := Sanitize(report(d), Options{}, testNow)
		if len(res.Events) != 0 {
			t.Fatalf("origin %q was kept, want dropped", o)
		}
		if res.Counters.DroppedOrigin != 1 {
			t.Fatalf("origin %q: dropped_origin = %d, want 1", o, res.Counters.DroppedOrigin)
		}
	}
}

func TestSanitizeAcceptsOnlyBanDecisionsOnIPScope(t *testing.T) {
	t.Run("type", func(t *testing.T) {
		for _, typ := range []string{"captcha", "throttle", ""} {
			d := goodDecision()
			d.Type = typ
			res := Sanitize(report(d), Options{}, testNow)
			if len(res.Events) != 0 || res.Counters.DroppedType != 1 {
				t.Fatalf("type %q: events=%d dropped_type=%d", typ, len(res.Events), res.Counters.DroppedType)
			}
		}
		// CrowdSec's casing is "ban"; accept any casing rather than losing a
		// batch to a reporter that title-cases it.
		d := goodDecision()
		d.Type = "Ban"
		if res := Sanitize(report(d), Options{}, testNow); len(res.Events) != 1 {
			t.Fatal(`type "Ban" was dropped, want case-insensitive match`)
		}
	})

	t.Run("scope", func(t *testing.T) {
		for _, scope := range []string{"Range", "Country", "AS", ""} {
			d := goodDecision()
			d.Scope = scope
			res := Sanitize(report(d), Options{}, testNow)
			if len(res.Events) != 0 || res.Counters.DroppedScope != 1 {
				t.Fatalf("scope %q: events=%d dropped_scope=%d", scope, len(res.Events), res.Counters.DroppedScope)
			}
		}
		d := goodDecision()
		d.Scope = "ip"
		if res := Sanitize(report(d), Options{}, testNow); len(res.Events) != 1 {
			t.Fatal(`scope "ip" was dropped, want case-insensitive match`)
		}
	})
}

func TestSanitizeRecordsUnknownScenariosByName(t *testing.T) {
	d1, d2, d3 := goodDecision(), goodDecision(), goodDecision()
	d1.Scenario = "crowdsecurity/brand-new"
	d2.Scenario = "crowdsecurity/brand-new"
	d3.Scenario = "local/custom"

	res := Sanitize(report(d1, d2, d3), Options{}, testNow)

	if len(res.Events) != 0 {
		t.Fatalf("events: got %d, want 0", len(res.Events))
	}
	if res.Counters.DroppedScenario != 3 {
		t.Fatalf("dropped_scenario: got %d, want 3", res.Counters.DroppedScenario)
	}
	if res.Unknown["crowdsecurity/brand-new"] != 2 || res.Unknown["local/custom"] != 1 {
		t.Fatalf("unknown scenarios: got %v", res.Unknown)
	}
}

func TestSanitizeDropsUnparseableTimestamps(t *testing.T) {
	for _, ts := range []string{"", "yesterday", "2026-08-28 09:59:00"} {
		d := goodDecision()
		d.CreatedAt = ts
		res := Sanitize(report(d), Options{}, testNow)
		if len(res.Events) != 0 || res.Counters.DroppedTime != 1 {
			t.Fatalf("created_at %q: events=%d dropped_time=%d", ts, len(res.Events), res.Counters.DroppedTime)
		}
	}
}

// An edge with a broken clock must not be able to pin an entry into the
// future, where the TTL would never expire it.
func TestSanitizeClampsFarFutureTimestamps(t *testing.T) {
	d := goodDecision()
	d.CreatedAt = time.UnixMilli(testNow).UTC().Add(72 * time.Hour).Format(time.RFC3339)

	res := Sanitize(report(d), Options{}, testNow)

	if len(res.Events) != 1 {
		t.Fatalf("events: got %d, want 1", len(res.Events))
	}
	if res.Events[0].ObservedAt != testNow {
		t.Fatalf("observed_at: got %d, want clamped to now (%d)", res.Events[0].ObservedAt, testNow)
	}
}

// A small skew is normal and must survive untouched.
func TestSanitizeKeepsSmallClockSkew(t *testing.T) {
	skewed := time.UnixMilli(testNow).UTC().Add(time.Hour)
	d := goodDecision()
	d.CreatedAt = skewed.Format(time.RFC3339)

	res := Sanitize(report(d), Options{}, testNow)

	if res.Events[0].ObservedAt != skewed.UnixMilli() {
		t.Fatalf("observed_at: got %d, want %d", res.Events[0].ObservedAt, skewed.UnixMilli())
	}
}

// CrowdSec fires one decision per alert, so a node under sustained brute
// force reports the same (ip, category, second) repeatedly. Folding them here
// means the store's unique index is never fought at insert time.
func TestSanitizeCollapsesDuplicatesWithinOneBatch(t *testing.T) {
	res := Sanitize(report(goodDecision(), goodDecision(), goodDecision()), Options{}, testNow)

	if len(res.Events) != 1 {
		t.Fatalf("events: got %d, want 1", len(res.Events))
	}
	if res.Events[0].HitCount != 3 {
		t.Fatalf("hit_count: got %d, want 3", res.Events[0].HitCount)
	}
	if res.Counters.Accepted != 3 {
		t.Fatalf("accepted: got %d, want 3 (counters count decisions, not rows)", res.Counters.Accepted)
	}
}

// A probe under active attack is exactly the reporter whose batch must not be
// thrown away whole (spec §5.2).
func TestSanitizeTruncatesOverCapRatherThanRejecting(t *testing.T) {
	var ds []model.Decision
	for i := 0; i < 12; i++ {
		d := goodDecision()
		d.Value = fmt.Sprintf("203.0.113.%d", i+1)
		ds = append(ds, d)
	}

	res := Sanitize(report(ds...), Options{MaxDecisions: 10}, testNow)

	if len(res.Events) != 10 {
		t.Fatalf("events: got %d, want 10", len(res.Events))
	}
	if res.Counters.Truncated != 2 {
		t.Fatalf("truncated: got %d, want 2", res.Counters.Truncated)
	}
	if res.Counters.Accepted != 10 {
		t.Fatalf("accepted: got %d, want 10", res.Counters.Accepted)
	}
}

func TestSanitizeAppliesTheDefaultCap(t *testing.T) {
	var ds []model.Decision
	for i := 0; i < DefaultMaxDecisions+5; i++ {
		d := goodDecision()
		d.Value = netip.AddrFrom4([4]byte{203, 0, byte(i / 256), byte(i % 256)}).String()
		ds = append(ds, d)
	}

	res := Sanitize(report(ds...), Options{}, testNow)

	if res.Counters.Truncated != 5 {
		t.Fatalf("truncated: got %d, want 5", res.Counters.Truncated)
	}
}

// One bad decision must never cost the batch: ingest is fail-open on content
// and fail-closed only on authentication (spec §10).
func TestSanitizeKeepsTheBatchWhenOneDecisionIsMalformed(t *testing.T) {
	bad := goodDecision()
	bad.Value = "not-an-ip"
	capi := goodDecision()
	capi.Origin = "CAPI"
	capi.Value = "203.0.113.99"
	good := goodDecision()
	good.Value = "203.0.113.8"

	res := Sanitize(report(bad, capi, good), Options{}, testNow)

	if len(res.Events) != 1 || res.Events[0].AttackerIP != "203.0.113.8" {
		t.Fatalf("events: got %+v, want only 203.0.113.8", res.Events)
	}
	if res.Counters.DroppedBadIP != 1 || res.Counters.DroppedOrigin != 1 || res.Counters.Accepted != 1 {
		t.Fatalf("counters: got %+v", res.Counters)
	}
}

// Determinism: identical input must produce byte-identical output, the same
// rule the prompt package lives by.
func TestSanitizeOutputIsSorted(t *testing.T) {
	mk := func(ip, scenario string) model.Decision {
		d := goodDecision()
		d.Value = ip
		d.Scenario = scenario
		return d
	}
	res := Sanitize(report(
		mk("203.0.113.9", "crowdsecurity/ssh-bf"),
		mk("203.0.113.1", "crowdsecurity/port-scan"),
		mk("203.0.113.1", "crowdsecurity/ssh-bf"),
	), Options{}, testNow)

	var got []string
	for _, ev := range res.Events {
		got = append(got, ev.AttackerIP+"/"+ev.Category)
	}
	want := []string{"203.0.113.1/port_scan", "203.0.113.1/ssh_bruteforce", "203.0.113.9/ssh_bruteforce"}
	if len(got) != len(want) {
		t.Fatalf("events: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("events: got %v, want %v", got, want)
		}
	}
}

// The stored address must be normalized, so text equality in a portable TEXT
// column behaves like Postgres INET equality.
func TestSanitizeNormalizesTheStoredAddress(t *testing.T) {
	cases := map[string]string{
		"2001:0db8:0000:0000:0000:0000:0000:0001": "2001:db8::1",
		"::ffff:203.0.113.7":                      "203.0.113.7",
	}
	for in, want := range cases {
		d := goodDecision()
		d.Value = in
		res := Sanitize(report(d), Options{}, testNow)
		if len(res.Events) != 1 {
			t.Fatalf("%s: dropped (%+v)", in, res.Counters)
		}
		if res.Events[0].AttackerIP != want {
			t.Fatalf("%s: stored as %q, want %q", in, res.Events[0].AttackerIP, want)
		}
	}
}

func TestSanitizeHandlesAnEmptyReport(t *testing.T) {
	res := Sanitize(report(), Options{}, testNow)
	if len(res.Events) != 0 {
		t.Fatalf("events: got %d, want 0", len(res.Events))
	}
	if (res.Counters != model.ThreatCounters{}) {
		t.Fatalf("counters: got %+v, want zero", res.Counters)
	}
}
