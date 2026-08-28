// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package ui

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/store"
)

var errStore = errors.New("store unavailable")

// --- fakeReader's Threat Shield half ---

func (f *fakeReader) ListBlocklistEntries(_ context.Context, limit int) ([]store.BlocklistRow, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := f.blocklist
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeReader) ListThreatEvents(_ context.Context, systemID, attackerIP string, limit int) ([]store.ThreatEventRow, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []store.ThreatEventRow
	for _, e := range f.threatEvents {
		if systemID != "" && e.SystemID != systemID {
			continue
		}
		if attackerIP != "" && e.AttackerIP != attackerIP {
			continue
		}
		out = append(out, e)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (f *fakeReader) ThreatDailyStats(_ context.Context, _ int) ([]store.ThreatDailyRow, error) {
	return f.threatDaily, f.err
}

func (f *fakeReader) ThreatIngestStats(_ context.Context, _ int) ([]store.ThreatIngestRow, error) {
	return f.threatIngest, f.err
}

func (f *fakeReader) ListThreatAllowlist(_ context.Context) ([]store.AllowlistRow, error) {
	return f.allowlist, f.err
}

func (f *fakeReader) ListSystemEgress(_ context.Context) ([]store.EgressRow, error) {
	return f.egress, f.err
}

func (f *fakeReader) PendingAllowlistRequests(_ context.Context, limit int) ([]store.AllowlistRequestRow, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := f.allowlistRequest
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// fakeFeed is a fixed snapshot state.
type fakeFeed struct {
	ready       bool
	entries     int
	generatedAt int64
	etag        string
}

func (f fakeFeed) Ready() bool        { return f.ready }
func (f fakeFeed) Entries() int       { return f.entries }
func (f fakeFeed) GeneratedAt() int64 { return f.generatedAt }
func (f fakeFeed) ETag() string       { return f.etag }

func threatReader() *fakeReader {
	expires := int64(1700009000000)
	r := seededReader()
	r.blocklist = []store.BlocklistRow{{
		AttackerIP: "203.0.113.7", FirstListedAt: 1700000000000, LastSeenAt: 1700000100000,
		ExpiresAt: 1700086500000, DistinctSystems: 4,
		Scenarios: []string{"crowdsecurity/port-scan", "crowdsecurity/ssh-bf"},
		Reason: store.ListingReason{
			Systems: 4, Hits: 91, Scenarios: []string{"crowdsecurity/port-scan", "crowdsecurity/ssh-bf"},
			WindowMinutes: 60, MinSystems: 3, Rule: "v1", DecidedAt: 1700000100000,
		},
	}}
	r.threatEvents = []store.ThreatEventRow{
		{
			ID: "01EVENT0000000000000000000", SystemID: "sys-1", AttackerIP: "203.0.113.7",
			Scenario: "crowdsecurity/ssh-bf", ObservedAt: 1700000100000, HitCount: 3,
			Metadata: map[string]any{"duration_seconds": float64(14400)},
		},
		{
			ID: "01EVENT0000000000000000001", SystemID: "sys-2", AttackerIP: "198.51.100.9",
			Scenario: "crowdsecurity/port-scan", ObservedAt: 1700000090000, HitCount: 1,
		},
	}
	r.threatDaily = []store.ThreatDailyRow{
		{Day: "2026-08-27", Scenario: "crowdsecurity/ssh-bf", DistinctIPs: 12, TotalHits: 240},
	}
	r.threatIngest = []store.ThreatIngestRow{
		{Day: "2026-08-27", SystemID: "sys-1", Accepted: 40, Duplicates: 2},
	}
	r.allowlist = []store.AllowlistRow{
		{CIDR: "203.0.113.0/24", Reason: "partner scanner", CreatedBy: "ops", CreatedAt: 1700000000000},
		{CIDR: "198.51.100.0/24", Reason: "temporary", CreatedBy: "ops", CreatedAt: 1700000000000, ExpiresAt: &expires},
	}
	r.egress = []store.EgressRow{
		{SystemID: "sys-1", SourceIP: "192.0.2.10", UpdatedAt: 1700000100000},
	}
	return r
}

func TestBlocklistPageRendersEntriesAndExclusions(t *testing.T) {
	h := newTestServerWithFeed(t, threatReader(), nil,
		fakeFeed{ready: true, entries: 1, generatedAt: 1700000100000, etag: `"sha256-abc"`})

	body := get(t, h, "/blocklist").Body.String()

	for _, want := range []string{
		"203.0.113.7", // the promoted entry
		"crowdsecurity/port-scan, crowdsecurity/ssh-bf", // its scenarios
		"91",              // hits, from the snapshotted evidence
		"partner scanner", // the allowlist
		"192.0.2.10",      // the fleet egress set
		"sha256-abc",      // the served snapshot's ETag
		"permanent",       // an allowlist entry with no expiry
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/blocklist is missing %q", want)
		}
	}
}

// The snapshot state has three distinct renderings and none of them may
// panic: no feed at all, a feed that has not generated yet, and a live one.
func TestBlocklistPageHandlesEveryFeedState(t *testing.T) {
	cases := []struct {
		name                   string
		feed                   Feed
		wantOnFeed, wantOnHome string
	}{
		{"no feed", nil, "not wired into this process", "not wired into this process"},
		{"not generated", fakeFeed{ready: false}, "Not generated yet", "Not generated yet"},
		{"ready", fakeFeed{ready: true, entries: 3, generatedAt: 1700000100000, etag: `"e"`},
			"Entries served", "Blocklist feed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestServerWithFeed(t, threatReader(), nil, tc.feed)
			rec := get(t, h, "/blocklist")
			if rec.Code != http.StatusOK {
				t.Fatalf("status: got %d, want 200", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), tc.wantOnFeed) {
				t.Fatalf("/blocklist %s: missing %q", tc.name, tc.wantOnFeed)
			}
			// The status page renders the same state and must agree.
			if !strings.Contains(get(t, h, "/").Body.String(), tc.wantOnHome) {
				t.Fatalf("/ %s: missing %q", tc.name, tc.wantOnHome)
			}
		})
	}
}

func TestThreatEventsPageFilters(t *testing.T) {
	h := newTestServerWithFeed(t, threatReader(), nil, nil)

	all := get(t, h, "/threat-events").Body.String()
	if !strings.Contains(all, "203.0.113.7") || !strings.Contains(all, "198.51.100.9") {
		t.Fatalf("/threat-events did not render both events")
	}
	if !strings.Contains(all, "crowdsecurity/ssh-bf") {
		t.Fatal("/threat-events did not render the scenario from metadata")
	}

	bySystem := get(t, h, "/threat-events?system=sys-2").Body.String()
	if strings.Contains(bySystem, "203.0.113.7") {
		t.Fatal("?system= did not filter")
	}
	byIP := get(t, h, "/threat-events?ip=203.0.113.7").Body.String()
	if strings.Contains(byIP, "198.51.100.9") {
		t.Fatal("?ip= did not filter")
	}
}

// The filter values are reflected into the form, so they must be escaped
// rather than trusted -- this is an unauthenticated page.
func TestThreatEventsPageEscapesItsFilters(t *testing.T) {
	h := newTestServerWithFeed(t, threatReader(), nil, nil)

	body := get(t, h, "/threat-events?ip=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E").Body.String()

	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("the ip filter was reflected unescaped")
	}
	if !strings.Contains(body, "&lt;script&gt;") && !strings.Contains(body, "&#34;&gt;&lt;script&gt;") {
		t.Fatalf("expected the filter to be escaped into the form, got:\n%s", body)
	}
}

func TestThreatEventsPageClampsItsLimit(t *testing.T) {
	h := newTestServerWithFeed(t, threatReader(), nil, nil)
	body := get(t, h, "/threat-events?limit=99999").Body.String()
	if !strings.Contains(body, `value="500"`) {
		t.Fatal("the limit was not clamped to the page maximum")
	}
}

func TestThreatStatsPageRendersBothTables(t *testing.T) {
	h := newTestServerWithFeed(t, threatReader(), nil, nil)

	body := get(t, h, "/threat-stats").Body.String()

	for _, want := range []string{
		"2026-08-27",           // the daily rollup
		"crowdsecurity/ssh-bf", // rolled up per scenario, verbatim
		"240",                  // its hit total
		"sys-1",                // ingest accounting
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/threat-stats is missing %q", want)
		}
	}
}

// A store failure is a 503, never a half-rendered page.
func TestThreatPagesReportStoreFailures(t *testing.T) {
	broken := &fakeReader{err: errStore}
	h := newTestServerWithFeed(t, broken, nil, fakeFeed{ready: true})

	for _, path := range []string{"/blocklist", "/threat-events", "/threat-stats"} {
		rec := get(t, h, path)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: got %d, want 503", path, rec.Code)
		}
	}
}

// Every threat page must render on a fresh deployment with nothing stored.
func TestThreatPagesRenderEmpty(t *testing.T) {
	h := newTestServerWithFeed(t, &fakeReader{}, nil, nil)

	for _, tc := range []struct{ path, want string }{
		{"/blocklist", "nothing promoted yet"},
		{"/threat-events", "no threat events"},
		{"/threat-stats", "no rollup yet"},
	} {
		rec := get(t, h, tc.path)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: got %d, want 200", tc.path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), tc.want) {
			t.Fatalf("%s: missing the empty-state text %q", tc.path, tc.want)
		}
	}
}
