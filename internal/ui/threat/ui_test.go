// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package threat

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	threatstore "github.com/nethesis/nethesis-insights/internal/store/threat"
	"github.com/nethesis/nethesis-insights/internal/ui/chrome"
)

var errStore = errors.New("store unavailable")

// fakeReader is an in-package stand-in for the Reader slice of
// threatstore.Store. It never touches a database, so this package's tests
// never wait on a real store.
type fakeReader struct {
	counts           threatstore.Counts
	blocklist        []threatstore.BlocklistRow
	threatEvents     []threatstore.ThreatEventRow
	threatDaily      []threatstore.ThreatDailyRow
	threatIngest     []threatstore.ThreatIngestRow
	threatSystems    []threatstore.ThreatSystemRow
	allowlist        []threatstore.AllowlistRow
	allowlistRequest []threatstore.AllowlistRequestRow
	audit            []threatstore.AllowlistAuditRow

	err error // when set, every method returns this error instead
}

func (f *fakeReader) Counts(context.Context) (threatstore.Counts, error) {
	return f.counts, f.err
}

func (f *fakeReader) ListBlocklistEntries(_ context.Context, limit int) ([]threatstore.BlocklistRow, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := f.blocklist
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeReader) ListThreatEvents(_ context.Context, systemID, attackerIP string, limit int) ([]threatstore.ThreatEventRow, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []threatstore.ThreatEventRow
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

func (f *fakeReader) ThreatDailyStats(_ context.Context, _ int) ([]threatstore.ThreatDailyRow, error) {
	return f.threatDaily, f.err
}

func (f *fakeReader) ThreatIngestStats(_ context.Context, _ int) ([]threatstore.ThreatIngestRow, error) {
	return f.threatIngest, f.err
}

func (f *fakeReader) ListThreatSystems(_ context.Context) ([]threatstore.ThreatSystemRow, error) {
	return f.threatSystems, f.err
}

func (f *fakeReader) ListThreatAllowlist(_ context.Context) ([]threatstore.AllowlistRow, error) {
	return f.allowlist, f.err
}

func (f *fakeReader) PendingAllowlistRequests(_ context.Context, limit int) ([]threatstore.AllowlistRequestRow, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := f.allowlistRequest
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeReader) ListAllowlistAudit(_ context.Context, limit int) ([]threatstore.AllowlistAuditRow, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := f.audit
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

// fakeRuntime is a fixed ingest-queue state, mirroring logsui's fakeRuntime.
type fakeRuntime struct {
	depth, cap, workers int
}

func (f fakeRuntime) Depth() int   { return f.depth }
func (f fakeRuntime) Cap() int     { return f.cap }
func (f fakeRuntime) Workers() int { return f.workers }

func threatReader() *fakeReader {
	expires := int64(1700009000000)
	r := &fakeReader{
		counts: threatstore.Counts{Events: 2, BlocklistEntries: 1, AllowlistEntries: 2, PendingRequests: 0},
	}
	r.blocklist = []threatstore.BlocklistRow{{
		AttackerIP: "203.0.113.7", FirstListedAt: 1700000000000, LastSeenAt: 1700000100000,
		ExpiresAt: 1700086500000, DistinctSystems: 4,
		Scenarios: []string{"crowdsecurity/port-scan", "crowdsecurity/ssh-bf"},
		Reason: threatstore.ListingReason{
			Systems: 4, Hits: 91, Scenarios: []string{"crowdsecurity/port-scan", "crowdsecurity/ssh-bf"},
			WindowMinutes: 60, MinSystems: 3, Rule: "v1", DecidedAt: 1700000100000,
		},
	}}
	r.threatEvents = []threatstore.ThreatEventRow{
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
	r.threatDaily = []threatstore.ThreatDailyRow{
		{Day: "2026-08-27", Scenario: "crowdsecurity/ssh-bf", DistinctIPs: 12, TotalHits: 240},
		{Day: "2026-08-27", Scenario: "crowdsecurity/port-scan", DistinctIPs: 5, TotalHits: 60},
	}
	r.threatIngest = []threatstore.ThreatIngestRow{
		{Day: "2026-08-27", SystemID: "sys-1", Accepted: 40, Duplicates: 2},
	}
	lastEvent := int64(1700000100000)
	r.threatSystems = []threatstore.ThreatSystemRow{
		{SystemID: "sys-1", FirstDay: "2026-08-20", LastDay: "2026-08-27",
			Accepted: 40, Duplicates: 2, Events: 38, DistinctIPs: 12, DistinctScenarios: 2,
			TotalHits: 300, LastEventAt: &lastEvent},
		{SystemID: "sys-3", FirstDay: "2026-08-21", LastDay: "2026-08-21",
			Accepted: 0, Dropped: 5},
	}
	r.allowlist = []threatstore.AllowlistRow{
		{CIDR: "203.0.113.0/24", Reason: "partner scanner", CreatedBy: "ops", CreatedAt: 1700000000000},
		{CIDR: "198.51.100.0/24", Reason: "temporary", CreatedBy: "ops", CreatedAt: 1700000000000, ExpiresAt: &expires},
	}
	r.audit = []threatstore.AllowlistAuditRow{
		{ID: "01AUDIT0000000000000000001", CIDR: "198.51.100.0/24", Action: "allowlist.delete", Actor: "bob", At: 1700000200000},
		{ID: "01AUDIT0000000000000000000", CIDR: "203.0.113.0/24", Action: "allowlist.upsert", Actor: "alice", Detail: "partner scanner", At: 1700000000000},
	}
	return r
}

func testInfo() chrome.Info {
	return chrome.Info{
		StartedAt: 1700000000000,
		Build:     "test-build",
		Config: []chrome.ConfigItem{
			{Name: "ADMIN_API_KEY", Value: "set"},
			{Name: "DB_PATH", Value: "/tmp/threat.db"},
		},
	}
}

// newTestServerWithFeed builds a read-only server: no writer, no admin key.
// Every existing (pre-allowlist-management) test relies on writes being
// unreachable, which is also the off-by-default behavior this helper is
// meant to exercise. Use newWriteTestServer for the write-route tests.
func newTestServerWithFeed(t *testing.T, r Reader, feed Feed) http.Handler {
	t.Helper()
	h, err := NewServer(r, feed, nil, nil, chrome.Config{Info: testInfo()})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return h
}

// newTestServerWithRuntime builds a server exposing the ingest queue's
// live state on the status page.
func newTestServerWithRuntime(t *testing.T, r Reader, rt Runtime) http.Handler {
	t.Helper()
	h, err := NewServer(r, nil, nil, rt, chrome.Config{Info: testInfo()})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return h
}

// newWriteTestServer builds a server with the write routes enabled against
// w, authenticated with adminKey.
func newWriteTestServer(t *testing.T, r Reader, feed Feed, w Writer, adminKey string) http.Handler {
	t.Helper()
	h, err := NewServer(r, feed, w, nil, chrome.Config{AdminKey: adminKey, Info: testInfo()})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return h
}

func get(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

var routes = []struct {
	path   string
	marker string
}{
	{"/", "<h1>Blocklist</h1>"},
	{"/systems", "<h1>Systems</h1>"},
	{"/events", "<h1>Threat events</h1>"},
	{"/stats", "<h1>Threat stats</h1>"},
	{"/allowlist-requests", "<h1>Allowlist requests</h1>"},
	{"/audit", "<h1>Audit</h1>"},
	{"/status", "<h1>Status</h1>"},
}

func TestRoutesOK(t *testing.T) {
	h := newTestServerWithFeed(t, threatReader(), nil)
	for _, rt := range routes {
		t.Run(rt.path, func(t *testing.T) {
			rec := get(t, h, rt.path)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s: status = %d, want 200", rt.path, rec.Code)
			}
			if !strings.Contains(rec.Body.String(), rt.marker) {
				t.Fatalf("GET %s: body missing marker %q", rt.path, rt.marker)
			}
		})
	}
}

// The shared chrome layout must identify this dashboard as threatd's own --
// see chrome.Config.Name, set by this package's NewServer. Without it every
// pipeline sharing chrome would render whichever binary wrote layout.html,
// which insightsd's move to its own dashboard would otherwise have made
// permanent.
func TestPageIdentifiesAsThreatd(t *testing.T) {
	h := newTestServerWithFeed(t, threatReader(), nil)
	body := get(t, h, "/").Body.String()

	if !strings.Contains(body, "<title>threatd operator UI</title>") {
		t.Fatalf("missing threatd title, got:\n%s", body)
	}
	if !strings.Contains(body, "<strong>threatd</strong>") {
		t.Fatalf("missing threatd nav brand, got:\n%s", body)
	}
}

// The footer's write-routes clause must track whether writes are actually
// reachable: threatd is the one pipeline that has write routes, but only
// when ADMIN_API_KEY is configured.
func TestFooterWriteClauseTracksCanWrite(t *testing.T) {
	readOnly := newTestServerWithFeed(t, threatReader(), nil)
	if body := get(t, readOnly, "/").Body.String(); strings.Contains(body, "write routes require the admin key") {
		t.Fatalf("no admin key configured; the footer must not claim writes are available:\n%s", body)
	}

	writable := newWriteTestServer(t, threatReader(), nil, &fakeWriter{}, testAdminKey)
	if body := get(t, writable, "/").Body.String(); !strings.Contains(body, "write routes require the admin key") {
		t.Fatalf("an admin key is configured; the footer should say so:\n%s", body)
	}
}

func TestBlocklistPageRendersEntriesAndAllowlist(t *testing.T) {
	h := newTestServerWithFeed(t, threatReader(),
		fakeFeed{ready: true, entries: 1, generatedAt: 1700000100000, etag: `"sha256-abc"`})

	body := get(t, h, "/").Body.String()

	for _, want := range []string{
		"203.0.113.7", // the promoted entry
		"crowdsecurity/port-scan, crowdsecurity/ssh-bf", // its scenarios
		"91",              // hits, from the snapshotted evidence
		"partner scanner", // the allowlist
		"sha256-abc",      // the served snapshot's ETag
		"permanent",       // an allowlist entry with no expiry
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/ is missing %q", want)
		}
	}
}

// The status page's queue section has two renderings: no queue attached
// (rt == nil, the tests above all exercise this implicitly), and a queue
// reporting live depth/cap/workers -- both must render without panicking,
// and the live one must show the actual numbers.
func TestStatusPageShowsQueueState(t *testing.T) {
	cases := []struct {
		name string
		rt   Runtime
		want string
	}{
		{"no queue", nil, "no queue attached to this process"},
		{"live queue", fakeRuntime{depth: 3, cap: 256, workers: 2}, "<td class=\"num\">3</td>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestServerWithRuntime(t, threatReader(), tc.rt)
			body := get(t, h, "/status").Body.String()
			if !strings.Contains(body, tc.want) {
				t.Fatalf("/status %s: missing %q, got:\n%s", tc.name, tc.want, body)
			}
		})
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
			h := newTestServerWithFeed(t, threatReader(), tc.feed)
			rec := get(t, h, "/")
			if rec.Code != http.StatusOK {
				t.Fatalf("status: got %d, want 200", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), tc.wantOnFeed) {
				t.Fatalf("/ %s: missing %q", tc.name, tc.wantOnFeed)
			}
			// The status page renders the same state and must agree.
			if !strings.Contains(get(t, h, "/status").Body.String(), tc.wantOnHome) {
				t.Fatalf("/status %s: missing %q", tc.name, tc.wantOnHome)
			}
		})
	}
}

func TestThreatEventsPageFilters(t *testing.T) {
	h := newTestServerWithFeed(t, threatReader(), nil)

	all := get(t, h, "/events").Body.String()
	if !strings.Contains(all, "203.0.113.7") || !strings.Contains(all, "198.51.100.9") {
		t.Fatalf("/events did not render both events")
	}
	if !strings.Contains(all, "crowdsecurity/ssh-bf") {
		t.Fatal("/events did not render the scenario from metadata")
	}

	bySystem := get(t, h, "/events?system=sys-2").Body.String()
	if strings.Contains(bySystem, "203.0.113.7") {
		t.Fatal("?system= did not filter")
	}
	byIP := get(t, h, "/events?ip=203.0.113.7").Body.String()
	if strings.Contains(byIP, "198.51.100.9") {
		t.Fatal("?ip= did not filter")
	}
}

// The filter values are reflected into the form, so they must be escaped
// rather than trusted -- this is an unauthenticated page.
func TestThreatEventsPageEscapesItsFilters(t *testing.T) {
	h := newTestServerWithFeed(t, threatReader(), nil)

	body := get(t, h, "/events?ip=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E").Body.String()

	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("the ip filter was reflected unescaped")
	}
	if !strings.Contains(body, "&lt;script&gt;") && !strings.Contains(body, "&#34;&gt;&lt;script&gt;") {
		t.Fatalf("expected the filter to be escaped into the form, got:\n%s", body)
	}
}

func TestThreatEventsPageClampsItsLimit(t *testing.T) {
	h := newTestServerWithFeed(t, threatReader(), nil)
	body := get(t, h, "/events?limit=99999").Body.String()
	if !strings.Contains(body, `value="500"`) {
		t.Fatal("the limit was not clamped to the page maximum")
	}
}

func TestThreatStatsPageRendersBothTables(t *testing.T) {
	h := newTestServerWithFeed(t, threatReader(), nil)

	body := get(t, h, "/stats").Body.String()

	for _, want := range []string{
		"2026-08-27",           // the daily rollup
		"crowdsecurity/ssh-bf", // rolled up per scenario, verbatim
		"240",                  // its hit total
		"sys-1",                // ingest accounting
		"2026-08-27 total",     // the per-day subtotal row
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/stats is missing %q", want)
		}
	}
}

// The per-day total must sum every scenario's hits for that day (240 + 60),
// not just repeat one row's total.
func TestThreatStatsPageDailyTotalSumsAcrossScenarios(t *testing.T) {
	h := newTestServerWithFeed(t, threatReader(), nil)
	body := get(t, h, "/stats").Body.String()
	if !strings.Contains(body, "300") {
		t.Fatalf("/stats daily total: expected 300 (240+60) in body:\n%s", body)
	}
}

func TestThreatSystemsPageRendersEveryReportingSystem(t *testing.T) {
	h := newTestServerWithFeed(t, threatReader(), nil)
	body := get(t, h, "/systems").Body.String()

	for _, want := range []string{
		"sys-1", // has stored events
		"sys-3", // every report dropped, no stored events, must still appear
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/systems is missing %q", want)
		}
	}
}

// The audit page is the only reader of the trail the write routes append to
// (add, delete, approve, reject) -- without it the table is write-only, and
// "who removed the exemption that let this through" is answerable only from
// hand-written SQL.
func TestAuditPageRendersTheTrail(t *testing.T) {
	h := newTestServerWithFeed(t, threatReader(), nil)
	body := get(t, h, "/audit").Body.String()

	for _, want := range []string{
		"203.0.113.0/24",
		"allowlist.upsert",
		"alice",
		"partner scanner",
		"198.51.100.0/24",
		"allowlist.delete",
		"bob",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/audit is missing %q", want)
		}
	}
}

// A store failure is a 503, never a half-rendered page.
func TestThreatPagesReportStoreFailures(t *testing.T) {
	broken := &fakeReader{err: errStore}
	h := newTestServerWithFeed(t, broken, fakeFeed{ready: true})

	for _, path := range []string{"/", "/events", "/stats", "/systems", "/audit"} {
		rec := get(t, h, path)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: got %d, want 503", path, rec.Code)
		}
	}
}

// Every threat page must render on a fresh deployment with nothing stored.
func TestThreatPagesRenderEmpty(t *testing.T) {
	h := newTestServerWithFeed(t, &fakeReader{}, nil)

	for _, tc := range []struct{ path, want string }{
		{"/", "nothing promoted yet"},
		{"/events", "no threat events"},
		{"/stats", "no rollup yet"},
		{"/systems", "no systems have reported yet"},
		{"/audit", "no audit entries yet"},
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

func TestUnknownPathIs404(t *testing.T) {
	h := newTestServerWithFeed(t, threatReader(), nil)
	rec := get(t, h, "/nonsense")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /nonsense: status = %d, want 404", rec.Code)
	}
}

func TestPOSTMethodNotAllowed(t *testing.T) {
	h := newTestServerWithFeed(t, threatReader(), nil)
	for _, rt := range routes {
		t.Run(rt.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, rt.path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("POST %s: status = %d, want 405", rt.path, rec.Code)
			}
		})
	}
}
