// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package ui

import (
	"context"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/store"
)

// fakeReader is an in-package stand-in for the eight-method Reader slice of
// store.Store. It never touches a database, so this package's tests never
// wait on Agent A's store implementation.
type fakeReader struct {
	counts    store.Counts
	systems   []store.SystemRow
	analyses  []store.AnalysisRow
	gate      []store.GateRow
	cost      []store.CostRow
	findings  []model.Finding
	templates []store.TemplateRow
	baselines []store.BaselineRow

	blocklist        []store.BlocklistRow
	threatEvents     []store.ThreatEventRow
	threatDaily      []store.ThreatDailyRow
	threatIngest     []store.ThreatIngestRow
	allowlist        []store.AllowlistRow
	allowlistRequest []store.AllowlistRequestRow

	err error // when set, every method returns this error instead
}

func (f *fakeReader) Counts(ctx context.Context) (store.Counts, error) {
	return f.counts, f.err
}

func (f *fakeReader) ListSystems(ctx context.Context) ([]store.SystemRow, error) {
	return f.systems, f.err
}

func (f *fakeReader) ListAnalyses(ctx context.Context, systemID string, limit int) ([]store.AnalysisRow, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []store.AnalysisRow
	for _, a := range f.analyses {
		if systemID != "" && a.SystemID != systemID {
			continue
		}
		out = append(out, a)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (f *fakeReader) GateRollup(ctx context.Context) ([]store.GateRow, error) {
	return f.gate, f.err
}

func (f *fakeReader) CostRollup(ctx context.Context) ([]store.CostRow, error) {
	return f.cost, f.err
}

func (f *fakeReader) ListAllFindings(ctx context.Context, systemID, status, severity, idLike, sortMode string, limit int) ([]model.Finding, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []model.Finding
	for _, fnd := range f.findings {
		if systemID != "" && fnd.SystemID != systemID {
			continue
		}
		if status != "" && fnd.Status != status {
			continue
		}
		if severity != "" && fnd.Severity != severity {
			continue
		}
		if idLike != "" && !strings.HasPrefix(fnd.ID, strings.TrimSuffix(idLike, "%")) && !strings.HasPrefix(fnd.Fingerprint, strings.TrimSuffix(idLike, "%")) {
			continue
		}
		out = append(out, fnd)
	}
	if sortMode == store.SortRecent {
		sort.SliceStable(out, func(i, j int) bool { return out[i].LastSeen > out[j].LastSeen })
	} else {
		model.SortFindings(out)
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeReader) ListTemplates(ctx context.Context, systemID string, limit int) ([]store.TemplateRow, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []store.TemplateRow
	for _, t := range f.templates {
		if systemID != "" && t.SystemID != systemID {
			continue
		}
		out = append(out, t)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (f *fakeReader) ListBaselines(ctx context.Context, systemID string) ([]store.BaselineRow, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []store.BaselineRow
	for _, b := range f.baselines {
		if systemID != "" && b.SystemID != systemID {
			continue
		}
		out = append(out, b)
	}
	return out, nil
}

type fakeRuntime struct {
	depth, cap int
}

func (f fakeRuntime) Depth() int { return f.depth }
func (f fakeRuntime) Cap() int   { return f.cap }

func seededReader() *fakeReader {
	reopenedAt := int64(1700000200000)
	return &fakeReader{
		counts: store.Counts{Systems: 2, Templates: 5, Baselines: 3, Findings: 4, Analyses: 7},
		systems: []store.SystemRow{
			{
				SystemID: "sys-1", TenantID: "tenant-a", CollectorVersion: "1.2.3",
				FirstSeen: 1700000000000, LastSeen: 1700000100000,
				Templates: 5, OpenFindings: 1, Findings: 2, Windows: 10, LLMCalls: 3, CostMicros: 4200,
			},
		},
		analyses: []store.AnalysisRow{
			{
				ID: "01ANALYSISID000000000000000", SystemID: "sys-1",
				WindowStart: 1700000000000, WindowEnd: 1700000900000,
				Gated: true, LLMCalled: true, Completed: true,
				GateReasons: []string{"new_template"},
				InputTokens: 100, OutputTokens: 50, CostMicros: 4200,
				Model: "gpt-4o-mini", DurationMs: 820,
			},
		},
		gate: []store.GateRow{
			{Reasons: []string{"new_template"}, Windows: 4, LLMCalls: 4, CostMicros: 8000},
			{Reasons: nil, Windows: 10, LLMCalls: 0, CostMicros: 0},
		},
		cost: []store.CostRow{
			{Day: "2026-08-20", Model: "gpt-4o-mini", Windows: 4, LLMCalls: 4, InputTokens: 400, OutputTokens: 200, CostMicros: 8000},
		},
		findings: []model.Finding{
			{
				ID: "01FINDINGID0000000000000000", SystemID: "sys-1", Fingerprint: "abcd1234",
				Severity: "critical", Title: "sshd failing repeatedly", Summary: "many failed logins",
				SuggestedAction: "check sshd config", Modules: []string{"sshd"}, Evidence: []string{"line one"},
				Status: "open", OccurrenceCount: 12, FirstSeen: 1700000000000, LastSeen: 1700000100000,
				ReopenedAt: &reopenedAt, LLMModel: "gpt-4o-mini", PromptVersion: "v1",
			},
			{
				ID: "01FINDINGID0000000000000001", SystemID: "sys-2", Fingerprint: "efgh5678",
				Severity: "low", Title: "disk usage crept up", Summary: "slow growth",
				SuggestedAction: "monitor", Modules: []string{""}, Evidence: []string{"line two"},
				Status: "stale", OccurrenceCount: 2, FirstSeen: 1700000000000, LastSeen: 1700000050000,
				LLMModel: "gpt-4o-mini", PromptVersion: "v1",
			},
		},
		templates: []store.TemplateRow{
			{SystemID: "sys-1", Template: "sshd: Failed password for USER from IP", ModuleID: "sshd", Category: "security", Priority: 5, TotalCount: 42, FirstSeen: 1700000000000, LastSeen: 1700000100000},
			{SystemID: "sys-1", Template: "runagent: heartbeat", ModuleID: "", Category: "", Priority: 1, TotalCount: 99, FirstSeen: 1700000000000, LastSeen: 1700000100000},
		},
		baselines: []store.BaselineRow{
			{SystemID: "sys-1", ModuleID: "sshd", Priority: 5, EWMARate: 3.14159, UpdatedAt: 1700000100000},
		},
	}
}

func newTestServer(t *testing.T, r Reader, rt Runtime) http.Handler {
	t.Helper()
	return newTestServerWithFeed(t, r, rt, nil)
}

// newTestServerWithFeed builds a read-only server: no writer, no admin key.
// Every existing (pre-allowlist-management) test relies on writes being
// unreachable, which is also the off-by-default behavior this helper is
// meant to exercise. Use newWriteTestServer for the write-route tests.
func newTestServerWithFeed(t *testing.T, r Reader, rt Runtime, feed Feed) http.Handler {
	t.Helper()
	return NewServer(r, rt, feed, testInfo(), nil, "")
}

// newWriteTestServer builds a server with the write routes enabled against
// w, authenticated with adminKey.
func newWriteTestServer(t *testing.T, r Reader, rt Runtime, feed Feed, w Writer, adminKey string) http.Handler {
	t.Helper()
	return NewServer(r, rt, feed, testInfo(), w, adminKey)
}

func testInfo() Info {
	return Info{
		StartedAt: 1700000000000,
		Workers:   4,
		Build:     "test-build",
		Config: []ConfigItem{
			{Name: "LLM_API_KEY", Value: "set"},
			{Name: "AUTH_PEPPER", Value: "set"},
			{Name: "DB_PATH", Value: "/tmp/insights.db"},
		},
	}
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
	{"/", "<h1>Status</h1>"},
	{"/systems", "<h1>Systems</h1>"},
	{"/findings", "<h1>Findings</h1>"},
	{"/analyses", "<h1>Analyses</h1>"},
	{"/gate", "<h1>Gate</h1>"},
	{"/cost", "<h1>Cost</h1>"},
	{"/templates", "<h1>Templates</h1>"},
	{"/baselines", "<h1>Baselines</h1>"},
	{"/blocklist", "<h1>Blocklist</h1>"},
	{"/threat-events", "<h1>Threat events</h1>"},
	{"/threat-stats", "<h1>Threat stats</h1>"},
	{"/allowlist-requests", "<h1>Allowlist requests</h1>"},
}

func TestRoutesOK(t *testing.T) {
	h := newTestServer(t, seededReader(), fakeRuntime{depth: 2, cap: 100})
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

func TestStaticStyleCSS(t *testing.T) {
	h := newTestServer(t, seededReader(), nil)
	rec := get(t, h, "/static/style.css")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "css") {
		t.Fatalf("Content-Type = %q, want something containing css", ct)
	}
	if !strings.Contains(rec.Body.String(), "--sev-high") {
		t.Fatalf("style.css body does not look like our overrides stylesheet")
	}
}

// TestStaticPicoCSS asserts the vendored Pico stylesheet is actually served
// (not just embedded) with a CSS content type -- layout.html links it
// first, and this is the base every page's look depends on.
func TestStaticPicoCSS(t *testing.T) {
	h := newTestServer(t, seededReader(), nil)
	rec := get(t, h, "/static/pico.min.css")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "css") {
		t.Fatalf("Content-Type = %q, want something containing css", ct)
	}
	if !strings.Contains(rec.Body.String(), "Pico CSS") {
		t.Fatalf("pico.min.css body does not look like Pico's stylesheet")
	}
}

func TestPOSTMethodNotAllowed(t *testing.T) {
	h := newTestServer(t, seededReader(), fakeRuntime{})
	paths := append([]string{"/static/style.css", "/static/pico.min.css"}, pathsOf(routes)...)
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, p, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("POST %s: status = %d, want 405", p, rec.Code)
			}
		})
	}
}

func pathsOf(rs []struct {
	path   string
	marker string
}) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.path
	}
	return out
}

func TestUnknownPathIs404(t *testing.T) {
	h := newTestServer(t, seededReader(), fakeRuntime{})
	rec := get(t, h, "/nonsense")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /nonsense: status = %d, want 404", rec.Code)
	}
}

func TestRefreshMeta(t *testing.T) {
	h := newTestServer(t, seededReader(), fakeRuntime{})

	cases := []struct {
		name      string
		target    string
		wantTag   bool
		wantValue string
	}{
		{"present positive", "/?refresh=10", true, "10"},
		{"absent", "/", false, ""},
		{"zero", "/?refresh=0", false, ""},
		{"negative", "/?refresh=-1", false, ""},
		{"non-numeric", "/?refresh=abc", false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := get(t, h, c.target)
			body := rec.Body.String()
			hasTag := strings.Contains(body, `http-equiv="refresh"`)
			if hasTag != c.wantTag {
				t.Fatalf("target %s: meta refresh present = %v, want %v", c.target, hasTag, c.wantTag)
			}
			if c.wantTag && !strings.Contains(body, `content="`+c.wantValue+`"`) {
				t.Fatalf("target %s: body missing content=%q", c.target, c.wantValue)
			}
		})
	}

	// The raw invalid value must never be reflected into the page, anywhere.
	rec := get(t, h, "/?refresh=abc")
	if strings.Contains(rec.Body.String(), "abc") {
		t.Fatalf("invalid refresh value %q was reflected into the body", "abc")
	}
	rec = get(t, h, "/?refresh=-1")
	if strings.Contains(rec.Body.String(), "refresh=-1") {
		t.Fatalf("invalid refresh value was reflected into the body")
	}
}

var (
	scriptRe = regexp.MustCompile(`(?i)<script`)
	jsURLRe  = regexp.MustCompile(`(?i)javascript:`)
	onAttrRe = regexp.MustCompile(`(?i)\bon[a-z]+\s*=`)
)

func assertNoJS(t *testing.T, label string, body []byte) {
	t.Helper()
	s := string(body)
	if scriptRe.Match(body) {
		t.Errorf("%s: contains a <script tag", label)
	}
	if jsURLRe.Match(body) {
		t.Errorf("%s: contains a javascript: URL", label)
	}
	if loc := onAttrRe.FindStringIndex(s); loc != nil {
		t.Errorf("%s: contains an event-handler attribute near %q", label, s[max(0, loc[0]-20):min(len(s), loc[1]+20)])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// TestNoJavaScript is the guard that keeps the zero-JS constraint from
// eroding later: every embedded template and asset, and every rendered
// page, must be free of <script, javascript: and on<event>= constructs.
func TestNoJavaScript(t *testing.T) {
	err := fs.WalkDir(assets, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, err := fs.ReadFile(assets, path)
		if err != nil {
			return err
		}
		assertNoJS(t, "embedded asset "+path, b)
		return nil
	})
	if err != nil {
		t.Fatalf("walking embedded assets: %v", err)
	}

	h := newTestServer(t, seededReader(), fakeRuntime{depth: 1, cap: 10})
	for _, rt := range routes {
		rec := get(t, h, rt.path)
		assertNoJS(t, "rendered page "+rt.path, rec.Body.Bytes())
	}
	rec := get(t, h, "/static/style.css")
	assertNoJS(t, "rendered /static/style.css", rec.Body.Bytes())
	rec = get(t, h, "/static/pico.min.css")
	assertNoJS(t, "rendered /static/pico.min.css", rec.Body.Bytes())
}

// TestSecretRedaction asserts this package cannot leak a secret value even
// when handed one: Info.Config is the caller's contract to have already
// redacted LLM_API_KEY / AUTH_PEPPER down to set/unset, and a raw secret
// that was never placed in Config must never appear in the rendered page.
func TestSecretRedaction(t *testing.T) {
	const decoySecret = "sk-live-do-not-leak-1234567890"

	h := NewServer(seededReader(), fakeRuntime{}, nil, Info{
		StartedAt: 1700000000000,
		Workers:   2,
		Build:     "test-build",
		Config: []ConfigItem{
			{Name: "LLM_API_KEY", Value: "set"},
			{Name: "AUTH_PEPPER", Value: "set (ephemeral)"},
		},
	}, nil, "")

	rec := get(t, h, "/")
	body := rec.Body.String()
	if strings.Contains(body, decoySecret) {
		t.Fatalf("status page leaked a secret value never present in Info.Config")
	}
	if !strings.Contains(body, "set") {
		t.Fatalf("status page did not render the redacted set/unset markers")
	}
}

func TestFindingsFilters(t *testing.T) {
	h := newTestServer(t, seededReader(), fakeRuntime{})

	rec := get(t, h, "/findings?severity=critical")
	body := rec.Body.String()
	if !strings.Contains(body, "sshd failing repeatedly") {
		t.Fatalf("severity=critical: expected finding missing")
	}
	if strings.Contains(body, "disk usage crept up") {
		t.Fatalf("severity=critical: unexpected low-severity finding present")
	}

	// An unknown filter value is ignored (treated as "no filter"), not
	// reflected into the selected <option> or passed through as a narrowing
	// filter.
	rec = get(t, h, "/findings?severity=bogus")
	body = rec.Body.String()
	if !strings.Contains(body, "sshd failing repeatedly") || !strings.Contains(body, "disk usage crept up") {
		t.Fatalf("severity=bogus: expected an unfiltered result set, got %q", body)
	}
	if strings.Contains(body, `value="bogus"`) {
		t.Fatalf("severity=bogus: raw invalid value was reflected into the page")
	}
}

func TestNilRuntimeDoesNotPanic(t *testing.T) {
	h := newTestServer(t, seededReader(), nil)
	rec := get(t, h, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "n/a") {
		t.Fatalf("expected the queue section to render n/a with a nil Runtime")
	}
}

func TestEmptyStoreRendersEveryPage(t *testing.T) {
	h := newTestServer(t, &fakeReader{}, nil)
	for _, rt := range routes {
		rec := get(t, h, rt.path)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s against an empty store: status = %d, want 200", rt.path, rec.Code)
		}
	}
}
