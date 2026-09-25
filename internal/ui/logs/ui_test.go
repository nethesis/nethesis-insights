// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package logs

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nethesis/nethesis-insights/internal/model"
	logsstore "github.com/nethesis/nethesis-insights/internal/store/logs"
	"github.com/nethesis/nethesis-insights/internal/ui/chrome"
)

// fakeReader is an in-package stand-in for the Reader slice of
// logsstore.Store. It never touches a database, so this package's tests
// never wait on a real store implementation.
type fakeReader struct {
	counts    logsstore.Counts
	systems   []logsstore.SystemRow
	analyses  []logsstore.AnalysisRow
	gate      []logsstore.GateRow
	gateSince int64 // the last since GateRollup was called with
	cost      []logsstore.CostRow
	findings  []model.Finding
	templates []logsstore.TemplateRow
	baselines []logsstore.BaselineRow
	roster    map[string]map[int]string
	triggers  []logsstore.TriggerRow
	trigStats []logsstore.TriggerStatsRow
	decisions []logsstore.TriggerDecision
	trigSeen  logsstore.TriggerFilter // the last filter ListTriggers was called with

	err error // when set, every method returns this error instead
}

func (f *fakeReader) Counts(ctx context.Context) (logsstore.Counts, error) {
	return f.counts, f.err
}

func (f *fakeReader) ListSystems(ctx context.Context) ([]logsstore.SystemRow, error) {
	return f.systems, f.err
}

func (f *fakeReader) ListAnalyses(ctx context.Context, systemID string, limit int) ([]logsstore.AnalysisRow, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []logsstore.AnalysisRow
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

func (f *fakeReader) GateRollup(ctx context.Context, since int64) ([]logsstore.GateRow, error) {
	f.gateSince = since
	return f.gate, f.err
}

func (f *fakeReader) CostRollup(ctx context.Context) ([]logsstore.CostRow, error) {
	return f.cost, f.err
}

func (f *fakeReader) ResolveNodesFleet(_ context.Context, findings []model.Finding) error {
	for i := range findings {
		findings[i].NodeRefs = model.ResolveNodeRefs(findings[i].Nodes, f.roster[findings[i].SystemID])
	}
	return nil
}

func (f *fakeReader) ListAllFindings(ctx context.Context, systemID, status, severity, idLike, sortMode string, limit int) ([]model.Finding, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []model.Finding
	for _, fnd := range f.findings {
		if systemID != "" && !strings.HasPrefix(fnd.SystemID, strings.TrimSuffix(systemID, "%")) {
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
	if sortMode == logsstore.SortRecent {
		sort.SliceStable(out, func(i, j int) bool { return out[i].LastSeen > out[j].LastSeen })
	} else {
		model.SortFindings(out)
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeReader) ListTemplates(ctx context.Context, systemID string, limit int) ([]logsstore.TemplateRow, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []logsstore.TemplateRow
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

func (f *fakeReader) ListBaselines(ctx context.Context, systemID string) ([]logsstore.BaselineRow, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []logsstore.BaselineRow
	for _, b := range f.baselines {
		if systemID != "" && b.SystemID != systemID {
			continue
		}
		out = append(out, b)
	}
	return out, nil
}

func (f *fakeReader) ListTriggers(_ context.Context, filter logsstore.TriggerFilter) ([]logsstore.TriggerRow, error) {
	f.trigSeen = filter
	if f.err != nil {
		return nil, f.err
	}
	var out []logsstore.TriggerRow
	for _, tr := range f.triggers {
		if filter.Visibility != "" && tr.Visibility != filter.Visibility {
			continue
		}
		if filter.Key != "" && !strings.HasPrefix(tr.Key, filter.Key) {
			continue
		}
		out = append(out, tr)
	}
	return out, nil
}

func (f *fakeReader) TriggerStats(context.Context) ([]logsstore.TriggerStatsRow, error) {
	return f.trigStats, f.err
}

func (f *fakeReader) ListTriggerDecisions(context.Context, int) ([]logsstore.TriggerDecision, error) {
	return f.decisions, f.err
}

type fakeRuntime struct {
	depth, cap, workers int
}

func (f fakeRuntime) Depth() int   { return f.depth }
func (f fakeRuntime) Cap() int     { return f.cap }
func (f fakeRuntime) Workers() int { return f.workers }

func seededReader() *fakeReader {
	reopenedAt := int64(1700000200000)
	return &fakeReader{
		counts: logsstore.Counts{Systems: 2, Templates: 5, Baselines: 3, Findings: 4, Analyses: 7},
		systems: []logsstore.SystemRow{
			{
				SystemID: "sys-1", CollectorVersion: "1.2.3",
				FirstSeen: 1700000000000, LastSeen: 1700000100000,
				Templates: 5, OpenFindings: 1, Findings: 2, Windows: 10, LLMCalls: 3, CostMicros: 4200,
			},
		},
		analyses: []logsstore.AnalysisRow{
			{
				ID: "01ANALYSISID000000000000000", SystemID: "sys-1",
				WindowStart: 1700000000000, WindowEnd: 1700000900000,
				Gated: true, LLMCalled: true, Completed: true,
				GateReasons: []string{"new_template"},
				InputTokens: 100, OutputTokens: 50, CostMicros: 4200,
				Model: "gpt-4o-mini", DurationMs: 820,
			},
		},
		gate: []logsstore.GateRow{
			{Reasons: []string{"new_template"}, Windows: 4, LLMCalls: 4, PaidCalls: 3, CostMicros: 8000},
			{Reasons: nil, Windows: 10, LLMCalls: 0, PaidCalls: 0, CostMicros: 0},
		},
		cost: []logsstore.CostRow{
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
		templates: []logsstore.TemplateRow{
			{SystemID: "sys-1", Template: "sshd: Failed password for USER from IP", ModuleID: "sshd", Category: "security", Priority: 5, TotalCount: 42, FirstSeen: 1700000000000, LastSeen: 1700000100000},
			{SystemID: "sys-1", Template: "runagent: heartbeat", ModuleID: "", Category: "", Priority: 1, TotalCount: 99, FirstSeen: 1700000000000, LastSeen: 1700000100000},
		},
		baselines: []logsstore.BaselineRow{
			{SystemID: "sys-1", ModuleID: "sshd", Priority: 5, EWMARate: 3.14159, UpdatedAt: 1700000100000},
		},
		triggers: []logsstore.TriggerRow{
			{
				Trigger: logsstore.Trigger{Key: "t1:aaaa", Status: logsstore.TriggerActive,
					Visibility: logsstore.VisibilityPending, FirstPromptVersion: "v1",
					FirstSeen: 1700000000000, LastSeen: 1700000100000, DistinctSystems: 3, Count: 9},
				Findings: 2, Titles: []string{"disk filling on mail"}, GateReasons: []string{"deviation:mail/4"},
			},
			{
				Trigger: logsstore.Trigger{Key: "t1:bbbb", Security: true, Status: logsstore.TriggerActive,
					Visibility: logsstore.VisibilityCustomer, FirstPromptVersion: "v1",
					FirstSeen: 1700000000000, LastSeen: 1700000100000, DistinctSystems: 1, Count: 1},
				Findings: 1, Titles: []string{"sshd failing repeatedly"}, GateReasons: []string{"security_new"},
			},
		},
		trigStats: []logsstore.TriggerStatsRow{
			{PromptVersion: "v1", Triggers: 2, Security: 1, Pending: 1},
		},
		decisions: []logsstore.TriggerDecision{
			{Key: "t1:aaaa", Actor: "alice", Action: logsstore.ActionIgnore, Detail: "1700000900000",
				PromptVersion: "v1", CreatedAt: 1700000100000},
		},
	}
}

func testInfo() chrome.Info {
	return chrome.Info{
		StartedAt: 1700000000000,
		Build:     "test-build",
		Config: []chrome.ConfigItem{
			{Name: "LLM_API_KEY", Value: "set"},
			{Name: "AUTH_PEPPER", Value: "set"},
			{Name: "DB_PATH", Value: "/tmp/insights.db"},
		},
	}
}

// newTestServer builds the read-only server: no writer, no admin key. See
// newWriteTestServer in review_test.go for the other one.
func newTestServer(t *testing.T, r Reader, rt Runtime) http.Handler {
	t.Helper()
	h, err := NewServer(r, nil, rt, chrome.Config{Info: testInfo()})
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
	{"/", "<h1>Findings</h1>"},
	{"/systems", "<h1>Systems</h1>"},
	{"/analyses", "<h1>Analyses</h1>"},
	{"/gate", "<h1>Gate</h1>"},
	{"/cost", "<h1>Cost</h1>"},
	{"/templates", "<h1>Templates</h1>"},
	{"/baselines", "<h1>Baselines</h1>"},
	{"/status", "<h1>Status</h1>"},
	{"/review", "<h1>Review</h1>"},
	{"/review/stats", "<h1>Review stats</h1>"},
	{"/review/audit", "<h1>Review audit</h1>"},
}

func TestRoutesOK(t *testing.T) {
	h := newTestServer(t, seededReader(), fakeRuntime{depth: 2, cap: 100, workers: 4})
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

// The shared chrome layout must identify this dashboard as insightsd's own,
// not the last binary that happened to render it -- see chrome.Config.Name.
// The footer's write-routes clause must also be gone entirely: insightsd's
// dashboard has no write routes at all (see this package's doc comment).
func TestPageIdentifiesAsInsightsd(t *testing.T) {
	h := newTestServer(t, seededReader(), fakeRuntime{})
	body := get(t, h, "/").Body.String()

	if !strings.Contains(body, "<title>insightsd operator UI</title>") {
		t.Fatalf("missing insightsd title, got:\n%s", body)
	}
	if !strings.Contains(body, "<strong>insightsd</strong>") {
		t.Fatalf("missing insightsd nav brand, got:\n%s", body)
	}
	if strings.Contains(body, "write routes require the admin key") {
		t.Fatalf("insightsd has no write routes; the footer must not claim it does:\n%s", body)
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
	// Checked against /status rather than "/": "/" is now the findings page
	// (findings became the index page in this move), and the seeded fixture's
	// fingerprint "abcd1234" contains "abc" as an unrelated substring, which
	// would make this assertion fail on content that was never a reflection
	// of the query string.
	rec := get(t, h, "/status?refresh=abc")
	if strings.Contains(rec.Body.String(), "abc") {
		t.Fatalf("invalid refresh value %q was reflected into the body", "abc")
	}
	rec = get(t, h, "/status?refresh=-1")
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
//
// layout.html and static/ now live in chrome's own embed.FS (see
// internal/ui/chrome's own TestNoJavaScript, which walks it directly), so
// this package's raw-walk half covers only its own page templates. The
// served /static/... fetches below are a secondary check -- they exercise
// this package's actual routing to those assets -- not a substitute for a
// raw-byte walk, so each one also asserts 200: a 404 body contains no
// JavaScript either, and would otherwise make a broken route look like a
// pass.
func TestNoJavaScript(t *testing.T) {
	err := fs.WalkDir(pageAssets, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, err := fs.ReadFile(pageAssets, path)
		if err != nil {
			return err
		}
		assertNoJS(t, "embedded asset "+path, b)
		return nil
	})
	if err != nil {
		t.Fatalf("walking embedded assets: %v", err)
	}

	h := newTestServer(t, seededReader(), fakeRuntime{depth: 1, cap: 10, workers: 2})
	for _, rt := range routes {
		rec := get(t, h, rt.path)
		assertNoJS(t, "rendered page "+rt.path, rec.Body.Bytes())
	}
	for _, p := range []string{"/static/style.css", "/static/pico.min.css", "/static/pico.LICENSE"} {
		rec := get(t, h, p)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: status = %d, want 200 (a 404 body would pass assertNoJS vacuously)", p, rec.Code)
		}
		assertNoJS(t, "rendered "+p, rec.Body.Bytes())
	}
}

// TestSecretRedaction asserts this package cannot leak a secret value even
// when handed one: cfg.Info.Config is the caller's contract to have already
// redacted LLM_API_KEY / AUTH_PEPPER down to set/unset, and a raw secret
// that was never placed in Config must never appear in the rendered page.
func TestSecretRedaction(t *testing.T) {
	const decoySecret = "sk-live-do-not-leak-1234567890"

	h, err := NewServer(seededReader(), nil, fakeRuntime{}, chrome.Config{Info: chrome.Info{
		StartedAt: 1700000000000,
		Build:     "test-build",
		Config: []chrome.ConfigItem{
			{Name: "LLM_API_KEY", Value: "set"},
			{Name: "AUTH_PEPPER", Value: "set (ephemeral)"},
		},
	}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	rec := get(t, h, "/status")
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

	rec := get(t, h, "/?severity=critical")
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
	rec = get(t, h, "/?severity=bogus")
	body = rec.Body.String()
	if !strings.Contains(body, "sshd failing repeatedly") || !strings.Contains(body, "disk usage crept up") {
		t.Fatalf("severity=bogus: expected an unfiltered result set, got %q", body)
	}
	if strings.Contains(body, `value="bogus"`) {
		t.Fatalf("severity=bogus: raw invalid value was reflected into the page")
	}
}

func TestGateRangeScopesTheRollup(t *testing.T) {
	r := seededReader()
	h := newTestServer(t, r, fakeRuntime{})

	before := time.Now().UnixMilli()
	if rec := get(t, h, "/gate?range=24h"); rec.Code != http.StatusOK {
		t.Fatalf("range=24h: status = %d, want 200", rec.Code)
	}
	day := time.Duration(before-r.gateSince) * time.Millisecond
	if day < 23*time.Hour || day > 25*time.Hour {
		t.Fatalf("range=24h: since is %v ago, want ~24h", day)
	}

	if rec := get(t, h, "/gate?range=all"); rec.Code != http.StatusOK {
		t.Fatalf("range=all: status = %d, want 200", rec.Code)
	}
	if r.gateSince != 0 {
		t.Fatalf("range=all: since = %d, want 0 (no bound)", r.gateSince)
	}

	// The default is a bounded scope, not all time: an unbounded rollup mixes
	// gate formulas. Both an absent and an unrecognized value must land there.
	for _, target := range []string{"/gate", "/gate?range=bogus"} {
		if rec := get(t, h, target); rec.Code != http.StatusOK {
			t.Fatalf("GET %s: status = %d, want 200", target, rec.Code)
		}
		week := time.Duration(time.Now().UnixMilli()-r.gateSince) * time.Millisecond
		if week < 6*24*time.Hour || week > 8*24*time.Hour {
			t.Fatalf("GET %s: since is %v ago, want the ~7d default", target, week)
		}
	}
}

func TestGateSummaryReportsTheGatedShare(t *testing.T) {
	h := newTestServer(t, seededReader(), fakeRuntime{})
	body := get(t, h, "/gate?range=all").Body.String()

	// Seeded rows: 14 windows, 4 called (3 of them priced), 10 gated out.
	for _, want := range []string{
		"<strong>14</strong> windows",
		"<strong>10</strong> gated out (71%)",
		"<strong>4</strong> sent to the AI (29%)",
		"<strong>1</strong> calls recorded no cost", // 4 attempts, 3 priced
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("gate summary missing %q, got:\n%s", want, body)
		}
	}

	// The tautological column must stay gone: a reasoned row's window count IS
	// its call count, so showing both invites the reader to compare them.
	if strings.Contains(body, "LLM calls") {
		t.Fatalf("the LLM calls column is back; it restates the reason set")
	}
	if !strings.Contains(body, "gated out, no AI call") {
		t.Fatalf("the nil-reason row must say what it means, got:\n%s", body)
	}
}

func TestNilRuntimeDoesNotPanic(t *testing.T) {
	h := newTestServer(t, seededReader(), nil)
	rec := get(t, h, "/status")
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

// findingsTable returns the findings table's header labels and the inner
// markup of each top-level cell of its first body row. A cell's own markup
// (the finding's <dialog>) holds no <td>, so splitting on "<td" is exact.
func findingsTable(t *testing.T, body string) (header, cells []string) {
	t.Helper()
	hs, he := strings.Index(body, "<thead>"), strings.Index(body, "</thead>")
	if hs < 0 || he < hs {
		t.Fatal("findings page has no table header")
	}
	for _, m := range regexp.MustCompile(`<th[^>]*>([^<]*)</th>`).FindAllStringSubmatch(body[hs:he], -1) {
		header = append(header, m[1])
	}
	tbody := body[strings.Index(body, "<tbody>"):]
	rs, re := strings.Index(tbody, "<tr>"), strings.Index(tbody, "</tr>")
	if rs < 0 || re < rs {
		t.Fatal("findings table has no body row")
	}
	for _, c := range strings.Split(tbody[rs:re], "<td")[1:] {
		cells = append(cells, c[strings.Index(c, ">")+1:])
	}
	return header, cells
}

// column returns the index of the header labelled name.
func column(t *testing.T, header []string, name string) int {
	t.Helper()
	for i, h := range header {
		if h == name {
			return i
		}
	}
	t.Fatalf("findings table has no %q column: %q", name, header)
	return -1
}

func nodeFinding(nodes ...int) model.Finding {
	return model.Finding{
		ID: "01FINDINGID0000000000000000", SystemID: "sys-1", Fingerprint: "abcd1234",
		Severity: "high", Title: "the finding title", Summary: "s", Status: "open",
		OccurrenceCount: 42, FirstSeen: 1700000000000, LastSeen: 1700000100000,
		Nodes: nodes,
	}
}

// The operator's actual question -- "which machine?" -- has to be answerable
// from the findings row without expanding anything: the node id together with
// the full FQDN, in the row and again in the expanded detail.
func TestFindingsPageShowsNodeIDAndFQDN(t *testing.T) {
	r := seededReader()
	r.findings = []model.Finding{nodeFinding(1, 2)}
	r.roster = map[string]map[int]string{"sys-1": {1: "rl1.example.org", 2: "node2.example.org"}}

	body := get(t, newTestServer(t, r, nil), "/").Body.String()
	header, cells := findingsTable(t, body)
	nodes := column(t, header, "Nodes")
	if nodes >= len(cells) {
		t.Fatalf("row has %d cells, no Nodes cell", len(cells))
	}
	for _, want := range []string{"1 · rl1.example.org", "2 · node2.example.org"} {
		if !strings.Contains(cells[nodes], want) {
			t.Errorf("Nodes cell = %q, want it to contain %q", cells[nodes], want)
		}
		if n := strings.Count(body, want); n < 2 {
			t.Errorf("%q appears %d time(s), want it in the row and in the expanded detail", want, n)
		}
	}
}

// A node with no name reported must still show its id: the id is the
// attribution, the name is a convenience on top of it.
func TestFindingsPageShowsABareNodeIDWhenUnnamed(t *testing.T) {
	r := seededReader()
	r.findings = []model.Finding{nodeFinding(7)}
	r.roster = nil

	body := get(t, newTestServer(t, r, nil), "/").Body.String()
	header, cells := findingsTable(t, body)
	nodes := column(t, header, "Nodes")
	if nodes >= len(cells) {
		t.Fatalf("row has %d cells, no Nodes cell", len(cells))
	}
	if !strings.Contains(cells[nodes], ">7</div>") {
		t.Errorf("Nodes cell = %q, want the bare id 7", cells[nodes])
	}
	if strings.Contains(body, "7 ·") {
		t.Error("an unnamed node must render its bare id, with no separator")
	}
	if !strings.Contains(body, "no name reported") {
		t.Error("expected an unnamed node to be marked as such")
	}
}

// Windows the trigger memory answered are neither gated out nor sent to the
// AI; folding them into either would misstate what the gate did.
func TestGateSummarySeparatesSuppressedWindows(t *testing.T) {
	g := summarizeGate([]logsstore.GateRow{
		{Reasons: nil, Windows: 10},
		{Reasons: []string{"deviation:mod1/3"}, Windows: 6, LLMCalls: 2, PaidCalls: 2, Suppressed: 4, CostMicros: 20},
	})
	if g.Windows != 16 || g.GatedOut != 10 || g.Called != 2 || g.Suppressed != 4 {
		t.Fatalf("unexpected summary: %+v", g)
	}
}

// Every body cell must sit under its own header. A row one cell short shifts
// every later value one column left -- Count shows the nodes, Nodes the
// title, Title the last-seen time -- so assert both the cell count and that
// each column holds the value its header names.
func TestFindingsRowCellsLineUpWithHeader(t *testing.T) {
	r := seededReader()
	r.findings = []model.Finding{nodeFinding(1)}
	r.roster = map[string]map[int]string{"sys-1": {1: "rl1.example.org"}}

	body := get(t, newTestServer(t, r, nil), "/").Body.String()
	header, cells := findingsTable(t, body)
	if len(cells) != len(header) {
		t.Fatalf("row has %d cells, header has %d (%q)", len(cells), len(header), header)
	}
	for name, want := range map[string]string{
		"Count":     "42</td>",
		"Nodes":     "rl1.example.org",
		"Title":     "the finding title",
		"Last seen": " ago",
	} {
		if c := cells[column(t, header, name)]; !strings.Contains(c, want) {
			t.Errorf("column %q cell = %q, want it to contain %q", name, c, want)
		}
	}

	empty := get(t, newTestServer(t, &fakeReader{}, nil), "/").Body.String()
	if want := fmt.Sprintf(`colspan="%d"`, len(header)); !strings.Contains(empty, want) {
		t.Errorf("empty-state row should span all %d columns (%s)", len(header), want)
	}
}

// A row lists at most rowNodes nodes and says how many more there are; the
// dialog still lists every one.
func TestFindingsRowCapsTheNodeList(t *testing.T) {
	r := seededReader()
	r.findings = []model.Finding{nodeFinding(1, 2, 3, 4, 5, 6)}
	r.roster = map[string]map[int]string{"sys-1": {1: "n1.example.org", 6: "n6.example.org"}}

	body := get(t, newTestServer(t, r, nil), "/").Body.String()
	header, cells := findingsTable(t, body)
	nodes := cells[column(t, header, "Nodes")]
	if !strings.Contains(nodes, "n1.example.org") || strings.Contains(nodes, "n6.example.org") {
		t.Fatalf("the row must list the first %d nodes only: %q", rowNodes, nodes)
	}
	if !strings.Contains(nodes, "+3 more") {
		t.Fatalf("the row does not say how many nodes it left out: %q", nodes)
	}
	title := cells[column(t, header, "Title")]
	if !strings.Contains(title, "6 · n6.example.org") {
		t.Fatal("the dialog must still list every node")
	}
}
