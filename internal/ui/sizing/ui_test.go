// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package sizing

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/sizing"
	sizingstore "github.com/nethesis/nethesis-insights/internal/store/sizing"
	"github.com/nethesis/nethesis-insights/internal/ui/chrome"
)

var errStore = errors.New("store unavailable")

// fakeReader is an in-package stand-in for the Reader slice of
// sizingstore.Store. It never touches a database, so this package's tests
// never wait on a real store.
type fakeReader struct {
	sizingCounts  sizingstore.SizingCounts
	sizingNodes   []sizingstore.SizingNodeUIRow
	sizingModules []sizingstore.SizingModuleUIRow
	sizingCohorts []sizingstore.SizingCohortRow
	sizingIngest  []sizingstore.SizingIngestRow

	err error // when set, every method returns this error instead
}

func (f *fakeReader) ListSizingNodes(_ context.Context, _ string, _ int) ([]sizingstore.SizingNodeUIRow, error) {
	return f.sizingNodes, f.err
}

func (f *fakeReader) ListSizingModules(_ context.Context, _ string, _ int) ([]sizingstore.SizingModuleUIRow, error) {
	return f.sizingModules, f.err
}

func (f *fakeReader) ListSizingCohorts(_ context.Context, _ string, _ int) ([]sizingstore.SizingCohortRow, error) {
	return f.sizingCohorts, f.err
}

func (f *fakeReader) SizingIngestStats(_ context.Context, _ int) ([]sizingstore.SizingIngestRow, error) {
	return f.sizingIngest, f.err
}

func (f *fakeReader) SizingCounts(_ context.Context) (sizingstore.SizingCounts, error) {
	return f.sizingCounts, f.err
}

func ptr(v float64) *float64 { return &v }

func testInfo() chrome.Info {
	return chrome.Info{
		StartedAt: 1700000000000,
		Build:     "test-build",
		Config: []chrome.ConfigItem{
			{Name: "DB_PATH", Value: "/tmp/sizing.db"},
		},
	}
}

func newTestServer(t *testing.T, r Reader) http.Handler {
	t.Helper()
	h, err := NewServer(r, chrome.Config{Info: testInfo()})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return h
}

func getPage(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

var routes = []struct {
	path   string
	marker string
}{
	{"/", "<h1>Sizing &mdash; nodes</h1>"},
	{"/cohorts", "<h1>Sizing &mdash; recommendations</h1>"},
	{"/status", "<h1>Status</h1>"},
}

func TestRoutesOK(t *testing.T) {
	h := newTestServer(t, &fakeReader{})
	for _, rt := range routes {
		t.Run(rt.path, func(t *testing.T) {
			rec := getPage(t, h, rt.path)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s: status = %d, want 200", rt.path, rec.Code)
			}
			if !strings.Contains(rec.Body.String(), rt.marker) {
				t.Fatalf("GET %s: body missing marker %q, got:\n%s", rt.path, rt.marker, rec.Body.String())
			}
		})
	}
}

// The shared chrome layout must identify this dashboard as sizingd's own --
// see chrome.Config.Name, set by this package's NewServer.
func TestPageIdentifiesAsSizingd(t *testing.T) {
	h := newTestServer(t, &fakeReader{})
	body := getPage(t, h, "/").Body.String()

	if !strings.Contains(body, "<title>sizingd operator UI</title>") {
		t.Fatalf("missing sizingd title, got:\n%s", body)
	}
	if !strings.Contains(body, "<strong>sizingd</strong>") {
		t.Fatalf("missing sizingd nav brand, got:\n%s", body)
	}
}

// sizingd has no write routes at all, so the footer must never claim writes
// are available.
func TestFooterNeverClaimsWrites(t *testing.T) {
	body := getPage(t, newTestServer(t, &fakeReader{}), "/").Body.String()
	if strings.Contains(body, "write routes require the admin key") {
		t.Fatalf("sizingd has no write routes; the footer must not claim otherwise:\n%s", body)
	}
}

func TestSizingPageRendersNodeAndThresholds(t *testing.T) {
	r := &fakeReader{
		sizingCounts: sizingstore.SizingCounts{Systems: 1, Nodes: 2, NodeDays: 40, Undersized: 1},
		sizingNodes: []sizingstore.SizingNodeUIRow{{
			SystemID: "sys-a", NodeID: 1, Day: 20698,
			MetricsPresent: true, SampleCoverage: 0.99,
			CPUCores: 4, MemTotalBytes: 8 << 30,
			RAMUtilP95: ptr(0.93), RAMUsedBytesP95: ptr(7.6e9),
			Pressure: ptr(62), PMem: ptr(60), TopAxis: sizing.AxisMem,
			Reasons: []string{sizing.ReasonRAMHeadroom},
			Verdict: sizing.VerdictUndersized, VerdictTopAxis: sizing.AxisMem,
		}},
		sizingModules: []sizingstore.SizingModuleUIRow{{
			SystemID: "sys-a", NodeID: 1, Day: 20698, Family: "mail",
			Instances: 1, FactsOK: 1, Workload: "mailboxes=210",
		}},
	}
	rec := getPage(t, newTestServer(t, r), "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"sys-a", "62", "undersized", "mailboxes=210", "7.1 GiB"} {
		if !strings.Contains(body, want) {
			t.Errorf("page is missing %q", want)
		}
	}
	// The threshold table is the honesty requirement: an uncalibrated number
	// rendered with no label attached is a guess presented as advice.
	if !strings.Contains(body, "guess") {
		t.Error("the threshold table must label its guesses")
	}
}

// An unscored node must not render as a low-pressure node: pressure NULL
// means the coverage gate refused to score, which is not the same as zero.
func TestSizingPageRendersUnscoredAsNotApplicable(t *testing.T) {
	r := &fakeReader{sizingNodes: []sizingstore.SizingNodeUIRow{{
		SystemID: "sys-off", NodeID: 1, Day: 20698, SampleCoverage: 0.2,
	}}}
	body := getPage(t, newTestServer(t, r), "/").Body.String()
	if !strings.Contains(body, "n/a") {
		t.Error("an unscored node must render as n/a, never as 0")
	}
	if !strings.Contains(body, `data-pressure="unscored"`) {
		t.Error("an unscored node must not be styled as calm")
	}
}

// An empty cohorts page is the correct output for a fleet below the floor,
// and it has to say so rather than looking like a broken page.
func TestCohortsPageSaysInsufficientDataWhenEmpty(t *testing.T) {
	body := getPage(t, newTestServer(t, &fakeReader{}), "/cohorts").Body.String()
	if !strings.Contains(body, "Not enough data yet") {
		t.Error("an empty cohorts page must say the fleet is below the floor")
	}
}

func TestCohortsPageRendersCensoredCount(t *testing.T) {
	r := &fakeReader{sizingCohorts: []sizingstore.SizingCohortRow{{
		CohortKind: sizing.CohortFamilySolo, CohortKey: "mail",
		Nodes: 50, DistinctSystems: 31, CensoredNodes: 20,
		RAMUsedP90: 9.5e9, MinDistinctSystems: 20, MinNodes: 30, WindowDays: 28,
	}}}
	body := getPage(t, newTestServer(t, r), "/cohorts").Body.String()
	// A censored-heavy cohort publishes with the count visible rather than a
	// silently low percentile -- 40% censored is the finding, not a footnote.
	if !strings.Contains(body, "40%") {
		t.Error("the censored share must be rendered")
	}
	if !strings.Contains(body, "Nodes running only this module") {
		t.Error("the solo group must be labelled as the quotable one")
	}
}

func TestStatusPageRendersCounts(t *testing.T) {
	r := &fakeReader{sizingCounts: sizingstore.SizingCounts{
		Systems: 4, Nodes: 9, NodeDays: 120, Cohorts: 2, Undersized: 1, AtRisk: 1, Unscored: 3,
	}}
	body := getPage(t, newTestServer(t, r), "/status").Body.String()
	for _, want := range []string{"4", "9", "120", "2"} {
		if !strings.Contains(body, want) {
			t.Errorf("/status is missing %q", want)
		}
	}
}

// A store failure is a 503, never a half-rendered page.
func TestSizingPagesReportStoreFailures(t *testing.T) {
	broken := &fakeReader{err: errStore}
	h := newTestServer(t, broken)

	for _, path := range []string{"/", "/cohorts", "/status"} {
		rec := getPage(t, h, path)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: got %d, want 503", path, rec.Code)
		}
	}
}

// Every page must render on a fresh deployment with nothing stored.
func TestSizingPagesRenderEmpty(t *testing.T) {
	h := newTestServer(t, &fakeReader{})

	for _, tc := range []struct{ path, want string }{
		{"/", "no sizing reports yet"},
		{"/cohorts", "Not enough data yet"},
	} {
		rec := getPage(t, h, tc.path)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: got %d, want 200", tc.path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), tc.want) {
			t.Fatalf("%s: missing the empty-state text %q", tc.path, tc.want)
		}
	}
}

func TestUnknownPathIs404(t *testing.T) {
	h := newTestServer(t, &fakeReader{})
	rec := getPage(t, h, "/nonsense")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /nonsense: status = %d, want 404", rec.Code)
	}
}

func TestPOSTMethodNotAllowed(t *testing.T) {
	h := newTestServer(t, &fakeReader{})
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
