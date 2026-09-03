// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/sizing"
	"github.com/nethesis/nethesis-insights/internal/store"
)

func (f *fakeReader) ListSizingNodes(_ context.Context, systemID string, limit int) ([]store.SizingNodeUIRow, error) {
	return f.sizingNodes, f.err
}

func (f *fakeReader) ListSizingModules(_ context.Context, systemID string, limit int) ([]store.SizingModuleUIRow, error) {
	return f.sizingModules, f.err
}

func (f *fakeReader) ListSizingCohorts(_ context.Context, kind string, limit int) ([]store.SizingCohortRow, error) {
	return f.sizingCohorts, f.err
}

func (f *fakeReader) SizingIngestStats(_ context.Context, limit int) ([]store.SizingIngestRow, error) {
	return f.sizingIngest, f.err
}

func (f *fakeReader) SizingCounts(_ context.Context) (store.SizingCounts, error) {
	return f.sizingCounts, f.err
}

func ptr(v float64) *float64 { return &v }

func getPage(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestSizingPageRendersNodeAndThresholds(t *testing.T) {
	r := &fakeReader{
		sizingCounts: store.SizingCounts{Systems: 1, Nodes: 2, NodeDays: 40, Undersized: 1},
		sizingNodes: []store.SizingNodeUIRow{{
			SystemID: "sys-a", NodeID: 1, Day: 20698,
			MetricsPresent: true, SampleCoverage: 0.99,
			CPUCores: 4, MemTotalBytes: 8 << 30,
			RAMUtilP95: ptr(0.93), RAMUsedBytesP95: ptr(7.6e9),
			Pressure: ptr(62), PMem: ptr(60), TopAxis: sizing.AxisMem,
			Reasons: []string{sizing.ReasonRAMHeadroom},
			Verdict: sizing.VerdictUndersized, VerdictTopAxis: sizing.AxisMem,
		}},
		sizingModules: []store.SizingModuleUIRow{{
			SystemID: "sys-a", NodeID: 1, Day: 20698, Family: "mail",
			Instances: 1, FactsOK: 1, Workload: "mailboxes=210",
		}},
	}
	rec := getPage(t, newTestServer(t, r, nil), "/sizing")
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
	r := &fakeReader{sizingNodes: []store.SizingNodeUIRow{{
		SystemID: "sys-off", NodeID: 1, Day: 20698, SampleCoverage: 0.2,
	}}}
	body := getPage(t, newTestServer(t, r, nil), "/sizing").Body.String()
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
	body := getPage(t, newTestServer(t, &fakeReader{}, nil), "/cohorts").Body.String()
	if !strings.Contains(body, "Not enough data yet") {
		t.Error("an empty cohorts page must say the fleet is below the floor")
	}
}

func TestCohortsPageRendersCensoredCount(t *testing.T) {
	r := &fakeReader{sizingCohorts: []store.SizingCohortRow{{
		CohortKind: sizing.CohortFamilySolo, CohortKey: "mail",
		Nodes: 50, DistinctSystems: 31, CensoredNodes: 20,
		RAMUsedP90: 9.5e9, MinDistinctSystems: 20, MinNodes: 30, WindowDays: 28,
	}}}
	body := getPage(t, newTestServer(t, r, nil), "/cohorts").Body.String()
	// A censored-heavy cohort publishes with the count visible rather than a
	// silently low percentile -- 40% censored is the finding, not a footnote.
	if !strings.Contains(body, "40%") {
		t.Error("the censored share must be rendered")
	}
	if !strings.Contains(body, "Nodes running only this module") {
		t.Error("the solo group must be labelled as the quotable one")
	}
}
