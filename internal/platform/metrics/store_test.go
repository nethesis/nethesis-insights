// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package metrics

import (
	"strings"
	"testing"
)

func TestResultsArePreCreatedAndCounted(t *testing.T) {
	reg := NewRegistry(testService)
	r := NewResults(reg, "windows_total", "Windows by result.", "called", "gated_out")
	r.Inc("called")
	r.Add("gated_out", 3)
	r.Add("gated_out", 0)
	r.Add("gated_out", -1)

	body := scrapeRegistry(t, Handler(reg))
	for _, want := range []string{
		`svc_windows_total{result="called"} 1`,
		`svc_windows_total{result="gated_out"} 3`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape body missing %q", want)
		}
	}
}

func testStoreGauges(reg *Registry) *StoreGauges {
	return NewStoreGauges(reg,
		StoreGauge{Name: "active_systems", Help: "Systems."},
		StoreGauge{Name: "blocklist_entries", Help: "Entries."},
		StoreGauge{Name: "findings", Help: "Findings.", Label: "status", Values: []string{"open", "stale"}},
	)
}

func TestStoreGaugesExportTheLastReading(t *testing.T) {
	reg := NewRegistry(testService)
	g := testStoreGauges(reg)
	g.Set(StoreReading{"active_systems": {"": 1}})
	g.Set(StoreReading{
		"active_systems": {"": 42},
		// "stale" is omitted (exported at 0); "bogus" is outside the
		// vocabulary (never exported).
		"findings": {"open": 7, "bogus": 1},
	})

	body := scrapeRegistry(t, Handler(reg))
	for _, want := range []string{
		"svc_active_systems 42",
		`svc_findings{status="open"} 7`,
		`svc_findings{status="stale"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape body missing %q", want)
		}
	}
	if strings.Contains(body, "bogus") {
		t.Error("a label value outside the vocabulary was exported")
	}
	// A family the reading leaves out is absent rather than zero: "not
	// known yet" (the blocklist before its first pass) must not read as
	// "none".
	if strings.Contains(body, "svc_blocklist_entries") {
		t.Error("a family missing from the reading was exported")
	}
}

// Before the first pass has counted anything, nothing is exported.
func TestStoreGaugesAreAbsentBeforeTheFirstSet(t *testing.T) {
	reg := NewRegistry(testService)
	testStoreGauges(reg)

	body := scrapeRegistry(t, Handler(reg))
	for _, family := range []string{"svc_active_systems", "svc_blocklist_entries", "svc_findings"} {
		if strings.Contains(body, family) {
			t.Errorf("%s exported before any reading was set", family)
		}
	}
}
