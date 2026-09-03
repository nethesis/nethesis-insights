// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package sizing

import (
	"math"
	"testing"
)

// The class is DERIVED, not looked up, because the prior as originally given
// was already wrong in one instructive case: "samba without file shares =
// lite, with shares = medium" is a workload distinction, not a family one.
func TestClassOfDerivesSambaFromWorkload(t *testing.T) {
	if got := ClassOf("samba", nil); got != ClassLite {
		t.Errorf("samba with no shares = %q, want %q", got, ClassLite)
	}
	if got := ClassOf("samba", map[string]float64{"shared_folders": 0}); got != ClassLite {
		t.Errorf("samba with zero shares = %q, want %q", got, ClassLite)
	}
	if got := ClassOf("samba", map[string]float64{"shared_folders": 3}); got != ClassMedium {
		t.Errorf("samba with shares = %q, want %q", got, ClassMedium)
	}
}

// ns8-samba's real get-facts (imageroot/actions/get-facts/50facts) emits
// shared_folders_count, not shared_folders -- as written, ClassOf tested a
// key that never arrives on the wire and samba could never reach ClassMedium.
// The legacy key is kept working too, for an older or third-party reporter.
func TestClassOfAcceptsSambaSharedFoldersCount(t *testing.T) {
	if got := ClassOf("samba", map[string]float64{"shared_folders_count": 3}); got != ClassMedium {
		t.Errorf("samba with shared_folders_count = %q, want %q", got, ClassMedium)
	}
	if got := ClassOf("samba", map[string]float64{"shared_folders_count": 0}); got != ClassLite {
		t.Errorf("samba with zero shared_folders_count = %q, want %q", got, ClassLite)
	}
	if got := ClassOf("samba", map[string]float64{"shared_folders": 3}); got != ClassMedium {
		t.Errorf("samba with legacy shared_folders key = %q, want %q", got, ClassMedium)
	}
}

// A module nobody has classified must NOT be silently classed lite: that
// would quietly exclude it from every solo cohort's "plus lite modules"
// allowance and make the recommendation wrong for the product nobody had got
// round to classifying.
func TestClassOfDefaultsToUnknownNotLite(t *testing.T) {
	if got := ClassOf("somefutureproduct", nil); got != ClassUnknown {
		t.Errorf("an unclassified family = %q, want %q", got, ClassUnknown)
	}
	nonLite := NonLiteFamilies(map[string]map[string]float64{"somefutureproduct": nil})
	if len(nonLite) != 1 {
		t.Error("an unclassified family must count as non-lite")
	}
}

func TestCohortKeying(t *testing.T) {
	workloads := map[string]map[string]float64{
		"mail":     {"mailboxes": 210},
		"traefik":  {"routes": 12},
		"openldap": nil,
	}
	nonLite := NonLiteFamilies(workloads)
	if len(nonLite) != 1 || nonLite[0] != "mail" {
		t.Fatalf("non-lite = %v, want [mail]", nonLite)
	}
	if !IsSolo("mail", nonLite) {
		t.Error("mail alongside only lite modules must count as solo")
	}
	if IsSolo("traefik", nonLite) {
		t.Error("a lite family is never the solo family")
	}

	both := NonLiteFamilies(map[string]map[string]float64{
		"nethvoice": nil, "mail": nil, "traefik": nil,
	})
	if IsSolo("mail", both) {
		t.Error("mail co-tenanted with nethvoice is not solo")
	}
}

// Censoring is the defect the source draft does not see. An undersized node's
// observed demand is capped by the memory it has, which is systematic bias
// rather than noise -- no volume of data removes it.
func TestCensored(t *testing.T) {
	zero := 0.0
	cases := []struct {
		name                 string
		ramUtil, swapIn, oom *float64
		want                 bool
	}{
		{"comfortable", f(0.40), &zero, &zero, false},
		{"just under the censor line", f(CensorRAMUtil - 0.001), &zero, &zero, false},
		{"at the censor line", f(CensorRAMUtil), &zero, &zero, true},
		{"one page read back from swap", f(0.40), f(0.1), &zero, true},
		{"one OOM kill", f(0.40), &zero, f(1), true},
		{"nothing measured", nil, nil, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Censored(tc.ramUtil, tc.swapIn, tc.oom); got != tc.want {
				t.Errorf("Censored = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestQuantile(t *testing.T) {
	if _, ok := Quantile(nil, 0.9); ok {
		t.Error("a percentile of nothing must not be publishable")
	}
	if v, ok := Quantile([]float64{7}, 0.9); !ok || v != 7 {
		t.Errorf("Quantile of one value = %v, want 7", v)
	}

	values := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	median, _ := Quantile(values, 0.5)
	if math.Abs(median-5.5) > 1e-9 {
		t.Errorf("median = %v, want 5.5", median)
	}
	p90, _ := Quantile(values, 0.9)
	if math.Abs(p90-9.1) > 1e-9 {
		t.Errorf("p90 = %v, want 9.1", p90)
	}
	// Sorts a copy: the caller's slice must not be reordered under it.
	shuffled := []float64{5, 1, 4, 2, 3}
	_, _ = Quantile(shuffled, 0.5)
	if shuffled[0] != 5 {
		t.Error("Quantile reordered its input")
	}
}

// p90 across days, not the median: a 28-day window holds eight weekend days
// on which a business workload is idle, and the median then reads a mail
// server about 25 % low.
func TestReduceNodeUsesTheBusyDays(t *testing.T) {
	// Twenty business days climbing from 6 to 8 GiB, eight idle weekend days
	// at 1 GiB -- the shape a real business workload has.
	var daily []float64
	for i := 0; i < 20; i++ {
		daily = append(daily, 6e9+float64(i)*1e8)
	}
	for i := 0; i < 8; i++ {
		daily = append(daily, 1e9)
	}
	reduced, ok := ReduceNode(daily)
	if !ok {
		t.Fatal("a node with 28 days must reduce")
	}
	if reduced < 7.5e9 {
		t.Errorf("reduced to %v; the peak the hardware must survive is what matters", reduced)
	}
	median, _ := Quantile(daily, 0.5)
	if reduced <= median {
		t.Error("the p90 reduction must sit above the median")
	}
}
