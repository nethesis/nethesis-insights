// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package sizing

import (
	"math"
	"testing"
)

// The platform test is DERIVED, not a plain lookup, because samba has two
// roles: the account provider (platform) and, once shares are configured, a
// file server (a workload somebody chose). That is a workload distinction, not
// a family one.
func TestIsPlatformDerivesSambaFromWorkload(t *testing.T) {
	if !IsPlatform("samba", nil) {
		t.Error("samba with no shares is the account provider, which is platform")
	}
	if !IsPlatform("samba", map[string]float64{"shared_folders": 0}) {
		t.Error("samba with zero shares is still just the account provider")
	}
	if IsPlatform("samba", map[string]float64{"shared_folders": 3}) {
		t.Error("samba with shares is a file server, which is a chosen workload")
	}
}

// ns8-samba's real get-facts (imageroot/actions/get-facts/50facts) emits
// shared_folders_count, not shared_folders -- keyed on the wrong name, samba
// with shares would silently stay platform and contaminate solo cohorts. The
// legacy key is kept working too, for an older or third-party reporter.
func TestIsPlatformAcceptsSambaSharedFoldersCount(t *testing.T) {
	if IsPlatform("samba", map[string]float64{"shared_folders_count": 3}) {
		t.Error("shared_folders_count must take samba out of platform")
	}
	if !IsPlatform("samba", map[string]float64{"shared_folders_count": 0}) {
		t.Error("zero shared_folders_count leaves samba as platform")
	}
	if IsPlatform("samba", map[string]float64{"shared_folders": 3}) {
		t.Error("the legacy shared_folders key must still be honoured")
	}
}

// This is the executable form of the bug that made family_solo unreachable:
// every NS8 cluster runs these, so if any one of them counts as a chosen
// workload then no node is ever solo for anything and the cohort kind never
// publishes a row. It went unnoticed because the old prior asked which
// families were *light*, and loki is not light -- but it is on every node,
// which is the only property that matters here.
func TestMandatoryPlatformModulesAreIgnorable(t *testing.T) {
	for _, family := range []string{"loki", "ldapproxy", "metrics", "crowdsec", "traefik"} {
		if !IsPlatform(family, nil) {
			t.Errorf("%s runs on every cluster and must not block solo", family)
		}
	}
	business := BusinessFamilies(map[string]map[string]float64{
		"mail": {"mailboxes": 210}, "loki": nil, "ldapproxy": nil,
		"metrics": nil, "crowdsec": nil, "traefik": nil,
	})
	if len(business) != 1 || business[0] != "mail" {
		t.Fatalf("business families = %v, want [mail]", business)
	}
	if !IsSolo("mail", business) {
		t.Error("a mail node carrying the standard platform set must count as solo")
	}
}

// A module nobody has listed must NOT be silently treated as platform: it
// might be anything, and ignoring it would contaminate every solo cohort it
// appears in with a workload nobody had got round to listing.
func TestUnknownFamilyIsNeverPlatform(t *testing.T) {
	if IsPlatform("somefutureproduct", nil) {
		t.Error("an unlisted family must not be ignorable")
	}
	business := BusinessFamilies(map[string]map[string]float64{"somefutureproduct": nil})
	if len(business) != 1 {
		t.Error("an unlisted family must count as a business workload")
	}
}

func TestCohortKeying(t *testing.T) {
	workloads := map[string]map[string]float64{
		"mail":     {"mailboxes": 210},
		"traefik":  {"routes": 12},
		"openldap": nil,
	}
	business := BusinessFamilies(workloads)
	if len(business) != 1 || business[0] != "mail" {
		t.Fatalf("business = %v, want [mail]", business)
	}
	if !IsSolo("mail", business) {
		t.Error("mail alongside only platform modules must count as solo")
	}
	if IsSolo("traefik", business) {
		t.Error("a platform family is never the solo family")
	}

	both := BusinessFamilies(map[string]map[string]float64{
		"nethvoice": nil, "mail": nil, "traefik": nil,
	})
	if IsSolo("mail", both) {
		t.Error("mail co-tenanted with nethvoice is not solo")
	}

	// A companion module is implied by another rather than chosen, so it does
	// not make its parent co-tenanted.
	voice := BusinessFamilies(map[string]map[string]float64{
		"nethvoice": nil, "nethvoice-proxy": nil, "loki": nil,
	})
	if !IsSolo("nethvoice", voice) {
		t.Error("nethvoice plus its own proxy is still a nethvoice node")
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
