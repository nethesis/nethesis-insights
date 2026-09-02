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
	if got := ProfileKey(nonLite); got != "mail" {
		t.Errorf("profile key = %q, want mail", got)
	}

	both := NonLiteFamilies(map[string]map[string]float64{
		"nethvoice": nil, "mail": nil, "traefik": nil,
	})
	if got := ProfileKey(both); got != "mail+nethvoice" {
		t.Errorf("profile key = %q, want mail+nethvoice (sorted)", got)
	}
	if IsSolo("mail", both) {
		t.Error("mail co-tenanted with nethvoice is not solo")
	}
	if got := ProfileKey(nil); got != ProfileLiteOnly {
		t.Errorf("profile key = %q, want %q", got, ProfileLiteOnly)
	}
}

// The profile key must be canonical whatever order the families arrive in:
// two spellings of one deployment would split it into two cohorts, and
// neither would clear the floor.
func TestProfileKeyIsCanonical(t *testing.T) {
	a := ProfileKey([]string{"nethvoice", "mail", "loki"})
	b := ProfileKey([]string{"loki", "nethvoice", "mail"})
	if a != b {
		t.Errorf("profile key is order-dependent: %q vs %q", a, b)
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

func TestBucketWorkload(t *testing.T) {
	if BucketWorkload(nil) != nil {
		t.Error("no points must publish no buckets")
	}

	var points []WorkloadPoint
	for i := 1; i <= 90; i++ {
		points = append(points, WorkloadPoint{Value: float64(i), RAMBytes: float64(i) * 1e8})
	}
	buckets := BucketWorkload(points)
	if len(buckets) != 3 {
		t.Fatalf("buckets = %d, want 3", len(buckets))
	}
	if buckets[0].Name != BucketSmall || buckets[2].Name != BucketLarge {
		t.Errorf("bucket names = %q..%q", buckets[0].Name, buckets[2].Name)
	}
	// The top bucket has no finite ceiling: one would silently drop the
	// largest deployment.
	if !math.IsInf(buckets[2].Hi, 1) {
		t.Errorf("top bucket ceiling = %v, want +Inf", buckets[2].Hi)
	}
	total := 0
	for _, b := range buckets {
		total += b.Nodes
		if b.Nodes > 0 && b.RAMBytes <= 0 {
			t.Errorf("bucket %q has nodes but no median demand", b.Name)
		}
	}
	if total != len(points) {
		t.Errorf("buckets hold %d of %d points", total, len(points))
	}
	// Ordered and non-overlapping.
	for i := 1; i < len(buckets); i++ {
		if buckets[i].Lo < buckets[i-1].Lo {
			t.Error("buckets are not in ascending order")
		}
	}

	// Deterministic: a number published to customers must not change unless
	// the data changed.
	again := BucketWorkload(points)
	for i := range buckets {
		if buckets[i] != again[i] {
			t.Fatalf("bucket %d is not deterministic: %+v vs %+v", i, buckets[i], again[i])
		}
	}
}

// A degenerate distribution -- every node reporting the same value -- leaves
// buckets empty. They are still published so the boundaries stay legible.
func TestBucketWorkloadDegenerate(t *testing.T) {
	points := make([]WorkloadPoint, 10)
	for i := range points {
		points[i] = WorkloadPoint{Value: 5, RAMBytes: 1e9}
	}
	buckets := BucketWorkload(points)
	if len(buckets) != 3 {
		t.Fatalf("buckets = %d, want 3", len(buckets))
	}
	held := 0
	for _, b := range buckets {
		held += b.Nodes
	}
	if held != len(points) {
		t.Errorf("buckets hold %d of %d identical points", held, len(points))
	}
}

func TestClassOrderPutsHeavyFirst(t *testing.T) {
	if ClassOrder(ClassHeavy) >= ClassOrder(ClassMedium) ||
		ClassOrder(ClassMedium) >= ClassOrder(ClassUnknown) ||
		ClassOrder(ClassUnknown) >= ClassOrder(ClassLite) {
		t.Error("presentation order must run heavy, medium, unknown, lite")
	}
}
