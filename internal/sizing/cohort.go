// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package sizing

import (
	"math"
	"sort"
	"strings"
)

// Cohort kinds. Three keyings out of one pass, sharing all the machinery.
const (
	// CohortFamily answers "what does a node that runs mail look like" --
	// co-tenanted with whatever else happens to be installed, and it must be
	// labelled as such wherever it is shown.
	CohortFamily = "family"
	// CohortFamilySolo answers "what does a node running only mail (plus
	// lite modules) need". It is the only one of the three safe to quote as a
	// recommendation.
	CohortFamilySolo = "family_solo"
	// CohortProfile is keyed on the sorted non-lite family list, so it
	// surfaces the real common deployments. The long tail never clears the
	// floor, which is the intended behaviour.
	CohortProfile = "profile"
)

// ProfileSeparator joins a profile key's families. "+" and not "," so the key
// reads as a deployment rather than as a list.
const ProfileSeparator = "+"

// ProfileLiteOnly is the profile key for a node running nothing but lite
// modules. Named rather than empty: an empty cohort key would read as missing
// data on the page, and "a node that runs only lite modules" is a real and
// interesting profile.
const ProfileLiteOnly = "(lite-only)"

// Class is a module family's expected resource weight.
type Class string

const (
	ClassLite   Class = "lite"
	ClassMedium Class = "medium"
	ClassHeavy  Class = "heavy"
	// ClassUnknown is the explicit default. A new module must NOT be silently
	// classed lite: that would quietly exclude it from every solo cohort's
	// "plus lite modules" allowance and make the recommendation wrong for the
	// product nobody had classified yet.
	ClassUnknown Class = "unknown"
)

// familyClass is the lite/medium/heavy prior, and it appears in this codebase
// exactly once -- here.
//
// It is used for three things only: picking a node's primary family, deciding
// which families are ignorable when testing "solo", and ordering the UI. It
// is **never** a weight inside a published number. The pass exists to measure
// module cost; baking a cost prior into the estimator and then publishing the
// result as evidence for that prior would be circular.
var familyClass = map[string]Class{
	"openldap": ClassLite,
	"samba":    ClassLite,
	"traefik":  ClassLite,

	"mail":      ClassMedium,
	"imapsync":  ClassMedium,
	"nextcloud": ClassMedium,

	"nethvoice":               ClassHeavy,
	"loki":                    ClassHeavy,
	"nethsecurity-controller": ClassHeavy,
	"webtop":                  ClassHeavy,
}

// ClassOf resolves a family's class from its name **and its workload**.
//
// The prior as originally given was already wrong in one instructive case:
// "samba without file shares = lite, with shares = medium" is not a family
// distinction at all but a *workload* one -- which is exactly what the metric
// map is for. So the class is derived rather than looked up, one rule instead
// of two, and it stops being wrong for a whole product the moment anyone
// configures it.
func ClassOf(family string, workload map[string]float64) Class {
	base, known := familyClass[family]
	if !known {
		base = ClassUnknown
	}
	if family == "samba" && workload["shared_folders"] > 0 {
		return ClassMedium
	}
	return base
}

// NonLiteFamilies returns the sorted families on a node that are not lite.
//
// ClassUnknown counts as non-lite: an unclassified module might be anything,
// and treating it as ignorable would silently contaminate every solo cohort
// it appears in.
func NonLiteFamilies(workloads map[string]map[string]float64) []string {
	out := make([]string, 0, len(workloads))
	for family, w := range workloads {
		if ClassOf(family, w) != ClassLite {
			out = append(out, family)
		}
	}
	sort.Strings(out)
	return out
}

// ProfileKey builds the profile cohort key from a node's non-lite families.
func ProfileKey(nonLite []string) string {
	if len(nonLite) == 0 {
		return ProfileLiteOnly
	}
	// Already sorted by NonLiteFamilies; sorting again makes the function
	// safe to call with any slice and keeps the key canonical.
	sorted := make([]string, len(nonLite))
	copy(sorted, nonLite)
	sort.Strings(sorted)
	return strings.Join(sorted, ProfileSeparator)
}

// IsSolo reports whether family is the only non-lite family on the node.
func IsSolo(family string, nonLite []string) bool {
	return len(nonLite) == 1 && nonLite[0] == family
}

// ClassOrder gives the UI a stable presentation order: heavy first, because
// that is where the sizing question actually lives.
func ClassOrder(c Class) int {
	switch c {
	case ClassHeavy:
		return 0
	case ClassMedium:
		return 1
	case ClassUnknown:
		return 2
	default:
		return 3
	}
}

// --- censoring ---

// CensorRAMUtil is where a node's true memory demand stops being observable.
//
// This is the defect the source draft does not see, and it is systematic bias
// rather than noise: an undersized node's observed RAM use is capped by the
// RAM it has. A node that needs 12 GB but holds 8 reports about 7.6 GB. Feed
// that into any estimator of "how much RAM does a mail node need" and the
// answer comes out too small -- which then declares more nodes adequately
// sized, the exact inverse of what this feature is for. No volume of data and
// no choice of model removes it.
const CensorRAMUtil = 0.90

// Censored reports whether a node-day's memory demand is unobservable.
//
// Censored node-days are excluded from demand estimation but **counted and
// published** per cohort: a cohort that is 40 % censored means the fleet's own
// hardware for that profile is systematically too small, which is the most
// valuable finding this pass can produce.
//
// Note what is deliberately NOT here. Nodes are not excluded for being
// "unhealthy" in general, and iowait is not an exclusion at all: "what a
// healthy node uses", derived by deleting the unhealthy ones, is survivorship
// bias with extra steps, and excluding disk-bound nodes removes precisely the
// nodes whose existence is the answer. Censoring is the only health-shaped
// exclusion here, and it is justified by measurability, not by health.
func Censored(ramUtilP95, swapInPPS, oomKills *float64) bool {
	if ramUtilP95 != nil && *ramUtilP95 >= CensorRAMUtil {
		return true
	}
	if swapInPPS != nil && *swapInPPS > 0 {
		return true
	}
	return oomKills != nil && *oomKills > 0
}

// --- percentiles ---

// NodeReduceQuantile is the quantile used to reduce a node's daily values to
// one number.
//
// p90, not the median. A 28-day window holds eight weekend days on which a
// business workload is idle, and the median then reads a mail server about
// 25 % low. The peak the hardware has to survive is the number worth
// publishing.
const NodeReduceQuantile = 0.90

// Quantile returns the linear-interpolated quantile of values, which it
// sorts. An empty slice yields 0 and false -- callers must not publish a
// percentile of nothing.
//
// Deterministic by construction: same inputs, same output, run to run. That
// matters more here than the choice of estimator, because these numbers are
// published to customers and must not change unless the data changed.
func Quantile(values []float64, q float64) (float64, bool) {
	if len(values) == 0 {
		return 0, false
	}
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)
	if len(sorted) == 1 {
		return sorted[0], true
	}
	q = clamp(q, 0, 1)
	pos := q * float64(len(sorted)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return sorted[lo], true
	}
	frac := pos - float64(lo)
	return sorted[lo]*(1-frac) + sorted[hi]*frac, true
}

// ReduceNode collapses one node's daily values into the single number that
// enters the across-node percentiles. See NodeReduceQuantile for why p90.
//
// Two-stage aggregation exists because one node contributing 28 daily rows
// must count once. Without it, always-online nodes and one MSP's 40 identical
// clusters dominate every published number.
func ReduceNode(daily []float64) (float64, bool) {
	return Quantile(daily, NodeReduceQuantile)
}

// --- workload buckets ---

// Bucket boundaries for the deterministic t-shirt sizes. Quantile bucketing
// rather than k-means: it gives the same sizes, and it is stable run to run,
// which a number published to customers has to be.
const (
	BucketSmallQuantile  = 0.33
	BucketMediumQuantile = 0.66
)

// Bucket names.
const (
	BucketSmall  = "small"
	BucketMedium = "medium"
	BucketLarge  = "large"
)

// WorkloadPoint pairs one node's workload value with its observed memory
// demand, so a bucket can say both "how big" and "what it costs".
type WorkloadPoint struct {
	Value    float64
	RAMBytes float64
}

// Bucket is one t-shirt size for one (family, metric).
type Bucket struct {
	Name     string
	Lo, Hi   float64
	Nodes    int
	RAMBytes float64 // median observed demand inside the bucket
}

// BucketWorkload splits points into small/medium/large at the p33 and p66 of
// the workload value, and reports each bucket's node count and median memory
// demand.
//
// Hi is exclusive except on the last bucket, where it is math.Inf(1): a
// bucket set with a finite top would silently drop the largest deployment.
func BucketWorkload(points []WorkloadPoint) []Bucket {
	if len(points) == 0 {
		return nil
	}
	values := make([]float64, len(points))
	for i, p := range points {
		values[i] = p.Value
	}
	p33, _ := Quantile(values, BucketSmallQuantile)
	p66, _ := Quantile(values, BucketMediumQuantile)

	bounds := []struct {
		name   string
		lo, hi float64
	}{
		{BucketSmall, 0, p33},
		{BucketMedium, p33, p66},
		{BucketLarge, p66, math.Inf(1)},
	}

	out := make([]Bucket, 0, len(bounds))
	for i, b := range bounds {
		var ram []float64
		for _, p := range points {
			if p.Value >= b.lo && (p.Value < b.hi || i == len(bounds)-1) {
				ram = append(ram, p.RAMBytes)
			}
		}
		median, ok := Quantile(ram, 0.5)
		if !ok {
			// A degenerate distribution (every node reporting the same value)
			// leaves a bucket empty. It is published anyway, with zero nodes,
			// so the bucket boundaries stay legible on the page.
			median = 0
		}
		out = append(out, Bucket{Name: b.name, Lo: b.lo, Hi: b.hi, Nodes: len(ram), RAMBytes: median})
	}
	return out
}
