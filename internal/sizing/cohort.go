// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package sizing

import (
	"math"
	"sort"
)

// Cohort kinds. Two keyings out of one pass, sharing all the machinery.
const (
	// CohortFamily answers "what does a node that runs mail look like" --
	// co-tenanted with whatever else happens to be installed, and it must be
	// labelled as such wherever it is shown.
	CohortFamily = "family"
	// CohortFamilySolo answers "what does a node running only mail (plus the
	// platform modules every cluster has) need". It is the only one of the two
	// safe to quote as a recommendation.
	CohortFamilySolo = "family_solo"
)

// --- ignorability ---

// platformFamilies are the families a node runs because it is an NS8 cluster,
// not because somebody chose a workload. They are the families ignored when
// testing "solo".
//
// The axis here is **ubiquity, not weight**. An earlier version of this file
// carried a lite/medium/heavy prior and treated "lite" as ignorable, which got
// the question backwards and made `family_solo` unreachable: every NS8 cluster
// runs loki, ldapproxy, metrics and crowdsec, loki was classed heavy, so every
// node's non-ignorable count was at least two and no node was ever solo for
// anything. Zero family_solo rows had ever published. Whether loki is heavy is
// beside the point -- it is on every node either way, so it can never
// distinguish one node from another, which is the only thing this test is for.
//
// It is **never** a weight inside a published number. The pass exists to
// measure module cost; baking a cost prior into the estimator and then
// publishing the result as evidence for that prior would be circular. The
// consequence to state wherever a solo number is shown: the number includes
// the platform modules' own cost, because every node measured was running
// them. That is the honest reading, and it is also the useful one -- nobody
// deploys NS8 without them.
//
// A family nobody has listed here is NOT ignorable. An unlisted module might
// be anything, and treating it as platform would silently contaminate every
// solo cohort it appears in with a workload nobody had got round to listing.
var platformFamilies = map[string]bool{
	// Present on every cluster, or on every cluster this server sees at all:
	// log shipping, the identity proxy, metrics, intrusion prevention, and
	// the ingress every module publishes through.
	"loki":      true,
	"ldapproxy": true,
	"metrics":   true,
	"crowdsec":  true,
	"traefik":   true,

	// The account provider. Exactly one per cluster, and having one is not a
	// workload decision -- see IsPlatform for samba's second role.
	"openldap": true,
	"samba":    true,

	// Implied by another module rather than chosen: a nethvoice-proxy exists
	// because a nethvoice does. Its cost is real voice cost, and it stays
	// inside the numbers; what it must not do is stop a nethvoice node from
	// counting as a nethvoice node.
	"nethvoice-proxy": true,
}

// IsPlatform reports whether family is ignorable when testing "solo", from its
// name **and its workload**.
//
// The workload is what makes samba correct. samba is the account provider on
// most clusters, which is platform, but with file shares configured it is also
// a file server, which is a workload somebody chose. That is a *workload*
// distinction, not a family one -- exactly what the metric map is for -- so it
// is derived rather than listed, one rule instead of two.
func IsPlatform(family string, workload map[string]float64) bool {
	if !platformFamilies[family] {
		return false
	}
	// ns8-samba's get-facts (imageroot/actions/get-facts/50facts) emits
	// shared_folders_count; "shared_folders" is accepted too so an older or
	// third-party reporter still resolves correctly.
	if family == "samba" && (workload["shared_folders_count"] > 0 || workload["shared_folders"] > 0) {
		return false
	}
	return true
}

// BusinessFamilies returns the sorted families on a node that are not
// platform -- the workloads somebody actually chose to run there.
func BusinessFamilies(workloads map[string]map[string]float64) []string {
	out := make([]string, 0, len(workloads))
	for family, w := range workloads {
		if !IsPlatform(family, w) {
			out = append(out, family)
		}
	}
	sort.Strings(out)
	return out
}

// IsSolo reports whether family is the only business family on the node.
func IsSolo(family string, business []string) bool {
	return len(business) == 1 && business[0] == family
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
