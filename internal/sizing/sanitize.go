// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package sizing holds the pure half of the fleet-sizing pipeline: the ingest
// sanitizer, the pressure score, the multi-day verdict and the cohort keying.
//
// Same purity contract as gate, fingerprint, prompt and threat -- no I/O, no
// clock beyond an injected now -- and for two reasons.
//
// The first is data protection, as in threat: what a reporter sends carries
// per-customer commercial data (mailbox and PBX user counts, product mix) and
// the metrics it is derived from carry identifying labels (fqdn, main IP, DMI
// serial, nodename). Everything that decides what is stored lives here, so it
// is table-driven testable with no fixtures and no database.
//
// The second is that pressure is computed **server-side only**. Scoring on the
// edge would make every node an uncoordinated second implementation of the
// formula, and a threshold change would then need the fleet's cooperation
// instead of one recompute pass.
package sizing

import (
	"math"
	"sort"
	"strings"
	"time"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/threat"
)

// DayMillis is one UTC day in milliseconds. Day keys in this pipeline are
// integer day indices (unix millis / DayMillis) rather than formatted
// strings: the tables they key are range-queried constantly (a 28-day
// verdict window, a 90-day UI, a prune below a cutoff), an index does all
// three with the arithmetic the codebase already performs, and it removes the
// bug class where a formatter with the wrong location writes two rows for one
// day.
const DayMillis int64 = 86_400_000

// Shape caps. Every one truncates and counts rather than rejecting: a report
// that is too big in one dimension still carries real evidence in the others.
//
// These bound shape, never vocabulary. There is deliberately no list of
// known metric keys and no list of known module families, for the same reason
// threat has no scenario allowlist: the NS8 module set grows continuously, and
// a fixed set would silently discard every new product's metric until someone
// noticed and shipped a server release.
const (
	DefaultMaxNodes     = 16
	MaxFamiliesPerNode  = 64
	MaxMetricsPerFamily = 32
	MaxDaysPerReport    = 15

	// MaxMetricKeyLen bounds a workload key. The regex-equivalent shape is
	// ^[a-z][a-z0-9_]{0,39}$, so 40 runes.
	MaxMetricKeyLen = 40
	// MaxFamilyLen bounds a module family name.
	MaxFamilyLen = 64
	// MaxTextLen bounds each free-text descriptor (cpu_model, os_id,
	// os_version, kernel_release, virtualization, versions[]).
	MaxTextLen = 128
	// MaxVersions bounds the per-family version list, which is display-only.
	MaxVersions = 8
)

// Retention bounds on the day a report may claim.
//
// MaxDayAge is Prometheus' default retention: a day older than that cannot
// have been computed from real data, whatever the reporter says. MinDayAge is
// 1 because the newest complete UTC day is yesterday -- today is still
// accumulating, and a partial day stored under a day label is exactly the
// undefined report this contract exists to prevent.
const (
	MaxDayAge = 15
	MinDayAge = 1
)

// Options carries the per-request inputs the sanitizer cannot derive.
type Options struct {
	// MaxNodes caps nodes per report; <= 0 means DefaultMaxNodes.
	MaxNodes int
}

// Result is one sanitized report.
type Result struct {
	Days     []model.SanitizedSizingDay
	Counters model.SizingCounters
}

// Sanitize turns a reported cluster-day batch into storable rows.
//
// It is fail-open on content and total on input: every node, family and
// metric either becomes a row or increments exactly one counter, and no input
// can make this function fail. now is unix millis.
func Sanitize(r model.SizingReport, opts Options, now int64) Result {
	maxNodes := opts.MaxNodes
	if maxNodes <= 0 {
		maxNodes = DefaultMaxNodes
	}

	var res Result

	days := r.Days
	if len(days) > MaxDaysPerReport {
		res.Counters.TruncatedDays = len(days) - MaxDaysPerReport
		days = days[:MaxDaysPerReport]
	}

	today := now / DayMillis
	seenDay := map[int64]bool{}

	for _, d := range days {
		day, ok := parseDay(d.Day)
		if !ok || day > today-MinDayAge || day < today-MaxDayAge {
			res.Counters.DroppedDay++
			continue
		}
		if seenDay[day] {
			// Two entries for one day in one report: the second cannot be
			// reconciled with the first (both claim to be the whole day), so
			// the first wins and the duplicate is counted. Across requests
			// the rule is the opposite -- a later request recomputes the row
			// -- because there the reporter has had a chance to fix itself.
			res.Counters.DroppedDuplicate++
			continue
		}
		seenDay[day] = true

		nodes := d.Nodes
		if len(nodes) > maxNodes {
			res.Counters.TruncatedNodes += len(nodes) - maxNodes
			nodes = nodes[:maxNodes]
		}

		out := model.SanitizedSizingDay{Day: day}
		seenNode := map[int]bool{}
		for _, n := range nodes {
			// NS8 node ids are small positive integers scoped to the cluster.
			// Zero or negative is a broken reporter, not a node.
			if n.NodeID < 1 {
				res.Counters.DroppedNode++
				continue
			}
			if seenNode[n.NodeID] {
				res.Counters.DroppedDuplicate++
				continue
			}
			seenNode[n.NodeID] = true
			out.Nodes = append(out.Nodes, sanitizeNode(n, &res.Counters))
			res.Counters.AcceptedNodes++
		}

		if d.Cluster != nil {
			out.ClusterWorkload = sanitizeClusterWorkload(d.Cluster.UserDomains, &res.Counters)
		}

		// Deterministic output: the same report must always produce the same
		// rows in the same order, for the same reason prompt sorts its
		// templates.
		sort.Slice(out.Nodes, func(i, j int) bool { return out.Nodes[i].NodeID < out.Nodes[j].NodeID })
		res.Days = append(res.Days, out)
	}

	sort.Slice(res.Days, func(i, j int) bool { return res.Days[i].Day < res.Days[j].Day })
	return res
}

// parseDay turns a "YYYY-MM-DD" day label into a UTC day index.
//
// time.Parse with no zone information yields UTC, which is what makes this
// the same arithmetic the store performs. A label carrying a time or a zone
// is rejected rather than coerced: the contract says a day, and a reporter
// sending an instant has computed its numbers over something other than a
// whole day.
func parseDay(s string) (int64, bool) {
	t, err := time.Parse("2006-01-02", strings.TrimSpace(s))
	if err != nil {
		return 0, false
	}
	return t.UnixMilli() / DayMillis, true
}

// DayString formats a UTC day index back into its "YYYY-MM-DD" label, for the
// UI and for log lines. The inverse of parseDay.
func DayString(day int64) string {
	return time.UnixMilli(day * DayMillis).UTC().Format("2006-01-02")
}

func sanitizeNode(n model.SizingNode, c *model.SizingCounters) model.SanitizedSizingNode {
	out := model.SanitizedSizingNode{
		NodeID:         n.NodeID,
		MetricsPresent: n.MetricsPresent,
		SampleCoverage: coverage(n.SampleCoverage),
		Hardware:       sanitizeHardware(n.Hardware),
		Resources:      sanitizeResources(n.Resources, c),
		Stress:         sanitizeStress(n.Stress, c),
	}

	families := n.Modules
	if len(families) > MaxFamiliesPerNode {
		c.TruncatedFamilies += len(families) - MaxFamiliesPerNode
		families = families[:MaxFamiliesPerNode]
	}

	// Duplicate families inside one node are folded rather than dropped: a
	// reporter listing nethvoice twice has two instances, and instances,
	// facts_ok and every workload metric are extensive.
	folded := map[string]*model.SanitizedSizingModule{}
	order := []string{}
	for _, m := range families {
		family := cleanFamily(m.Family)
		if family == "" {
			c.DroppedFamily++
			continue
		}
		mod, seen := folded[family]
		if !seen {
			mod = &model.SanitizedSizingModule{Family: family, Workload: map[string]float64{}}
			folded[family] = mod
			order = append(order, family)
			c.AcceptedModules++
		}
		mod.Instances += nonNegInt(m.Instances)
		mod.FactsOK += nonNegInt(m.FactsOK)
		mod.Versions = appendVersions(mod.Versions, m.Versions)
		mergeWorkload(mod.Workload, m.Workload, c)
	}

	sort.Strings(order)
	for _, family := range order {
		mod := folded[family]
		// facts_ok can exceed instances only through a reporter bug; clamping
		// keeps "facts_ok == instances" a usable "every call succeeded" test.
		if mod.FactsOK > mod.Instances {
			mod.FactsOK = mod.Instances
		}
		if len(mod.Workload) > MaxMetricsPerFamily {
			c.TruncatedMetrics += len(mod.Workload) - MaxMetricsPerFamily
			mod.Workload = truncateMetrics(mod.Workload)
		}
		c.AcceptedMetrics += len(mod.Workload)
		sort.Strings(mod.Versions)
		out.Modules = append(out.Modules, *mod)
	}
	return out
}

// mergeWorkload validates and sums one family entry's workload map.
//
// The key shape is the whole vocabulary rule, and "number" is the whole
// privacy rule: an FQDN, an IP address, a hostname or a DMI serial cannot be
// encoded in a float, which is a stronger guarantee than any field blocklist
// somebody has to maintain.
//
// Note where that rule is actually enforced. A JSON string, boolean, array or
// object never reaches this function: it cannot decode into
// model.SizingModule.Workload's float64 values, so the request is refused
// with a 400 before the sanitizer runs. That is the loud failure a reporter
// bug deserves, and it is why this function only has to reject numbers that
// are not finite and non-negative.
func mergeWorkload(dst, src map[string]float64, c *model.SizingCounters) {
	// Iterating a map is unordered, but the outcome is not: keys land in dst
	// keyed by themselves and values are summed, so the result is
	// order-independent.
	for k, v := range src {
		key := strings.TrimSpace(k)
		if !validMetricKey(key) {
			c.DroppedMetricKey++
			continue
		}
		if !validValue(v) {
			c.DroppedMetricValue++
			continue
		}
		dst[key] += v
	}
}

// truncateMetrics keeps the MaxMetricsPerFamily lexicographically first keys.
// Deterministic rather than "whichever the map yielded first": the same
// report must produce the same rows.
func truncateMetrics(m map[string]float64) map[string]float64 {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]float64, MaxMetricsPerFamily)
	for _, k := range keys[:MaxMetricsPerFamily] {
		out[k] = m[k]
	}
	return out
}

// sanitizeClusterWorkload sums the per-domain counters. They are extensive, so
// two user domains with 100 users each are 200 users on this cluster.
func sanitizeClusterWorkload(domains []map[string]float64, c *model.SizingCounters) map[string]float64 {
	if len(domains) == 0 {
		return nil
	}
	out := map[string]float64{}
	for _, d := range domains {
		mergeWorkload(out, d, c)
	}
	if len(out) > MaxMetricsPerFamily {
		c.TruncatedMetrics += len(out) - MaxMetricsPerFamily
		out = truncateMetrics(out)
	}
	c.AcceptedMetrics += len(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// validMetricKey implements ^[a-z][a-z0-9_]{0,39}$ without a regexp. Lowercase
// only, so "Users" and "users" cannot become two columns of the same thing.
func validMetricKey(k string) bool {
	if k == "" || len(k) > MaxMetricKeyLen {
		return false
	}
	for i, r := range k {
		switch {
		case r >= 'a' && r <= 'z':
		case i > 0 && (r >= '0' && r <= '9' || r == '_'):
		default:
			return false
		}
	}
	return true
}

// validValue is the numbers-only rule made executable: finite and
// non-negative. NaN and +Inf both fail the comparison chain, which is why it
// is written as an explicit IsNaN/IsInf check rather than as v >= 0.
func validValue(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0
}

// cleanFamily normalizes a reported family name.
//
// model.ModuleFamily is applied even though the contract says to send a
// family: it is the single definition of module identity in this codebase and
// a reporter sending "nethvoice20" must not mint a second cohort. The shape
// check then bounds what reaches an HTML page and a database column.
func cleanFamily(s string) string {
	s = strings.ToLower(threat.CleanText(s, MaxFamilyLen))
	if s == "" {
		return ""
	}
	s = model.ModuleFamily(s)
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return ""
		}
	}
	return s
}

// appendVersions collects the display-only version strings, bounded and
// de-duplicated. Never scored, never a cohort key: a version is not
// extensive, so it has no place in a workload map either.
func appendVersions(dst []string, src []string) []string {
	for _, v := range src {
		v = threat.CleanText(v, MaxTextLen)
		if v == "" || len(dst) >= MaxVersions {
			continue
		}
		dup := false
		for _, existing := range dst {
			if existing == v {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, v)
		}
	}
	return dst
}

// sanitizeHardware bounds the free-text descriptors. These five, plus
// versions[], are the only free text in the whole payload -- see
// model.SizingHardware for what is deliberately not here.
//
// Negative or absurd capacity is normalized to zero rather than dropped: the
// coverage gate turns a zero denominator into an absent pressure, which is
// what "a score from missing data is worse than no score" means in practice.
func sanitizeHardware(h model.SizingHardware) model.SizingHardware {
	return model.SizingHardware{
		CPUCores:       nonNegInt(h.CPUCores),
		MemTotalBytes:  nonNegInt64(h.MemTotalBytes),
		CPUModel:       threat.CleanText(h.CPUModel, MaxTextLen),
		OSID:           threat.CleanText(h.OSID, MaxTextLen),
		OSVersion:      threat.CleanText(h.OSVersion, MaxTextLen),
		KernelRelease:  threat.CleanText(h.KernelRelease, MaxTextLen),
		Virtualization: threat.CleanText(h.Virtualization, MaxTextLen),
	}
}

func sanitizeResources(r model.SizingResources, c *model.SizingCounters) model.SizingResources {
	return model.SizingResources{
		RAMUtilP95:       fraction(r.RAMUtilP95, c),
		RAMUsedBytesP95:  quantity(r.RAMUsedBytesP95, c),
		CPUUtilP95:       fraction(r.CPUUtilP95, c),
		CPUCoresUsedP95:  quantity(r.CPUCoresUsedP95, c),
		Load15PerCoreP95: quantity(r.Load15PerCoreP95, c),
		FSUsedFracMax:    fraction(r.FSUsedFracMax, c),
		FSDaysToFull:     quantity(r.FSDaysToFull, c),
		DiskIOUtilP95:    fraction(r.DiskIOUtilP95, c),
	}
}

func sanitizeStress(s model.SizingStress, c *model.SizingCounters) model.SizingStress {
	return model.SizingStress{
		IOWaitBusyFrac: fraction(s.IOWaitBusyFrac, c),
		SwapInPPSP95:   quantity(s.SwapInPPSP95, c),
		OOMKills:       quantity(s.OOMKills, c),
		Reboots:        quantity(s.Reboots, c),
	}
}

// fraction validates a 0..1 field. A value above 1 is clamped rather than
// dropped -- a p95 utilization of 1.0000001 is a rounding artifact, not a
// broken reporter -- but a negative or non-finite one is dropped and the term
// it feeds becomes absent.
func fraction(v *float64, c *model.SizingCounters) *float64 {
	if v == nil {
		return nil
	}
	if !validValue(*v) {
		c.DroppedResourceValue++
		return nil
	}
	out := math.Min(*v, 1)
	return &out
}

// quantity validates an unbounded non-negative field (bytes, cores, days,
// counts, rates). There is no upper clamp: an unbounded field has no
// defensible ceiling, and every term that consumes one saturates on its own.
func quantity(v *float64, c *model.SizingCounters) *float64 {
	if v == nil {
		return nil
	}
	if !validValue(*v) {
		c.DroppedResourceValue++
		return nil
	}
	out := *v
	return &out
}

// coverage normalizes sample_coverage into 0..1. A non-finite or negative
// value becomes 0, which fails the coverage gate -- the safe direction, since
// coverage is what distinguishes "idle" from "was switched off".
func coverage(v float64) float64 {
	if !validValue(v) {
		return 0
	}
	return math.Min(v, 1)
}

func nonNegInt(v int) int {
	if v < 0 {
		return 0
	}
	return v
}

func nonNegInt64(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}

// CleanReporterVersion bounds the reporter's self-reported version. Kept for
// display and for answering "which reporter release produced this row"; never
// parsed, never compared, never a cohort key.
func CleanReporterVersion(s string) string {
	return threat.CleanText(s, MaxTextLen)
}
