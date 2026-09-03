// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package sizing

import (
	"math"
	"sort"

	"github.com/nethesis/nethesis-insights/internal/model"
)

// PressureVersion stamps every stored pressure value.
//
// Versioning here diverges from fingerprint.Version on purpose. A
// fingerprint is an *identity*, so it is never backfilled: the whole point of
// bumping it is that the change is visible as a new finding. Pressure is a
// *derived analytic* over inputs that are all stored as first-class columns,
// so leaving 100 days of mixed-definition scores in place would make every
// trailing verdict wrong and every cohort statistic incomparable. The
// baseline pass therefore recomputes rows whose pressure_version is stale, in
// a bounded batch, before it builds cohorts.
//
// Bump this whenever any threshold, cap or combination rule below changes.
const PressureVersion = 1

// Axis names. Stored on a verdict as top_axis and used nowhere else as a
// string literal.
const (
	AxisMem  = "mem"
	AxisCPU  = "cpu"
	AxisIO   = "io"
	AxisDisk = "disk"
)

// Pressure reasons: sorted, value-free codes.
//
// Value-free for the gate-reasons lesson (CLAUDE.md, "Gate reasons carry no
// computed values"): embedding a ratio made every deviating window its own
// rollup group of one. The numbers are not lost -- every input is a stored
// column right next to the reason -- so any rollup over these must still be
// time-bounded, because a reason set is spelled the way the formula that
// produced it spelled it.
const (
	ReasonRAMHeadroom = "ram_headroom"
	ReasonSwapIn      = "swap_in"
	ReasonOOMKill     = "oom_kill"
	ReasonCPUUtil     = "cpu_util"
	ReasonRunqueue    = "runqueue"
	ReasonIOWait      = "iowait"
	ReasonFSLevel     = "fs_level"
	ReasonFSFull      = "fs_full"
	ReasonFSTrend     = "fs_trend"

	// ReasonInsufficientCoverage means the coverage gate refused to score:
	// the node was off, the scrape was broken, or the denominators are zero.
	ReasonInsufficientCoverage = "insufficient_coverage"
	// ReasonNoMetrics means coverage was fine but not one scored input
	// arrived -- a reporter bug, distinct from a node that was switched off.
	ReasonNoMetrics = "no_metrics"
)

// Coverage gate. A node that was off for 18 hours is not a low-pressure node,
// and a score computed from a zero denominator is worse than no score -- so
// these produce no pressure at all rather than a clamped number.
const (
	MinSampleCoverage = 0.80
	MinCPUCores       = 1
)

// Penalty knees, ceilings and caps.
//
// Three kinds of number live here and the difference is worth knowing before
// changing one:
//
//   - Physically grounded: RAMUtilFull (0.97), FSFull (0.98),
//     LoadPerCoreKnee (1.0 -- one runnable task per core is by definition a
//     saturated run queue).
//   - Grounded by convention: FSLevelKnee (0.85) is deliberately the same
//     constant as ns8-metrics' DiskSpaceLow alert, so the fleet report and
//     the node's own alert never disagree about when a disk is filling.
//   - Deliberately calibrated: IOWaitKnee (0.05 = 72 minutes a day, above any
//     nightly backup). That calibration is the entire point of the term --
//     the draft's max_iowait let one 25-minute backup drive a 50-point
//     penalty.
//
// Everything else is a **guess**, to be calibrated once ~30 days of fleet
// data exist: RAMUtilKnee, the CPU pair, the swap-in pair, LoadPerCoreFull,
// the days-to-full pair, all four axis caps, CompoundFactor and OOMBase. They
// are labelled as guesses in the operator UI rather than presented as advice.
// See Thresholds below, which is what the UI renders.
//
// Calibration procedure: set each noisy knee at the fleet p90 and each
// ceiling at the fleet p99, leave the physical knees fixed, bump
// PressureVersion, recompute. Storing every input as a column is what makes
// that a one-pass operation needing no fleet cooperation.
const (
	RAMUtilKnee = 0.85
	RAMUtilFull = 0.97
	MemCap      = 60.0

	SwapInKnee = 1.0
	SwapInFull = 200.0

	// OOMBase is a step, not a ramp: a kill is proof rather than a gradient.
	// It stops short of 100 at one kill because a single runaway process is
	// not evidence that the node is undersized.
	OOMBase     = 40.0
	OOMKillsMax = 5.0
	OOMRampCap  = 60.0

	CPUUtilKnee     = 0.80
	CPUUtilFull     = 0.95
	LoadPerCoreKnee = 1.0
	LoadPerCoreFull = 4.0
	CPUCap          = 40.0

	IOWaitKnee = 0.05
	IOWaitFull = 0.40
	IOCap      = 40.0

	FSLevelKnee = 0.85
	FSLevelFull = 0.97
	FSLevelCap  = 70.0
	FSFull      = 0.98

	// FSTrendHorizon is the point at which "days until full" starts to
	// matter, and FSTrendUrgent the point at which the term saturates.
	// fs_days_to_full is the only genuinely predictive term in the score, and
	// predicting a capacity failure is what "sizing" ought to mean.
	FSTrendHorizon = 90.0
	FSTrendUrgent  = 15.0
	FSTrendCap     = 60.0

	// CompoundFactor weights every axis but the worst one. A plain sum
	// over-penalises correlated axes; a plain max ranks three-axis trouble
	// level with one.
	CompoundFactor = 0.5

	MaxPressure = 100.0
)

// Score is one node-day's pressure, its per-axis breakdown and the reasons
// that fired.
//
// The number is named pressure, not "score", and its direction is fixed: 0 is
// no pressure, 100 is severe. "score" reads either way depending on which
// word one takes as the noun, and that ambiguity reliably produces an
// inverted comparison within a month. There is a boundary test asserting the
// direction.
//
// Pressure and each axis are pointers because absent is not zero: a nil axis
// was not measured, a zero axis was measured and is fine. Only measured axes
// contribute to the combination.
type Score struct {
	Version  int
	Pressure *float64
	Mem      *float64
	CPU      *float64
	IO       *float64
	Disk     *float64
	TopAxis  string
	Reasons  []string
}

// clamp is the one clamp in this package.
func clamp(x, lo, hi float64) float64 {
	return math.Min(hi, math.Max(lo, x))
}

// ramp is the one shape every penalty term has: zero at or below x0, cap at
// or above x1, linear between. Monotone and defined for every input,
// including x0 == x1 (which would be a programming error and is asserted
// against in a test).
func ramp(x, x0, x1, ceiling float64) float64 {
	if x1 <= x0 {
		// Unreachable with the constants above; guarded so a future edit
		// cannot turn into a division by zero in production.
		if x >= x1 {
			return ceiling
		}
		return 0
	}
	return ceiling * clamp((x-x0)/(x1-x0), 0, 1)
}

// Evaluate computes one node-day's pressure.
//
// The coverage gate runs first and unconditionally: metrics absent, coverage
// under MinSampleCoverage, fewer than one core or no memory means no
// pressure at all. Everything after it is total -- no input can make this
// panic, divide by zero or produce a NaN.
func Evaluate(n model.SanitizedSizingNode) Score {
	s := Score{Version: PressureVersion}

	if !n.MetricsPresent ||
		n.SampleCoverage < MinSampleCoverage ||
		n.Hardware.CPUCores < MinCPUCores ||
		n.Hardware.MemTotalBytes <= 0 {
		s.Reasons = []string{ReasonInsufficientCoverage}
		return s
	}

	var reasons []string
	add := func(code string) { reasons = append(reasons, code) }

	// --- memory ---
	// max WITHIN the axis, because ram_util and swap-in are two lenses on one
	// saturation. Summing them is the double-counting the draft's
	// P_iowait + P_load suffered.
	mem := newAxis()
	if v := n.Resources.RAMUtilP95; v != nil {
		if p := ramp(*v, RAMUtilKnee, RAMUtilFull, MemCap); mem.consider(p) && p > 0 {
			add(ReasonRAMHeadroom)
		}
	}
	if v := n.Stress.SwapInPPSP95; v != nil {
		if p := ramp(*v, SwapInKnee, SwapInFull, MemCap); mem.consider(p) && p > 0 {
			add(ReasonSwapIn)
		}
	}
	if v := n.Stress.OOMKills; v != nil {
		p := 0.0
		if *v > 0 {
			p = OOMBase + ramp(*v, 1, OOMKillsMax, OOMRampCap)
		}
		if mem.consider(p); p > 0 {
			add(ReasonOOMKill)
		}
	}

	// --- cpu ---
	cpu := newAxis()
	if v := n.Resources.CPUUtilP95; v != nil {
		if p := ramp(*v, CPUUtilKnee, CPUUtilFull, CPUCap); cpu.consider(p) && p > 0 {
			add(ReasonCPUUtil)
		}
	}
	if v := n.Resources.Load15PerCoreP95; v != nil {
		if p := ramp(*v, LoadPerCoreKnee, LoadPerCoreFull, CPUCap); cpu.consider(p) && p > 0 {
			add(ReasonRunqueue)
		}
	}

	// --- io ---
	// A duration, never a 24-hour max: a duration has a denominator, so a
	// 25-minute backup is 1.7 % of the day and a starved node is 30 %.
	io := newAxis()
	if v := n.Stress.IOWaitBusyFrac; v != nil {
		if p := ramp(*v, IOWaitKnee, IOWaitFull, IOCap); io.consider(p) && p > 0 {
			add(ReasonIOWait)
		}
	}

	// --- disk ---
	// The most common real capacity failure, and absent from the draft
	// entirely.
	disk := newAxis()
	if v := n.Resources.FSUsedFracMax; v != nil {
		if p := ramp(*v, FSLevelKnee, FSLevelFull, FSLevelCap); disk.consider(p) && p > 0 {
			add(ReasonFSLevel)
		}
		if *v >= FSFull {
			// Physically grounded and deliberately terminal: a filesystem at
			// 98 % is not "under pressure", it is about to stop working.
			disk.consider(MaxPressure)
			add(ReasonFSFull)
		}
	}
	if v := n.Resources.FSDaysToFull; v != nil && *v < FSTrendHorizon {
		p := ramp(FSTrendHorizon-*v, 0, FSTrendHorizon-FSTrendUrgent, FSTrendCap)
		if disk.consider(p); p > 0 {
			add(ReasonFSTrend)
		}
	}

	s.Mem, s.CPU, s.IO, s.Disk = mem.value(), cpu.value(), io.value(), disk.value()

	axes := []struct {
		name string
		v    *float64
	}{{AxisMem, s.Mem}, {AxisCPU, s.CPU}, {AxisIO, s.IO}, {AxisDisk, s.Disk}}

	var sum, worst float64
	measured := 0
	for _, a := range axes {
		if a.v == nil {
			continue
		}
		measured++
		sum += *a.v
		if *a.v > worst || s.TopAxis == "" {
			worst = *a.v
			s.TopAxis = a.name
		}
	}
	if measured == 0 {
		s.TopAxis = ""
		s.Reasons = []string{ReasonNoMetrics}
		return s
	}

	// Worst axis at full weight plus the rest at half.
	p := clamp(worst+CompoundFactor*(sum-worst), 0, MaxPressure)
	s.Pressure = &p

	sort.Strings(reasons)
	s.Reasons = reasons
	return s
}

// axis accumulates the maximum of one axis's terms while remembering whether
// any term was measured at all. A nil axis means "not measured"; a zero axis
// means "measured, and fine".
type axis struct {
	max      float64
	measured bool
}

func newAxis() *axis { return &axis{} }

// consider folds one term in and reports true, so callers can write
// `if a.consider(p) && p > 0` and keep the reason next to the term.
func (a *axis) consider(p float64) bool {
	a.measured = true
	if p > a.max {
		a.max = p
	}
	return true
}

func (a *axis) value() *float64 {
	if !a.measured {
		return nil
	}
	v := a.max
	return &v
}

// --- multi-day verdict ---

// Verdict states.
const (
	VerdictOK               = "ok"
	VerdictAtRisk           = "at_risk"
	VerdictUndersized       = "undersized"
	VerdictInsufficientData = "insufficient_data"
)

// Verdict thresholds. A single day is not a verdict, and an average across
// days is the wrong aggregator twice over: it washes out one catastrophic day
// and inflates 28 mediocre ones. So this is k-of-n with hysteresis --
// undersizing is recurrence.
const (
	VerdictWindowDays = 28
	MinDaysPresent    = 14

	UndersizedPressure = 50.0
	UndersizedDays     = 7

	AtRiskPressure = 25.0
	AtRiskDays     = 14

	// HysteresisBadDays is where an established undersized verdict releases.
	// Without it a node hovering at seven bad days flaps every pass, and a
	// flapping verdict is one nobody acts on.
	HysteresisBadDays = 3

	// PlacementSpread is the per-node ram_util_p95 spread at which a
	// multi-node cluster's answer is "rebalance", not "buy hardware". This
	// output exists only because a system_id is a cluster, and it is the
	// highest-value thing that falls out of that framing.
	PlacementSpread = 0.50
)

// DayScore is one day of a node's history, as the verdict sees it.
type DayScore struct {
	Day      int64
	Pressure *float64
	TopAxis  string
}

// Verdict is a node's multi-day answer.
type Verdict struct {
	State       string
	TopAxis     string
	DaysPresent int
	BadDays     int
	RiskDays    int
	WindowDays  int
}

// EvaluateVerdict folds a node's window into one verdict.
//
// previous is the node's last stored state, which is what makes the
// hysteresis work: once undersized, the verdict holds until bad days fall to
// HysteresisBadDays or below.
func EvaluateVerdict(days []DayScore, previous string) Verdict {
	v := Verdict{State: VerdictInsufficientData, WindowDays: VerdictWindowDays}

	axisBad := map[string]int{}
	for _, d := range days {
		if d.Pressure == nil {
			continue
		}
		v.DaysPresent++
		if *d.Pressure >= AtRiskPressure {
			v.RiskDays++
		}
		if *d.Pressure >= UndersizedPressure {
			v.BadDays++
			axisBad[d.TopAxis]++
		}
	}

	if v.DaysPresent < MinDaysPresent {
		return v
	}

	switch {
	case v.BadDays >= UndersizedDays,
		previous == VerdictUndersized && v.BadDays > HysteresisBadDays:
		v.State, v.TopAxis = VerdictUndersized, dominantAxis(axisBad)
	case v.RiskDays >= AtRiskDays:
		v.State, v.TopAxis = VerdictAtRisk, dominantAxis(axisBad)
	default:
		v.State = VerdictOK
	}
	return v
}

// dominantAxis reports the axis that was the top penalty on the most bad days,
// or "" if there were none.
//
// Deterministic on a tie: two axes at the same count is a real possibility,
// and the answer must not depend on map iteration order.
func dominantAxis(counts map[string]int) string {
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)
	best, bestN := "", 0
	for _, name := range names {
		if counts[name] > bestN {
			best, bestN = name, counts[name]
		}
	}
	return best
}

// ClusterPlacement answers the question only a cluster can be asked: is this
// undersized, or merely badly balanced?
//
// ramUtil is one entry per node in the cluster for the most recent day
// present. Fewer than two nodes has no placement answer at all -- the spread
// of one number is zero, and reporting "balanced" for a single-node cluster
// would read as advice.
func ClusterPlacement(ramUtil []float64) (spread float64, advice string) {
	if len(ramUtil) < 2 {
		return 0, ""
	}
	lo, hi := ramUtil[0], ramUtil[0]
	for _, v := range ramUtil[1:] {
		lo, hi = math.Min(lo, v), math.Max(hi, v)
	}
	spread = hi - lo
	if spread >= PlacementSpread {
		return spread, "rebalance"
	}
	return spread, "balanced"
}

// --- threshold honesty ---

// Basis records how a threshold was arrived at. It exists so the operator UI
// can say which numbers are grounded and which are guesses, rather than
// presenting a guess as advice.
type Basis string

const (
	BasisPhysical   Basis = "physical"
	BasisConvention Basis = "convention"
	BasisGuess      Basis = "guess"
)

// Threshold is one row of the UI's threshold table.
type Threshold struct {
	Name  string
	Value float64
	Basis Basis
	Note  string
}

// Thresholds returns every constant the score depends on, labelled with how
// it was arrived at. Rendered on the sizing page.
func Thresholds() []Threshold {
	return []Threshold{
		{"ram_util knee", RAMUtilKnee, BasisGuess, "calibrate to fleet p90"},
		{"ram_util full", RAMUtilFull, BasisPhysical, "a node at 97% has no headroom left"},
		{"swap_in knee (pps)", SwapInKnee, BasisGuess, "one page read back per second"},
		{"swap_in full (pps)", SwapInFull, BasisGuess, "calibrate to fleet p99"},
		{"oom step", OOMBase, BasisGuess, "a kill is proof, not a gradient"},
		{"cpu_util knee", CPUUtilKnee, BasisGuess, "calibrate to fleet p90"},
		{"cpu_util full", CPUUtilFull, BasisGuess, "calibrate to fleet p99"},
		{"load15/core knee", LoadPerCoreKnee, BasisPhysical, "one runnable task per core is a saturated run queue"},
		{"load15/core full", LoadPerCoreFull, BasisGuess, "calibrate to fleet p99"},
		{"iowait duration knee", IOWaitKnee, BasisConvention, "72 min/day, above a nightly backup"},
		{"iowait duration full", IOWaitFull, BasisGuess, "calibrate to fleet p99"},
		{"fs used knee", FSLevelKnee, BasisConvention, "same constant as ns8-metrics DiskSpaceLow"},
		{"fs used full", FSLevelFull, BasisPhysical, ""},
		{"fs full", FSFull, BasisPhysical, "about to stop working"},
		{"days-to-full horizon", FSTrendHorizon, BasisGuess, ""},
		{"days-to-full urgent", FSTrendUrgent, BasisGuess, ""},
		{"mem axis cap", MemCap, BasisGuess, ""},
		{"cpu axis cap", CPUCap, BasisGuess, ""},
		{"io axis cap", IOCap, BasisGuess, ""},
		{"disk axis cap", FSLevelCap, BasisGuess, ""},
		{"compounding factor", CompoundFactor, BasisGuess, "worst axis at full weight, the rest at half"},
		{"coverage floor", MinSampleCoverage, BasisConvention, "below this, no pressure is computed"},
		{"placement spread", PlacementSpread, BasisGuess, "rebalance rather than buy hardware"},
	}
}
