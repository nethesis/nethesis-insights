// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package sizing

import (
	"math"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/model"
)

func f(v float64) *float64 { return &v }

func scored() model.SanitizedSizingNode {
	return model.SanitizedSizingNode{
		NodeID:         1,
		MetricsPresent: true,
		SampleCoverage: 0.99,
		Hardware:       model.SizingHardware{CPUCores: 4, MemTotalBytes: 8 << 30},
	}
}

// idle is a node that reported every input and every one of them is fine.
func idle() model.SanitizedSizingNode {
	n := scored()
	n.Resources = model.SizingResources{
		RAMUtilP95: f(0.20), RAMUsedBytesP95: f(1.6e9),
		CPUUtilP95: f(0.05), CPUCoresUsedP95: f(0.2),
		Load15PerCoreP95: f(0.05), FSUsedFracMax: f(0.30),
		FSDaysToFull: f(4000), DiskIOUtilP95: f(0.01),
	}
	n.Stress = model.SizingStress{
		IOWaitBusyFrac: f(0), SwapInPPSP95: f(0), OOMKills: f(0), Reboots: f(0),
	}
	return n
}

// TestPressureDirection is the direction test. The number is named pressure,
// not "score", precisely because "score" reads either way depending on which
// word one takes as the noun -- and that ambiguity reliably produces an
// inverted comparison within a month. 0 is no pressure; 100 is severe.
func TestPressureDirection(t *testing.T) {
	calm := Evaluate(idle())
	if calm.Pressure == nil {
		t.Fatal("a fully measured idle node must be scored")
	}
	if *calm.Pressure != 0 {
		t.Errorf("a fully idle node scored %v, want 0", *calm.Pressure)
	}
	if len(calm.Reasons) != 0 {
		t.Errorf("a fully idle node fired reasons: %v", calm.Reasons)
	}

	hot := idle()
	hot.Resources.RAMUtilP95 = f(1.0)
	hot.Resources.CPUUtilP95 = f(1.0)
	hot.Resources.FSUsedFracMax = f(0.99)
	hot.Stress.IOWaitBusyFrac = f(0.9)
	loaded := Evaluate(hot)
	if loaded.Pressure == nil || *loaded.Pressure <= *calm.Pressure {
		t.Fatalf("a saturated node scored %v, must exceed the idle node's %v",
			loaded.Pressure, *calm.Pressure)
	}
	if *loaded.Pressure > MaxPressure {
		t.Errorf("pressure %v exceeds the ceiling", *loaded.Pressure)
	}
}

// The coverage gate runs first and unconditionally. A node that was off for
// eighteen hours is not a low-pressure node, and a score from a zero
// denominator is worse than no score.
func TestCoverageGate(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*model.SanitizedSizingNode)
	}{
		{"no metrics at all", func(n *model.SanitizedSizingNode) { n.MetricsPresent = false }},
		{"coverage below the floor", func(n *model.SanitizedSizingNode) { n.SampleCoverage = 0.79 }},
		{"no coverage reported", func(n *model.SanitizedSizingNode) { n.SampleCoverage = 0 }},
		{"zero cores", func(n *model.SanitizedSizingNode) { n.Hardware.CPUCores = 0 }},
		{"zero memory", func(n *model.SanitizedSizingNode) { n.Hardware.MemTotalBytes = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := idle()
			tc.mut(&n)
			got := Evaluate(n)
			if got.Pressure != nil {
				t.Errorf("pressure = %v, want nil", *got.Pressure)
			}
			if len(got.Reasons) != 1 || got.Reasons[0] != ReasonInsufficientCoverage {
				t.Errorf("reasons = %v, want [%s]", got.Reasons, ReasonInsufficientCoverage)
			}
			// Not a division: the axes must be absent, not zero.
			if got.Mem != nil || got.CPU != nil || got.IO != nil || got.Disk != nil {
				t.Error("a gated node must carry no axis penalties")
			}
		})
	}
}

// Coverage fine but not one scored input present is a reporter bug, and it is
// a distinct condition from a node that was switched off.
func TestNoMeasuredAxisIsItsOwnReason(t *testing.T) {
	got := Evaluate(scored())
	if got.Pressure != nil {
		t.Errorf("pressure = %v, want nil", *got.Pressure)
	}
	if len(got.Reasons) != 1 || got.Reasons[0] != ReasonNoMetrics {
		t.Errorf("reasons = %v, want [%s]", got.Reasons, ReasonNoMetrics)
	}
}

// Every penalty term is checked below its knee, exactly at it, mid-ramp,
// exactly at its ceiling, above it, and absent.
func TestPenaltyTermBoundaries(t *testing.T) {
	cases := []struct {
		name   string
		set    func(*model.SanitizedSizingNode, float64)
		axis   func(Score) *float64
		reason string
		x0, x1 float64
		ceil   float64
	}{
		{"ram_util", func(n *model.SanitizedSizingNode, v float64) { n.Resources.RAMUtilP95 = f(v) },
			func(s Score) *float64 { return s.Mem }, ReasonRAMHeadroom, RAMUtilKnee, RAMUtilFull, MemCap},
		{"swap_in", func(n *model.SanitizedSizingNode, v float64) { n.Stress.SwapInPPSP95 = f(v) },
			func(s Score) *float64 { return s.Mem }, ReasonSwapIn, SwapInKnee, SwapInFull, MemCap},
		{"cpu_util", func(n *model.SanitizedSizingNode, v float64) { n.Resources.CPUUtilP95 = f(v) },
			func(s Score) *float64 { return s.CPU }, ReasonCPUUtil, CPUUtilKnee, CPUUtilFull, CPUCap},
		{"load15/core", func(n *model.SanitizedSizingNode, v float64) { n.Resources.Load15PerCoreP95 = f(v) },
			func(s Score) *float64 { return s.CPU }, ReasonRunqueue, LoadPerCoreKnee, LoadPerCoreFull, CPUCap},
		{"iowait duration", func(n *model.SanitizedSizingNode, v float64) { n.Stress.IOWaitBusyFrac = f(v) },
			func(s Score) *float64 { return s.IO }, ReasonIOWait, IOWaitKnee, IOWaitFull, IOCap},
		{"fs level", func(n *model.SanitizedSizingNode, v float64) { n.Resources.FSUsedFracMax = f(v) },
			func(s Score) *float64 { return s.Disk }, ReasonFSLevel, FSLevelKnee, FSLevelFull, FSLevelCap},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mid := tc.x0 + (tc.x1-tc.x0)/2

			// Below the knee and exactly at it: measured, and fine.
			for _, v := range []float64{0, tc.x0 * 0.5, tc.x0} {
				n := idle()
				tc.set(&n, v)
				got := Evaluate(n)
				if a := tc.axis(got); a == nil {
					t.Fatalf("x=%v: axis is absent though the input was present", v)
				} else if *a != 0 {
					t.Errorf("x=%v: axis penalty = %v, want 0 at or below the knee", v, *a)
				}
				if hasReason(got.Reasons, tc.reason) {
					t.Errorf("x=%v: reason %q fired at or below the knee", v, tc.reason)
				}
			}

			// Mid-ramp: strictly between 0 and the ceiling, with the reason.
			n := idle()
			tc.set(&n, mid)
			got := Evaluate(n)
			a := tc.axis(got)
			if a == nil || *a <= 0 || *a >= tc.ceil {
				t.Errorf("x=%v: axis penalty = %v, want strictly inside (0, %v)", mid, a, tc.ceil)
			}
			if !hasReason(got.Reasons, tc.reason) {
				t.Errorf("x=%v: reason %q did not fire mid-ramp (got %v)", mid, tc.reason, got.Reasons)
			}

			// At the ceiling and above it: saturated, never beyond.
			for _, v := range []float64{tc.x1, tc.x1 * 2, tc.x1 + 1000} {
				n := idle()
				tc.set(&n, v)
				got := Evaluate(n)
				a := tc.axis(got)
				if a == nil || *a < tc.ceil {
					t.Errorf("x=%v: axis penalty = %v, want at least the ceiling %v", v, a, tc.ceil)
				}
			}

			// Absent: the axis is absent too, not zero.
			n = idle()
			n.Resources = model.SizingResources{}
			n.Stress = model.SizingStress{}
			if got := Evaluate(n); got.Pressure != nil {
				t.Error("with every input absent there must be no pressure")
			}
		})
	}
}

// max WITHIN an axis, because ram_util and swap-in measure one saturation
// through two lenses. This is the double-counting fix: the draft's
// P_iowait + P_load reached 80 penalty points from a single disk-bound cause.
func TestAxisTakesMaxNotSum(t *testing.T) {
	n := idle()
	n.Resources.RAMUtilP95 = f(RAMUtilFull) // saturates the ram term
	n.Stress.SwapInPPSP95 = f(SwapInFull)   // saturates the swap term too
	got := Evaluate(n)
	if got.Mem == nil || *got.Mem != MemCap {
		t.Fatalf("mem axis = %v, want exactly the cap %v (max, not sum)", got.Mem, MemCap)
	}
}

// A kill is proof, not a gradient, so the OOM term is a step -- and it stops
// short of 100 at one kill, because a single runaway process is not evidence
// that the node is undersized.
func TestOOMTermIsAStepShortOf100(t *testing.T) {
	n := idle()
	n.Stress.OOMKills = f(1)
	one := Evaluate(n)
	if one.Mem == nil || *one.Mem != OOMBase {
		t.Fatalf("one kill scored %v on the mem axis, want %v", one.Mem, OOMBase)
	}
	if one.Pressure == nil || *one.Pressure >= MaxPressure {
		t.Errorf("one kill produced pressure %v, must stay short of %v", one.Pressure, MaxPressure)
	}
	if !hasReason(one.Reasons, ReasonOOMKill) {
		t.Errorf("reasons = %v, want %s", one.Reasons, ReasonOOMKill)
	}

	n.Stress.OOMKills = f(OOMKillsMax)
	many := Evaluate(n)
	if many.Mem == nil || *many.Mem <= *one.Mem {
		t.Error("five kills must score above one")
	}
}

// A filesystem at 98% is not "under pressure": it is about to stop working.
func TestFilesystemFullIsTerminal(t *testing.T) {
	n := idle()
	n.Resources.FSUsedFracMax = f(FSFull)
	got := Evaluate(n)
	if got.Disk == nil || *got.Disk != MaxPressure {
		t.Fatalf("disk axis = %v, want %v at %v full", got.Disk, MaxPressure, FSFull)
	}
	if got.Pressure == nil || *got.Pressure != MaxPressure {
		t.Errorf("pressure = %v, want %v", got.Pressure, MaxPressure)
	}
	if !hasReason(got.Reasons, ReasonFSFull) {
		t.Errorf("reasons = %v, want %s", got.Reasons, ReasonFSFull)
	}
}

// fs_days_to_full is the only genuinely predictive term, and predicting a
// capacity failure is what "sizing" ought to mean.
func TestDaysToFullTrend(t *testing.T) {
	cases := []struct {
		days     float64
		wantFire bool
	}{
		{4000, false}, {FSTrendHorizon, false}, {FSTrendHorizon - 1, true},
		{FSTrendUrgent, true}, {0, true},
	}
	for _, tc := range cases {
		n := idle()
		n.Resources.FSDaysToFull = f(tc.days)
		got := Evaluate(n)
		if fired := hasReason(got.Reasons, ReasonFSTrend); fired != tc.wantFire {
			t.Errorf("days=%v: fs_trend fired = %v, want %v", tc.days, fired, tc.wantFire)
		}
	}

	// Monotone: fewer days remaining is never less pressure.
	prev := 0.0
	for _, d := range []float64{FSTrendHorizon, 60, 30, FSTrendUrgent, 5, 0} {
		n := idle()
		n.Resources.FSDaysToFull = f(d)
		got := Evaluate(n)
		if got.Disk == nil {
			t.Fatal("the disk axis must be measured when days_to_full is present")
		}
		if *got.Disk < prev {
			t.Errorf("days=%v scored %v, below the previous %v -- the term is not monotone", d, *got.Disk, prev)
		}
		prev = *got.Disk
	}
}

// disk_io_util_p95 is stored but never scored: io_time saturation is
// meaningless on NVMe, where the device happily services a queue while
// reporting "100% utilized".
func TestDiskIOUtilIsNotScored(t *testing.T) {
	n := idle()
	n.Resources.DiskIOUtilP95 = f(1.0)
	if got := Evaluate(n); got.Pressure == nil || *got.Pressure != 0 {
		t.Errorf("pressure = %v, want 0 -- disk_io_util must not be scored", got.Pressure)
	}
}

// Worst axis at full weight plus the rest at half. A plain sum over-penalises
// correlated axes; a plain max ranks three-axis trouble level with one.
func TestCompoundingIsWorstPlusHalfTheRest(t *testing.T) {
	one := idle()
	one.Resources.RAMUtilP95 = f(RAMUtilFull) // mem = MemCap, others 0
	single := Evaluate(one)
	if single.Pressure == nil || *single.Pressure != MemCap {
		t.Fatalf("one saturated axis = %v, want %v", single.Pressure, MemCap)
	}

	three := one
	three.Resources.CPUUtilP95 = f(CPUUtilFull)
	three.Stress.IOWaitBusyFrac = f(IOWaitFull)
	multi := Evaluate(three)
	want := MemCap + CompoundFactor*(CPUCap+IOCap)
	if multi.Pressure == nil || math.Abs(*multi.Pressure-want) > 1e-9 {
		t.Fatalf("three saturated axes = %v, want %v", multi.Pressure, want)
	}
	if *multi.Pressure <= *single.Pressure {
		t.Error("three-axis trouble must rank above one-axis trouble")
	}
	if multi.TopAxis != AxisMem {
		t.Errorf("top axis = %q, want %q", multi.TopAxis, AxisMem)
	}
}

func TestReasonsAreSortedAndValueFree(t *testing.T) {
	n := idle()
	n.Resources.RAMUtilP95 = f(0.95)
	n.Resources.CPUUtilP95 = f(0.9)
	n.Stress.IOWaitBusyFrac = f(0.2)
	n.Resources.FSUsedFracMax = f(0.9)
	got := Evaluate(n)

	for i := 1; i < len(got.Reasons); i++ {
		if got.Reasons[i-1] > got.Reasons[i] {
			t.Fatalf("reasons are not sorted: %v", got.Reasons)
		}
	}
	// Value-free: the gate-reasons lesson. An embedded float made every
	// deviating window its own rollup group of one.
	for _, r := range got.Reasons {
		for _, c := range r {
			if c >= '0' && c <= '9' {
				t.Errorf("reason %q carries a computed value", r)
			}
		}
	}
}

// ramp must never divide by zero, whatever a future edit does to the
// constants. This is the assertion the score's doc comment promises.
func TestEveryRampHasARealInterval(t *testing.T) {
	intervals := []struct {
		name   string
		x0, x1 float64
	}{
		{"ram_util", RAMUtilKnee, RAMUtilFull},
		{"swap_in", SwapInKnee, SwapInFull},
		{"oom", 1, OOMKillsMax},
		{"cpu_util", CPUUtilKnee, CPUUtilFull},
		{"load15/core", LoadPerCoreKnee, LoadPerCoreFull},
		{"iowait", IOWaitKnee, IOWaitFull},
		{"fs level", FSLevelKnee, FSLevelFull},
		{"fs trend", 0, FSTrendHorizon - FSTrendUrgent},
	}
	for _, in := range intervals {
		if in.x1 <= in.x0 {
			t.Errorf("%s: x1 (%v) must be greater than x0 (%v)", in.name, in.x1, in.x0)
		}
	}
	// And the guard itself holds: a degenerate interval yields a defined
	// value rather than a NaN.
	if v := ramp(5, 1, 1, 60); math.IsNaN(v) {
		t.Error("a degenerate ramp produced NaN")
	}
}

func TestThresholdsAreAllLabelled(t *testing.T) {
	all := Thresholds()
	if len(all) == 0 {
		t.Fatal("the UI has no thresholds to render")
	}
	guesses := 0
	for _, th := range all {
		switch th.Basis {
		case BasisPhysical, BasisConvention:
		case BasisGuess:
			guesses++
		default:
			t.Errorf("threshold %q has no basis", th.Name)
		}
	}
	// If nothing is labelled a guess, someone has quietly promoted an
	// uncalibrated number to advice.
	if guesses == 0 {
		t.Error("no threshold is labelled a guess; calibration has not happened yet")
	}
}

func hasReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}

// --- verdict ---

func days(n int, pressure float64) []DayScore {
	out := make([]DayScore, 0, n)
	for i := 0; i < n; i++ {
		p := pressure
		out = append(out, DayScore{Day: int64(20000 + i), Pressure: &p, TopAxis: AxisMem})
	}
	return out
}

func TestVerdictKOfN(t *testing.T) {
	cases := []struct {
		name     string
		days     []DayScore
		previous string
		want     string
	}{
		{"nothing reported", nil, "", VerdictInsufficientData},
		{"one day is not a verdict", days(1, 90), "", VerdictInsufficientData},
		{"just under the presence floor", days(MinDaysPresent-1, 90), "", VerdictInsufficientData},
		{"quiet fleet", days(MinDaysPresent, 5), "", VerdictOK},
		{"persistently elevated", days(AtRiskDays, AtRiskPressure), "", VerdictAtRisk},
		{"persistently bad", days(MinDaysPresent, UndersizedPressure), "", VerdictUndersized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EvaluateVerdict(tc.days, tc.previous); got.State != tc.want {
				t.Errorf("verdict = %q, want %q (%+v)", got.State, tc.want, got)
			}
		})
	}
}

func TestVerdictUndersizedNeedsSevenBadDays(t *testing.T) {
	// Six bad days plus enough quiet days to clear the presence floor.
	mixed := append(days(UndersizedDays-1, 90), days(MinDaysPresent, 1)...)
	if got := EvaluateVerdict(mixed, ""); got.State == VerdictUndersized {
		t.Errorf("six bad days produced %q; undersizing is recurrence", got.State)
	}
	seven := append(days(UndersizedDays, 90), days(MinDaysPresent, 1)...)
	if got := EvaluateVerdict(seven, ""); got.State != VerdictUndersized {
		t.Errorf("seven bad days produced %q, want undersized (%+v)", got.State, got)
	}
}

// Once undersized, the verdict holds until the bad days fall away. Without
// hysteresis a node hovering at seven bad days flaps every pass, and a
// flapping verdict is one nobody acts on.
func TestVerdictHysteresis(t *testing.T) {
	recovering := append(days(HysteresisBadDays+1, 90), days(MinDaysPresent, 1)...)
	if got := EvaluateVerdict(recovering, VerdictUndersized); got.State != VerdictUndersized {
		t.Errorf("verdict = %q, want the previous undersized to hold", got.State)
	}
	recovered := append(days(HysteresisBadDays, 90), days(MinDaysPresent, 1)...)
	if got := EvaluateVerdict(recovered, VerdictUndersized); got.State == VerdictUndersized {
		t.Error("at or below the hysteresis floor the verdict must release")
	}
}

// The verdict names the resource that was worst on the most bad days, and the
// answer must not depend on map iteration order.
func TestVerdictNamesTheMostFrequentCause(t *testing.T) {
	agreed := append(days(UndersizedDays, 90), days(MinDaysPresent, 1)...)
	got := EvaluateVerdict(agreed, "")
	if got.State != VerdictUndersized {
		t.Fatalf("verdict = %q, want undersized", got.State)
	}
	if got.TopAxis != AxisMem {
		t.Errorf("top axis = %q, want %q", got.TopAxis, AxisMem)
	}

	// Four bad days on mem, three on cpu: mem wins, deterministically.
	var mixed []DayScore
	for i, axis := range []string{AxisMem, AxisCPU, AxisMem, AxisCPU, AxisMem, AxisCPU, AxisMem} {
		p := 90.0
		mixed = append(mixed, DayScore{Day: int64(20000 + i), Pressure: &p, TopAxis: axis})
	}
	mixed = append(mixed, days(MinDaysPresent, 1)...)
	for i := 0; i < 20; i++ {
		if got := EvaluateVerdict(mixed, ""); got.TopAxis != AxisMem {
			t.Fatalf("top axis = %q, want %q on every run", got.TopAxis, AxisMem)
		}
	}
}

// An unmeasured day is not a good day: it must not count toward presence.
func TestVerdictIgnoresUnscoredDays(t *testing.T) {
	unscored := make([]DayScore, VerdictWindowDays)
	for i := range unscored {
		unscored[i] = DayScore{Day: int64(20000 + i)}
	}
	if got := EvaluateVerdict(unscored, ""); got.State != VerdictInsufficientData {
		t.Errorf("verdict = %q, want insufficient_data", got.State)
	}
}

// Placement is the question only a cluster can be asked, and it is the
// highest-value thing that falls out of a system_id being a cluster.
func TestClusterPlacement(t *testing.T) {
	if _, advice := ClusterPlacement([]float64{0.9}); advice != "" {
		t.Errorf("a single-node cluster has no placement answer, got %q", advice)
	}
	if _, advice := ClusterPlacement(nil); advice != "" {
		t.Errorf("an empty cluster has no placement answer, got %q", advice)
	}
	spread, advice := ClusterPlacement([]float64{0.95, 0.20, 0.40})
	if advice != "rebalance" {
		t.Errorf("advice = %q, want rebalance", advice)
	}
	if math.Abs(spread-0.75) > 1e-9 {
		t.Errorf("spread = %v, want 0.75", spread)
	}
	if _, advice := ClusterPlacement([]float64{0.50, 0.55, 0.60}); advice != "balanced" {
		t.Errorf("advice = %q, want balanced", advice)
	}
}
