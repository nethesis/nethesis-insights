// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package store

import (
	"context"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/model"
)

const (
	testSizingSystem = "sys-sizing"
	// 2026-09-01 as a UTC day index.
	testSizingDay = int64(20698)
	testSizingNow = testSizingDay * dayMillis
)

func fp(v float64) *float64 { return &v }

func sizingNodeRow(nodeID int, ramUtil float64) SizingNodeDayRow {
	r := SizingNodeDayRow{
		NodeID:         nodeID,
		MetricsPresent: true,
		SampleCoverage: 0.99,
		Hardware: model.SizingHardware{
			CPUCores: 4, MemTotalBytes: 8 << 30, CPUModel: "test cpu", OSID: "rocky",
		},
		Resources: model.SizingResources{
			RAMUtilP95:      fp(ramUtil),
			RAMUsedBytesP95: fp(ramUtil * float64(int64(8)<<30)),
			CPUUtilP95:      fp(0.2),
			CPUCoresUsedP95: fp(0.8),
		},
		Stress: model.SizingStress{
			IOWaitBusyFrac: fp(0.01), SwapInPPSP95: fp(0), OOMKills: fp(0), Reboots: fp(0),
		},
		Modules: []model.SanitizedSizingModule{{
			Family: "mail", Instances: 1, FactsOK: 1, Versions: []string{"1.2.3"},
			Workload: map[string]float64{"mailboxes": 210, "domains": 3},
		}},
	}
	r.SetScore(SizingScore{
		Pressure: fp(12), Mem: fp(10), CPU: fp(4), IO: fp(0), Disk: fp(0),
		TopAxis: "mem", Reasons: []string{"ram_headroom"}, Version: 1,
	})
	return r
}

func oneSizingDay(rows ...SizingNodeDayRow) []SizingDayRows {
	return []SizingDayRows{{
		Day:             testSizingDay,
		Nodes:           rows,
		ClusterWorkload: map[string]float64{"total_users": 210},
	}}
}

func TestUpsertSizingDaysStoresEverything(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	stored, err := s.UpsertSizingDays(ctx, testSizingSystem, "1.0.0",
		oneSizingDay(sizingNodeRow(1, 0.41), sizingNodeRow(2, 0.55)), testSizingNow)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if stored != 2 {
		t.Fatalf("stored = %d, want 2", stored)
	}

	window, err := s.SizingWindow(ctx, testSizingDay-1, testSizingDay+1)
	if err != nil {
		t.Fatalf("window: %v", err)
	}
	if len(window) != 2 {
		t.Fatalf("window rows = %d, want 2", len(window))
	}
	if window[0].Pressure == nil || *window[0].Pressure != 12 {
		t.Errorf("pressure = %v, want 12", window[0].Pressure)
	}

	families, err := s.SizingWindowFamilies(ctx, testSizingDay-1, testSizingDay+1)
	if err != nil {
		t.Fatalf("families: %v", err)
	}
	if len(families) != 2 || families[0].Family != "mail" {
		t.Fatalf("families = %#v", families)
	}

	metrics, err := s.SizingWindowMetrics(ctx, testSizingDay-1, testSizingDay+1)
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	if len(metrics) != 4 {
		t.Errorf("metric rows = %d, want 4 (2 nodes x 2 metrics)", len(metrics))
	}
}

// The same day posted three times must converge on identical measurement
// columns and must not double any counter: a day is an absolute fact, so the
// second and third sends are byte-identical restatements.
//
// The other half of the same rule: sizing_ingest_daily ACCUMULATES while
// sizing_node_daily RECOMPUTES. Mixing the two idioms would be silent, which
// is why both halves are asserted here.
func TestSizingRedeliveryRecomputesButCountersAccumulate(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	counters := model.SizingCounters{AcceptedNodes: 1, AcceptedModules: 1, AcceptedMetrics: 2, DroppedFamily: 1}

	for i := 0; i < 3; i++ {
		if _, err := s.UpsertSizingDays(ctx, testSizingSystem, "1.0.0",
			oneSizingDay(sizingNodeRow(1, 0.41)), testSizingNow); err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
		if err := s.RecordSizingIngest(ctx, testSizingDay, testSizingSystem, "1.0.0", counters, testSizingNow); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	window, err := s.SizingWindow(ctx, testSizingDay, testSizingDay)
	if err != nil {
		t.Fatalf("window: %v", err)
	}
	if len(window) != 1 {
		t.Fatalf("node-day rows = %d, want exactly 1 after three sends", len(window))
	}

	metrics, err := s.SizingWindowMetrics(ctx, testSizingDay, testSizingDay)
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	if len(metrics) != 2 {
		t.Fatalf("metric rows = %d, want 2", len(metrics))
	}
	for _, m := range metrics {
		if m.Metric == "mailboxes" && m.Value != 210 {
			t.Errorf("mailboxes = %v, want 210 (recomputed, never summed)", m.Value)
		}
	}

	ingest, err := s.SizingIngestStats(ctx, 10)
	if err != nil {
		t.Fatalf("ingest stats: %v", err)
	}
	if len(ingest) != 1 {
		t.Fatalf("ingest rows = %d, want 1", len(ingest))
	}
	if ingest[0].Reports != 3 {
		t.Errorf("reports = %d, want 3", ingest[0].Reports)
	}
	if ingest[0].AcceptedNodes != 3 || ingest[0].DroppedFamily != 3 {
		t.Errorf("counters did not accumulate: %+v", ingest[0].SizingCounters)
	}
}

// A family that has been uninstalled must disappear rather than linger
// forever: recompute means recompute.
func TestUpsertSizingDaysDropsRemovedFamilies(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	first := sizingNodeRow(1, 0.41)
	first.Modules = append(first.Modules, model.SanitizedSizingModule{
		Family: "nextcloud", Instances: 1, FactsOK: 1,
		Workload: map[string]float64{"users": 40},
	})
	if _, err := s.UpsertSizingDays(ctx, testSizingSystem, "1.0.0", oneSizingDay(first), testSizingNow); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// nextcloud uninstalled; the same day is restated.
	if _, err := s.UpsertSizingDays(ctx, testSizingSystem, "1.0.0",
		oneSizingDay(sizingNodeRow(1, 0.41)), testSizingNow); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}

	families, err := s.SizingWindowFamilies(ctx, testSizingDay, testSizingDay)
	if err != nil {
		t.Fatalf("families: %v", err)
	}
	if len(families) != 1 || families[0].Family != "mail" {
		t.Errorf("families = %#v, want only mail", families)
	}
}

// Node identity is not stable: a replaced machine keeps its cluster-scoped
// node id with different hardware, and the cohort pass has to be able to see
// that so its percentiles do not straddle two physical machines.
func TestSizingNodeDimensionRecordsHardwareChange(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.UpsertSizingDays(ctx, testSizingSystem, "1.0.0",
		oneSizingDay(sizingNodeRow(1, 0.41)), testSizingNow); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	window, _ := s.SizingWindow(ctx, testSizingDay, testSizingDay)
	if window[0].HWChangedAt != 0 {
		t.Error("a first sighting must not record a hardware change")
	}

	bigger := sizingNodeRow(1, 0.41)
	bigger.Hardware.MemTotalBytes = 16 << 30
	later := testSizingNow + dayMillis
	if _, err := s.UpsertSizingDays(ctx, testSizingSystem, "1.0.0",
		[]SizingDayRows{{Day: testSizingDay + 1, Nodes: []SizingNodeDayRow{bigger}}}, later); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	window, _ = s.SizingWindow(ctx, testSizingDay, testSizingDay+1)
	found := false
	for _, row := range window {
		if row.HWChangedAt == later {
			found = true
		}
	}
	if !found {
		t.Error("a memory change must set hw_changed_at")
	}
}

// A degraded report carries no hardware; it must not read as the machine
// having been swapped for a smaller one.
func TestSizingDegradedReportIsNotAHardwareChange(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.UpsertSizingDays(ctx, testSizingSystem, "1.0.0",
		oneSizingDay(sizingNodeRow(1, 0.41)), testSizingNow); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	degraded := SizingNodeDayRow{NodeID: 1}
	degraded.SetScore(SizingScore{Reasons: []string{"insufficient_coverage"}, Version: 1})
	later := testSizingNow + dayMillis
	if _, err := s.UpsertSizingDays(ctx, testSizingSystem, "1.0.0",
		[]SizingDayRows{{Day: testSizingDay + 1, Nodes: []SizingNodeDayRow{degraded}}}, later); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	window, _ := s.SizingWindow(ctx, testSizingDay+1, testSizingDay+1)
	if len(window) != 1 {
		t.Fatalf("the degraded node-day was not stored")
	}
	if window[0].Pressure != nil {
		t.Error("a degraded report must store no pressure")
	}
	if window[0].HWChangedAt != 0 {
		t.Error("a report with no hardware must not count as a hardware change")
	}
}

// A pressure_version bump must be findable without a full scan, and the
// recompute path must touch nothing but the derived columns.
func TestStaleSizingScoresAndUpdate(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.UpsertSizingDays(ctx, testSizingSystem, "1.0.0",
		oneSizingDay(sizingNodeRow(1, 0.41)), testSizingNow); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	if stale, err := s.StaleSizingScores(ctx, 1, 100); err != nil {
		t.Fatalf("stale: %v", err)
	} else if len(stale) != 0 {
		t.Fatalf("stale rows at the current version = %d, want 0", len(stale))
	}

	stale, err := s.StaleSizingScores(ctx, 2, 100)
	if err != nil {
		t.Fatalf("stale: %v", err)
	}
	if len(stale) != 1 {
		t.Fatalf("stale rows after a bump = %d, want 1", len(stale))
	}
	// Every input the formula needs must come back, or the recompute would
	// silently score against missing data.
	got := stale[0]
	if got.Resources.RAMUtilP95 == nil || *got.Resources.RAMUtilP95 != 0.41 {
		t.Errorf("ram_util_p95 did not survive the round trip: %v", got.Resources.RAMUtilP95)
	}
	if !got.MetricsPresent || got.SampleCoverage != 0.99 || got.Hardware.CPUCores != 4 {
		t.Errorf("coverage inputs did not survive: %+v", got)
	}

	got.SetScore(SizingScore{
		Pressure: fp(77), Mem: fp(70), TopAxis: "mem",
		Reasons: []string{"oom_kill"}, Version: 2,
	})
	if err := s.UpdateSizingScores(ctx, []SizingNodeDayRow{got}); err != nil {
		t.Fatalf("update: %v", err)
	}

	window, _ := s.SizingWindow(ctx, testSizingDay, testSizingDay)
	if window[0].Pressure == nil || *window[0].Pressure != 77 {
		t.Errorf("pressure = %v, want 77", window[0].Pressure)
	}
	if left, _ := s.StaleSizingScores(ctx, 2, 100); len(left) != 0 {
		t.Errorf("stale rows after recompute = %d, want 0", len(left))
	}
}

func TestSizingCohortsPublishAndExpire(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	row := SizingCohortRow{
		CohortKind: "family_solo", CohortKey: "mail",
		Nodes: 40, DistinctSystems: 25, CensoredNodes: 4,
		RAMUsedP90: 9.5e9, MinDistinctSystems: 20, MinNodes: 30,
		WindowDays: 28, PressureVersion: 1, UpdatedAt: 1000,
	}
	if err := s.UpsertSizingCohorts(ctx, []SizingCohortRow{row}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := s.ListSizingCohorts(ctx, "", 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].CensoredNodes != 4 {
		t.Fatalf("cohorts = %#v", got)
	}

	// A cohort that no longer clears the floor is deleted, not left stale: a
	// published baseline with no evidence behind it is worse than none.
	n, err := s.DeleteStaleSizingCohorts(ctx, 2000)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted = %d, want 1", n)
	}
	if got, _ := s.ListSizingCohorts(ctx, "", 10); len(got) != 0 {
		t.Errorf("cohorts survived the expiry: %#v", got)
	}
}

// The rollup must precede the prune, or the day being dropped loses its
// history permanently. This asserts the surviving artifact, which is what
// makes the ordering visible.
func TestRollupSizingMonthlyThenPrune(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.UpsertSizingDays(ctx, testSizingSystem, "1.0.0",
		oneSizingDay(sizingNodeRow(1, 0.41)), testSizingNow); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := s.RollupSizingMonthly(ctx, testSizingDay-40, testSizingDay); err != nil {
		t.Fatalf("rollup: %v", err)
	}

	var month string
	var daysPresent int
	err := s.db.QueryRowContext(ctx,
		`SELECT month, days_present FROM sizing_node_monthly WHERE system_id = ?`,
		testSizingSystem).Scan(&month, &daysPresent)
	if err != nil {
		t.Fatalf("read monthly: %v", err)
	}
	if month != "2026-09" {
		t.Errorf("month = %q, want 2026-09", month)
	}
	if daysPresent != 1 {
		t.Errorf("days_present = %d, want 1", daysPresent)
	}

	pruned, err := s.PruneSizingDaily(ctx, testSizingDay+1)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if pruned == 0 {
		t.Error("the prune removed nothing")
	}
	if window, _ := s.SizingWindow(ctx, 0, testSizingDay+10); len(window) != 0 {
		t.Error("the pruned day is still present")
	}
	// The rollup that ran first is what survives.
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sizing_node_monthly`).Scan(&count); err != nil {
		t.Fatalf("count monthly: %v", err)
	}
	if count != 1 {
		t.Errorf("monthly rows after the prune = %d, want 1", count)
	}
}

func TestSizingUIReadsAndCounts(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.UpsertSizingDays(ctx, testSizingSystem, "1.0.0",
		oneSizingDay(sizingNodeRow(1, 0.41), sizingNodeRow(2, 0.55)), testSizingNow); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := s.UpsertSizingVerdicts(ctx, []SizingVerdictRow{{
		SystemID: testSizingSystem, NodeID: 1, Verdict: "undersized", TopAxis: "mem",
		DaysPresent: 28, BadDays: 9, WindowDays: 28, ClusterNodes: 2,
		ClusterRAMUtilSpread: fp(0.14), Placement: "balanced", UpdatedAt: testSizingNow,
	}}); err != nil {
		t.Fatalf("verdicts: %v", err)
	}

	nodes, err := s.ListSizingNodes(ctx, "", 100)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes = %d, want 2", len(nodes))
	}
	if nodes[0].Verdict != "undersized" && nodes[1].Verdict != "undersized" {
		t.Error("the verdict was not joined onto the node row")
	}
	if len(nodes[0].Reasons) != 1 || nodes[0].Reasons[0] != "ram_headroom" {
		t.Errorf("reasons = %#v", nodes[0].Reasons)
	}

	mods, err := s.ListSizingModules(ctx, testSizingSystem, 100)
	if err != nil {
		t.Fatalf("list modules: %v", err)
	}
	if len(mods) != 2 {
		t.Fatalf("module rows = %d, want 2", len(mods))
	}
	// The workload map is folded for display, sorted so the string is stable.
	if mods[0].Workload != "domains=3, mailboxes=210" {
		t.Errorf("workload = %q", mods[0].Workload)
	}

	counts, err := s.SizingCounts(ctx)
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	if counts.Systems != 1 || counts.Nodes != 2 || counts.NodeDays != 2 {
		t.Errorf("counts = %+v", counts)
	}
	if counts.Undersized != 1 {
		t.Errorf("undersized = %d, want 1", counts.Undersized)
	}
	if counts.LatestDay != testSizingDay {
		t.Errorf("latest day = %d, want %d", counts.LatestDay, testSizingDay)
	}
}

// An empty database is an ordinary state, not an error: SUM over no rows is
// SQL NULL, and every count here has to survive that.
func TestSizingCountsOnAnEmptyDatabase(t *testing.T) {
	got, err := newTestStore(t).SizingCounts(context.Background())
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	if got.Systems != 0 || got.Undersized != 0 || got.LatestDay != 0 {
		t.Errorf("counts = %+v, want all zero", got)
	}
}

func TestMonthRangesCoverEveryTouchedMonth(t *testing.T) {
	// 2026-08-15 .. 2026-10-02
	from := int64(20680)
	to := from + 48
	got := monthRanges(from, to)
	if len(got) != 3 {
		t.Fatalf("months = %d (%#v), want 3", len(got), got)
	}
	if got[0].label != "2026-08" || got[2].label != "2026-10" {
		t.Errorf("labels = %q..%q", got[0].label, got[2].label)
	}
	for i, m := range got {
		if m.to < m.from {
			t.Errorf("month %d has an inverted range: %+v", i, m)
		}
		if i > 0 && m.from != got[i-1].to+1 {
			t.Errorf("months %d and %d are not contiguous: %+v %+v", i-1, i, got[i-1], m)
		}
	}
	if monthRanges(to, from) != nil {
		t.Error("an inverted window must enumerate no months")
	}
}
