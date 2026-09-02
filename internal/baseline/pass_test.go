// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package baseline

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/sizing"
	"github.com/nethesis/nethesis-insights/internal/store"
)

// The exclusions and the floors ARE the SQL and the folding, so these run
// against a real temp-file SQLite database rather than a mock -- the same
// reasoning as internal/blocklist's consensus tests.
func newTestStore(t *testing.T) *store.SQLiteStore {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

const (
	// 2026-09-01 as a UTC day index.
	testDay = int64(20698)
	testNow = testDay * sizing.DayMillis
)

func fp(v float64) *float64 { return &v }

func testConfig() Config {
	return Config{WindowDays: 28, MinDistinctSystems: 20, MinNodes: 30}
}

type nodeSpec struct {
	ramUtil  float64
	ramUsed  float64
	swapIn   float64
	oomKills float64
	family   string
	factsOK  int
	workload map[string]float64
	version  int
}

func defaultSpec() nodeSpec {
	return nodeSpec{
		ramUtil: 0.45, ramUsed: 3.6e9, family: "mail", factsOK: 1,
		workload: map[string]float64{"mailboxes": 210},
		version:  sizing.PressureVersion,
	}
}

// seed writes `systems` clusters of `nodesPer` nodes, each with `days` days of
// history, all matching spec.
func seed(t *testing.T, s *store.SQLiteStore, systems, nodesPer, days int, spec nodeSpec) {
	t.Helper()
	ctx := context.Background()

	for sysIdx := 0; sysIdx < systems; sysIdx++ {
		systemID := fmt.Sprintf("sys-%03d", sysIdx)
		var rows []store.SizingDayRows
		for d := 0; d < days; d++ {
			day := testDay - int64(d)
			var nodes []store.SizingNodeDayRow
			for nodeID := 1; nodeID <= nodesPer; nodeID++ {
				nodes = append(nodes, nodeRow(nodeID, spec))
			}
			rows = append(rows, store.SizingDayRows{Day: day, Nodes: nodes})
		}
		if _, err := s.UpsertSizingDays(ctx, systemID, "1.0.0", rows, testNow); err != nil {
			t.Fatalf("seed %s: %v", systemID, err)
		}
	}
}

func nodeRow(nodeID int, spec nodeSpec) store.SizingNodeDayRow {
	r := store.SizingNodeDayRow{
		NodeID:         nodeID,
		MetricsPresent: true,
		SampleCoverage: 0.99,
		Hardware:       model.SizingHardware{CPUCores: 4, MemTotalBytes: 8 << 30},
		Resources: model.SizingResources{
			RAMUtilP95:      fp(spec.ramUtil),
			RAMUsedBytesP95: fp(spec.ramUsed),
			CPUUtilP95:      fp(0.2),
			CPUCoresUsedP95: fp(0.8),
		},
		Stress: model.SizingStress{
			IOWaitBusyFrac: fp(0.01),
			SwapInPPSP95:   fp(spec.swapIn),
			OOMKills:       fp(spec.oomKills),
			Reboots:        fp(0),
		},
		Modules: []model.SanitizedSizingModule{{
			Family: spec.family, Instances: 1, FactsOK: spec.factsOK, Workload: spec.workload,
		}},
	}
	r.SetScore(fp(10), fp(8), fp(4), fp(0), fp(0), sizing.AxisMem, nil, spec.version, false)
	return r
}

func cohortFor(t *testing.T, s *store.SQLiteStore, kind, key string) *store.SizingCohortRow {
	t.Helper()
	rows, err := s.ListSizingCohorts(context.Background(), kind, 500)
	if err != nil {
		t.Fatalf("list cohorts: %v", err)
	}
	for i := range rows {
		if rows[i].CohortKey == key {
			return &rows[i]
		}
	}
	return nil
}

// The floor counts DISTINCT system_id, the same rule and the same reason as
// Threat Shield's promotion: 19 clusters publishes nothing and 20 publishes.
func TestFloorNeedsTwentyDistinctSystems(t *testing.T) {
	for _, tc := range []struct {
		systems int
		want    bool
	}{{19, false}, {20, true}} {
		t.Run(fmt.Sprintf("%d systems", tc.systems), func(t *testing.T) {
			s := newTestStore(t)
			seed(t, s, tc.systems, 2, 3, defaultSpec())

			if err := New(s, testConfig()).Run(context.Background(), testNow); err != nil {
				t.Fatalf("run: %v", err)
			}
			got := cohortFor(t, s, sizing.CohortFamilySolo, "mail")
			if tc.want && got == nil {
				t.Fatal("nothing published though the floor was cleared")
			}
			if !tc.want && got != nil {
				t.Fatalf("published below the floor: %+v", got)
			}
			if got != nil && got.DistinctSystems != tc.systems {
				t.Errorf("distinct systems = %d, want %d", got.DistinctSystems, tc.systems)
			}
		})
	}
}

// One MSP's forty identical clusters is one opinion about hardware, not
// forty -- and one cluster with forty nodes is likewise one opinion.
func TestOneSystemWithManyNodesDoesNotPublish(t *testing.T) {
	s := newTestStore(t)
	seed(t, s, 1, 40, 3, defaultSpec())

	if err := New(s, testConfig()).Run(context.Background(), testNow); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := cohortFor(t, s, sizing.CohortFamilySolo, "mail"); got != nil {
		t.Fatalf("one system with 40 nodes published a baseline: %+v", got)
	}
}

// A censored-heavy cohort publishes with the count set rather than a silently
// low percentile: a cohort that is largely censored means the fleet's own
// hardware for that profile is systematically too small, which is the most
// valuable finding the pass can produce.
func TestCensoredNodesAreCountedNotHidden(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	roomy := defaultSpec()
	roomy.ramUsed = 3.6e9
	seed(t, s, 20, 1, 3, roomy)

	// A second, larger set of clusters whose memory demand is unobservable:
	// their observed use is capped by the RAM they have.
	squeezed := defaultSpec()
	squeezed.ramUtil = 0.96
	squeezed.ramUsed = 7.6e9
	for sysIdx := 100; sysIdx < 115; sysIdx++ {
		systemID := fmt.Sprintf("sys-%03d", sysIdx)
		var rows []store.SizingDayRows
		for d := 0; d < 3; d++ {
			rows = append(rows, store.SizingDayRows{
				Day:   testDay - int64(d),
				Nodes: []store.SizingNodeDayRow{nodeRow(1, squeezed)},
			})
		}
		if _, err := s.UpsertSizingDays(ctx, systemID, "1.0.0", rows, testNow); err != nil {
			t.Fatalf("seed censored: %v", err)
		}
	}

	if err := New(s, testConfig()).Run(ctx, testNow); err != nil {
		t.Fatalf("run: %v", err)
	}
	got := cohortFor(t, s, sizing.CohortFamilySolo, "mail")
	if got == nil {
		t.Fatal("nothing published")
	}
	if got.CensoredNodes != 15 {
		t.Errorf("censored nodes = %d, want 15", got.CensoredNodes)
	}
	if got.Nodes != 35 {
		t.Errorf("nodes = %d, want 35 (censored nodes are counted, not dropped)", got.Nodes)
	}
	// The published percentile must come from the uncensored nodes only, or
	// the estimate is dragged toward the hardware ceiling of the small ones.
	if got.RAMUsedP90 > 4e9 {
		t.Errorf("p90 = %v; a censored node's capped demand leaked into the estimate", got.RAMUsedP90)
	}
}

// A node whose hardware changed inside the window is two machines, so its
// percentiles would straddle both.
func TestHardwareChangeExcludesTheNode(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seed(t, s, 20, 2, 3, defaultSpec())

	// Swap one node's memory, which stamps hw_changed_at inside the window.
	bigger := defaultSpec()
	swapped := nodeRow(1, bigger)
	swapped.Hardware.MemTotalBytes = 32 << 30
	if _, err := s.UpsertSizingDays(ctx, "sys-000", "1.0.0",
		[]store.SizingDayRows{{Day: testDay, Nodes: []store.SizingNodeDayRow{swapped}}}, testNow); err != nil {
		t.Fatalf("swap: %v", err)
	}

	if err := New(s, testConfig()).Run(ctx, testNow); err != nil {
		t.Fatalf("run: %v", err)
	}
	got := cohortFor(t, s, sizing.CohortFamilySolo, "mail")
	if got == nil {
		t.Fatal("nothing published")
	}
	if got.Nodes != 39 {
		t.Errorf("nodes = %d, want 39 -- the replaced machine must be excluded", got.Nodes)
	}
}

// facts_ok is what tells "zero mailboxes" from "the facts call failed". A
// failed call is genuinely unknown, so it must not become a workload bucket
// data point -- while a genuinely idle instance must.
func TestFailedFactsCallDoesNotBucket(t *testing.T) {
	s := newTestStore(t)
	failed := defaultSpec()
	failed.factsOK = 0
	failed.workload = map[string]float64{"mailboxes": 0}
	seed(t, s, 20, 2, 3, failed)

	if err := New(s, testConfig()).Run(context.Background(), testNow); err != nil {
		t.Fatalf("run: %v", err)
	}
	buckets, err := s.ListSizingBuckets(context.Background(), 100)
	if err != nil {
		t.Fatalf("list buckets: %v", err)
	}
	if len(buckets) != 0 {
		t.Errorf("buckets = %#v; a failed facts call is unknown, not idle", buckets)
	}

	// The same fleet with the call succeeding and a genuine zero does bucket:
	// an idle instance gives the floor cost of running the module.
	s2 := newTestStore(t)
	idle := defaultSpec()
	idle.workload = map[string]float64{"mailboxes": 0}
	seed(t, s2, 20, 2, 3, idle)
	if err := New(s2, testConfig()).Run(context.Background(), testNow); err != nil {
		t.Fatalf("run: %v", err)
	}
	if buckets, _ := s2.ListSizingBuckets(context.Background(), 100); len(buckets) == 0 {
		t.Error("an idle instance must still be bucketed")
	}
}

// A cohort that falls below the floor is DELETED, not left stale: a published
// baseline with no evidence behind it is worse than no baseline, because
// nothing on the page says how old it is.
func TestCohortFallingBelowTheFloorIsDeleted(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seed(t, s, 20, 2, 3, defaultSpec())

	runner := New(s, testConfig())
	if err := runner.Run(ctx, testNow); err != nil {
		t.Fatalf("run: %v", err)
	}
	if cohortFor(t, s, sizing.CohortFamilySolo, "mail") == nil {
		t.Fatal("nothing published on the first pass")
	}

	// Raise the floor above what the fleet can support and run again.
	strict := testConfig()
	strict.MinDistinctSystems = 500
	if err := New(s, strict).Run(ctx, testNow+1000); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if got := cohortFor(t, s, sizing.CohortFamilySolo, "mail"); got != nil {
		t.Fatalf("a cohort below the floor was left stale: %+v", got)
	}
}

// Step 1 before step 4 is load-bearing: a pressure_version bump must be
// recomputed BEFORE cohorts are built, or a baseline mixes two score
// definitions.
func TestStalePressureIsRecomputedBeforeCohorts(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	stale := defaultSpec()
	stale.version = sizing.PressureVersion - 1
	seed(t, s, 20, 2, 3, stale)

	if left, err := s.StaleSizingScores(ctx, sizing.PressureVersion, 10); err != nil {
		t.Fatalf("stale: %v", err)
	} else if len(left) == 0 {
		t.Fatal("the fixture is not actually stale")
	}

	if err := New(s, testConfig()).Run(ctx, testNow); err != nil {
		t.Fatalf("run: %v", err)
	}

	left, err := s.StaleSizingScores(ctx, sizing.PressureVersion, 10)
	if err != nil {
		t.Fatalf("stale: %v", err)
	}
	if len(left) != 0 {
		t.Errorf("stale rows after the pass = %d, want 0", len(left))
	}
	got := cohortFor(t, s, sizing.CohortFamilySolo, "mail")
	if got == nil {
		t.Fatal("nothing published")
	}
	if got.PressureVersion != sizing.PressureVersion {
		t.Errorf("cohort pressure_version = %d, want %d", got.PressureVersion, sizing.PressureVersion)
	}
}

func TestVerdictsAndPlacementArePublished(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	// One cluster, two nodes, one of them under sustained memory pressure and
	// the other idle -- so the cluster's answer is "rebalance".
	hot := defaultSpec()
	hot.ramUtil = 0.88
	cold := defaultSpec()
	cold.ramUtil = 0.10

	var rows []store.SizingDayRows
	for d := 0; d < sizing.MinDaysPresent+2; d++ {
		hotRow := nodeRow(1, hot)
		hotRow.SetScore(fp(80), fp(70), fp(4), fp(0), fp(0), sizing.AxisMem, nil, sizing.PressureVersion, false)
		coldRow := nodeRow(2, cold)
		coldRow.SetScore(fp(2), fp(2), fp(0), fp(0), fp(0), sizing.AxisMem, nil, sizing.PressureVersion, false)
		rows = append(rows, store.SizingDayRows{
			Day:   testDay - int64(d),
			Nodes: []store.SizingNodeDayRow{hotRow, coldRow},
		})
	}
	if _, err := s.UpsertSizingDays(ctx, "sys-hot", "1.0.0", rows, testNow); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := New(s, testConfig()).Run(ctx, testNow); err != nil {
		t.Fatalf("run: %v", err)
	}

	states, err := s.SizingVerdictStates(ctx)
	if err != nil {
		t.Fatalf("verdict states: %v", err)
	}
	if got := states[store.SizingNodeKey("sys-hot", 1)]; got != sizing.VerdictUndersized {
		t.Errorf("hot node verdict = %q, want %q", got, sizing.VerdictUndersized)
	}
	if got := states[store.SizingNodeKey("sys-hot", 2)]; got != sizing.VerdictOK {
		t.Errorf("idle node verdict = %q, want %q", got, sizing.VerdictOK)
	}

	nodes, err := s.ListSizingNodes(ctx, "sys-hot", 10)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	for _, n := range nodes {
		if n.Placement != "rebalance" {
			t.Errorf("node %d placement = %q, want rebalance", n.NodeID, n.Placement)
		}
		if n.ClusterNodes != 2 {
			t.Errorf("node %d cluster_nodes = %d, want 2", n.NodeID, n.ClusterNodes)
		}
	}
}

func TestPassOnAnEmptyDatabase(t *testing.T) {
	s := newTestStore(t)
	if err := New(s, testConfig()).Run(context.Background(), testNow); err != nil {
		t.Fatalf("a pass over an empty database must succeed: %v", err)
	}
	if got, _ := s.ListSizingCohorts(context.Background(), "", 10); len(got) != 0 {
		t.Errorf("cohorts = %#v, want none", got)
	}
}

// --- housekeeping order and failure handling ---
//
// These use a fake Reader rather than SQLite, because what is under test is
// the ORDER of the calls and what happens when one fails, neither of which a
// real store can be made to demonstrate.

type recordingReader struct {
	calls        []string
	rollupErr    error
	pruneErr     error
	pruneCalled  bool
	verdictCalls int
}

func (r *recordingReader) note(name string) { r.calls = append(r.calls, name) }

func (r *recordingReader) StaleSizingScores(context.Context, int, int) ([]store.SizingNodeDayRow, error) {
	r.note("stale")
	return nil, nil
}
func (r *recordingReader) UpdateSizingScores(context.Context, []store.SizingNodeDayRow) error {
	r.note("update")
	return nil
}
func (r *recordingReader) SizingWindow(context.Context, int64, int64) ([]store.SizingWindowRow, error) {
	r.note("window")
	return nil, nil
}
func (r *recordingReader) SizingWindowFamilies(context.Context, int64, int64) ([]store.SizingNodeFamilyRow, error) {
	r.note("families")
	return nil, nil
}
func (r *recordingReader) SizingWindowMetrics(context.Context, int64, int64) ([]store.SizingFamilyMetricRow, error) {
	r.note("metrics")
	return nil, nil
}
func (r *recordingReader) SizingVerdictStates(context.Context) (map[string]string, error) {
	r.note("states")
	return map[string]string{}, nil
}
func (r *recordingReader) UpsertSizingVerdicts(_ context.Context, rows []store.SizingVerdictRow) error {
	r.note("verdicts")
	r.verdictCalls = len(rows)
	return nil
}
func (r *recordingReader) UpsertSizingCohorts(context.Context, []store.SizingCohortRow) error {
	r.note("cohorts")
	return nil
}
func (r *recordingReader) DeleteStaleSizingCohorts(context.Context, int64) (int, error) {
	r.note("expire-cohorts")
	return 0, nil
}
func (r *recordingReader) UpsertSizingBuckets(context.Context, []store.SizingBucketRow) error {
	r.note("buckets")
	return nil
}
func (r *recordingReader) DeleteStaleSizingBuckets(context.Context, int64) (int, error) {
	r.note("expire-buckets")
	return 0, nil
}
func (r *recordingReader) RollupSizingMonthly(context.Context, int64, int64) error {
	r.note("rollup")
	return r.rollupErr
}
func (r *recordingReader) PruneSizingDaily(context.Context, int64) (int, error) {
	r.note("prune")
	r.pruneCalled = true
	return 0, r.pruneErr
}

func indexOf(calls []string, want string) int {
	for i, c := range calls {
		if c == want {
			return i
		}
	}
	return -1
}

// Roll up before pruning, or the day being dropped loses its history
// permanently -- the same constraint, and the same reason, as Threat Shield's
// RollupThreatDailyStats before PruneThreatEvents.
func TestRollupPrecedesPrune(t *testing.T) {
	r := &recordingReader{}
	cfg := testConfig()
	cfg.Retention = 100 * 24 * 60 * 60 * 1e9 // 100 days
	if err := New(r, cfg).Run(context.Background(), testNow); err != nil {
		t.Fatalf("run: %v", err)
	}
	rollup, prune := indexOf(r.calls, "rollup"), indexOf(r.calls, "prune")
	if rollup < 0 || prune < 0 {
		t.Fatalf("calls = %v", r.calls)
	}
	if rollup > prune {
		t.Errorf("the prune ran before the rollup: %v", r.calls)
	}
	// And the recompute precedes the cohort build, or a version bump
	// publishes a baseline mixing two score definitions.
	if indexOf(r.calls, "stale") > indexOf(r.calls, "cohorts") {
		t.Errorf("cohorts were built before the recompute: %v", r.calls)
	}
}

// A failed rollup must skip the prune entirely: pruning a day whose history
// was not saved destroys it.
func TestFailedRollupSkipsPrune(t *testing.T) {
	r := &recordingReader{rollupErr: errors.New("boom")}
	cfg := testConfig()
	cfg.Retention = 100 * 24 * 60 * 60 * 1e9
	if err := New(r, cfg).Run(context.Background(), testNow); err != nil {
		t.Fatalf("a housekeeping failure must not abort the pass: %v", err)
	}
	if r.pruneCalled {
		t.Error("the prune ran after the rollup failed")
	}
}

// Housekeeping failures are logged, not fatal: they must not undo the
// verdicts and baselines the pass just published.
func TestFailedPruneDoesNotAbortThePass(t *testing.T) {
	r := &recordingReader{pruneErr: errors.New("boom")}
	cfg := testConfig()
	cfg.Retention = 100 * 24 * 60 * 60 * 1e9
	if err := New(r, cfg).Run(context.Background(), testNow); err != nil {
		t.Fatalf("a prune failure must not abort the pass: %v", err)
	}
	if indexOf(r.calls, "cohorts") < 0 {
		t.Error("the pass did not get as far as publishing")
	}
}

// Retention unset means no prune at all, so a deployment that has not opted
// into retention never loses data.
func TestNoRetentionMeansNoPrune(t *testing.T) {
	r := &recordingReader{}
	if err := New(r, testConfig()).Run(context.Background(), testNow); err != nil {
		t.Fatalf("run: %v", err)
	}
	if r.pruneCalled {
		t.Error("the prune ran with no retention configured")
	}
}
