// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package baseline runs the fleet-sizing cohort pass: it recomputes stale
// pressure scores, folds each node's window into a verdict, answers the
// placement question a cluster can be asked, and publishes the cohort
// baselines that clear the floor.
//
// It mirrors internal/blocklist -- a narrow Reader, a Config, a
// Runner.Run(ctx, now) error, a documented step order and housekeeping that
// is logged rather than fatal -- because it is the same shape of job: a
// periodic pass that turns stored evidence into a published artifact.
package baseline

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/nethesis/nethesis-insights/internal/sizing"
	"github.com/nethesis/nethesis-insights/internal/store"
)

// Reader is the slice of store.Store the pass needs. Declared here, like
// blocklist.Reader and ui.Reader, so this package is testable with a fake and
// the layering stays a DAG. *store.SQLiteStore satisfies it.
type Reader interface {
	StaleSizingScores(ctx context.Context, version, limit int) ([]store.SizingNodeDayRow, error)
	UpdateSizingScores(ctx context.Context, rows []store.SizingNodeDayRow) error
	SizingWindow(ctx context.Context, fromDay, toDay int64) ([]store.SizingWindowRow, error)
	SizingWindowFamilies(ctx context.Context, fromDay, toDay int64) ([]store.SizingNodeFamilyRow, error)
	SizingWindowMetrics(ctx context.Context, fromDay, toDay int64) ([]store.SizingFamilyMetricRow, error)
	SizingVerdictStates(ctx context.Context) (map[string]string, error)
	UpsertSizingVerdicts(ctx context.Context, rows []store.SizingVerdictRow) error
	UpsertSizingCohorts(ctx context.Context, rows []store.SizingCohortRow) error
	DeleteStaleSizingCohorts(ctx context.Context, before int64) (int, error)
	RollupSizingMonthly(ctx context.Context, fromDay, toDay int64) error
	PruneSizingDaily(ctx context.Context, olderThanDay int64) (int, error)
}

// Config is the cohort rule plus its housekeeping windows.
type Config struct {
	// WindowDays is the trailing window for verdicts and cohorts.
	WindowDays int
	// MinDistinctSystems and MinNodes are the publication floor. Both are
	// guesses; they are this pipeline's analogue of Threat Shield's "never
	// serve blank" -- below the floor, publish nothing at all rather than a
	// percentile computed from three nodes.
	MinDistinctSystems int
	MinNodes           int
	// Retention is how long daily rows are kept.
	Retention time.Duration
	// RecomputeBatch bounds one pass's version-bump catch-up. Unbounded, a
	// bump would rewrite 100 days of history through a single-writer
	// connection in one pass; bounded, the pass simply catches up over
	// several runs.
	RecomputeBatch int
}

// DefaultRecomputeBatch is used when Config.RecomputeBatch is unset.
const DefaultRecomputeBatch = 5000

// MonthlyRollupDays is how far back RollupSizingMonthly is asked to
// recompute. Wide enough to cover the previous calendar month after a few
// missed passes, narrow enough that the work stays two grouped queries.
const MonthlyRollupDays = 45

// Runner performs one cohort pass.
type Runner struct {
	store Reader
	cfg   Config
}

func New(r Reader, cfg Config) *Runner {
	if cfg.RecomputeBatch <= 0 {
		cfg.RecomputeBatch = DefaultRecomputeBatch
	}
	if cfg.WindowDays <= 0 {
		cfg.WindowDays = sizing.VerdictWindowDays
	}
	return &Runner{store: r, cfg: cfg}
}

// Run executes the pass in a fixed order:
//
//  1. Recompute pressure where pressure_version is stale (bounded batch)
//  2. Recompute node verdicts over the trailing window
//  3. Recompute cluster imbalance for multi-node clusters
//  4. Build cohorts: per-node reduction, then across-node percentiles,
//     applying and counting the censoring / coverage / hardware-change
//     exclusions
//  5. Upsert the baselines that clear the floor
//  6. DELETE the cohorts that no longer clear it
//  7. RollupSizingMonthly           housekeeping: logged, never fatal
//  8. PruneSizingDaily              only if 7 succeeded
//
// Two of those orderings are load-bearing. **1 before 4**, or a
// pressure_version bump publishes a baseline mixing two score definitions.
// **7 before 8**, or the day being dropped loses its history permanently --
// the same constraint, and the same reason, as Threat Shield's
// RollupThreatDailyStats before PruneThreatEvents.
//
// Steps 2, 3 and 4 all read the same window rows, in one query, because a
// second query would be a second chance for them to disagree.
func (r *Runner) Run(ctx context.Context, now int64) error {
	passStart := now
	today := now / sizing.DayMillis
	fromDay := today - int64(r.cfg.WindowDays)
	toDay := today

	recomputed, err := r.recompute(ctx)
	if err != nil {
		return err
	}

	window, err := r.store.SizingWindow(ctx, fromDay, toDay)
	if err != nil {
		return fmt.Errorf("baseline: window: %w", err)
	}
	previous, err := r.store.SizingVerdictStates(ctx)
	if err != nil {
		return fmt.Errorf("baseline: verdict states: %w", err)
	}

	nodes := foldNodes(window, fromDay, passStart)
	verdicts := buildVerdicts(nodes, previous, r.cfg.WindowDays, passStart)
	if err := r.store.UpsertSizingVerdicts(ctx, verdicts); err != nil {
		return fmt.Errorf("baseline: verdicts: %w", err)
	}

	families, err := r.store.SizingWindowFamilies(ctx, fromDay, toDay)
	if err != nil {
		return fmt.Errorf("baseline: window families: %w", err)
	}
	metrics, err := r.store.SizingWindowMetrics(ctx, fromDay, toDay)
	if err != nil {
		return fmt.Errorf("baseline: window metrics: %w", err)
	}
	attachFamilies(nodes, families, metrics)

	cohorts := r.build(nodes, passStart)
	if err := r.store.UpsertSizingCohorts(ctx, cohorts); err != nil {
		return fmt.Errorf("baseline: cohorts: %w", err)
	}

	// Deleting what this pass did not republish is exactly "delete a cohort
	// that has fallen below the floor", and it mirrors ExpireBlocklist: a
	// published baseline with no evidence behind it is worse than no
	// baseline, because nothing on the page says how old it is.
	droppedCohorts, err := r.store.DeleteStaleSizingCohorts(ctx, passStart)
	if err != nil {
		return fmt.Errorf("baseline: expire cohorts: %w", err)
	}

	// Housekeeping failures are logged, not fatal: they must not undo the
	// verdicts and baselines this pass just published.
	pruned := 0
	if err := r.store.RollupSizingMonthly(ctx, today-MonthlyRollupDays, today); err != nil {
		slog.Error("baseline: monthly rollup failed", "error", err)
	} else if r.cfg.Retention > 0 {
		// Only prune when the rollup that protects the history succeeded.
		cutoff := today - int64(r.cfg.Retention/(24*time.Hour))
		if n, err := r.store.PruneSizingDaily(ctx, cutoff); err != nil {
			slog.Error("baseline: prune failed", "error", err)
		} else {
			pruned = n
		}
	}

	slog.Info("sizing cohort pass",
		"recomputed", recomputed, "node_days", len(window), "nodes", len(nodes),
		"verdicts", len(verdicts), "cohorts", len(cohorts),
		"cohorts_dropped", droppedCohorts, "pruned", pruned,
		"min_distinct_systems", r.cfg.MinDistinctSystems, "min_nodes", r.cfg.MinNodes,
		"pressure_version", sizing.PressureVersion)
	return nil
}

// recompute is step 1: rescore rows stamped with an older pressure_version.
//
// This is where sizing's versioning deliberately diverges from
// fingerprint's. A fingerprint is an identity and is never backfilled,
// because the whole point of a bump is that the change is visible. Pressure
// is a derived analytic over inputs that are all stored as first-class
// columns, so leaving 100 days of mixed-definition scores would make every
// trailing verdict wrong and every cohort statistic incomparable.
func (r *Runner) recompute(ctx context.Context) (int, error) {
	stale, err := r.store.StaleSizingScores(ctx, sizing.PressureVersion, r.cfg.RecomputeBatch)
	if err != nil {
		return 0, fmt.Errorf("baseline: stale scores: %w", err)
	}
	if len(stale) == 0 {
		return 0, nil
	}
	for i := range stale {
		row := &stale[i]
		score := sizing.Evaluate(row.ScoreInput())
		row.SetScore(store.SizingScore{
			Pressure: score.Pressure,
			Mem:      score.Mem,
			CPU:      score.CPU,
			IO:       score.IO,
			Disk:     score.Disk,
			TopAxis:  score.TopAxis,
			Reasons:  score.Reasons,
			Version:  score.Version,
		})
	}
	if err := r.store.UpdateSizingScores(ctx, stale); err != nil {
		return 0, fmt.Errorf("baseline: update scores: %w", err)
	}
	slog.Debug("baseline: recomputed stale pressure", "rows", len(stale),
		"version", sizing.PressureVersion)
	return len(stale), nil
}

// node is one node folded across the window.
type node struct {
	systemID string
	nodeID   int

	days []sizing.DayScore

	// usable holds the days that passed the coverage and measurement
	// filters, which are what the two-stage reduction runs over.
	usableRAMUsed   []float64
	usableCPUCores  []float64
	usableRAMUtil   []float64
	latestRAMUtil   *float64
	latestDay       int64
	maxSwapIn       float64
	maxOOM          float64
	installedRAM    float64
	installedCores  float64
	hardwareChanged bool

	// workloads is family -> metric -> value, filled by attachFamilies. The
	// metrics are here for sizing.ClassOf, which decides whether a family is
	// ignorable when testing "solo" -- samba's class turns on its share
	// count. Nothing else reads a workload value.
	workloads map[string]map[string]float64
}

// foldNodes groups the window's node-days per node and applies the per-day
// exclusions.
//
// Per-day: a day with sample_coverage below the floor, or with no pressure,
// or with no memory measurement, is not a measurement of demand and is
// dropped from the reduction. It still counts toward nothing -- the verdict
// counts days that *were* scored, which is the same set.
//
// Per-node: hardware that changed inside the window means the percentiles
// would straddle two physical machines, so the node is excluded from demand
// estimation entirely.
func foldNodes(window []store.SizingWindowRow, fromDay int64, now int64) map[string]*node {
	fromMillis := fromDay * sizing.DayMillis
	out := map[string]*node{}
	for _, row := range window {
		key := store.SizingNodeKey(row.SystemID, row.NodeID)
		n, seen := out[key]
		if !seen {
			n = &node{
				systemID:  row.SystemID,
				nodeID:    row.NodeID,
				workloads: map[string]map[string]float64{},
			}
			out[key] = n
		}

		n.days = append(n.days, sizing.DayScore{
			Day:      row.Day,
			Pressure: row.Pressure,
			TopAxis:  row.TopAxis,
		})
		if row.HWChangedAt >= fromMillis && row.HWChangedAt <= now {
			n.hardwareChanged = true
		}
		if float64(row.CPUCores) > n.installedCores {
			n.installedCores = float64(row.CPUCores)
		}
		if float64(row.MemTotalBytes) > n.installedRAM {
			n.installedRAM = float64(row.MemTotalBytes)
		}
		if row.SwapInPPSP95 != nil && *row.SwapInPPSP95 > n.maxSwapIn {
			n.maxSwapIn = *row.SwapInPPSP95
		}
		if row.OOMKills != nil && *row.OOMKills > n.maxOOM {
			n.maxOOM = *row.OOMKills
		}
		if row.Day >= n.latestDay {
			n.latestDay = row.Day
			n.latestRAMUtil = row.RAMUtilP95
		}

		if row.SampleCoverage < sizing.MinSampleCoverage || row.Pressure == nil {
			continue
		}
		if row.RAMUsedBytesP95 != nil {
			n.usableRAMUsed = append(n.usableRAMUsed, *row.RAMUsedBytesP95)
		}
		if row.CPUCoresUsedP95 != nil {
			n.usableCPUCores = append(n.usableCPUCores, *row.CPUCoresUsedP95)
		}
		if row.RAMUtilP95 != nil {
			n.usableRAMUtil = append(n.usableRAMUtil, *row.RAMUtilP95)
		}
	}
	return out
}

// attachFamilies joins the module inventory and workload metrics onto the
// folded nodes.
func attachFamilies(nodes map[string]*node, families []store.SizingNodeFamilyRow, metrics []store.SizingFamilyMetricRow) {
	for _, f := range families {
		n, ok := nodes[store.SizingNodeKey(f.SystemID, f.NodeID)]
		if !ok {
			continue
		}
		if _, seen := n.workloads[f.Family]; !seen {
			n.workloads[f.Family] = map[string]float64{}
		}
	}
	for _, m := range metrics {
		n, ok := nodes[store.SizingNodeKey(m.SystemID, m.NodeID)]
		if !ok {
			continue
		}
		w, seen := n.workloads[m.Family]
		if !seen {
			w = map[string]float64{}
			n.workloads[m.Family] = w
		}
		w[m.Metric] = m.Value
	}
}

// buildVerdicts is steps 2 and 3: the per-node k-of-n verdict, plus the
// per-cluster placement answer denormalised onto every node of that cluster
// so one query renders the page.
func buildVerdicts(nodes map[string]*node, previous map[string]string, windowDays int, now int64) []store.SizingVerdictRow {
	// Cluster placement first, because the verdict row carries it.
	clusterRAMUtil := map[string][]float64{}
	for _, n := range nodes {
		if n.latestRAMUtil != nil {
			clusterRAMUtil[n.systemID] = append(clusterRAMUtil[n.systemID], *n.latestRAMUtil)
		}
	}

	out := make([]store.SizingVerdictRow, 0, len(nodes))
	for key, n := range nodes {
		v := sizing.EvaluateVerdict(n.days, previous[key])

		row := store.SizingVerdictRow{
			SystemID:    n.systemID,
			NodeID:      n.nodeID,
			Verdict:     v.State,
			TopAxis:     v.TopAxis,
			DaysPresent: v.DaysPresent,
			BadDays:     v.BadDays,
			RiskDays:    v.RiskDays,
			WindowDays:  windowDays,
			UpdatedAt:   now,
		}
		util := clusterRAMUtil[n.systemID]
		row.ClusterNodes = len(util)
		if spread, advice := sizing.ClusterPlacement(util); advice != "" {
			s := spread
			row.ClusterRAMUtilSpread = &s
			row.Placement = advice
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SystemID != out[j].SystemID {
			return out[i].SystemID < out[j].SystemID
		}
		return out[i].NodeID < out[j].NodeID
	})
	return out
}

// cohortKey identifies one published baseline: a keying and its key.
type cohortKey struct{ kind, key string }

// cohort accumulates one cohortKey across nodes.
type cohort struct {
	nodes    int
	systems  map[string]bool
	censored int

	ramUsed        []float64
	cpuCoresUsed   []float64
	installedRAM   []float64
	installedCores []float64
}

// build is steps 4 and 5: the two-stage aggregation, the censoring exclusion,
// the two keyings and the floor.
func (r *Runner) build(nodes map[string]*node, now int64) []store.SizingCohortRow {
	cohorts := map[cohortKey]*cohort{}

	// Deterministic iteration: a published number must not depend on map
	// order, even where the arithmetic is order-independent.
	keys := make([]string, 0, len(nodes))
	for key := range nodes {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		n := nodes[key]

		// A node whose hardware changed inside the window is two machines,
		// not one, and neither its reduction nor its censoring status means
		// anything.
		if n.hardwareChanged {
			continue
		}
		if len(n.usableRAMUsed) == 0 {
			continue
		}

		// Two-stage aggregation, stage one: reduce the node to the p90 across
		// its daily p95s. p90 and not the median, because a 28-day window
		// holds eight weekend days on which a business workload is idle and
		// the median then reads a mail server about 25 % low.
		ramUsed, _ := sizing.ReduceNode(n.usableRAMUsed)
		cpuCoresUsed, _ := sizing.ReduceNode(n.usableCPUCores)
		ramUtil, _ := sizing.ReduceNode(n.usableRAMUtil)

		swapIn, oom := n.maxSwapIn, n.maxOOM
		censored := sizing.Censored(&ramUtil, &swapIn, &oom)

		add := func(kind, ckey string) {
			c, seen := cohorts[cohortKey{kind, ckey}]
			if !seen {
				c = &cohort{systems: map[string]bool{}}
				cohorts[cohortKey{kind, ckey}] = c
			}
			c.nodes++
			c.systems[n.systemID] = true
			if censored {
				c.censored++
				return
			}
			c.ramUsed = append(c.ramUsed, ramUsed)
			c.cpuCoresUsed = append(c.cpuCoresUsed, cpuCoresUsed)
			c.installedRAM = append(c.installedRAM, n.installedRAM)
			c.installedCores = append(c.installedCores, n.installedCores)
		}

		nonLite := sizing.NonLiteFamilies(n.workloads)
		families := make([]string, 0, len(n.workloads))
		for family := range n.workloads {
			families = append(families, family)
		}
		sort.Strings(families)

		for _, family := range families {
			add(sizing.CohortFamily, family)
			if sizing.IsSolo(family, nonLite) {
				add(sizing.CohortFamilySolo, family)
			}
		}
	}

	return r.publishCohorts(cohorts, now)
}

// publishCohorts applies the floor and turns each surviving cohort into a
// row.
//
// The floor counts **distinct system_id**, the same rule and the same reason
// as Threat Shield's promotion: one MSP's forty identical clusters is one
// opinion about hardware, not forty.
func (r *Runner) publishCohorts(cohorts map[cohortKey]*cohort, now int64) []store.SizingCohortRow {
	out := make([]store.SizingCohortRow, 0, len(cohorts))
	for id, c := range cohorts {
		if len(c.systems) < r.cfg.MinDistinctSystems || c.nodes < r.cfg.MinNodes {
			continue
		}
		row := store.SizingCohortRow{
			CohortKind:         id.kind,
			CohortKey:          id.key,
			Nodes:              c.nodes,
			DistinctSystems:    len(c.systems),
			CensoredNodes:      c.censored,
			WindowDays:         r.cfg.WindowDays,
			MinDistinctSystems: r.cfg.MinDistinctSystems,
			MinNodes:           r.cfg.MinNodes,
			PressureVersion:    sizing.PressureVersion,
			UpdatedAt:          now,
		}
		// Stage two: percentiles ACROSS nodes, each node counting once.
		// Absolute bytes and cores, never utilization -- utilization is a
		// property of hardware someone happened to buy, and the deliverable
		// is advice on what to buy. The recommendation is p90 of observed
		// peak demand among the uncensored nodes.
		row.RAMUsedP50, _ = sizing.Quantile(c.ramUsed, 0.50)
		row.RAMUsedP75, _ = sizing.Quantile(c.ramUsed, 0.75)
		row.RAMUsedP90, _ = sizing.Quantile(c.ramUsed, 0.90)
		row.CPUCoresUsedP50, _ = sizing.Quantile(c.cpuCoresUsed, 0.50)
		row.CPUCoresUsedP75, _ = sizing.Quantile(c.cpuCoresUsed, 0.75)
		row.CPUCoresUsedP90, _ = sizing.Quantile(c.cpuCoresUsed, 0.90)
		row.InstalledRAMP50, _ = sizing.Quantile(c.installedRAM, 0.50)
		row.InstalledRAMP90, _ = sizing.Quantile(c.installedRAM, 0.90)
		row.InstalledCoresP50, _ = sizing.Quantile(c.installedCores, 0.50)
		row.InstalledCoresP90, _ = sizing.Quantile(c.installedCores, 0.90)
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CohortKind != out[j].CohortKind {
			return out[i].CohortKind < out[j].CohortKind
		}
		return out[i].CohortKey < out[j].CohortKey
	})
	return out
}
