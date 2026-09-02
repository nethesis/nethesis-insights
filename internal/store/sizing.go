// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nethesis/nethesis-insights/internal/model"
)

// Fleet-sizing storage: ingest, the cohort pass's inputs and outputs, and the
// rollups that outlive the daily rows. Write methods take the same mutex as
// the rest of the store; read methods do not.
//
// This file deliberately imports nothing but model. The pressure formula
// lives in internal/sizing (pure) and reaches the store as already-derived
// columns on SizingNodeDayRow, so "what the score is" and "where rows go" can
// never drift into each other.

// MonthlyBadDayPressure is the pressure at which the monthly rollup counts a
// day as bad. It is deliberately a plain number here rather than an import of
// sizing.UndersizedPressure: this file imports only model, and the rollup is a
// coarse historical summary, not the verdict. If the two ever need to agree
// exactly, move the count into the pass and out of SQL.
const MonthlyBadDayPressure = 50.0

// SizingNodeDayRow is one node-day: the measurements as received plus the
// pressure the caller derived from them.
//
// Every measurement is a pointer, and nil means "not measured" -- never zero.
// A zero says "measured, and fine", which is the opposite, and the pressure
// formula depends on the difference.
type SizingNodeDayRow struct {
	SystemID string
	NodeID   int
	Day      int64

	MetricsPresent bool
	SampleCoverage float64
	Hardware       model.SizingHardware
	Resources      model.SizingResources
	Stress         model.SizingStress
	Modules        []model.SanitizedSizingModule

	// Derived by internal/sizing. Pressure is nil when the coverage gate
	// refused to score.
	Pressure        *float64
	PMem            *float64
	PCPU            *float64
	PIO             *float64
	PDisk           *float64
	TopAxis         string
	Reasons         []string
	PressureVersion int
	OOMSuspect      bool
}

// SetScore copies a derived pressure onto the row.
//
// It takes loose parameters rather than a sizing.Score because store must not
// import sizing -- sizing is pure and store is not, and the dependency has to
// point that way. It exists so the ingest path (internal/api) and the
// recompute path (internal/baseline) share one mapping: two copies of it
// would eventually store different columns for the same score.
func (r *SizingNodeDayRow) SetScore(pressure, pMem, pCPU, pIO, pDisk *float64,
	topAxis string, reasons []string, version int, oomSuspect bool) {
	r.Pressure = pressure
	r.PMem, r.PCPU, r.PIO, r.PDisk = pMem, pCPU, pIO, pDisk
	r.TopAxis = topAxis
	r.Reasons = reasons
	r.PressureVersion = version
	r.OOMSuspect = oomSuspect
}

// SizingDayRows is one cluster-day as the store accepts it.
type SizingDayRows struct {
	Day             int64
	Nodes           []SizingNodeDayRow
	ClusterWorkload map[string]float64
}

// SizingWindowRow is one node-day as the cohort pass reads it back: the
// derived pressure, the axis breakdown, and the inputs the censoring and
// two-stage reduction need.
type SizingWindowRow struct {
	SystemID string
	NodeID   int
	Day      int64

	SampleCoverage  float64
	CPUCores        int
	MemTotalBytes   int64
	HWChangedAt     int64
	Pressure        *float64
	TopAxis         string
	OOMSuspect      bool
	RAMUtilP95      *float64
	RAMUsedBytesP95 *float64
	CPUCoresUsedP95 *float64
	SwapInPPSP95    *float64
	OOMKills        *float64
}

// SizingNodeFamilyRow is one (system, node, family) seen inside the window.
// instances and facts_ok are the window's maximum, not a sum: they are a
// per-day fact about what was installed, and summing 28 days of them would
// report 56 nethvoice instances on a node that has always had two.
type SizingNodeFamilyRow struct {
	SystemID  string
	NodeID    int
	Family    string
	Instances int
	FactsOK   int
}

// SizingFamilyMetricRow is one workload metric for one (system, node,
// family), reduced across the window with MAX for the same reason.
type SizingFamilyMetricRow struct {
	SystemID string
	NodeID   int
	Family   string
	Metric   string
	Value    float64
}

// SizingVerdictRow is one node's multi-day verdict plus its cluster's
// placement answer.
type SizingVerdictRow struct {
	SystemID             string
	NodeID               int
	Verdict              string
	TopAxis              string
	DaysPresent          int
	BadDays              int
	RiskDays             int
	WindowDays           int
	ClusterNodes         int
	ClusterRAMUtilSpread *float64
	Placement            string
	UpdatedAt            int64
}

// SizingCohortRow is one published baseline.
type SizingCohortRow struct {
	CohortKind         string
	CohortKey          string
	Nodes              int
	DistinctSystems    int
	CensoredNodes      int
	RAMUsedP50         float64
	RAMUsedP75         float64
	RAMUsedP90         float64
	CPUCoresUsedP50    float64
	CPUCoresUsedP75    float64
	CPUCoresUsedP90    float64
	InstalledRAMP50    float64
	InstalledRAMP90    float64
	InstalledCoresP50  float64
	InstalledCoresP90  float64
	WindowDays         int
	MinDistinctSystems int
	MinNodes           int
	PressureVersion    int
	UpdatedAt          int64
}

// SizingBucketRow is one t-shirt size. Hi is nil on the top bucket: a finite
// ceiling there would silently drop the largest deployment.
type SizingBucketRow struct {
	Family    string
	Metric    string
	Bucket    string
	Lo        float64
	Hi        *float64
	Nodes     int
	RAMMedian float64
	UpdatedAt int64
}

// SizingIngestRow is one (day, system) accounting row.
type SizingIngestRow struct {
	Day             int64
	SystemID        string
	Reports         int
	LastReportAt    int64
	ReporterVersion string
	model.SizingCounters
}

// UpsertSizingDays stores one report's cluster-days in a single transaction.
//
// The upsert **recomputes** every measurement row: a day is an absolute fact,
// so the second and third of a reporter's three daily sends are
// byte-identical restatements and must overwrite rather than accumulate. The
// per-family and per-metric rows for a stored node-day are deleted before
// being reinserted, so a family that has been uninstalled disappears instead
// of lingering forever.
//
// sizing_ingest_daily is the one sizing table that accumulates, and it is
// written by RecordSizingIngest, not here.
func (s *SQLiteStore) UpsertSizingDays(ctx context.Context, systemID, reporterVersion string, days []SizingDayRows, now int64) (int, error) {
	if len(days) == 0 {
		return 0, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: upsert sizing days: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stored := 0
	for _, d := range days {
		for _, n := range d.Nodes {
			if err := upsertSizingNodeDay(ctx, tx, systemID, reporterVersion, d.Day, n, now); err != nil {
				return 0, err
			}
			if err := upsertSizingNodeDimension(ctx, tx, systemID, n, now); err != nil {
				return 0, err
			}
			stored++
		}
		if err := replaceSizingClusterDay(ctx, tx, systemID, d.Day, d.ClusterWorkload); err != nil {
			return 0, err
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit sizing days: %w", err)
	}
	return stored, nil
}

func upsertSizingNodeDay(ctx context.Context, tx bun.Tx, systemID, reporterVersion string, day int64, n SizingNodeDayRow, now int64) error {
	reasons, err := json.Marshal(n.Reasons)
	if err != nil {
		return fmt.Errorf("store: marshal pressure reasons: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO sizing_node_daily (
			system_id, node_id, day, received_at, reporter_version,
			metrics_present, sample_coverage, cpu_cores, mem_total_bytes,
			cpu_model, os_id, os_version, kernel_release, virtualization,
			ram_util_p95, ram_used_bytes_p95, cpu_util_p95, cpu_cores_used_p95,
			load15_per_core_p95, fs_used_frac_max, fs_days_to_full, disk_io_util_p95,
			iowait_busy_frac, swapin_pps_p95, oom_kills, reboots,
			pressure, p_mem, p_cpu, p_io, p_disk,
			pressure_top_axis, pressure_reasons, pressure_version, oom_suspect)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(system_id, node_id, day) DO UPDATE SET
			received_at = excluded.received_at,
			reporter_version = excluded.reporter_version,
			metrics_present = excluded.metrics_present,
			sample_coverage = excluded.sample_coverage,
			cpu_cores = excluded.cpu_cores,
			mem_total_bytes = excluded.mem_total_bytes,
			cpu_model = excluded.cpu_model,
			os_id = excluded.os_id,
			os_version = excluded.os_version,
			kernel_release = excluded.kernel_release,
			virtualization = excluded.virtualization,
			ram_util_p95 = excluded.ram_util_p95,
			ram_used_bytes_p95 = excluded.ram_used_bytes_p95,
			cpu_util_p95 = excluded.cpu_util_p95,
			cpu_cores_used_p95 = excluded.cpu_cores_used_p95,
			load15_per_core_p95 = excluded.load15_per_core_p95,
			fs_used_frac_max = excluded.fs_used_frac_max,
			fs_days_to_full = excluded.fs_days_to_full,
			disk_io_util_p95 = excluded.disk_io_util_p95,
			iowait_busy_frac = excluded.iowait_busy_frac,
			swapin_pps_p95 = excluded.swapin_pps_p95,
			oom_kills = excluded.oom_kills,
			reboots = excluded.reboots,
			pressure = excluded.pressure,
			p_mem = excluded.p_mem,
			p_cpu = excluded.p_cpu,
			p_io = excluded.p_io,
			p_disk = excluded.p_disk,
			pressure_top_axis = excluded.pressure_top_axis,
			pressure_reasons = excluded.pressure_reasons,
			pressure_version = excluded.pressure_version,
			oom_suspect = excluded.oom_suspect
	`,
		systemID, n.NodeID, day, now, reporterVersion,
		boolInt(n.MetricsPresent), n.SampleCoverage, n.Hardware.CPUCores, n.Hardware.MemTotalBytes,
		n.Hardware.CPUModel, n.Hardware.OSID, n.Hardware.OSVersion, n.Hardware.KernelRelease, n.Hardware.Virtualization,
		nullFloat(n.Resources.RAMUtilP95), nullFloat(n.Resources.RAMUsedBytesP95),
		nullFloat(n.Resources.CPUUtilP95), nullFloat(n.Resources.CPUCoresUsedP95),
		nullFloat(n.Resources.Load15PerCoreP95), nullFloat(n.Resources.FSUsedFracMax),
		nullFloat(n.Resources.FSDaysToFull), nullFloat(n.Resources.DiskIOUtilP95),
		nullFloat(n.Stress.IOWaitBusyFrac), nullFloat(n.Stress.SwapInPPSP95),
		nullFloat(n.Stress.OOMKills), nullFloat(n.Stress.Reboots),
		nullFloat(n.Pressure), nullFloat(n.PMem), nullFloat(n.PCPU), nullFloat(n.PIO), nullFloat(n.PDisk),
		n.TopAxis, string(reasons), n.PressureVersion, boolInt(n.OOMSuspect),
	)
	if err != nil {
		return fmt.Errorf("store: upsert sizing node day: %w", err)
	}

	// Delete-then-insert rather than upsert, so a family or a metric that has
	// gone away actually disappears. Recompute means recompute.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM sizing_module_daily WHERE system_id = ? AND node_id = ? AND day = ?`,
		systemID, n.NodeID, day); err != nil {
		return fmt.Errorf("store: clear sizing modules: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM sizing_module_metric WHERE system_id = ? AND node_id = ? AND day = ?`,
		systemID, n.NodeID, day); err != nil {
		return fmt.Errorf("store: clear sizing metrics: %w", err)
	}

	for _, m := range n.Modules {
		versions, err := json.Marshal(m.Versions)
		if err != nil {
			return fmt.Errorf("store: marshal module versions: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO sizing_module_daily (system_id, node_id, day, module_family, instances, facts_ok, versions)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, systemID, n.NodeID, day, m.Family, m.Instances, m.FactsOK, string(versions)); err != nil {
			return fmt.Errorf("store: insert sizing module: %w", err)
		}
		for metric, value := range m.Workload {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO sizing_module_metric (system_id, node_id, day, module_family, metric, value)
				VALUES (?, ?, ?, ?, ?, ?)
			`, systemID, n.NodeID, day, m.Family, metric, value); err != nil {
				return fmt.Errorf("store: insert sizing metric: %w", err)
			}
		}
	}
	return nil
}

// upsertSizingNodeDimension maintains the (system_id, node_id) dimension and,
// with it, hw_changed_at.
//
// Node identity is not stable: `node` is a small integer scoped to the
// cluster, so a replaced machine keeps its id with different hardware and the
// percentiles then straddle two physical machines. Recording *when* the
// installed capacity last changed is what lets the cohort pass exclude such a
// node for the length of its window.
//
// A first sighting sets no hw_changed_at: nothing changed, this is simply the
// first hardware we have seen.
func upsertSizingNodeDimension(ctx context.Context, tx bun.Tx, systemID string, n SizingNodeDayRow, now int64) error {
	var (
		cores sql.NullInt64
		mem   sql.NullInt64
	)
	err := tx.QueryRowContext(ctx,
		`SELECT cpu_cores, mem_total_bytes FROM sizing_node WHERE system_id = ? AND node_id = ?`,
		systemID, n.NodeID).Scan(&cores, &mem)
	switch {
	case err == sql.ErrNoRows:
	case err != nil:
		return fmt.Errorf("store: read sizing node: %w", err)
	}

	changed := cores.Valid && mem.Valid &&
		(cores.Int64 != int64(n.Hardware.CPUCores) || mem.Int64 != n.Hardware.MemTotalBytes)

	// A degraded report carries no hardware at all; it must not read as the
	// machine having been swapped for a smaller one.
	if n.Hardware.CPUCores == 0 && n.Hardware.MemTotalBytes == 0 {
		changed = false
	}

	var hwChanged any
	if changed {
		hwChanged = now
	}

	query := `
		INSERT INTO sizing_node (system_id, node_id, first_seen, last_seen, cpu_cores, mem_total_bytes, hw_changed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(system_id, node_id) DO UPDATE SET
			last_seen = excluded.last_seen,
			cpu_cores = excluded.cpu_cores,
			mem_total_bytes = excluded.mem_total_bytes`
	if changed {
		query += `,
			hw_changed_at = excluded.hw_changed_at`
	}
	if _, err := tx.ExecContext(ctx, query,
		systemID, n.NodeID, now, now, n.Hardware.CPUCores, n.Hardware.MemTotalBytes, hwChanged); err != nil {
		return fmt.Errorf("store: upsert sizing node: %w", err)
	}
	return nil
}

func replaceSizingClusterDay(ctx context.Context, tx bun.Tx, systemID string, day int64, workload map[string]float64) error {
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM sizing_cluster_daily WHERE system_id = ? AND day = ?`, systemID, day); err != nil {
		return fmt.Errorf("store: clear sizing cluster day: %w", err)
	}
	for metric, value := range workload {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO sizing_cluster_daily (system_id, day, metric, value) VALUES (?, ?, ?, ?)
		`, systemID, day, metric, value); err != nil {
			return fmt.Errorf("store: insert sizing cluster metric: %w", err)
		}
	}
	return nil
}

// RecordSizingIngest accumulates one request's outcome into the day's row for
// that system.
//
// Accumulate, unlike every other sizing table: the measurements recompute but
// the counters count requests, and "this cluster posts three times a day and
// stores nothing" is only visible if they do.
//
// When a report carried no usable day at all, day is 0 and the counters land
// under the day the request arrived -- there is nowhere else to put them, and
// dropping them would hide precisely the reporter that needs fixing.
func (s *SQLiteStore) RecordSizingIngest(ctx context.Context, day int64, systemID, reporterVersion string, c model.SizingCounters, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if day == 0 {
		day = now / dayMillis
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sizing_ingest_daily (day, system_id, reports, last_report_at, reporter_version,
			accepted_nodes, accepted_modules, accepted_metrics,
			dropped_day, dropped_duplicate, dropped_node, dropped_family,
			dropped_metric_key, dropped_metric_value, dropped_resource_value,
			truncated_days, truncated_nodes, truncated_families, truncated_metrics)
		VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(day, system_id) DO UPDATE SET
			reports = sizing_ingest_daily.reports + 1,
			last_report_at = excluded.last_report_at,
			reporter_version = excluded.reporter_version,
			accepted_nodes = sizing_ingest_daily.accepted_nodes + excluded.accepted_nodes,
			accepted_modules = sizing_ingest_daily.accepted_modules + excluded.accepted_modules,
			accepted_metrics = sizing_ingest_daily.accepted_metrics + excluded.accepted_metrics,
			dropped_day = sizing_ingest_daily.dropped_day + excluded.dropped_day,
			dropped_duplicate = sizing_ingest_daily.dropped_duplicate + excluded.dropped_duplicate,
			dropped_node = sizing_ingest_daily.dropped_node + excluded.dropped_node,
			dropped_family = sizing_ingest_daily.dropped_family + excluded.dropped_family,
			dropped_metric_key = sizing_ingest_daily.dropped_metric_key + excluded.dropped_metric_key,
			dropped_metric_value = sizing_ingest_daily.dropped_metric_value + excluded.dropped_metric_value,
			dropped_resource_value = sizing_ingest_daily.dropped_resource_value + excluded.dropped_resource_value,
			truncated_days = sizing_ingest_daily.truncated_days + excluded.truncated_days,
			truncated_nodes = sizing_ingest_daily.truncated_nodes + excluded.truncated_nodes,
			truncated_families = sizing_ingest_daily.truncated_families + excluded.truncated_families,
			truncated_metrics = sizing_ingest_daily.truncated_metrics + excluded.truncated_metrics
	`, day, systemID, now, reporterVersion,
		c.AcceptedNodes, c.AcceptedModules, c.AcceptedMetrics,
		c.DroppedDay, c.DroppedDuplicate, c.DroppedNode, c.DroppedFamily,
		c.DroppedMetricKey, c.DroppedMetricValue, c.DroppedResourceValue,
		c.TruncatedDays, c.TruncatedNodes, c.TruncatedFamilies, c.TruncatedMetrics)
	if err != nil {
		return fmt.Errorf("store: record sizing ingest: %w", err)
	}
	return nil
}

// --- the cohort pass's reads and writes ---

// StaleSizingScores returns node-days whose pressure_version is not version,
// in a bounded batch, newest first.
//
// The bound is what keeps a version bump from turning one pass into an
// unbounded rewrite of 100 days of history through a single-writer
// connection; the pass simply catches up over several runs. Newest first
// because the trailing verdict window is what a stale score breaks first.
func (s *SQLiteStore) StaleSizingScores(ctx context.Context, version, limit int) ([]SizingNodeDayRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT system_id, node_id, day, metrics_present, sample_coverage,
			cpu_cores, mem_total_bytes,
			ram_util_p95, ram_used_bytes_p95, cpu_util_p95, cpu_cores_used_p95,
			load15_per_core_p95, fs_used_frac_max, fs_days_to_full, disk_io_util_p95,
			iowait_busy_frac, swapin_pps_p95, oom_kills, reboots
		FROM sizing_node_daily
		WHERE pressure_version IS NULL OR pressure_version <> ?
		ORDER BY day DESC, system_id, node_id
		LIMIT ?
	`, version, limit)
	if err != nil {
		return nil, fmt.Errorf("store: stale sizing scores: %w", err)
	}
	defer rows.Close()

	result := []SizingNodeDayRow{}
	for rows.Next() {
		var (
			r        SizingNodeDayRow
			present  sql.NullInt64
			coverage sql.NullFloat64
			cores    sql.NullInt64
			mem      sql.NullInt64
			f        [12]sql.NullFloat64
		)
		if err := rows.Scan(&r.SystemID, &r.NodeID, &r.Day, &present, &coverage, &cores, &mem,
			&f[0], &f[1], &f[2], &f[3], &f[4], &f[5], &f[6], &f[7], &f[8], &f[9], &f[10], &f[11]); err != nil {
			return nil, fmt.Errorf("store: scan stale sizing score: %w", err)
		}
		r.MetricsPresent = present.Int64 != 0
		r.SampleCoverage = coverage.Float64
		r.Hardware.CPUCores = int(cores.Int64)
		r.Hardware.MemTotalBytes = mem.Int64
		r.Resources = model.SizingResources{
			RAMUtilP95: floatPtr(f[0]), RAMUsedBytesP95: floatPtr(f[1]),
			CPUUtilP95: floatPtr(f[2]), CPUCoresUsedP95: floatPtr(f[3]),
			Load15PerCoreP95: floatPtr(f[4]), FSUsedFracMax: floatPtr(f[5]),
			FSDaysToFull: floatPtr(f[6]), DiskIOUtilP95: floatPtr(f[7]),
		}
		r.Stress = model.SizingStress{
			IOWaitBusyFrac: floatPtr(f[8]), SwapInPPSP95: floatPtr(f[9]),
			OOMKills: floatPtr(f[10]), Reboots: floatPtr(f[11]),
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// UpdateSizingScores writes recomputed pressure back, touching nothing else.
func (s *SQLiteStore) UpdateSizingScores(ctx context.Context, rows []SizingNodeDayRow) error {
	if len(rows) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: update sizing scores: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, r := range rows {
		reasons, err := json.Marshal(r.Reasons)
		if err != nil {
			return fmt.Errorf("store: marshal pressure reasons: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE sizing_node_daily SET
				pressure = ?, p_mem = ?, p_cpu = ?, p_io = ?, p_disk = ?,
				pressure_top_axis = ?, pressure_reasons = ?, pressure_version = ?, oom_suspect = ?
			WHERE system_id = ? AND node_id = ? AND day = ?
		`, nullFloat(r.Pressure), nullFloat(r.PMem), nullFloat(r.PCPU), nullFloat(r.PIO), nullFloat(r.PDisk),
			r.TopAxis, string(reasons), r.PressureVersion, boolInt(r.OOMSuspect),
			r.SystemID, r.NodeID, r.Day); err != nil {
			return fmt.Errorf("store: update sizing score: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit sizing scores: %w", err)
	}
	return nil
}

// SizingWindow returns every node-day in [fromDay, toDay], joined to the node
// dimension for hw_changed_at.
//
// One query serves three of the pass's steps -- the verdicts, the cluster
// imbalance and the cohort reduction -- because they read the same rows and a
// second query would be a second chance for them to disagree.
func (s *SQLiteStore) SizingWindow(ctx context.Context, fromDay, toDay int64) ([]SizingWindowRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT d.system_id, d.node_id, d.day, d.sample_coverage, d.cpu_cores, d.mem_total_bytes,
			n.hw_changed_at, d.pressure, d.pressure_top_axis, d.oom_suspect,
			d.ram_util_p95, d.ram_used_bytes_p95, d.cpu_cores_used_p95,
			d.swapin_pps_p95, d.oom_kills
		FROM sizing_node_daily d
		LEFT JOIN sizing_node n ON n.system_id = d.system_id AND n.node_id = d.node_id
		WHERE d.day >= ? AND d.day <= ?
		ORDER BY d.system_id, d.node_id, d.day
	`, fromDay, toDay)
	if err != nil {
		return nil, fmt.Errorf("store: sizing window: %w", err)
	}
	defer rows.Close()

	result := []SizingWindowRow{}
	for rows.Next() {
		var (
			r          SizingWindowRow
			coverage   sql.NullFloat64
			cores      sql.NullInt64
			mem        sql.NullInt64
			hwChanged  sql.NullInt64
			topAxis    sql.NullString
			oomSuspect sql.NullInt64
			f          [6]sql.NullFloat64
		)
		if err := rows.Scan(&r.SystemID, &r.NodeID, &r.Day, &coverage, &cores, &mem,
			&hwChanged, &f[0], &topAxis, &oomSuspect,
			&f[1], &f[2], &f[3], &f[4], &f[5]); err != nil {
			return nil, fmt.Errorf("store: scan sizing window: %w", err)
		}
		r.SampleCoverage = coverage.Float64
		r.CPUCores = int(cores.Int64)
		r.MemTotalBytes = mem.Int64
		r.HWChangedAt = hwChanged.Int64
		r.Pressure = floatPtr(f[0])
		r.TopAxis = topAxis.String
		r.OOMSuspect = oomSuspect.Int64 != 0
		r.RAMUtilP95 = floatPtr(f[1])
		r.RAMUsedBytesP95 = floatPtr(f[2])
		r.CPUCoresUsedP95 = floatPtr(f[3])
		r.SwapInPPSP95 = floatPtr(f[4])
		r.OOMKills = floatPtr(f[5])
		result = append(result, r)
	}
	return result, rows.Err()
}

// SizingWindowFamilies returns each (system, node, family) present in the
// window with the window's maximum instances and facts_ok. MAX and not SUM:
// these say what was installed on a day, and summing 28 days of them would
// report 56 nethvoice instances on a node that has always had two.
func (s *SQLiteStore) SizingWindowFamilies(ctx context.Context, fromDay, toDay int64) ([]SizingNodeFamilyRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT system_id, node_id, module_family, MAX(instances), MAX(facts_ok)
		FROM sizing_module_daily
		WHERE day >= ? AND day <= ?
		GROUP BY system_id, node_id, module_family
		ORDER BY system_id, node_id, module_family
	`, fromDay, toDay)
	if err != nil {
		return nil, fmt.Errorf("store: sizing window families: %w", err)
	}
	defer rows.Close()

	result := []SizingNodeFamilyRow{}
	for rows.Next() {
		var (
			r         SizingNodeFamilyRow
			instances sql.NullInt64
			factsOK   sql.NullInt64
		)
		if err := rows.Scan(&r.SystemID, &r.NodeID, &r.Family, &instances, &factsOK); err != nil {
			return nil, fmt.Errorf("store: scan sizing window family: %w", err)
		}
		r.Instances, r.FactsOK = int(instances.Int64), int(factsOK.Int64)
		result = append(result, r)
	}
	return result, rows.Err()
}

// SizingWindowMetrics returns each (system, node, family, metric) in the
// window reduced with MAX, for the same reason as SizingWindowFamilies.
func (s *SQLiteStore) SizingWindowMetrics(ctx context.Context, fromDay, toDay int64) ([]SizingFamilyMetricRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT system_id, node_id, module_family, metric, MAX(value)
		FROM sizing_module_metric
		WHERE day >= ? AND day <= ?
		GROUP BY system_id, node_id, module_family, metric
		ORDER BY system_id, node_id, module_family, metric
	`, fromDay, toDay)
	if err != nil {
		return nil, fmt.Errorf("store: sizing window metrics: %w", err)
	}
	defer rows.Close()

	result := []SizingFamilyMetricRow{}
	for rows.Next() {
		var (
			r     SizingFamilyMetricRow
			value sql.NullFloat64
		)
		if err := rows.Scan(&r.SystemID, &r.NodeID, &r.Family, &r.Metric, &value); err != nil {
			return nil, fmt.Errorf("store: scan sizing window metric: %w", err)
		}
		r.Value = value.Float64
		result = append(result, r)
	}
	return result, rows.Err()
}

// SizingVerdictStates returns the current verdict per node, keyed
// "<system_id>/<node_id>". The pass needs it because the verdict has
// hysteresis: once undersized, it holds until the bad days fall away.
func (s *SQLiteStore) SizingVerdictStates(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT system_id, node_id, verdict FROM sizing_node_verdict`)
	if err != nil {
		return nil, fmt.Errorf("store: sizing verdict states: %w", err)
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var (
			systemID string
			nodeID   int
			verdict  sql.NullString
		)
		if err := rows.Scan(&systemID, &nodeID, &verdict); err != nil {
			return nil, fmt.Errorf("store: scan sizing verdict state: %w", err)
		}
		out[SizingNodeKey(systemID, nodeID)] = verdict.String
	}
	return out, rows.Err()
}

// SizingNodeKey is the one spelling of a node's composite key as a string.
// Two spellings that must agree eventually disagree.
func SizingNodeKey(systemID string, nodeID int) string {
	return fmt.Sprintf("%s/%d", systemID, nodeID)
}

// UpsertSizingVerdicts replaces the verdict rows the pass recomputed.
func (s *SQLiteStore) UpsertSizingVerdicts(ctx context.Context, rows []SizingVerdictRow) error {
	if len(rows) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: upsert sizing verdicts: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, r := range rows {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO sizing_node_verdict (system_id, node_id, verdict, top_axis,
				days_present, bad_days, risk_days, window_days,
				cluster_nodes, cluster_ram_util_spread, placement, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(system_id, node_id) DO UPDATE SET
				verdict = excluded.verdict,
				top_axis = excluded.top_axis,
				days_present = excluded.days_present,
				bad_days = excluded.bad_days,
				risk_days = excluded.risk_days,
				window_days = excluded.window_days,
				cluster_nodes = excluded.cluster_nodes,
				cluster_ram_util_spread = excluded.cluster_ram_util_spread,
				placement = excluded.placement,
				updated_at = excluded.updated_at
		`, r.SystemID, r.NodeID, r.Verdict, r.TopAxis,
			r.DaysPresent, r.BadDays, r.RiskDays, r.WindowDays,
			r.ClusterNodes, nullFloat(r.ClusterRAMUtilSpread), r.Placement, r.UpdatedAt); err != nil {
			return fmt.Errorf("store: upsert sizing verdict: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit sizing verdicts: %w", err)
	}
	return nil
}

// UpsertSizingCohorts publishes the baselines that cleared the floor.
func (s *SQLiteStore) UpsertSizingCohorts(ctx context.Context, rows []SizingCohortRow) error {
	if len(rows) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: upsert sizing cohorts: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, r := range rows {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO sizing_cohort_baseline (cohort_kind, cohort_key, nodes, distinct_systems, censored_nodes,
				ram_used_p50, ram_used_p75, ram_used_p90,
				cpu_cores_used_p50, cpu_cores_used_p75, cpu_cores_used_p90,
				installed_ram_p50, installed_ram_p90, installed_cores_p50, installed_cores_p90,
				window_days, min_distinct_systems, min_nodes, pressure_version, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(cohort_kind, cohort_key) DO UPDATE SET
				nodes = excluded.nodes,
				distinct_systems = excluded.distinct_systems,
				censored_nodes = excluded.censored_nodes,
				ram_used_p50 = excluded.ram_used_p50,
				ram_used_p75 = excluded.ram_used_p75,
				ram_used_p90 = excluded.ram_used_p90,
				cpu_cores_used_p50 = excluded.cpu_cores_used_p50,
				cpu_cores_used_p75 = excluded.cpu_cores_used_p75,
				cpu_cores_used_p90 = excluded.cpu_cores_used_p90,
				installed_ram_p50 = excluded.installed_ram_p50,
				installed_ram_p90 = excluded.installed_ram_p90,
				installed_cores_p50 = excluded.installed_cores_p50,
				installed_cores_p90 = excluded.installed_cores_p90,
				window_days = excluded.window_days,
				min_distinct_systems = excluded.min_distinct_systems,
				min_nodes = excluded.min_nodes,
				pressure_version = excluded.pressure_version,
				updated_at = excluded.updated_at
		`, r.CohortKind, r.CohortKey, r.Nodes, r.DistinctSystems, r.CensoredNodes,
			r.RAMUsedP50, r.RAMUsedP75, r.RAMUsedP90,
			r.CPUCoresUsedP50, r.CPUCoresUsedP75, r.CPUCoresUsedP90,
			r.InstalledRAMP50, r.InstalledRAMP90, r.InstalledCoresP50, r.InstalledCoresP90,
			r.WindowDays, r.MinDistinctSystems, r.MinNodes, r.PressureVersion, r.UpdatedAt); err != nil {
			return fmt.Errorf("store: upsert sizing cohort: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit sizing cohorts: %w", err)
	}
	return nil
}

// DeleteStaleSizingCohorts removes cohorts this pass did not republish --
// which is exactly the cohorts that have fallen below the floor.
//
// Deleting rather than leaving a stale row, mirroring ExpireBlocklist: a
// published baseline that no longer has the evidence behind it is worse than
// no baseline, because nothing on the page says how old it is.
func (s *SQLiteStore) DeleteStaleSizingCohorts(ctx context.Context, before int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.ExecContext(ctx,
		`DELETE FROM sizing_cohort_baseline WHERE updated_at IS NULL OR updated_at < ?`, before)
	if err != nil {
		return 0, fmt.Errorf("store: delete stale sizing cohorts: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: delete stale sizing cohorts rows: %w", err)
	}
	return int(n), nil
}

// UpsertSizingBuckets publishes the workload t-shirt sizes.
func (s *SQLiteStore) UpsertSizingBuckets(ctx context.Context, rows []SizingBucketRow) error {
	if len(rows) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: upsert sizing buckets: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, r := range rows {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO sizing_workload_bucket (module_family, metric, bucket, lo, hi, nodes, ram_bytes_median, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(module_family, metric, bucket) DO UPDATE SET
				lo = excluded.lo,
				hi = excluded.hi,
				nodes = excluded.nodes,
				ram_bytes_median = excluded.ram_bytes_median,
				updated_at = excluded.updated_at
		`, r.Family, r.Metric, r.Bucket, r.Lo, nullFloat(r.Hi), r.Nodes, r.RAMMedian, r.UpdatedAt); err != nil {
			return fmt.Errorf("store: upsert sizing bucket: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit sizing buckets: %w", err)
	}
	return nil
}

// DeleteStaleSizingBuckets is DeleteStaleSizingCohorts for the buckets.
func (s *SQLiteStore) DeleteStaleSizingBuckets(ctx context.Context, before int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.ExecContext(ctx,
		`DELETE FROM sizing_workload_bucket WHERE updated_at IS NULL OR updated_at < ?`, before)
	if err != nil {
		return 0, fmt.Errorf("store: delete stale sizing buckets: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: delete stale sizing buckets rows: %w", err)
	}
	return int(n), nil
}

// sizingMonthlyRow is one node's aggregate for one calendar month.
type sizingMonthlyRow struct {
	systemID                         string
	nodeID                           int
	month                            string
	daysPresent, daysScored, badDays int

	pressureAvg, pressureMax                            sql.NullFloat64
	ramUtilMax, ramUsedMax, cpuUtilMax, cpuCoresUsedMax sql.NullFloat64
	fsMax, oomTotal                                     sql.NullFloat64
	cores, mem                                          sql.NullInt64
}

// RollupSizingMonthly recomputes the monthly rows covering [fromDay, toDay].
//
// The aggregates are computed in SQL but the *grouping key* is computed in Go:
// one query per calendar month over an explicit day range, because SQLite and
// Postgres share no date function and a month is not a fixed number of days.
// That also keeps the work bounded -- a couple of queries returning one row
// per node, rather than pulling every node-day through a single-writer
// connection.
//
// It recomputes rather than accumulates, so running it twice, or after a
// missed pass, converges instead of double counting. It must run BEFORE
// PruneSizingDaily, or the day being dropped loses its history permanently.
func (s *SQLiteStore) RollupSizingMonthly(ctx context.Context, fromDay, toDay int64) error {
	for _, m := range monthRanges(fromDay, toDay) {
		rows, err := s.readSizingMonthly(ctx, m.label, m.from, m.to)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			continue
		}
		if err := s.writeSizingMonthly(ctx, rows); err != nil {
			return err
		}
	}
	return nil
}

type monthRange struct {
	label    string
	from, to int64
}

// monthRanges enumerates the calendar months touching [fromDay, toDay] as
// explicit day-index bounds. The label is what lands in the month TEXT
// column; nothing ever does arithmetic on it.
func monthRanges(fromDay, toDay int64) []monthRange {
	if toDay < fromDay {
		return nil
	}
	cursor := time.UnixMilli(fromDay * dayMillis).UTC()
	cursor = time.Date(cursor.Year(), cursor.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := time.UnixMilli(toDay * dayMillis).UTC()

	var out []monthRange
	for !cursor.After(end) {
		next := cursor.AddDate(0, 1, 0)
		out = append(out, monthRange{
			label: cursor.Format("2006-01"),
			from:  cursor.UnixMilli() / dayMillis,
			to:    next.UnixMilli()/dayMillis - 1,
		})
		cursor = next
	}
	return out
}

// readSizingMonthly is the read half, split from the write half so its rows
// are closed before the write mutex is taken.
func (s *SQLiteStore) readSizingMonthly(ctx context.Context, month string, fromDay, toDay int64) ([]sizingMonthlyRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT system_id, node_id, COUNT(*), COUNT(pressure),
			SUM(CASE WHEN pressure >= ? THEN 1 ELSE 0 END),
			AVG(pressure), MAX(pressure),
			MAX(ram_util_p95), MAX(ram_used_bytes_p95), MAX(cpu_util_p95),
			MAX(cpu_cores_used_p95), MAX(fs_used_frac_max), SUM(oom_kills),
			MAX(cpu_cores), MAX(mem_total_bytes)
		FROM sizing_node_daily
		WHERE day >= ? AND day <= ?
		GROUP BY system_id, node_id
		ORDER BY system_id, node_id
	`, MonthlyBadDayPressure, fromDay, toDay)
	if err != nil {
		return nil, fmt.Errorf("store: rollup sizing monthly: %w", err)
	}
	defer rows.Close()

	out := []sizingMonthlyRow{}
	for rows.Next() {
		r := sizingMonthlyRow{month: month}
		if err := rows.Scan(&r.systemID, &r.nodeID, &r.daysPresent, &r.daysScored, &r.badDays,
			&r.pressureAvg, &r.pressureMax,
			&r.ramUtilMax, &r.ramUsedMax, &r.cpuUtilMax, &r.cpuCoresUsedMax,
			&r.fsMax, &r.oomTotal, &r.cores, &r.mem); err != nil {
			return nil, fmt.Errorf("store: scan sizing monthly: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) writeSizingMonthly(ctx context.Context, rows []sizingMonthlyRow) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: rollup sizing monthly: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, r := range rows {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO sizing_node_monthly (system_id, node_id, month, days_present, days_scored, bad_days,
				pressure_avg, pressure_max, ram_util_p95_max, ram_used_bytes_p95_max,
				cpu_util_p95_max, cpu_cores_used_p95_max, fs_used_frac_max_max, oom_kills_total,
				cpu_cores, mem_total_bytes)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(system_id, node_id, month) DO UPDATE SET
				days_present = excluded.days_present,
				days_scored = excluded.days_scored,
				bad_days = excluded.bad_days,
				pressure_avg = excluded.pressure_avg,
				pressure_max = excluded.pressure_max,
				ram_util_p95_max = excluded.ram_util_p95_max,
				ram_used_bytes_p95_max = excluded.ram_used_bytes_p95_max,
				cpu_util_p95_max = excluded.cpu_util_p95_max,
				cpu_cores_used_p95_max = excluded.cpu_cores_used_p95_max,
				fs_used_frac_max_max = excluded.fs_used_frac_max_max,
				oom_kills_total = excluded.oom_kills_total,
				cpu_cores = excluded.cpu_cores,
				mem_total_bytes = excluded.mem_total_bytes
		`, r.systemID, r.nodeID, r.month, r.daysPresent, r.daysScored, r.badDays,
			nullFloat(floatPtr(r.pressureAvg)), nullFloat(floatPtr(r.pressureMax)),
			nullFloat(floatPtr(r.ramUtilMax)), nullFloat(floatPtr(r.ramUsedMax)),
			nullFloat(floatPtr(r.cpuUtilMax)), nullFloat(floatPtr(r.cpuCoresUsedMax)),
			nullFloat(floatPtr(r.fsMax)), nullFloat(floatPtr(r.oomTotal)),
			r.cores.Int64, r.mem.Int64); err != nil {
			return fmt.Errorf("store: upsert sizing monthly: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit sizing monthly: %w", err)
	}
	return nil
}

// PruneSizingDaily drops daily rows below olderThanDay.
//
// It must run AFTER RollupSizingMonthly, or the day being dropped loses its
// history permanently -- the same ordering constraint, and the same reason, as
// PruneThreatEvents.
func (s *SQLiteStore) PruneSizingDaily(ctx context.Context, olderThanDay int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: prune sizing daily: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	total := 0
	for _, table := range []string{
		"sizing_node_daily", "sizing_module_daily", "sizing_module_metric",
		"sizing_cluster_daily", "sizing_ingest_daily",
	} {
		res, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE day < ?`, olderThanDay)
		if err != nil {
			return 0, fmt.Errorf("store: prune %s: %w", table, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("store: prune %s rows: %w", table, err)
		}
		total += int(n)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit prune sizing daily: %w", err)
	}
	return total, nil
}

// --- small shared helpers ---

// nullFloat renders an optional measurement for a bind parameter. nil becomes
// SQL NULL, which is what "not measured" is stored as.
func nullFloat(v *float64) any {
	if v == nil {
		return nil
	}
	return *v
}

// floatPtr is nullFloat's inverse on the read path.
func floatPtr(v sql.NullFloat64) *float64 {
	if !v.Valid {
		return nil
	}
	out := v.Float64
	return &out
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
