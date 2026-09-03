// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Cross-system, read-only paths for the operator UI's two sizing pages.
//
// No mutex (these are reads), an explicit limit on every list, and nothing
// here returns a raw sample or an identifying label -- there are none to
// return: the ingest sanitizer refuses anything but numbers in a workload
// map, and the report carries no FQDN, IP, serial or nodename at all.
//
// Worth stating explicitly for this pipeline rather than inheriting it by
// accident: the UI's GET surface is unauthenticated and fleet-wide, and these
// rows carry per-customer commercial data (mailbox and PBX user counts,
// product mix). Bind the UI to loopback.

// SizingNodeUIRow is one node's most recent day plus its multi-day verdict --
// the sizing page's main table.
type SizingNodeUIRow struct {
	SystemID string
	NodeID   int
	Day      int64

	MetricsPresent bool
	SampleCoverage float64
	CPUCores       int
	MemTotalBytes  int64
	CPUModel       string
	OSID           string
	OSVersion      string
	Virtualization string

	RAMUtilP95      *float64
	RAMUsedBytesP95 *float64
	CPUUtilP95      *float64
	CPUCoresUsedP95 *float64
	FSUsedFracMax   *float64
	FSDaysToFull    *float64
	IOWaitBusyFrac  *float64
	SwapInPPSP95    *float64
	OOMKills        *float64

	Pressure        *float64
	PMem            *float64
	PCPU            *float64
	PIO             *float64
	PDisk           *float64
	TopAxis         string
	Reasons         []string
	PressureVersion int

	Verdict              string
	VerdictTopAxis       string
	DaysPresent          int
	BadDays              int
	ClusterNodes         int
	ClusterRAMUtilSpread *float64
	Placement            string
	HWChangedAt          int64
}

// SizingModuleUIRow is one module family on one node, on that node's most
// recent day, with its workload map rendered for display.
type SizingModuleUIRow struct {
	SystemID  string
	NodeID    int
	Day       int64
	Family    string
	Instances int
	FactsOK   int
	Versions  []string
	Workload  string
}

// SizingCounts is the sizing pipeline's headline numbers, for the status page.
type SizingCounts struct {
	Systems    int
	Nodes      int
	NodeDays   int
	Cohorts    int
	LatestDay  int64
	Undersized int
	AtRisk     int
	Unscored   int
	LastReport int64
}

// ListSizingNodes returns each node's most recent day, joined to its verdict.
//
// The join on a grouped MAX(day) subquery is deliberately plain SQL rather
// than a window function: this has to run on SQLite today and Postgres later.
// The NULL-aware ordering is written as (pressure IS NULL) rather than
// NULLS LAST for the same reason.
func (s *SQLiteStore) ListSizingNodes(ctx context.Context, systemID string, limit int) ([]SizingNodeUIRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT d.system_id, d.node_id, d.day, d.metrics_present, d.sample_coverage,
			d.cpu_cores, d.mem_total_bytes, d.cpu_model, d.os_id, d.os_version, d.virtualization,
			d.ram_util_p95, d.ram_used_bytes_p95, d.cpu_util_p95, d.cpu_cores_used_p95,
			d.fs_used_frac_max, d.fs_days_to_full, d.iowait_busy_frac, d.swapin_pps_p95, d.oom_kills,
			d.pressure, d.p_mem, d.p_cpu, d.p_io, d.p_disk,
			d.pressure_top_axis, d.pressure_reasons, d.pressure_version,
			v.verdict, v.top_axis, v.days_present, v.bad_days,
			v.cluster_nodes, v.cluster_ram_util_spread, v.placement,
			n.hw_changed_at
		FROM sizing_node_daily d
		JOIN (
			SELECT system_id, node_id, MAX(day) AS day
			FROM sizing_node_daily
			GROUP BY system_id, node_id
		) latest ON latest.system_id = d.system_id AND latest.node_id = d.node_id AND latest.day = d.day
		LEFT JOIN sizing_node_verdict v ON v.system_id = d.system_id AND v.node_id = d.node_id
		LEFT JOIN sizing_node n ON n.system_id = d.system_id AND n.node_id = d.node_id
		WHERE (? = '' OR d.system_id = ?)
		ORDER BY (d.pressure IS NULL), d.pressure DESC, d.system_id, d.node_id
		LIMIT ?
	`, systemID, systemID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list sizing nodes: %w", err)
	}
	defer rows.Close()

	result := []SizingNodeUIRow{}
	for rows.Next() {
		var (
			r          SizingNodeUIRow
			present    sql.NullInt64
			coverage   sql.NullFloat64
			cores, mem sql.NullInt64
			text       [4]sql.NullString
			f          [14]sql.NullFloat64
			topAxis    sql.NullString
			reasons    sql.NullString
			version    sql.NullInt64
			verdict    sql.NullString
			vAxis      sql.NullString
			vDays      sql.NullInt64
			vBad       sql.NullInt64
			cNodes     sql.NullInt64
			spread     sql.NullFloat64
			placement  sql.NullString
			hwChanged  sql.NullInt64
		)
		if err := rows.Scan(&r.SystemID, &r.NodeID, &r.Day, &present, &coverage,
			&cores, &mem, &text[0], &text[1], &text[2], &text[3],
			&f[0], &f[1], &f[2], &f[3], &f[4], &f[5], &f[6], &f[7], &f[8],
			&f[9], &f[10], &f[11], &f[12], &f[13],
			&topAxis, &reasons, &version,
			&verdict, &vAxis, &vDays, &vBad, &cNodes, &spread, &placement, &hwChanged); err != nil {
			return nil, fmt.Errorf("store: scan sizing node: %w", err)
		}
		r.MetricsPresent = present.Int64 != 0
		r.SampleCoverage = coverage.Float64
		r.CPUCores, r.MemTotalBytes = int(cores.Int64), mem.Int64
		r.CPUModel, r.OSID, r.OSVersion, r.Virtualization = text[0].String, text[1].String, text[2].String, text[3].String
		r.RAMUtilP95, r.RAMUsedBytesP95 = floatPtr(f[0]), floatPtr(f[1])
		r.CPUUtilP95, r.CPUCoresUsedP95 = floatPtr(f[2]), floatPtr(f[3])
		r.FSUsedFracMax, r.FSDaysToFull = floatPtr(f[4]), floatPtr(f[5])
		r.IOWaitBusyFrac, r.SwapInPPSP95, r.OOMKills = floatPtr(f[6]), floatPtr(f[7]), floatPtr(f[8])
		r.Pressure = floatPtr(f[9])
		r.PMem, r.PCPU, r.PIO, r.PDisk = floatPtr(f[10]), floatPtr(f[11]), floatPtr(f[12]), floatPtr(f[13])
		r.TopAxis, r.PressureVersion = topAxis.String, int(version.Int64)
		r.Reasons = parseReasons(reasons.String)
		r.Verdict, r.VerdictTopAxis = verdict.String, vAxis.String
		r.DaysPresent, r.BadDays = int(vDays.Int64), int(vBad.Int64)
		r.ClusterNodes, r.ClusterRAMUtilSpread = int(cNodes.Int64), floatPtr(spread)
		r.Placement, r.HWChangedAt = placement.String, hwChanged.Int64
		result = append(result, r)
	}
	return result, rows.Err()
}

// ListSizingModules returns the module inventory for each node's most recent
// day, with the workload map folded into a display string.
//
// The fold happens in Go and the grouping in SQL, following the threat
// precedent: JSON is parsed in Go for display fields only, because whenever
// the grouping is the correctness it belongs in SQL.
func (s *SQLiteStore) ListSizingModules(ctx context.Context, systemID string, limit int) ([]SizingModuleUIRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT m.system_id, m.node_id, m.day, m.module_family, m.instances, m.facts_ok, m.versions
		FROM sizing_module_daily m
		JOIN (
			SELECT system_id, node_id, MAX(day) AS day
			FROM sizing_module_daily
			GROUP BY system_id, node_id
		) latest ON latest.system_id = m.system_id AND latest.node_id = m.node_id AND latest.day = m.day
		WHERE (? = '' OR m.system_id = ?)
		ORDER BY m.system_id, m.node_id, m.module_family
		LIMIT ?
	`, systemID, systemID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list sizing modules: %w", err)
	}

	result := []SizingModuleUIRow{}
	index := map[string]int{}
	err = func() error {
		defer rows.Close()
		for rows.Next() {
			var (
				r         SizingModuleUIRow
				instances sql.NullInt64
				factsOK   sql.NullInt64
				versions  sql.NullString
			)
			if err := rows.Scan(&r.SystemID, &r.NodeID, &r.Day, &r.Family,
				&instances, &factsOK, &versions); err != nil {
				return fmt.Errorf("store: scan sizing module: %w", err)
			}
			r.Instances, r.FactsOK = int(instances.Int64), int(factsOK.Int64)
			if versions.String != "" {
				_ = json.Unmarshal([]byte(versions.String), &r.Versions)
			}
			index[moduleKey(r.SystemID, r.NodeID, r.Day, r.Family)] = len(result)
			result = append(result, r)
		}
		return rows.Err()
	}()
	if err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return result, nil
	}

	// The "latest day" subquery reads sizing_module_daily, NOT
	// sizing_module_metric: a node-day whose families all reported an empty
	// workload has rows in the first table and none in the second, so keying
	// off the metric table would pick an older day and silently render the
	// wrong workload beside a current inventory row.
	metrics, err := s.db.QueryContext(ctx, `
		SELECT k.system_id, k.node_id, k.day, k.module_family, k.metric, k.value
		FROM sizing_module_metric k
		JOIN (
			SELECT system_id, node_id, MAX(day) AS day
			FROM sizing_module_daily
			GROUP BY system_id, node_id
		) latest ON latest.system_id = k.system_id AND latest.node_id = k.node_id AND latest.day = k.day
		WHERE (? = '' OR k.system_id = ?)
		ORDER BY k.system_id, k.node_id, k.module_family, k.metric
	`, systemID, systemID)
	if err != nil {
		return nil, fmt.Errorf("store: list sizing metrics: %w", err)
	}
	defer metrics.Close()

	folded := map[int][]string{}
	for metrics.Next() {
		var (
			row    SizingFamilyMetricRow
			day    int64
			value  sql.NullFloat64
			metric string
		)
		if err := metrics.Scan(&row.SystemID, &row.NodeID, &day, &row.Family, &metric, &value); err != nil {
			return nil, fmt.Errorf("store: scan sizing metric: %w", err)
		}
		i, ok := index[moduleKey(row.SystemID, row.NodeID, day, row.Family)]
		if !ok {
			continue
		}
		folded[i] = append(folded[i], metric+"="+strconv.FormatFloat(value.Float64, 'f', -1, 64))
	}
	if err := metrics.Err(); err != nil {
		return nil, fmt.Errorf("store: list sizing metrics: %w", err)
	}

	for i, parts := range folded {
		sort.Strings(parts)
		result[i].Workload = strings.Join(parts, ", ")
	}
	return result, nil
}

func moduleKey(systemID string, nodeID int, day int64, family string) string {
	return fmt.Sprintf("%s/%d/%d/%s", systemID, nodeID, day, family)
}

// ListSizingCohorts returns the published baselines, optionally filtered to
// one kind. An empty result is the correct answer for a fleet below the
// floor -- the page says "insufficient fleet data" rather than showing a
// percentile computed from three nodes.
func (s *SQLiteStore) ListSizingCohorts(ctx context.Context, kind string, limit int) ([]SizingCohortRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT cohort_kind, cohort_key, nodes, distinct_systems, censored_nodes,
			ram_used_p50, ram_used_p75, ram_used_p90,
			cpu_cores_used_p50, cpu_cores_used_p75, cpu_cores_used_p90,
			installed_ram_p50, installed_ram_p90, installed_cores_p50, installed_cores_p90,
			window_days, min_distinct_systems, min_nodes, pressure_version, updated_at
		FROM sizing_cohort_baseline
		WHERE (? = '' OR cohort_kind = ?)
		ORDER BY cohort_kind, ram_used_p90 DESC, cohort_key
		LIMIT ?
	`, kind, kind, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list sizing cohorts: %w", err)
	}
	defer rows.Close()

	result := []SizingCohortRow{}
	for rows.Next() {
		var r SizingCohortRow
		if err := rows.Scan(&r.CohortKind, &r.CohortKey, &r.Nodes, &r.DistinctSystems, &r.CensoredNodes,
			&r.RAMUsedP50, &r.RAMUsedP75, &r.RAMUsedP90,
			&r.CPUCoresUsedP50, &r.CPUCoresUsedP75, &r.CPUCoresUsedP90,
			&r.InstalledRAMP50, &r.InstalledRAMP90, &r.InstalledCoresP50, &r.InstalledCoresP90,
			&r.WindowDays, &r.MinDistinctSystems, &r.MinNodes, &r.PressureVersion, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: scan sizing cohort: %w", err)
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// SizingIngestStats returns the per-day, per-system drop accounting, newest
// first. This is how "why does this cluster send but store nothing" is
// answered without reading logs.
func (s *SQLiteStore) SizingIngestStats(ctx context.Context, limit int) ([]SizingIngestRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT day, system_id, reports, last_report_at, reporter_version,
			accepted_nodes, accepted_modules, accepted_metrics,
			dropped_day, dropped_duplicate, dropped_node, dropped_family,
			dropped_metric_key, dropped_metric_value, dropped_resource_value,
			truncated_days, truncated_nodes, truncated_families, truncated_metrics
		FROM sizing_ingest_daily
		ORDER BY day DESC, system_id
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: sizing ingest stats: %w", err)
	}
	defer rows.Close()

	result := []SizingIngestRow{}
	for rows.Next() {
		var (
			r        SizingIngestRow
			lastAt   sql.NullInt64
			reporter sql.NullString
		)
		if err := rows.Scan(&r.Day, &r.SystemID, &r.Reports, &lastAt, &reporter,
			&r.AcceptedNodes, &r.AcceptedModules, &r.AcceptedMetrics,
			&r.DroppedDay, &r.DroppedDuplicate, &r.DroppedNode, &r.DroppedFamily,
			&r.DroppedMetricKey, &r.DroppedMetricValue, &r.DroppedResourceValue,
			&r.TruncatedDays, &r.TruncatedNodes, &r.TruncatedFamilies, &r.TruncatedMetrics); err != nil {
			return nil, fmt.Errorf("store: scan sizing ingest stat: %w", err)
		}
		r.LastReportAt, r.ReporterVersion = lastAt.Int64, reporter.String
		result = append(result, r)
	}
	return result, rows.Err()
}

// SizingCounts is the status page's one-line summary of the pipeline.
func (s *SQLiteStore) SizingCounts(ctx context.Context) (SizingCounts, error) {
	var c SizingCounts

	var latest, lastReport sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT system_id), COUNT(*), MAX(day)
		FROM sizing_node_daily
	`).Scan(&c.Systems, &c.NodeDays, &latest)
	if err != nil {
		return c, fmt.Errorf("store: sizing counts: %w", err)
	}
	c.LatestDay = latest.Int64

	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sizing_node`).Scan(&c.Nodes); err != nil {
		return c, fmt.Errorf("store: sizing counts: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sizing_cohort_baseline`).Scan(&c.Cohorts); err != nil {
		return c, fmt.Errorf("store: sizing counts: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(last_report_at) FROM sizing_ingest_daily`).Scan(&lastReport); err != nil {
		return c, fmt.Errorf("store: sizing counts: %w", err)
	}
	c.LastReport = lastReport.Int64

	// Verdict distribution. Counted with SUM(CASE ...) rather than three
	// queries so the three numbers are consistent with each other. SUM over
	// an empty table is NULL, not 0, hence the NullInt64s -- an empty
	// dashboard is an ordinary state, not an error.
	var undersized, atRisk, unscored sql.NullInt64
	err = s.db.QueryRowContext(ctx, `
		SELECT
			SUM(CASE WHEN verdict = 'undersized' THEN 1 ELSE 0 END),
			SUM(CASE WHEN verdict = 'at_risk' THEN 1 ELSE 0 END),
			SUM(CASE WHEN verdict = 'insufficient_data' OR verdict IS NULL THEN 1 ELSE 0 END)
		FROM sizing_node_verdict
	`).Scan(&undersized, &atRisk, &unscored)
	if err != nil {
		return c, fmt.Errorf("store: sizing counts: %w", err)
	}
	c.Undersized, c.AtRisk, c.Unscored = int(undersized.Int64), int(atRisk.Int64), int(unscored.Int64)
	return c, nil
}

// parseReasons decodes a stored pressure_reasons array. A row written before
// any reason existed, or by a version that stored SQL NULL, decodes to nil
// rather than to an error -- the UI renders that as "no pressure", which is
// what it means.
func parseReasons(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" || raw == "[]" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}
