// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/sizing"
	"github.com/nethesis/nethesis-insights/internal/store"
)

// SizingStore is the slice of the store the sizing ingest handler needs.
// Declared here, narrow, so the handler is testable with a small fake instead
// of a fifty-method stub. *store.SQLiteStore satisfies it.
type SizingStore interface {
	UpsertSizingDays(ctx context.Context, systemID, reporterVersion string, days []store.SizingDayRows, now int64) (int, error)
	RecordSizingIngest(ctx context.Context, day int64, systemID, reporterVersion string, c model.SizingCounters, now int64) error
}

// SizingConfig wires POST /v1/sizing-reports. The zero value leaves it
// unregistered, which is what api's own tests use.
type SizingConfig struct {
	Store    SizingStore
	MaxNodes int
	Now      func() int64
}

func (c SizingConfig) enabled() bool { return c.Store != nil }

// maxSizingReportSize matches the bundle and threat limits. A report is a
// handful of numbers per node per day, so it is far smaller in practice; the
// cap exists to bound a malicious or broken reporter, not the honest one.
const maxSizingReportSize = 8 << 20 // 8 MiB

// handleSizingReports ingests one cluster's complete-day workload and
// performance report.
//
// Fail-closed on authentication, fail-open on content: a malformed node,
// family or metric is dropped with a counter and the rest of the report is
// stored, because a cluster with one broken module must not lose the other
// fifteen. Synchronous -- there is no LLM here, so no queue.
//
// The pressure score is computed here, on the server, and never on the edge:
// scoring at the edge would make every node an uncoordinated second
// implementation of the formula, and then a threshold recalibration would
// need the fleet's cooperation instead of one recompute pass.
func (s *server) handleSizingReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	authenticatedSystemID, ok := s.authenticate(w, r)
	if !ok {
		return
	}

	// A declared over-cap body is answered 413 rather than being truncated
	// into a confusing 400. A reporter that lies about Content-Length still
	// hits the LimitReader below and gets the 400.
	if r.ContentLength > maxSizingReportSize {
		reject(w, r, http.StatusRequestEntityTooLarge, "report too large",
			"content_length", r.ContentLength, "limit", maxSizingReportSize)
		return
	}

	var reader io.Reader = io.LimitReader(r.Body, maxSizingReportSize)
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(reader)
		if err != nil {
			reject(w, r, http.StatusBadRequest, "invalid gzip body", "error", err.Error())
			return
		}
		defer gz.Close()
		reader = gz
	}

	var report model.SizingReport
	if err := json.NewDecoder(reader).Decode(&report); err != nil {
		reject(w, r, http.StatusBadRequest, "invalid json body",
			"error", err.Error(), "content_length", r.ContentLength)
		return
	}

	if report.SchemaVersion != model.SizingSchemaVersion {
		reject(w, r, http.StatusBadRequest, "unsupported schema_version",
			"got", report.SchemaVersion, "want", model.SizingSchemaVersion)
		return
	}
	// system_id is optional -- the credential already identifies the reporter
	// -- but a mismatch is a broken reporter, not something to silently
	// override. Same rule as handleBundles and handleThreatEvents.
	if report.SystemID != "" && report.SystemID != authenticatedSystemID {
		reject(w, r, http.StatusForbidden, "system_id does not match authenticated system",
			"report_system_id", report.SystemID, "authenticated_system_id", authenticatedSystemID)
		return
	}

	now := s.sizing.Now()
	res := sizing.Sanitize(report, sizing.Options{MaxNodes: s.sizing.MaxNodes}, now)
	reporterVersion := sizing.CleanReporterVersion(report.ReporterVersion)

	days := scoreSizingDays(res.Days)

	stored, err := s.sizing.Store.UpsertSizingDays(r.Context(), authenticatedSystemID, reporterVersion, days, now)
	if err != nil {
		slog.Error("upsert sizing days failed", "system_id", authenticatedSystemID, "error", err)
		writeJSONError(w, http.StatusServiceUnavailable, "temporarily unavailable")
		return
	}

	// Accounting failures must never cost the reporter its 202: the
	// measurements are already stored, and the counters are an operator
	// convenience. The day the counters land under is the newest day the
	// report carried, or the arrival day when it carried none.
	var counterDay int64
	if n := len(days); n > 0 {
		counterDay = days[n-1].Day
	}
	if err := s.sizing.Store.RecordSizingIngest(r.Context(), counterDay, authenticatedSystemID, reporterVersion, res.Counters, now); err != nil {
		slog.Error("record sizing ingest failed", "system_id", authenticatedSystemID, "error", err)
	}

	slog.Debug("sizing report accepted",
		"system_id", authenticatedSystemID,
		"days", len(report.Days),
		"stored_days", len(days),
		"stored_nodes", stored,
		"counters", res.Counters,
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(sizingIngestResponse{
		Accepted:    true,
		StoredDays:  len(days),
		StoredNodes: stored,
		Dropped:     res.Counters,
	})
}

type sizingIngestResponse struct {
	Accepted    bool                 `json:"accepted"`
	StoredDays  int                  `json:"stored_days"`
	StoredNodes int                  `json:"stored_nodes"`
	Dropped     model.SizingCounters `json:"dropped"`
}

// scoreSizingDays turns sanitized days into store rows, scoring each node-day
// on the way through.
//
// Kept as a function rather than inlined because internal/baseline runs the
// same Evaluate over rows it read back after a pressure_version bump, and the
// two paths must not be able to score differently.
func scoreSizingDays(days []model.SanitizedSizingDay) []store.SizingDayRows {
	out := make([]store.SizingDayRows, 0, len(days))
	for _, d := range days {
		row := store.SizingDayRows{Day: d.Day, ClusterWorkload: d.ClusterWorkload}
		for _, n := range d.Nodes {
			row.Nodes = append(row.Nodes, store.SizingNodeDayRow{
				NodeID:         n.NodeID,
				MetricsPresent: n.MetricsPresent,
				SampleCoverage: n.SampleCoverage,
				Hardware:       n.Hardware,
				Resources:      n.Resources,
				Stress:         n.Stress,
				Modules:        n.Modules,
			})
			score := sizing.Evaluate(n)
			row.Nodes[len(row.Nodes)-1].SetScore(score.Pressure, score.Mem, score.CPU, score.IO, score.Disk,
				score.TopAxis, score.Reasons, score.Version, score.OOMSuspect)
		}
		out = append(out, row)
	}
	return out
}
