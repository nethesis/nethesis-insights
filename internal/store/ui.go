// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Cross-system, read-only query paths for the operator UI (internal/ui). Kept
// in a separate file so store.go, which is the write path used by the
// analyzer, does not balloon.
//
// None of these take s.mu: that mutex serializes writers only, and the
// existing read paths (KnownTemplates, Baselines, queryFindings) already
// follow that precedent.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nethesis/nethesis-insights/internal/model"
)

// defaultListLimit is applied whenever a caller passes limit <= 0. This data
// is served to an unauthenticated UI, so "no limit" is never an option.
const defaultListLimit = 200

// likePattern turns operator search input into a SQL LIKE pattern: a value
// already containing "%" is passed through so a caller can write %mid% for a
// substring search, otherwise "%" is appended for a prefix match -- the
// common case of pasting the short ID shown in the findings table.
func likePattern(s string) string {
	if s == "" || strings.Contains(s, "%") {
		return s
	}
	return s + "%"
}

const dayMillis = 86400000

// Counts is per-table row counts, for the status page.
type Counts struct {
	Systems, Templates, Baselines, Findings, Analyses int
	ThreatEvents, BlocklistEntries                    int
}

// SystemRow is one system plus the cross-table aggregates the operator UI's
// /systems page needs.
type SystemRow struct {
	SystemID, TenantID, CollectorVersion string
	FirstSeen, LastSeen                  int64
	Templates, OpenFindings, Findings    int
	Windows, LLMCalls                    int
	CostMicros                           int64
}

// AnalysisRow is one row of the cost ledger, including the columns the
// Analysis struct omits because the analyzer never reads them back.
type AnalysisRow struct {
	ID, SystemID           string
	WindowStart, WindowEnd int64
	Gated, LLMCalled       bool
	Completed              bool
	GateReasons            []string
	InputTokens            int
	OutputTokens           int
	CachedTokens           int
	CostMicros             int64
	Model                  string
	DurationMs             int
	Error                  string

	// SuppressedBy names the budget limit that stopped this window, if one
	// did. A gated row with a value here was not cheap -- it was refused.
	SuppressedBy string
	CreatedAt    int64
}

// GateRow is one distinct gate-reason set, after the three empty spellings
// have been normalized and merged.
//
// LLMCalls counts *attempts*: the analyzer sets llm_called on the transient-error,
// permanent-error and parse-error paths too, and those record no cost. PaidCalls
// counts only the rows that actually cost money, so LLMCalls-PaidCalls is the
// number of calls that were made and produced nothing.
type GateRow struct {
	Reasons                      []string // nil means "no reasons"
	Windows, LLMCalls, PaidCalls int
	CostMicros                   int64
}

// CostRow is spend and token totals for one UTC day and model.
type CostRow struct {
	Day                       string // "2006-01-02", UTC
	Model                     string
	Windows, LLMCalls         int
	InputTokens, OutputTokens int
	CostMicros                int64
}

// TemplateRow is one system_templates row, for the /templates page.
type TemplateRow struct {
	SystemID, Template, ModuleID, Category string
	Priority                               int
	TotalCount                             int64
	FirstSeen, LastSeen                    int64
}

// BaselineRow is one module_baselines row, for the /baselines page.
type BaselineRow struct {
	SystemID, ModuleID string
	Priority           int
	EWMARate           float64
	UpdatedAt          int64
}

// clampLimit applies defaultListLimit whenever the caller passed a
// non-positive value. This data is served to an unauthenticated UI, so an
// unbounded query is never acceptable.
func clampLimit(limit int) int {
	if limit <= 0 {
		return defaultListLimit
	}
	return limit
}

// normalizeGateReasons collapses the three stored spellings of "no reasons"
// -- the bare empty string BeginAnalysis writes, and the "null"/"[]" that
// json.Marshal of a nil/empty slice produces in FinalizeAnalysis -- into a
// nil slice. The bare empty string is not valid JSON, so it must be checked
// before attempting to unmarshal.
func normalizeGateReasons(raw string) []string {
	switch raw {
	case "", "null", "[]":
		return nil
	}
	var reasons []string
	if err := json.Unmarshal([]byte(raw), &reasons); err != nil {
		// Defensively treat anything unparseable as "no reasons" rather than
		// failing the whole page over one malformed row.
		return nil
	}
	if len(reasons) == 0 {
		return nil
	}
	return reasons
}

// Counts reports per-table row counts.
func (s *SQLiteStore) Counts(ctx context.Context) (Counts, error) {
	var c Counts
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM systems`).Scan(&c.Systems); err != nil {
		return Counts{}, fmt.Errorf("store: count systems: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM system_templates`).Scan(&c.Templates); err != nil {
		return Counts{}, fmt.Errorf("store: count templates: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM module_baselines`).Scan(&c.Baselines); err != nil {
		return Counts{}, fmt.Errorf("store: count baselines: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM findings`).Scan(&c.Findings); err != nil {
		return Counts{}, fmt.Errorf("store: count findings: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM analyses`).Scan(&c.Analyses); err != nil {
		return Counts{}, fmt.Errorf("store: count analyses: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM threat_events`).Scan(&c.ThreatEvents); err != nil {
		return Counts{}, fmt.Errorf("store: count threat events: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM threat_blocklist`).Scan(&c.BlocklistEntries); err != nil {
		return Counts{}, fmt.Errorf("store: count blocklist entries: %w", err)
	}
	return c, nil
}

// ListSystems returns every system plus per-system aggregates, ordered by
// last_seen descending. The six correlated subqueries each hit an index
// prefixed by system_id.
func (s *SQLiteStore) ListSystems(ctx context.Context) ([]SystemRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT
			s.system_id, s.tenant_id, s.collector_version, s.first_seen, s.last_seen,
			(SELECT count(*) FROM system_templates st WHERE st.system_id = s.system_id) AS templates,
			(SELECT count(*) FROM findings f WHERE f.system_id = s.system_id AND f.status = ?) AS open_findings,
			(SELECT count(*) FROM findings f WHERE f.system_id = s.system_id) AS findings,
			(SELECT count(*) FROM analyses a WHERE a.system_id = s.system_id) AS windows,
			(SELECT coalesce(sum(a.llm_called), 0) FROM analyses a WHERE a.system_id = s.system_id) AS llm_calls,
			(SELECT coalesce(sum(a.cost_micros), 0) FROM analyses a WHERE a.system_id = s.system_id) AS cost_micros
		FROM systems s
		ORDER BY s.last_seen DESC
	`, model.StatusOpen)
	if err != nil {
		return nil, fmt.Errorf("store: list systems: %w", err)
	}
	defer rows.Close()

	result := []SystemRow{}
	for rows.Next() {
		var r SystemRow
		if err := rows.Scan(&r.SystemID, &r.TenantID, &r.CollectorVersion, &r.FirstSeen, &r.LastSeen,
			&r.Templates, &r.OpenFindings, &r.Findings, &r.Windows, &r.LLMCalls, &r.CostMicros); err != nil {
			return nil, fmt.Errorf("store: scan system row: %w", err)
		}
		result = append(result, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list systems: %w", err)
	}
	return result, nil
}

// ListAnalyses returns the cost ledger, most recent window first. systemID
// == "" means every system.
func (s *SQLiteStore) ListAnalyses(ctx context.Context, systemID string, limit int) ([]AnalysisRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, system_id, window_start, window_end, gated, llm_called, completed,
		       gate_reasons, input_tokens, output_tokens, cached_tokens, cost_micros, model,
		       duration_ms, error, suppressed_by, created_at
		FROM analyses
		WHERE (? = '' OR system_id = ?)
		ORDER BY window_start DESC
		LIMIT ?
	`, systemID, systemID, clampLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("store: list analyses: %w", err)
	}
	defer rows.Close()

	result := []AnalysisRow{}
	for rows.Next() {
		var r AnalysisRow
		var gated, llmCalled, completed int
		var gateReasons string
		var errMsg, suppressedBy sql.NullString
		var cachedTokens sql.NullInt64
		if err := rows.Scan(&r.ID, &r.SystemID, &r.WindowStart, &r.WindowEnd, &gated, &llmCalled, &completed,
			&gateReasons, &r.InputTokens, &r.OutputTokens, &cachedTokens, &r.CostMicros, &r.Model,
			&r.DurationMs, &errMsg, &suppressedBy, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scan analysis row: %w", err)
		}
		r.CachedTokens = int(cachedTokens.Int64)
		r.SuppressedBy = suppressedBy.String
		r.Gated = gated != 0
		r.LLMCalled = llmCalled != 0
		r.Completed = completed != 0
		r.GateReasons = normalizeGateReasons(gateReasons)
		r.Error = errMsg.String
		result = append(result, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list analyses: %w", err)
	}
	return result, nil
}

// GateRollup reports, per distinct gate-reason set, how many windows fired
// it, how many of those called the LLM, how many of those calls cost money,
// and the total cost. The three stored spellings of "no reasons" are merged
// into one nil-Reasons row. Ordered by Windows descending, with a stable
// tiebreak on the reason set so output is deterministic.
//
// since bounds the scan to rows created at or after that unix-millis instant;
// 0 means all time. The bound is not cosmetic: gate reasons are stored as the
// formula that produced them spelled them, so an all-time rollup silently mixes
// formulas. Every row written before the security condition became
// novelty-scoped carries "security_category" and embedded counts and ratios
// ("new_templates=5", "deviation:/3=3.03"), which both group as separate keys
// and answer a question about a gate that no longer exists.
func (s *SQLiteStore) GateRollup(ctx context.Context, since int64) ([]GateRow, error) {
	// count(case when ...) rather than sum(cost_micros > 0): SQLite yields 1/0
	// for a comparison, Postgres yields a boolean sum() will not take.
	rows, err := s.db.QueryContext(ctx, `
		SELECT gate_reasons,
		       count(*) AS windows,
		       coalesce(sum(llm_called), 0) AS llm_calls,
		       count(CASE WHEN cost_micros > 0 THEN 1 END) AS paid_calls,
		       coalesce(sum(cost_micros), 0) AS cost_micros
		FROM analyses
		WHERE created_at >= ?
		GROUP BY gate_reasons
	`, since)
	if err != nil {
		return nil, fmt.Errorf("store: gate rollup: %w", err)
	}
	defer rows.Close()

	// Grouping on the raw stored string is otherwise sound (gate reasons are
	// sorted before storage, so identical reason sets produce identical
	// JSON) -- but "no reasons" has three distinct spellings, so several raw
	// groups can normalize to the same key and must be merged here.
	merged := map[string]*GateRow{}
	for rows.Next() {
		var raw string
		var windows, llmCalls, paidCalls int
		var costMicros int64
		if err := rows.Scan(&raw, &windows, &llmCalls, &paidCalls, &costMicros); err != nil {
			return nil, fmt.Errorf("store: scan gate row: %w", err)
		}
		reasons := normalizeGateReasons(raw)
		key := strings.Join(reasons, "\x1f")
		if existing, ok := merged[key]; ok {
			existing.Windows += windows
			existing.LLMCalls += llmCalls
			existing.PaidCalls += paidCalls
			existing.CostMicros += costMicros
		} else {
			merged[key] = &GateRow{
				Reasons:    reasons,
				Windows:    windows,
				LLMCalls:   llmCalls,
				PaidCalls:  paidCalls,
				CostMicros: costMicros,
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: gate rollup: %w", err)
	}

	result := make([]GateRow, 0, len(merged))
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys) // stable tiebreak input
	for _, k := range keys {
		result = append(result, *merged[k])
	}
	sort.SliceStable(result, func(i, j int) bool {
		return result[i].Windows > result[j].Windows
	})
	return result, nil
}

// CostRollup buckets analyses that called the LLM into UTC days, per model.
// Bucketing is portable integer division on the unix-millis column, exactly
// as the spec requires -- SQLite and Postgres agree on integer /.
func (s *SQLiteStore) CostRollup(ctx context.Context) ([]CostRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT created_at / ? AS day_idx, model,
		       count(*) AS windows, coalesce(sum(llm_called), 0) AS llm_calls,
		       coalesce(sum(input_tokens), 0) AS in_tok, coalesce(sum(output_tokens), 0) AS out_tok,
		       coalesce(sum(cost_micros), 0) AS cost_micros
		FROM analyses
		WHERE llm_called = 1
		GROUP BY created_at / ?, model
		ORDER BY created_at / ? DESC, model
	`, dayMillis, dayMillis, dayMillis)
	if err != nil {
		return nil, fmt.Errorf("store: cost rollup: %w", err)
	}
	defer rows.Close()

	result := []CostRow{}
	for rows.Next() {
		var dayIdx int64
		var r CostRow
		if err := rows.Scan(&dayIdx, &r.Model, &r.Windows, &r.LLMCalls, &r.InputTokens, &r.OutputTokens, &r.CostMicros); err != nil {
			return nil, fmt.Errorf("store: scan cost row: %w", err)
		}
		r.Day = time.UnixMilli(dayIdx * dayMillis).UTC().Format("2006-01-02")
		result = append(result, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: cost rollup: %w", err)
	}
	return result, nil
}

// SortRecent orders ListAllFindings' result by last_seen descending only,
// ignoring severity -- the UI's alternative to the canonical
// model.SortFindings order, for an operator who wants to see what just fired
// regardless of severity. It is a display concern local to this package, not
// a second definition of findings ordering: model.SortFindings (severity,
// then last_seen) stays the one used everywhere else, per CLAUDE.md.
const SortRecent = "recent"

// ListAllFindings is the fleet-wide counterpart to ListFindings: no implicit
// system scope, and systemID/status/severity/idLike are each optional filters
// ("" means no filter). systemID and idLike both match with SQL LIKE, letting
// an operator paste a prefix of the (unshortened) system ID or the short
// finding ID shown in the UI table; see likePattern for how a bare value (no
// "%") is turned into a prefix match. Results are capped to limit (most
// recently seen first). sort selects the order of that capped page: ""
// (default) re-sorts into the canonical severity/last_seen order via
// model.SortFindings; SortRecent leaves the SQL's last_seen-descending order
// as is.
func (s *SQLiteStore) ListAllFindings(ctx context.Context, systemID, status, severity, idLike, sort string, limit int) ([]model.Finding, error) {
	query := `
		SELECT id, system_id, fingerprint, severity, title, summary, suggested_action, modules, evidence, status, occurrence_count, first_seen, last_seen, reopened_at, llm_model, prompt_version
		FROM findings
		WHERE (? = '' OR system_id LIKE ?) AND (? = '' OR status = ?) AND (? = '' OR severity = ?)
		  AND (? = '' OR id LIKE ? OR fingerprint LIKE ?)
		ORDER BY last_seen DESC
		LIMIT ?
	`
	systemPattern := likePattern(systemID)
	idPattern := likePattern(idLike)
	findings, err := s.queryFindings(ctx, query, systemID, systemPattern, status, status, severity, severity, idLike, idPattern, idPattern, clampLimit(limit))
	if err != nil {
		return nil, err
	}
	if findings == nil {
		findings = []model.Finding{}
	}
	if sort != SortRecent {
		model.SortFindings(findings)
	}
	return findings, nil
}

// ListTemplates returns system_templates rows, most recently seen first.
// systemID == "" means every system.
func (s *SQLiteStore) ListTemplates(ctx context.Context, systemID string, limit int) ([]TemplateRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT system_id, template, module_id, priority, category, total_count, first_seen, last_seen
		FROM system_templates
		WHERE (? = '' OR system_id = ?)
		ORDER BY last_seen DESC
		LIMIT ?
	`, systemID, systemID, clampLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("store: list templates: %w", err)
	}
	defer rows.Close()

	result := []TemplateRow{}
	for rows.Next() {
		var r TemplateRow
		if err := rows.Scan(&r.SystemID, &r.Template, &r.ModuleID, &r.Priority, &r.Category, &r.TotalCount, &r.FirstSeen, &r.LastSeen); err != nil {
			return nil, fmt.Errorf("store: scan template row: %w", err)
		}
		result = append(result, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list templates: %w", err)
	}
	return result, nil
}

// ListBaselines returns module_baselines rows. systemID == "" means every
// system. Unlike the other list methods this has no limit: baselines are
// bounded by (system_id, module_id, priority) cardinality, not by an
// unbounded event stream.
func (s *SQLiteStore) ListBaselines(ctx context.Context, systemID string) ([]BaselineRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT system_id, module_id, priority, ewma_rate, updated_at
		FROM module_baselines
		WHERE (? = '' OR system_id = ?)
		ORDER BY system_id, module_id, priority
	`, systemID, systemID)
	if err != nil {
		return nil, fmt.Errorf("store: list baselines: %w", err)
	}
	defer rows.Close()

	result := []BaselineRow{}
	for rows.Next() {
		var r BaselineRow
		if err := rows.Scan(&r.SystemID, &r.ModuleID, &r.Priority, &r.EWMARate, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: scan baseline row: %w", err)
		}
		result = append(result, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list baselines: %w", err)
	}
	return result, nil
}
