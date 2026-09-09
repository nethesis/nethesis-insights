// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package logs is insightsd's storage: the ingest bookkeeping (systems,
// templates, baselines), the analyses cost ledger, the findings table, and
// the cross-system reads the operator UI needs (see ui.go). It is
// insightsd's only store package -- a separate SQLite file from the threat
// and sizing pipelines, sharing nothing with them but the sqlitex runtime
// settings.
package logs

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/nethesis/nethesis-insights/internal/gate"
	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/platform/sqlitex"
)

type Outcome string

const (
	OutcomeInserted Outcome = "inserted"
	OutcomeBumped   Outcome = "bumped"
	OutcomeReopened Outcome = "reopened"
)

type System struct {
	SystemID         string
	TenantID         string
	CollectorVersion string
	FirstSeen        int64
	LastSeen         int64
}

type Analysis struct {
	SystemID     string
	WindowStart  int64
	WindowEnd    int64
	Gated        bool
	GateReasons  []string
	LLMCalled    bool
	InputTokens  int
	OutputTokens int
	CostMicros   int64
	Model        string
	DurationMs   int
	Error        string

	// CachedTokens is the part of InputTokens the provider served from its
	// prompt cache and charges at half rate. It is recorded rather than
	// inferred so the cost column stays arithmetic anyone can check.
	CachedTokens int

	// SuppressedBy names the budget limit that stopped this window, if one
	// did. A suppressed window carries no gate reasons: the gate is why a
	// window is worth money, and this is why it did not get any.
	SuppressedBy string
}

// Store is insightsd's SQLite-backed store: ingest bookkeeping, the analyses
// cost ledger, findings, and the operator UI's cross-system reads (ui.go).
// Write methods take the shared write mutex (sqlitex.DB.Lock/Unlock); read
// methods do not.
type Store struct {
	db *sqlitex.DB
}

// Open opens the logs pipeline's database at path with the project's
// standard SQLite runtime settings (WAL, busy_timeout, a single connection
// plus the write mutex) -- see internal/platform/sqlitex.
func Open(path string) (*Store, error) {
	db, err := sqlitex.Open(path)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// Init creates the logs pipeline's tables if they do not already exist.
func (s *Store) Init(ctx context.Context) error {
	s.db.Lock()
	defer s.db.Unlock()

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS systems (
			system_id TEXT PRIMARY KEY,
			tenant_id TEXT,
			collector_version TEXT,
			first_seen INTEGER,
			last_seen INTEGER
		)`,
		// Keyed on template_key (model.CanonicalTemplate), not on the raw
		// template text. Two consequences, both deliberate: the leaked
		// variants of one line share a row instead of minting novelty every
		// window, and the module is part of the key -- the old
		// (system_id, template) key merged the same line seen in two modules,
		// so a line genuinely new for one module read as known because
		// another module had emitted it.
		//
		// `module_id` holds the module *family* (model.ModuleFamily), not the
		// instance: 82 nethvoice instances emitting one cron line are one
		// condition, not 82. `template` likewise holds the raw text of the
		// variant last seen rather than the key. Both columns follow the same
		// idiom -- the key is canonical, the column next to it keeps what an
		// operator needs to read.
		`CREATE TABLE IF NOT EXISTS system_templates (
			system_id TEXT,
			template_key TEXT,
			template TEXT,
			module_id TEXT,
			priority INTEGER,
			category TEXT,
			first_seen INTEGER,
			last_seen INTEGER,
			total_count INTEGER,
			PRIMARY KEY (system_id, module_id, template_key)
		)`,
		`CREATE TABLE IF NOT EXISTS module_baselines (
			system_id TEXT,
			module_id TEXT,
			priority INTEGER,
			ewma_rate REAL,
			updated_at INTEGER,
			PRIMARY KEY (system_id, module_id, priority)
		)`,
		`CREATE TABLE IF NOT EXISTS findings (
			id TEXT PRIMARY KEY,
			system_id TEXT,
			fingerprint TEXT,
			severity TEXT,
			title TEXT,
			summary TEXT,
			suggested_action TEXT,
			modules TEXT,
			evidence TEXT,
			status TEXT,
			occurrence_count INTEGER,
			first_seen INTEGER,
			last_seen INTEGER,
			reopened_at INTEGER,
			llm_model TEXT,
			prompt_version TEXT
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_system_fingerprint ON findings(system_id, fingerprint)`,
		`CREATE TABLE IF NOT EXISTS analyses (
			id TEXT PRIMARY KEY,
			system_id TEXT,
			window_start INTEGER,
			window_end INTEGER,
			gated INTEGER,
			gate_reasons TEXT,
			llm_called INTEGER,
			input_tokens INTEGER,
			output_tokens INTEGER,
			cost_micros INTEGER,
			model TEXT,
			duration_ms INTEGER,
			error TEXT,
			cached_tokens INTEGER,
			suppressed_by TEXT,
			completed INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_analyses_system_window ON analyses(system_id, window_start)`,
	}

	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("store: init: %w", err)
		}
	}

	return nil
}

func (s *Store) UpsertSystem(ctx context.Context, sys System) error {
	s.db.Lock()
	defer s.db.Unlock()

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO systems (system_id, tenant_id, collector_version, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(system_id) DO UPDATE SET
			tenant_id = excluded.tenant_id,
			collector_version = excluded.collector_version,
			last_seen = excluded.last_seen
	`, sys.SystemID, sys.TenantID, sys.CollectorVersion, sys.FirstSeen, sys.LastSeen)
	if err != nil {
		return fmt.Errorf("store: upsert system: %w", err)
	}
	return nil
}

func (s *Store) KnownTemplates(ctx context.Context, systemID string) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT module_id, template_key FROM system_templates WHERE system_id = ?`, systemID)
	if err != nil {
		return nil, fmt.Errorf("store: known templates: %w", err)
	}
	defer rows.Close()

	// The key the gate looks up joins the module and the canonical text. The
	// two are stored in separate columns and joined here rather than stored
	// pre-joined, so no separator byte has to survive a round trip through
	// the database.
	result := map[string]bool{}
	for rows.Next() {
		var moduleID, key string
		if err := rows.Scan(&moduleID, &key); err != nil {
			return nil, fmt.Errorf("store: scan template: %w", err)
		}
		result[model.CanonicalKey(moduleID, key)] = true
	}
	return result, rows.Err()
}

func (s *Store) UpsertTemplates(ctx context.Context, systemID string, ts []model.Template, now int64) error {
	s.db.Lock()
	defer s.db.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin tx: %w", err)
	}
	defer tx.Rollback()

	for _, t := range ts {
		firstSeen := t.FirstSeen
		if firstSeen == 0 {
			firstSeen = now
		}
		lastSeen := t.LastSeen
		if lastSeen == 0 {
			lastSeen = now
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO system_templates (system_id, template_key, template, module_id, priority, category, first_seen, last_seen, total_count)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(system_id, module_id, template_key) DO UPDATE SET
				template = excluded.template,
				priority = excluded.priority,
				category = excluded.category,
				last_seen = excluded.last_seen,
				total_count = system_templates.total_count + excluded.total_count
		`, systemID, model.CanonicalTemplate(t.Template), t.Template, model.ModuleFamily(t.ModuleID),
			t.Priority, t.Category, firstSeen, lastSeen, t.Count)
		if err != nil {
			return fmt.Errorf("store: upsert template: %w", err)
		}
	}

	return tx.Commit()
}

func (s *Store) Baselines(ctx context.Context, systemID string) (map[gate.BaselineKey]float64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT module_id, priority, ewma_rate FROM module_baselines WHERE system_id = ?`, systemID)
	if err != nil {
		return nil, fmt.Errorf("store: baselines: %w", err)
	}
	defer rows.Close()

	result := map[gate.BaselineKey]float64{}
	for rows.Next() {
		var moduleID string
		var priority int
		var rate float64
		if err := rows.Scan(&moduleID, &priority, &rate); err != nil {
			return nil, fmt.Errorf("store: scan baseline: %w", err)
		}
		result[gate.BaselineKey{ModuleID: moduleID, Priority: priority}] = rate
	}
	return result, rows.Err()
}

func (s *Store) UpsertBaselines(ctx context.Context, systemID string, d []model.DigestEntry, alpha float64) error {
	s.db.Lock()
	defer s.db.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin tx: %w", err)
	}
	defer tx.Rollback()

	now := nowMillis()

	for _, e := range d {
		var prev sql.NullFloat64
		err := tx.QueryRowContext(ctx, `SELECT ewma_rate FROM module_baselines WHERE system_id = ? AND module_id = ? AND priority = ?`,
			systemID, e.ModuleID, e.Priority).Scan(&prev)
		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("store: read baseline: %w", err)
		}

		var newRate float64
		if !prev.Valid {
			newRate = float64(e.Observed)
		} else {
			newRate = alpha*float64(e.Observed) + (1-alpha)*prev.Float64
		}

		_, err = tx.ExecContext(ctx, `
			INSERT INTO module_baselines (system_id, module_id, priority, ewma_rate, updated_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(system_id, module_id, priority) DO UPDATE SET
				ewma_rate = excluded.ewma_rate,
				updated_at = excluded.updated_at
		`, systemID, e.ModuleID, e.Priority, newRate, now)
		if err != nil {
			return fmt.Errorf("store: upsert baseline: %w", err)
		}
	}

	return tx.Commit()
}

func (s *Store) BeginAnalysis(ctx context.Context, systemID string, windowStart, windowEnd, now int64) (bool, error) {
	s.db.Lock()
	defer s.db.Unlock()

	// A window is claimable unless a COMPLETED analysis already exists for it.
	//
	// Claiming on insert alone was wrong: a transient LLM failure left the row
	// behind, so the edge's retry was rejected as a duplicate and the window
	// could never be processed again. Only FinalizeAnalysis sets completed, so
	// a failed attempt stays claimable while a genuine duplicate is still
	// rejected. The row is kept either way -- a repeatedly failing system
	// should be visible in the ledger, not absent from it.
	id := ulid.Make().String()
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO analyses (id, system_id, window_start, window_end, gated, gate_reasons, llm_called, input_tokens, output_tokens, cost_micros, model, duration_ms, error, completed, created_at)
		VALUES (?, ?, ?, ?, 0, '', 0, 0, 0, 0, '', 0, '', 0, ?)
		ON CONFLICT(system_id, window_start) DO UPDATE SET
			window_end = excluded.window_end,
			created_at = excluded.created_at
		WHERE analyses.completed = 0
	`, id, systemID, windowStart, windowEnd, now)
	if err != nil {
		return false, fmt.Errorf("store: begin analysis: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: begin analysis rows affected: %w", err)
	}
	return n > 0, nil
}

// RecordAttemptError records a failed attempt WITHOUT marking the analysis
// complete, so the edge's retry of the same window is still claimable.
//
// This is the difference between a transient failure and a permanent one. A
// timeout or a 5xx must leave the window reprocessable; only a completed run,
// or a failure that will recur identically, may close it.
func (s *Store) RecordAttemptError(ctx context.Context, systemID string, windowStart int64, reasons []string, durationMs int, msg string) error {
	s.db.Lock()
	defer s.db.Unlock()

	reasonsJSON, err := json.Marshal(reasons)
	if err != nil {
		return fmt.Errorf("store: marshal gate reasons: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		UPDATE analyses SET
			gate_reasons = ?, llm_called = 1, duration_ms = ?, error = ?
		WHERE system_id = ? AND window_start = ?
	`, string(reasonsJSON), durationMs, msg, systemID, windowStart)
	if err != nil {
		return fmt.Errorf("store: record attempt error: %w", err)
	}
	return nil
}

func (s *Store) FinalizeAnalysis(ctx context.Context, a Analysis) error {
	s.db.Lock()
	defer s.db.Unlock()

	reasonsJSON, err := json.Marshal(a.GateReasons)
	if err != nil {
		return fmt.Errorf("store: marshal gate reasons: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		UPDATE analyses SET
			gated = ?, gate_reasons = ?, llm_called = ?, input_tokens = ?, output_tokens = ?,
			cached_tokens = ?, cost_micros = ?, model = ?, duration_ms = ?, error = ?,
			suppressed_by = ?, completed = 1
		WHERE system_id = ? AND window_start = ?
	`, boolToInt(a.Gated), string(reasonsJSON), boolToInt(a.LLMCalled), a.InputTokens, a.OutputTokens,
		a.CachedTokens, a.CostMicros, a.Model, a.DurationMs, a.Error, a.SuppressedBy,
		a.SystemID, a.WindowStart)
	if err != nil {
		return fmt.Errorf("store: finalize analysis: %w", err)
	}
	return nil
}

// DailySpendMicros sums what the fleet has spent since `since`. It reads the
// analyses ledger rather than an in-process counter, so a restart cannot reset
// the cap.
func (s *Store) DailySpendMicros(ctx context.Context, since int64) (int64, error) {
	var total sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT SUM(cost_micros) FROM analyses WHERE created_at >= ?`, since).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("store: daily spend: %w", err)
	}
	return total.Int64, nil
}

// SystemCallsSince counts LLM calls attempted for one system since `since`.
// It counts attempts, not successes: a system whose calls keep failing is
// still spending, and is still the thing the cap exists to bound.
func (s *Store) SystemCallsSince(ctx context.Context, systemID string, since int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM analyses WHERE system_id = ? AND created_at >= ? AND llm_called = 1`,
		systemID, since).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: system calls: %w", err)
	}
	return n, nil
}

func (s *Store) OpenFindings(ctx context.Context, systemID string) ([]model.Finding, error) {
	return s.queryFindings(ctx, `SELECT id, system_id, fingerprint, severity, title, summary, suggested_action, modules, evidence, status, occurrence_count, first_seen, last_seen, reopened_at, llm_model, prompt_version FROM findings WHERE system_id = ? AND status = ?`, systemID, model.StatusOpen)
}

func (s *Store) UpsertFinding(ctx context.Context, f model.Finding, now int64) (Outcome, error) {
	s.db.Lock()
	defer s.db.Unlock()

	// Read prior status FIRST: it is what distinguishes a bump from a
	// reopen, and the upsert below would otherwise destroy it.
	var priorStatus sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT status FROM findings WHERE system_id = ? AND fingerprint = ?`, f.SystemID, f.Fingerprint).Scan(&priorStatus)
	if err != nil && err != sql.ErrNoRows {
		return "", fmt.Errorf("store: read prior finding: %w", err)
	}

	var outcome Outcome
	switch {
	case !priorStatus.Valid:
		outcome = OutcomeInserted
	case priorStatus.String == model.StatusOpen:
		outcome = OutcomeBumped
	default:
		outcome = OutcomeReopened
	}

	modulesJSON, err := json.Marshal(f.Modules)
	if err != nil {
		return "", fmt.Errorf("store: marshal modules: %w", err)
	}
	evidenceJSON, err := json.Marshal(f.Evidence)
	if err != nil {
		return "", fmt.Errorf("store: marshal evidence: %w", err)
	}

	id := f.ID
	if id == "" {
		id = ulid.Make().String()
	}

	// The common columns updated on every path (insert, bump, reopen).
	// reopened_at is handled separately below since it must only be
	// stamped when actually reopening -- a plain bump must leave whatever
	// reopened_at value the row already has untouched.
	baseSQL := `
		INSERT INTO findings (id, system_id, fingerprint, severity, title, summary, suggested_action, modules, evidence, status, occurrence_count, first_seen, last_seen, reopened_at, llm_model, prompt_version)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, NULL, ?, ?)
		ON CONFLICT(system_id, fingerprint) DO UPDATE SET
			severity = excluded.severity,
			title = excluded.title,
			summary = excluded.summary,
			suggested_action = excluded.suggested_action,
			modules = excluded.modules,
			evidence = excluded.evidence,
			status = ?,
			occurrence_count = findings.occurrence_count + 1,
			last_seen = ?%s
	`
	args := []any{id, f.SystemID, f.Fingerprint, f.Severity, f.Title, f.Summary, f.SuggestedAction, string(modulesJSON), string(evidenceJSON), model.StatusOpen, now, now, f.LLMModel, f.PromptVersion, model.StatusOpen, now}

	var extraSet string
	if outcome == OutcomeReopened {
		extraSet = ",\n\t\t\treopened_at = ?"
		args = append(args, now)
	}
	extraSet += ",\n\t\t\tllm_model = excluded.llm_model,\n\t\t\tprompt_version = excluded.prompt_version"

	query := fmt.Sprintf(baseSQL, extraSet)
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return "", fmt.Errorf("store: upsert finding: %w", err)
	}

	return outcome, nil
}

func (s *Store) MarkStale(ctx context.Context, systemID string, olderThan int64) (int, error) {
	s.db.Lock()
	defer s.db.Unlock()

	res, err := s.db.ExecContext(ctx, `UPDATE findings SET status = ? WHERE system_id = ? AND status = ? AND last_seen < ?`,
		model.StatusStale, systemID, model.StatusOpen, olderThan)
	if err != nil {
		return 0, fmt.Errorf("store: mark stale: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: mark stale rows affected: %w", err)
	}
	return int(n), nil
}

func (s *Store) ListFindings(ctx context.Context, systemID string, since int64, status string) ([]model.Finding, error) {
	query := `SELECT id, system_id, fingerprint, severity, title, summary, suggested_action, modules, evidence, status, occurrence_count, first_seen, last_seen, reopened_at, llm_model, prompt_version FROM findings WHERE system_id = ? AND last_seen >= ?`
	args := []any{systemID, since}
	if status != "" {
		query += ` AND status = ?`
		args = append(args, status)
	}

	findings, err := s.queryFindings(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	model.SortFindings(findings)
	return findings, nil
}

func (s *Store) queryFindings(ctx context.Context, query string, args ...any) ([]model.Finding, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query findings: %w", err)
	}
	defer rows.Close()

	var result []model.Finding
	for rows.Next() {
		var f model.Finding
		var modulesJSON, evidenceJSON string
		var reopenedAt sql.NullInt64
		if err := rows.Scan(&f.ID, &f.SystemID, &f.Fingerprint, &f.Severity, &f.Title, &f.Summary, &f.SuggestedAction,
			&modulesJSON, &evidenceJSON, &f.Status, &f.OccurrenceCount, &f.FirstSeen, &f.LastSeen, &reopenedAt,
			&f.LLMModel, &f.PromptVersion); err != nil {
			return nil, fmt.Errorf("store: scan finding: %w", err)
		}
		if err := json.Unmarshal([]byte(modulesJSON), &f.Modules); err != nil {
			return nil, fmt.Errorf("store: unmarshal modules: %w", err)
		}
		if err := json.Unmarshal([]byte(evidenceJSON), &f.Evidence); err != nil {
			return nil, fmt.Errorf("store: unmarshal evidence: %w", err)
		}
		if reopenedAt.Valid {
			v := reopenedAt.Int64
			f.ReopenedAt = &v
		}
		result = append(result, f)
	}
	return result, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nowMillis() int64 {
	return time.Now().UnixMilli()
}
