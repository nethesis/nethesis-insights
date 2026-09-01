// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	_ "modernc.org/sqlite"

	"github.com/nethesis/nethesis-insights/internal/gate"
	"github.com/nethesis/nethesis-insights/internal/model"
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
}

type Store interface {
	Init(ctx context.Context) error
	Close() error

	UpsertSystem(ctx context.Context, s System) error
	KnownTemplates(ctx context.Context, systemID string) (map[string]bool, error)
	UpsertTemplates(ctx context.Context, systemID string, ts []model.Template, now int64) error
	Baselines(ctx context.Context, systemID string) (map[gate.BaselineKey]float64, error)
	UpsertBaselines(ctx context.Context, systemID string, d []model.DigestEntry, alpha float64) error
	BeginAnalysis(ctx context.Context, systemID string, windowStart, windowEnd, now int64) (bool, error)
	FinalizeAnalysis(ctx context.Context, a Analysis) error
	RecordAttemptError(ctx context.Context, systemID string, windowStart int64, reasons []string, durationMs int, msg string) error
	OpenFindings(ctx context.Context, systemID string) ([]model.Finding, error)
	UpsertFinding(ctx context.Context, f model.Finding, now int64) (Outcome, error)
	MarkStale(ctx context.Context, systemID string, olderThan int64) (int, error)
	ListFindings(ctx context.Context, systemID string, since int64, status string) ([]model.Finding, error)

	// Cross-system, read-only paths for the operator UI (internal/ui).
	// Every one takes an explicit limit and never returns raw samples.
	Counts(ctx context.Context) (Counts, error)
	ListSystems(ctx context.Context) ([]SystemRow, error)
	ListAnalyses(ctx context.Context, systemID string, limit int) ([]AnalysisRow, error)
	GateRollup(ctx context.Context) ([]GateRow, error)
	CostRollup(ctx context.Context) ([]CostRow, error)
	ListAllFindings(ctx context.Context, systemID, status, severity, idLike string, limit int) ([]model.Finding, error)
	ListTemplates(ctx context.Context, systemID string, limit int) ([]TemplateRow, error)
	ListBaselines(ctx context.Context, systemID string) ([]BaselineRow, error)

	// Threat Shield ingest and consensus (internal/api, internal/blocklist).
	InsertThreatEvents(ctx context.Context, systemID string, ev []model.ThreatEvent) (inserted, duplicates int, err error)
	RecordIngestCounters(ctx context.Context, day, systemID string, c model.ThreatCounters, duplicates int) error
	ConsensusCandidates(ctx context.Context, since int64) ([]ThreatCandidateRow, error)
	ThreatAllowlist(ctx context.Context, now int64) ([]AllowlistRow, error)
	UpsertThreatAllowlistEntry(ctx context.Context, e AllowlistRow) error
	DeleteThreatAllowlistEntry(ctx context.Context, cidr string) (bool, error)
	UpsertBlocklistEntries(ctx context.Context, rows []BlocklistRow) error
	ExpireBlocklist(ctx context.Context, now int64) (int, error)
	ListBlocklist(ctx context.Context, now int64, limit int) ([]BlocklistRow, error)
	RollupThreatDailyStats(ctx context.Context) error
	PruneThreatEvents(ctx context.Context, olderThan int64) (int, error)

	// Threat Shield cross-system reads for the operator UI.
	ListBlocklistEntries(ctx context.Context, limit int) ([]BlocklistRow, error)
	ListThreatEvents(ctx context.Context, systemID, attackerIP string, limit int) ([]ThreatEventRow, error)
	ThreatDailyStats(ctx context.Context, limit int) ([]ThreatDailyRow, error)
	ThreatIngestStats(ctx context.Context, limit int) ([]ThreatIngestRow, error)
	ListThreatAllowlist(ctx context.Context) ([]AllowlistRow, error)

	// Allowlist management: a client-facing request queue (internal/api),
	// and the admin API / operator UI writes that turn a reviewed request,
	// or an out-of-band decision, into a threat_allowlist row
	// (internal/admin, internal/ui). See docs/plans/2026-08-28-allowlist-management.md.
	UpsertAllowlistRequest(ctx context.Context, cidr, systemID, reason string, now int64) (distinctSystems int, err error)
	PendingAllowlistRequests(ctx context.Context, limit int) ([]AllowlistRequestRow, error)
	UpsertAllowlistReview(ctx context.Context, cidr, state, decidedBy, note string, now int64) error
	DeleteAllowlistRequests(ctx context.Context, cidr string) (removed int, err error)
	AppendAllowlistAudit(ctx context.Context, cidr, action, actor, detail string, now int64) error
	ListAllowlistAudit(ctx context.Context, limit int) ([]AllowlistAuditRow, error)
}

type SQLiteStore struct {
	db *bun.DB
	mu sync.Mutex
}

func Open(path string) (*SQLiteStore, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", path)
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	sqldb.SetMaxOpenConns(1)

	db := bun.NewDB(sqldb, sqlitedialect.New())
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.DB.Close()
}

func (s *SQLiteStore) Init(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS systems (
			system_id TEXT PRIMARY KEY,
			tenant_id TEXT,
			collector_version TEXT,
			first_seen INTEGER,
			last_seen INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS system_templates (
			system_id TEXT,
			template TEXT,
			module_id TEXT,
			priority INTEGER,
			category TEXT,
			first_seen INTEGER,
			last_seen INTEGER,
			total_count INTEGER,
			PRIMARY KEY (system_id, template)
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
			completed INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_analyses_system_window ON analyses(system_id, window_start)`,

		// --- Threat Shield ---
		//
		// A separate pipeline from everything above: CrowdSec ban decisions in,
		// fleet-consensus blocklist out, no LLM and no fingerprint anywhere in
		// it. attacker_ip is always a normalized netip.Addr.String(), which is
		// what lets a portable TEXT column behave like Postgres INET: text
		// equality is address identity.
		`CREATE TABLE IF NOT EXISTS threat_events (
			id TEXT PRIMARY KEY,
			system_id TEXT,
			attacker_ip TEXT,
			scenario TEXT,
			observed_at INTEGER,
			hit_count INTEGER,
			metadata TEXT
		)`,
		// Redelivery idempotency: a reporter that retries a batch must not be
		// able to inflate hit_count and manufacture its own consensus.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_threat_events_dedup
			ON threat_events(system_id, attacker_ip, scenario, observed_at)`,
		`CREATE INDEX IF NOT EXISTS idx_threat_events_ip ON threat_events(attacker_ip, observed_at)`,
		`CREATE INDEX IF NOT EXISTS idx_threat_events_observed ON threat_events(observed_at)`,
		`CREATE TABLE IF NOT EXISTS threat_blocklist (
			attacker_ip TEXT PRIMARY KEY,
			first_listed_at INTEGER,
			last_seen_at INTEGER,
			expires_at INTEGER,
			distinct_systems INTEGER,
			scenarios TEXT,
			listing_reason TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_threat_blocklist_expires ON threat_blocklist(expires_at)`,
		`CREATE TABLE IF NOT EXISTS threat_allowlist (
			cidr TEXT PRIMARY KEY,
			reason TEXT,
			created_by TEXT,
			created_at INTEGER,
			expires_at INTEGER
		)`,
		// Rolled up before the raw events are pruned, so the long-term trend
		// asset survives the retention window at a few rows per day.
		`CREATE TABLE IF NOT EXISTS threat_daily_stats (
			day TEXT,
			scenario TEXT,
			distinct_ips INTEGER,
			total_hits INTEGER,
			PRIMARY KEY (day, scenario)
		)`,
		// Ingest accounting. Without it, "this node contributes nothing and
		// here is which rule is dropping it" is answerable only from logs.
		`CREATE TABLE IF NOT EXISTS threat_ingest_daily (
			day TEXT,
			system_id TEXT,
			accepted INTEGER,
			duplicates INTEGER,
			dropped_type INTEGER,
			dropped_scope INTEGER,
			dropped_origin INTEGER,
			dropped_bad_ip INTEGER,
			dropped_private_ip INTEGER,
			dropped_time INTEGER,
			truncated INTEGER,
			PRIMARY KEY (day, system_id)
		)`,

		// --- Allowlist management ---
		//
		// threat_allowlist itself (above) is unchanged. These three tables add
		// a client-facing request queue and its audit trail on top of it, with
		// no path from a request to a live entry that does not pass through an
		// explicit admin decision -- see the "no automatic promotion" rule in
		// CLAUDE.md.
		//
		// Requests are append-only per (cidr, system_id): a rejection or an
		// approval never deletes them, so "who asked, and when" survives the
		// decision. The counter that ranks the review queue is
		// COUNT(DISTINCT system_id) over this table, mirroring the blocklist's
		// own distinct-systems rule.
		`CREATE TABLE IF NOT EXISTS threat_allowlist_requests (
			cidr TEXT,
			system_id TEXT,
			reason TEXT,
			created_at INTEGER,
			PRIMARY KEY (cidr, system_id)
		)`,
		// The latest decision for a cidr, and nothing more: state is
		// "approved" or "rejected". It does not gate the pending queue --
		// handling a request deletes the threat_allowlist_requests rows that
		// raised it, so a later ask for the same cidr is reviewed on its own
		// merits instead of being silently swallowed by an old decision.
		// Re-reviewing an already-decided cidr overwrites the row rather than
		// erroring, since an admin may reject and then reconsider.
		`CREATE TABLE IF NOT EXISTS threat_allowlist_reviews (
			cidr TEXT PRIMARY KEY,
			state TEXT,
			decided_by TEXT,
			decided_at INTEGER,
			note TEXT
		)`,
		// Append-only, and deliberately never updated or deleted: DELETE on
		// threat_allowlist removes the very row that would otherwise hold the
		// trail, so without this table "who removed the exemption that let
		// this through" is unanswerable -- which is the question that gets
		// asked.
		`CREATE TABLE IF NOT EXISTS threat_allowlist_audit (
			id TEXT PRIMARY KEY,
			cidr TEXT,
			action TEXT,
			actor TEXT,
			at INTEGER,
			detail TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_allowlist_audit_at ON threat_allowlist_audit(at)`,
	}

	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("store: init: %w", err)
		}
	}
	return nil
}

func (s *SQLiteStore) UpsertSystem(ctx context.Context, sys System) error {
	s.mu.Lock()
	defer s.mu.Unlock()

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

func (s *SQLiteStore) KnownTemplates(ctx context.Context, systemID string) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT template FROM system_templates WHERE system_id = ?`, systemID)
	if err != nil {
		return nil, fmt.Errorf("store: known templates: %w", err)
	}
	defer rows.Close()

	result := map[string]bool{}
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, fmt.Errorf("store: scan template: %w", err)
		}
		result[t] = true
	}
	return result, rows.Err()
}

func (s *SQLiteStore) UpsertTemplates(ctx context.Context, systemID string, ts []model.Template, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

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
			INSERT INTO system_templates (system_id, template, module_id, priority, category, first_seen, last_seen, total_count)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(system_id, template) DO UPDATE SET
				module_id = excluded.module_id,
				priority = excluded.priority,
				category = excluded.category,
				last_seen = excluded.last_seen,
				total_count = system_templates.total_count + excluded.total_count
		`, systemID, t.Template, t.ModuleID, t.Priority, t.Category, firstSeen, lastSeen, t.Count)
		if err != nil {
			return fmt.Errorf("store: upsert template: %w", err)
		}
	}

	return tx.Commit()
}

func (s *SQLiteStore) Baselines(ctx context.Context, systemID string) (map[gate.BaselineKey]float64, error) {
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

func (s *SQLiteStore) UpsertBaselines(ctx context.Context, systemID string, d []model.DigestEntry, alpha float64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

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

func (s *SQLiteStore) BeginAnalysis(ctx context.Context, systemID string, windowStart, windowEnd, now int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

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
func (s *SQLiteStore) RecordAttemptError(ctx context.Context, systemID string, windowStart int64, reasons []string, durationMs int, msg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

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

func (s *SQLiteStore) FinalizeAnalysis(ctx context.Context, a Analysis) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	reasonsJSON, err := json.Marshal(a.GateReasons)
	if err != nil {
		return fmt.Errorf("store: marshal gate reasons: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		UPDATE analyses SET
			gated = ?, gate_reasons = ?, llm_called = ?, input_tokens = ?, output_tokens = ?,
			cost_micros = ?, model = ?, duration_ms = ?, error = ?, completed = 1
		WHERE system_id = ? AND window_start = ?
	`, boolToInt(a.Gated), string(reasonsJSON), boolToInt(a.LLMCalled), a.InputTokens, a.OutputTokens,
		a.CostMicros, a.Model, a.DurationMs, a.Error, a.SystemID, a.WindowStart)
	if err != nil {
		return fmt.Errorf("store: finalize analysis: %w", err)
	}
	return nil
}

func (s *SQLiteStore) OpenFindings(ctx context.Context, systemID string) ([]model.Finding, error) {
	return s.queryFindings(ctx, `SELECT id, system_id, fingerprint, severity, title, summary, suggested_action, modules, evidence, status, occurrence_count, first_seen, last_seen, reopened_at, llm_model, prompt_version FROM findings WHERE system_id = ? AND status = ?`, systemID, model.StatusOpen)
}

func (s *SQLiteStore) UpsertFinding(ctx context.Context, f model.Finding, now int64) (Outcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

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

func (s *SQLiteStore) MarkStale(ctx context.Context, systemID string, olderThan int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

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

func (s *SQLiteStore) ListFindings(ctx context.Context, systemID string, since int64, status string) ([]model.Finding, error) {
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

func (s *SQLiteStore) queryFindings(ctx context.Context, query string, args ...any) ([]model.Finding, error) {
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
