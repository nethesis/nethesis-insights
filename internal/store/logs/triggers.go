// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package logs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"github.com/oklog/ulid/v2"

	"github.com/nethesis/nethesis-insights/internal/model"
)

// Trigger memory: what the analyzer consults between the gate and the LLM
// call. A trigger key (internal/trigger) names the condition the gate saw,
// fleet-wide; this file stores what is known about each one -- where it has
// been seen, when this system last paid for it, and what an operator decided.
//
// None of it reaches the prompt. The prompt is rendered from the bundle and
// the open findings only, so an operator decision can change what is paid
// for and (later) what is delivered, never what the model is told.

const (
	TriggerActive  = "active"
	TriggerIgnored = "ignored"

	// A new trigger is pending review, except a security one, which is
	// delivered without review: a break-in must never wait in a queue.
	VisibilityPending  = "pending"
	VisibilityCustomer = "customer"
	VisibilityOperator = "operator"

	ActionIgnore = "ignore"
)

var (
	ErrUnknownTrigger = errors.New("store: unknown trigger")
	// ErrSecurityTrigger refuses a decision that would silence a security
	// trigger. The analyzer never lets an ignore suppress one either; this
	// is the second lock, on the write side.
	ErrSecurityTrigger = errors.New("store: security triggers cannot be ignored")
	ErrIgnoreExpiry    = errors.New("store: an ignore must expire in the future")
)

// Trigger is one triggers row.
type Trigger struct {
	Key                string
	Security           bool
	Status             string
	IgnoreUntil        int64
	Visibility         string
	SeverityOverride   string
	DocRef             string
	FirstPromptVersion string
	FirstSeen          int64
	LastSeen           int64
	DistinctSystems    int
	Count              int
}

// TriggerLookup is everything the analyzer needs to decide a window, read
// before anything about it is written.
type TriggerLookup struct {
	// Root is the key after alias resolution; every write uses it.
	Root string
	// Known is whether the fleet has seen Root before.
	Known        bool
	Security     bool
	IgnoredUntil int64 // non-zero only while status is ignored

	// SystemSeen is whether this system has a system_triggers row for Root,
	// and LastCalledAt when it last paid an LLM call for it.
	SystemSeen   bool
	LastCalledAt int64

	// LinkedOpen and LinkedNotOpen count this system's findings under Root
	// that the last paid call raised or a reuse has bumped since -- i.e.
	// last_seen >= LastCalledAt. Older findings under the same key belong to
	// an earlier call and say nothing about the current answer.
	LinkedOpen    int
	LinkedNotOpen int
}

// TriggerSighting records one window's encounter with a trigger.
type TriggerSighting struct {
	SystemID      string
	Key           string // TriggerLookup.Root
	Security      bool
	PromptVersion string
	// Called is set when this window paid for an LLM call; only then does
	// last_called_at move, so a reuse can never extend its own window.
	Called bool
	// Reused is set when the window was answered from memory: the findings
	// the last call linked are bumped the way a recurrence would bump them.
	Reused bool
	Now    int64
}

// TriggerDecision is one trigger_decisions row.
type TriggerDecision struct {
	Key           string
	Actor         string
	Action        string
	Detail        string
	PromptVersion string
	CreatedAt     int64
}

// resolveTrigger returns the root key an alias points at, or key itself.
// Aliases always point at a root (merges rewrite them), so one lookup is the
// whole resolution.
func resolveTrigger(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, key string) (string, error) {
	var root string
	err := q.QueryRowContext(ctx, `SELECT canonical_key FROM trigger_aliases WHERE alias_key = ?`, key).Scan(&root)
	if errors.Is(err, sql.ErrNoRows) {
		return key, nil
	}
	if err != nil {
		return "", fmt.Errorf("store: resolve trigger: %w", err)
	}
	return root, nil
}

// LookupTrigger resolves key and reads its fleet-wide and per-system state.
func (s *Store) LookupTrigger(ctx context.Context, systemID, key string) (TriggerLookup, error) {
	root, err := resolveTrigger(ctx, s.db, key)
	if err != nil {
		return TriggerLookup{}, err
	}
	look := TriggerLookup{Root: root}

	var security int
	var status string
	var ignoreUntil sql.NullInt64
	err = s.db.QueryRowContext(ctx,
		`SELECT security, status, ignore_until FROM triggers WHERE trigger_key = ?`, root).
		Scan(&security, &status, &ignoreUntil)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return look, nil
	case err != nil:
		return TriggerLookup{}, fmt.Errorf("store: lookup trigger: %w", err)
	}
	look.Known = true
	look.Security = security != 0
	if status == TriggerIgnored {
		look.IgnoredUntil = ignoreUntil.Int64
	}

	var lastCalled sql.NullInt64
	err = s.db.QueryRowContext(ctx,
		`SELECT last_called_at FROM system_triggers WHERE system_id = ? AND trigger_key = ?`, systemID, root).
		Scan(&lastCalled)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return look, nil
	case err != nil:
		return TriggerLookup{}, fmt.Errorf("store: lookup system trigger: %w", err)
	}
	look.SystemSeen = true
	look.LastCalledAt = lastCalled.Int64

	err = s.db.QueryRowContext(ctx, `
		SELECT count(CASE WHEN status = ? THEN 1 END), count(CASE WHEN status != ? THEN 1 END)
		FROM findings
		WHERE trigger_key = ? AND system_id = ? AND last_seen >= ?
	`, model.StatusOpen, model.StatusOpen, root, systemID, look.LastCalledAt).
		Scan(&look.LinkedOpen, &look.LinkedNotOpen)
	if err != nil {
		return TriggerLookup{}, fmt.Errorf("store: lookup linked findings: %w", err)
	}
	return look, nil
}

// RecordTriggerSighting records one window's encounter with a trigger, in one
// transaction: the fleet-wide row (created on first sight, pending review
// unless it is a security trigger), the per-system row, distinct_systems when
// this system is new to the trigger, and -- for a reuse -- the bump of the
// findings the last call linked.
func (s *Store) RecordTriggerSighting(ctx context.Context, sg TriggerSighting) error {
	s.db.Lock()
	defer s.db.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var one int
	err = tx.QueryRowContext(ctx,
		`SELECT 1 FROM system_triggers WHERE system_id = ? AND trigger_key = ?`, sg.SystemID, sg.Key).Scan(&one)
	newSystem := errors.Is(err, sql.ErrNoRows)
	if err != nil && !newSystem {
		return fmt.Errorf("store: read system trigger: %w", err)
	}

	visibility := VisibilityPending
	if sg.Security {
		visibility = VisibilityCustomer
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO triggers (trigger_key, security, status, visibility, first_prompt_version,
		                      first_seen, last_seen, distinct_systems, count)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)
		ON CONFLICT(trigger_key) DO NOTHING
	`, sg.Key, boolToInt(sg.Security), TriggerActive, visibility, sg.PromptVersion, sg.Now, sg.Now); err != nil {
		return fmt.Errorf("store: insert trigger: %w", err)
	}
	newSystems := 0
	if newSystem {
		newSystems = 1
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE triggers SET
			last_seen = CASE WHEN last_seen < ? THEN ? ELSE last_seen END,
			count = count + 1,
			distinct_systems = distinct_systems + ?
		WHERE trigger_key = ?
	`, sg.Now, sg.Now, newSystems, sg.Key); err != nil {
		return fmt.Errorf("store: update trigger: %w", err)
	}

	if sg.Reused {
		// Bumped before the system row is touched, against the unchanged
		// last_called_at: the same "raised by the last call" set
		// LookupTrigger counted.
		if _, err := tx.ExecContext(ctx, `
			UPDATE findings SET occurrence_count = occurrence_count + 1, last_seen = ?
			WHERE trigger_key = ? AND system_id = ? AND status = ?
			  AND last_seen >= (SELECT coalesce(last_called_at, 0) FROM system_triggers
			                    WHERE system_id = ? AND trigger_key = ?)
		`, sg.Now, sg.Key, sg.SystemID, model.StatusOpen, sg.SystemID, sg.Key); err != nil {
			return fmt.Errorf("store: bump reused findings: %w", err)
		}
	}

	var calledAt sql.NullInt64
	if sg.Called {
		calledAt = sql.NullInt64{Int64: sg.Now, Valid: true}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO system_triggers (system_id, trigger_key, first_seen, last_seen, last_called_at, count)
		VALUES (?, ?, ?, ?, ?, 1)
		ON CONFLICT(system_id, trigger_key) DO UPDATE SET
			last_seen = excluded.last_seen,
			last_called_at = coalesce(excluded.last_called_at, system_triggers.last_called_at),
			count = system_triggers.count + 1
	`, sg.SystemID, sg.Key, sg.Now, sg.Now, calledAt); err != nil {
		return fmt.Errorf("store: upsert system trigger: %w", err)
	}

	return tx.Commit()
}

// IgnoreTrigger stops paying for a trigger fleet-wide until `until`, and
// appends the decision to the audit trail in the same transaction -- an
// ignore with no record of who made it is the one outcome this must not
// allow. A security trigger is refused, and so is an expiry that is not in
// the future: an ignore always ends.
func (s *Store) IgnoreTrigger(ctx context.Context, key string, until int64, actor string, now int64) error {
	s.db.Lock()
	defer s.db.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	root, err := resolveTrigger(ctx, tx, key)
	if err != nil {
		return err
	}
	var security int
	var promptVersion sql.NullString
	err = tx.QueryRowContext(ctx,
		`SELECT security, first_prompt_version FROM triggers WHERE trigger_key = ?`, root).
		Scan(&security, &promptVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnknownTrigger
	}
	if err != nil {
		return fmt.Errorf("store: read trigger: %w", err)
	}
	if security != 0 {
		return ErrSecurityTrigger
	}
	if until <= now {
		return ErrIgnoreExpiry
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE triggers SET status = ?, ignore_until = ? WHERE trigger_key = ?`,
		TriggerIgnored, until, root); err != nil {
		return fmt.Errorf("store: ignore trigger: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO trigger_decisions (id, trigger_key, actor, action, detail, prompt_version, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, ulid.Make().String(), root, actor, ActionIgnore, strconv.FormatInt(until, 10),
		promptVersion.String, now); err != nil {
		return fmt.Errorf("store: record trigger decision: %w", err)
	}
	return tx.Commit()
}

// GetTrigger reads one triggers row by its exact key (no alias resolution).
func (s *Store) GetTrigger(ctx context.Context, key string) (Trigger, bool, error) {
	var t Trigger
	var security int
	var ignoreUntil sql.NullInt64
	var severity, docRef, promptVersion sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT trigger_key, security, status, ignore_until, visibility, severity_override, doc_ref,
		       first_prompt_version, first_seen, last_seen, distinct_systems, count
		FROM triggers WHERE trigger_key = ?
	`, key).Scan(&t.Key, &security, &t.Status, &ignoreUntil, &t.Visibility, &severity, &docRef,
		&promptVersion, &t.FirstSeen, &t.LastSeen, &t.DistinctSystems, &t.Count)
	if errors.Is(err, sql.ErrNoRows) {
		return Trigger{}, false, nil
	}
	if err != nil {
		return Trigger{}, false, fmt.Errorf("store: get trigger: %w", err)
	}
	t.Security = security != 0
	t.IgnoreUntil = ignoreUntil.Int64
	t.SeverityOverride = severity.String
	t.DocRef = docRef.String
	t.FirstPromptVersion = promptVersion.String
	return t, true, nil
}

// TriggerDecisions returns a trigger's audit trail, oldest first.
func (s *Store) TriggerDecisions(ctx context.Context, key string) ([]TriggerDecision, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT trigger_key, actor, action, detail, prompt_version, created_at
		FROM trigger_decisions WHERE trigger_key = ? ORDER BY created_at, id
	`, key)
	if err != nil {
		return nil, fmt.Errorf("store: trigger decisions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []TriggerDecision
	for rows.Next() {
		var d TriggerDecision
		var detail, promptVersion sql.NullString
		if err := rows.Scan(&d.Key, &d.Actor, &d.Action, &detail, &promptVersion, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scan trigger decision: %w", err)
		}
		d.Detail = detail.String
		d.PromptVersion = promptVersion.String
		out = append(out, d)
	}
	return out, rows.Err()
}

// nullIfEmpty stores an empty string as NULL, so "no value" has one spelling.
func nullIfEmpty(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}
