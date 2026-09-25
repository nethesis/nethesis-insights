// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package logs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/nethesis/nethesis-insights/internal/model"
)

// Trigger memory: what the analyzer consults between the gate and the LLM
// call. A trigger key (internal/trigger) names the condition the gate saw,
// per system; this file stores what this system last paid for it and what
// its last paid call raised, so an unchanged condition is answered from
// memory instead of paid for again.
//
// Nothing an operator decides lives here any more -- that is finding_classes
// (see classes.go). A trigger key is per-system reuse memory only: it never
// reaches the prompt, and no decision is ever recorded against it.

// TriggerLookup is everything the analyzer needs to decide a window, read
// before anything about it is written.
type TriggerLookup struct {
	// SystemSeen is whether this system has a system_triggers row for key,
	// and LastCalledAt when it last paid an LLM call for it.
	SystemSeen   bool
	LastCalledAt int64

	// LinkedOpen and LinkedNotOpen count this system's findings under key
	// that the last paid call raised or a reuse has bumped since -- i.e.
	// last_seen >= LastCalledAt. Older findings under the same key belong to
	// an earlier call and say nothing about the current answer.
	LinkedOpen    int
	LinkedNotOpen int
}

// TriggerSighting records one window's encounter with a trigger.
type TriggerSighting struct {
	SystemID string
	Key      string
	// Called is set when this window paid for an LLM call; only then does
	// last_called_at move, so a reuse can never extend its own window.
	Called bool
	// Reused is set when the window was answered from memory: the findings
	// the last call linked are bumped the way a recurrence would bump them.
	Reused bool
	Now    int64
}

// LookupTrigger reads a system's per-trigger state directly -- no alias
// resolution, no fleet-wide row: those belonged to the operator decisions
// this file no longer keeps.
func (s *Store) LookupTrigger(ctx context.Context, systemID, key string) (TriggerLookup, error) {
	var look TriggerLookup

	var lastCalled sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT last_called_at FROM system_triggers WHERE system_id = ? AND trigger_key = ?`, systemID, key).
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
	`, model.StatusOpen, model.StatusOpen, key, systemID, look.LastCalledAt).
		Scan(&look.LinkedOpen, &look.LinkedNotOpen)
	if err != nil {
		return TriggerLookup{}, fmt.Errorf("store: lookup linked findings: %w", err)
	}
	return look, nil
}

// RecordTriggerSighting records one window's encounter with a trigger: the
// per-system row, and -- for a reuse -- the bump of the findings the last
// call linked.
func (s *Store) RecordTriggerSighting(ctx context.Context, sg TriggerSighting) error {
	s.db.Lock()
	defer s.db.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

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

// nullIfEmpty stores an empty string as NULL, so "no value" has one spelling.
func nullIfEmpty(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}
