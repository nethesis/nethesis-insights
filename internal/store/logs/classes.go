// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package logs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/oklog/ulid/v2"
	"github.com/uptrace/bun"

	"github.com/nethesis/nethesis-insights/internal/model"
)

// Finding classes: what an operator reviews. A class (fingerprint.Class) is
// a finding's identity without its system, so one decision covers the same
// conclusion on every system that raises it, now and later. The review state
// lives here and is joined at read time; nothing is copied onto findings.
//
// None of it reaches the prompt: OpenFindings does not join finding_classes.

const (
	// A new class is pending review; its findings are withheld from the
	// customer until an operator delivers it. Security classes too.
	VisibilityPending  = "pending"
	VisibilityCustomer = "customer"
	VisibilityOperator = "operator"
	// A dismissed class is hidden from every view, customer and operator
	// alike. Hidden, not dropped: its findings still upsert on recurrence and
	// OpenFindings still returns them, so the prompt keeps listing them as
	// known and the model does not re-raise them on every paid call.
	VisibilityDismissed = "dismissed"

	// The class_decisions actions, one per operator decision.
	ActionDeliver  = "deliver"
	ActionInternal = "internal"
	ActionDismiss  = "dismiss"
	ActionSecurity = "security"
	ActionSeverity = "severity"
	ActionDocRef   = "doc_ref"
)

var (
	ErrUnknownClass      = errors.New("store: unknown finding class")
	ErrInvalidSeverity   = errors.New("store: unknown severity")
	ErrInvalidVisibility = errors.New("store: visibility must be customer, operator or dismissed")
)

// Class is one finding_classes row.
type Class struct {
	Key                string
	Visibility         string
	Security           bool
	SeverityOverride   string
	DocRef             string
	FirstPromptVersion string
	FirstSeen          int64
	LastSeen           int64
}

// ClassDecision is one class_decisions row.
type ClassDecision struct {
	Key           string
	Actor         string
	Action        string
	Detail        string
	PromptVersion string
	CreatedAt     int64
}

// classDecision is the shape every review decision shares: refuse an unknown
// class, apply the change, append the audit row -- one transaction, because
// a changed class with no record of who changed it is the one outcome this
// must not allow.
func (s *Store) classDecision(ctx context.Context, key, actor, action string, now int64,
	apply func(tx bun.Tx) (detail string, err error)) error {
	s.db.Lock()
	defer s.db.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var pv sql.NullString
	err = tx.QueryRowContext(ctx,
		`SELECT first_prompt_version FROM finding_classes WHERE class_key = ?`, key).Scan(&pv)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnknownClass
	}
	if err != nil {
		return fmt.Errorf("store: read finding class: %w", err)
	}
	detail, err := apply(tx)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO class_decisions (id, class_key, actor, action, detail, prompt_version, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, ulid.Make().String(), key, actor, action, nullIfEmpty(detail), pv.String, now); err != nil {
		return fmt.Errorf("store: record class decision: %w", err)
	}
	return tx.Commit()
}

// visibilityAction maps a decidable visibility to its class_decisions action.
func visibilityAction(visibility string) (string, bool) {
	switch visibility {
	case VisibilityCustomer:
		return ActionDeliver, true
	case VisibilityOperator:
		return ActionInternal, true
	case VisibilityDismissed:
		return ActionDismiss, true
	}
	return "", false
}

// SetClassVisibility decides whether a class's findings reach the customer
// (VisibilityCustomer, "deliver"), stay on the operator UI
// (VisibilityOperator, "internal") or leave every view (VisibilityDismissed,
// "dismiss"). Never back to pending: a decision can be changed, not taken
// back, so a dismissal is undone by delivering or keeping the class internal.
func (s *Store) SetClassVisibility(ctx context.Context, key, visibility, actor string, now int64) error {
	action, ok := visibilityAction(visibility)
	if !ok {
		return ErrInvalidVisibility
	}
	return s.classDecision(ctx, key, actor, action, now, func(tx bun.Tx) (string, error) {
		if _, err := tx.ExecContext(ctx,
			`UPDATE finding_classes SET visibility = ? WHERE class_key = ?`, visibility, key); err != nil {
			return "", fmt.Errorf("store: set class visibility: %w", err)
		}
		return "", nil
	})
}

// SetClassSecurity sets the security tag the customer reads. The edge's
// classification seeds it when the class is first seen; from then on it is
// the operator's, and a recurrence never resets it.
func (s *Store) SetClassSecurity(ctx context.Context, key string, security bool, actor string, now int64) error {
	return s.classDecision(ctx, key, actor, ActionSecurity, now, func(tx bun.Tx) (string, error) {
		if _, err := tx.ExecContext(ctx,
			`UPDATE finding_classes SET security = ? WHERE class_key = ?`, boolToInt(security), key); err != nil {
			return "", fmt.Errorf("store: set class security: %w", err)
		}
		if security {
			return "on", nil
		}
		return "off", nil
	})
}

// SetClassSeverity overrides the severity the customer reads for every
// finding in the class; "" clears it. Applied in ListFindings only, never
// written into findings.severity, which prompt.Render prints.
func (s *Store) SetClassSeverity(ctx context.Context, key, severity, actor string, now int64) error {
	if severity != "" && !model.ValidSeverity(severity) {
		return ErrInvalidSeverity
	}
	return s.classDecision(ctx, key, actor, ActionSeverity, now, func(tx bun.Tx) (string, error) {
		if _, err := tx.ExecContext(ctx,
			`UPDATE finding_classes SET severity_override = ? WHERE class_key = ?`, nullIfEmpty(severity), key); err != nil {
			return "", fmt.Errorf("store: set class severity: %w", err)
		}
		return severity, nil
	})
}

// SetClassDocRef points every finding in the class at remediation
// documentation; "" clears it. The caller validates the value (the operator
// UI accepts only an http(s) URL).
func (s *Store) SetClassDocRef(ctx context.Context, key, docRef, actor string, now int64) error {
	return s.classDecision(ctx, key, actor, ActionDocRef, now, func(tx bun.Tx) (string, error) {
		if _, err := tx.ExecContext(ctx,
			`UPDATE finding_classes SET doc_ref = ? WHERE class_key = ?`, nullIfEmpty(docRef), key); err != nil {
			return "", fmt.Errorf("store: set class doc_ref: %w", err)
		}
		return docRef, nil
	})
}

// ClassUpdate is a class's whole decidable state, as the review dialog's one
// form posts it.
type ClassUpdate struct {
	// Visibility is VisibilityCustomer, VisibilityOperator or
	// VisibilityDismissed; "" leaves it as it is (a pending class the
	// operator has not decided yet).
	Visibility       string
	Security         bool
	SeverityOverride string // "" is the AI's severity
	DocRef           string // "" is none
}

// UpdateClass applies a ClassUpdate in one transaction, compared against the
// stored row: only the fields that differ change, each with its own
// class_decisions row under the same action as the single-field methods
// above, in a fixed order (visibility, security, severity, doc_ref). It
// returns how many changed; nothing changed records nothing.
func (s *Store) UpdateClass(ctx context.Context, key string, u ClassUpdate, actor string, now int64) (int, error) {
	visAction := ""
	if u.Visibility != "" {
		var ok bool
		if visAction, ok = visibilityAction(u.Visibility); !ok {
			return 0, ErrInvalidVisibility
		}
	}
	if u.SeverityOverride != "" && !model.ValidSeverity(u.SeverityOverride) {
		return 0, ErrInvalidSeverity
	}

	s.db.Lock()
	defer s.db.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var cur Class
	var security int
	var severity, docRef, pv sql.NullString
	err = tx.QueryRowContext(ctx, `
		SELECT visibility, security, severity_override, doc_ref, first_prompt_version
		FROM finding_classes WHERE class_key = ?
	`, key).Scan(&cur.Visibility, &security, &severity, &docRef, &pv)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrUnknownClass
	}
	if err != nil {
		return 0, fmt.Errorf("store: read finding class: %w", err)
	}

	type change struct {
		column, action, detail string
		value                  any
	}
	var changes []change
	if u.Visibility != "" && u.Visibility != cur.Visibility {
		changes = append(changes, change{"visibility", visAction, "", u.Visibility})
	}
	if u.Security != (security != 0) {
		detail := "off"
		if u.Security {
			detail = "on"
		}
		changes = append(changes, change{"security", ActionSecurity, detail, boolToInt(u.Security)})
	}
	if u.SeverityOverride != severity.String {
		changes = append(changes, change{"severity_override", ActionSeverity, u.SeverityOverride, nullIfEmpty(u.SeverityOverride)})
	}
	if u.DocRef != docRef.String {
		changes = append(changes, change{"doc_ref", ActionDocRef, u.DocRef, nullIfEmpty(u.DocRef)})
	}

	for _, c := range changes {
		// c.column is one of the four literals above, never request input.
		if _, err := tx.ExecContext(ctx,
			`UPDATE finding_classes SET `+c.column+` = ? WHERE class_key = ?`, c.value, key); err != nil { // #nosec G202
			return 0, fmt.Errorf("store: set class %s: %w", c.column, err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO class_decisions (id, class_key, actor, action, detail, prompt_version, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, ulid.Make().String(), key, actor, c.action, nullIfEmpty(c.detail), pv.String, now); err != nil {
			return 0, fmt.Errorf("store: record class decision: %w", err)
		}
	}
	if len(changes) == 0 {
		return 0, nil
	}
	return len(changes), tx.Commit()
}

// GetClass reads one finding_classes row.
func (s *Store) GetClass(ctx context.Context, key string) (Class, bool, error) {
	var c Class
	var security int
	var severity, docRef, pv sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT class_key, visibility, security, severity_override, doc_ref, first_prompt_version, first_seen, last_seen
		FROM finding_classes WHERE class_key = ?
	`, key).Scan(&c.Key, &c.Visibility, &security, &severity, &docRef, &pv, &c.FirstSeen, &c.LastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return Class{}, false, nil
	}
	if err != nil {
		return Class{}, false, fmt.Errorf("store: get finding class: %w", err)
	}
	c.Security = security != 0
	c.SeverityOverride = severity.String
	c.DocRef = docRef.String
	c.FirstPromptVersion = pv.String
	return c, true, nil
}

// ClassDecisions returns a class's audit trail, oldest first.
func (s *Store) ClassDecisions(ctx context.Context, key string) ([]ClassDecision, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT class_key, actor, action, detail, prompt_version, created_at
		FROM class_decisions WHERE class_key = ? ORDER BY created_at, id
	`, key)
	if err != nil {
		return nil, fmt.Errorf("store: class decisions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanClassDecisions(rows)
}

// scanClassDecisions reads class_decisions rows in the column order every
// decision query selects.
func scanClassDecisions(rows *sql.Rows) ([]ClassDecision, error) {
	out := []ClassDecision{}
	for rows.Next() {
		var d ClassDecision
		var detail, pv sql.NullString
		if err := rows.Scan(&d.Key, &d.Actor, &d.Action, &detail, &pv, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scan class decision: %w", err)
		}
		d.Detail = detail.String
		d.PromptVersion = pv.String
		out = append(out, d)
	}
	return out, rows.Err()
}

// nullIfEmpty stores an empty string as NULL, so "no value" has one spelling.
func nullIfEmpty(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}
