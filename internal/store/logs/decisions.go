// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package logs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/oklog/ulid/v2"
	"github.com/uptrace/bun"

	"github.com/nethesis/nethesis-insights/internal/decide"
)

// Automatic review decisions: the pass in internal/classdecide asks the
// Decisions API about pending classes and applies a confident answer. The
// only writes to finding_classes from here are pending-guarded -- an
// operator's decision always wins the race -- and every one leaves a
// class_decisions row with an automatic actor.
const (
	ActorDecisionsAPI = "decisions-api"
	ActorSecurityRule = "security-rule"

	AskApplied = "applied"
	AskUnsure  = "unsure"
	AskFailed  = "failed"
	AskLate    = "late"
)

// IsAutomaticActor reports whether actor is one of the automatic deciders.
func IsAutomaticActor(actor string) bool {
	return actor == ActorDecisionsAPI || actor == ActorSecurityRule
}

// lastVisibilityActor is a correlated subquery over an outer finding_classes
// row aliased c: the actor of the class's newest visibility decision, or NULL
// when it has none.
const lastVisibilityActor = `(SELECT d.actor FROM class_decisions d
	WHERE d.class_key = c.class_key AND d.action IN ('deliver', 'internal', 'dismiss')
	ORDER BY d.created_at DESC, d.id DESC LIMIT 1)`

// DecisionCandidate is a pending class to ask about. Vector is nil when the
// class is not embedded under the requested embedding model.
type DecisionCandidate struct {
	Key    string
	Class  decide.Class
	Vector []float32
}

// DecisionAsk is one call to the Decisions API and its outcome.
type DecisionAsk struct {
	Key, RulesVersion, Model, Result, Choice string
	Confidence                               float64
	Usage                                    decide.Usage
	CostMicros                               int64
	Detail                                   string
	At                                       int64
}

// PendingSecurityClasses lists the pending classes tagged security.
func (s *Store) PendingSecurityClasses(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT class_key FROM finding_classes
		WHERE visibility = ? AND security = 1 ORDER BY first_seen, class_key
	`, VisibilityPending)
	if err != nil {
		return nil, fmt.Errorf("store: pending security classes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []string{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, fmt.Errorf("store: scan security class: %w", err)
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: pending security classes: %w", err)
	}
	return out, nil
}

type classDescription struct {
	key        string
	visibility string
	class      decide.Class
}

// describedClasses returns the classes matching where (over finding_classes
// aliased c; args are its binds), each described by its latest retained
// finding (max last_seen, tiebreak id) and its class wording, oldest
// first_seen first. Classes with no retained finding are skipped.
func (s *Store) describedClasses(ctx context.Context, where string, args []any, limit int) ([]classDescription, error) {
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, `
		SELECT class_key, visibility, modules, evidence, title, summary FROM (
			SELECT c.class_key, c.visibility, c.first_seen, f.modules, f.evidence,
			       coalesce(nullif(t.title_override, ''), t.title, '') AS title,
			       coalesce(nullif(t.summary_override, ''), t.summary, '') AS summary,
			       ROW_NUMBER() OVER (PARTITION BY c.class_key ORDER BY f.last_seen DESC, f.id) AS rn
			FROM finding_classes c
			JOIN findings f ON f.class_key = c.class_key
			LEFT JOIN class_texts t ON t.class_key = c.class_key
			WHERE `+where+`
		) WHERE rn = 1
		ORDER BY first_seen, class_key
		LIMIT ?
	`, args...) // #nosec G202 -- where is built from constants in this file
	if err != nil {
		return nil, fmt.Errorf("store: described classes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []classDescription{}
	for rows.Next() {
		var d classDescription
		var modulesJSON, evidenceJSON, title, summary string
		if err := rows.Scan(&d.key, &d.visibility, &modulesJSON, &evidenceJSON, &title, &summary); err != nil {
			return nil, fmt.Errorf("store: scan described class: %w", err)
		}
		var modules, evidence []string
		if err := json.Unmarshal([]byte(modulesJSON), &modules); err != nil {
			return nil, fmt.Errorf("store: unmarshal class modules: %w", err)
		}
		if err := json.Unmarshal([]byte(evidenceJSON), &evidence); err != nil {
			return nil, fmt.Errorf("store: unmarshal class evidence: %w", err)
		}
		d.class = decide.Describe(modules, evidence, title, summary)
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: described classes: %w", err)
	}
	return out, nil
}

// classVectors reads the vectors recorded under embedModel for keys.
func (s *Store) classVectors(ctx context.Context, embedModel string, where string, args []any) (map[string][]float32, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT g.class_key, g.vector FROM class_groups g WHERE g.model = ?`+where,
		append([]any{embedModel}, args...)...) // #nosec G202 -- where is built from constants in this file
	if err != nil {
		return nil, fmt.Errorf("store: class vectors: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string][]float32{}
	for rows.Next() {
		var key, vec string
		if err := rows.Scan(&key, &vec); err != nil {
			return nil, fmt.Errorf("store: scan class vector: %w", err)
		}
		var v []float32
		if err := json.Unmarshal([]byte(vec), &v); err != nil {
			return nil, fmt.Errorf("store: unmarshal class vector: %w", err)
		}
		out[key] = v
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: class vectors: %w", err)
	}
	return out, nil
}

// DecisionCandidates returns up to limit pending, non-security classes with a
// retained finding and no ask recorded under (rulesVersion, model), oldest
// first_seen first. Vector is set only from a class_groups row recorded under
// embedModel; with embedModel "" vectors are not read.
func (s *Store) DecisionCandidates(ctx context.Context, rulesVersion, model, embedModel string, limit int) ([]DecisionCandidate, error) {
	ds, err := s.describedClasses(ctx, `c.visibility = ? AND c.security = 0
		AND NOT EXISTS (SELECT 1 FROM class_decision_asks a
			WHERE a.class_key = c.class_key AND a.rules_version = ? AND a.model = ?)`,
		[]any{VisibilityPending, rulesVersion, model}, limit)
	if err != nil {
		return nil, err
	}
	var vecs map[string][]float32
	if embedModel != "" && len(ds) > 0 {
		vecs, err = s.classVectors(ctx, embedModel, ` AND g.class_key IN (SELECT class_key FROM finding_classes WHERE visibility = ? AND security = 0)`, []any{VisibilityPending})
		if err != nil {
			return nil, err
		}
	}
	out := make([]DecisionCandidate, 0, len(ds))
	for _, d := range ds {
		out = append(out, DecisionCandidate{Key: d.key, Class: d.class, Vector: vecs[d.key]})
	}
	return out, nil
}

// DecisionPrecedents returns the decided classes whose latest visibility
// decision was made by a person and that are embedded under embedModel, each
// carrying its current visibility as the Decision. embedModel "" yields nil.
func (s *Store) DecisionPrecedents(ctx context.Context, embedModel string) ([]decide.Candidate, error) {
	if embedModel == "" {
		return nil, nil
	}
	vecs, err := s.classVectors(ctx, embedModel, "", nil)
	if err != nil {
		return nil, err
	}
	ds, err := s.describedClasses(ctx, `c.visibility <> ?
		AND coalesce(`+lastVisibilityActor+`, '') NOT IN (?, ?)
		AND c.class_key IN (SELECT class_key FROM class_groups WHERE model = ?)`,
		[]any{VisibilityPending, ActorDecisionsAPI, ActorSecurityRule, embedModel}, -1)
	if err != nil {
		return nil, err
	}
	out := make([]decide.Candidate, 0, len(ds))
	for _, d := range ds {
		out = append(out, decide.Candidate{Class: d.class, Decision: d.visibility, Vector: vecs[d.key]})
	}
	return out, nil
}

// RecordDecisionAsk stores an ask. An applied answer first decides the class,
// but only if it is still pending: when an operator got there first the ask is
// stored as AskLate and nothing else changes. All in one transaction; it
// returns the result actually stored.
func (s *Store) RecordDecisionAsk(ctx context.Context, a DecisionAsk) (string, error) {
	result := a.Result
	s.db.Lock()
	defer s.db.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("store: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if result == AskApplied {
		action, ok := visibilityAction(a.Choice)
		if !ok {
			return "", ErrInvalidVisibility
		}
		applied, err := decidePending(ctx, tx, a.Key, a.Choice, action, a.Detail, ActorDecisionsAPI, a.At)
		if err != nil {
			return "", err
		}
		if !applied {
			result = AskLate
		}
	}

	var choice any
	if a.Choice != "" {
		choice = a.Choice
	}
	var confidence any
	if a.Result != AskFailed {
		confidence = a.Confidence
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO class_decision_asks (id, class_key, rules_version, model, result, choice, confidence,
			input_tokens, cached_tokens, output_tokens, cost_micros, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, ulid.Make().String(), a.Key, a.RulesVersion, a.Model, result, choice, confidence,
		a.Usage.InputTokens, a.Usage.CachedTokens, a.Usage.OutputTokens, a.CostMicros, a.At); err != nil {
		return "", fmt.Errorf("store: record decision ask: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("store: commit decision ask: %w", err)
	}
	return result, nil
}

// DeliverSecurityClass delivers a pending class to the customer under the
// security rule. false if it is no longer pending (or unknown).
func (s *Store) DeliverSecurityClass(ctx context.Context, key string, now int64) (bool, error) {
	s.db.Lock()
	defer s.db.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("store: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	ok, err := decidePending(ctx, tx, key, VisibilityCustomer, ActionDeliver, "security tag", ActorSecurityRule, now)
	if err != nil || !ok {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("store: commit security delivery: %w", err)
	}
	return true, nil
}

// decidePending sets visibility only while the class is still pending and,
// when it was, appends the class_decisions row.
func decidePending(ctx context.Context, tx bun.Tx, key, visibility, action, detail, actor string, now int64) (bool, error) {
	var pv sql.NullString
	err := tx.QueryRowContext(ctx,
		`SELECT first_prompt_version FROM finding_classes WHERE class_key = ? AND visibility = ?`,
		key, VisibilityPending).Scan(&pv)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: read pending class: %w", err)
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE finding_classes SET visibility = ? WHERE class_key = ? AND visibility = ?`,
		visibility, key, VisibilityPending)
	if err != nil {
		return false, fmt.Errorf("store: set class visibility: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return false, err
	}
	if err := insertClassDecision(ctx, tx, key, pv, actor, action, detail, now); err != nil {
		return false, err
	}
	return true, nil
}
