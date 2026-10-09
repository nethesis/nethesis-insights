// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package logs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/oklog/ulid/v2"
	"github.com/uptrace/bun"

	"github.com/nethesis/nethesis-insights/internal/grouping"
)

// Review grouping: class_groups holds, per embedded finding class, the anchor
// it was grouped under and its embedding. Only the grouping pass writes it
// (SetClassGroup); a suggestion never changes a decision on its own -- the
// only writer of finding_classes from here is SetGroupVisibility, called by
// an operator POST.

// ClassEvidence is what the grouping pass embeds for one class: the modules
// and cited evidence of its latest finding. No model-authored text.
type ClassEvidence struct {
	Key      string
	Modules  []string
	Evidence []string
}

// ClassGroup is one class_groups row.
type ClassGroup struct {
	Key, Anchor           string
	Similarity, Threshold float64
	Model                 string
	Vector                []float32
	At                    int64
}

// UngroupedClasses returns up to limit classes with no class_groups row for
// model (none at all, or one recorded under another model), oldest first_seen
// first, with the modules and evidence of each class's latest finding (max
// last_seen, tiebreak id -- the one ListClasses shows). Classes with no
// retained finding are skipped: there is nothing to embed.
func (s *Store) UngroupedClasses(ctx context.Context, model string, limit int) ([]ClassEvidence, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT class_key, modules, evidence FROM (
			SELECT c.class_key, c.first_seen, f.modules, f.evidence,
			       ROW_NUMBER() OVER (PARTITION BY c.class_key ORDER BY f.last_seen DESC, f.id) AS rn
			FROM finding_classes c
			JOIN findings f ON f.class_key = c.class_key
			WHERE NOT EXISTS (SELECT 1 FROM class_groups g WHERE g.class_key = c.class_key AND g.model = ?)
		) WHERE rn = 1
		ORDER BY first_seen, class_key
		LIMIT ?
	`, model, limit)
	if err != nil {
		return nil, fmt.Errorf("store: ungrouped classes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []ClassEvidence{}
	for rows.Next() {
		var e ClassEvidence
		var modulesJSON, evidenceJSON string
		if err := rows.Scan(&e.Key, &modulesJSON, &evidenceJSON); err != nil {
			return nil, fmt.Errorf("store: scan ungrouped class: %w", err)
		}
		if err := json.Unmarshal([]byte(modulesJSON), &e.Modules); err != nil {
			return nil, fmt.Errorf("store: unmarshal class modules: %w", err)
		}
		if err := json.Unmarshal([]byte(evidenceJSON), &e.Evidence); err != nil {
			return nil, fmt.Errorf("store: unmarshal class evidence: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: ungrouped classes: %w", err)
	}
	return out, nil
}

// GroupAnchors returns every anchor row (anchor_key = class_key) recorded
// under model. Vectors of another model are never returned.
func (s *Store) GroupAnchors(ctx context.Context, model string) ([]grouping.Anchor, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT class_key, vector FROM class_groups
		WHERE model = ? AND anchor_key = class_key ORDER BY created_at, class_key
	`, model)
	if err != nil {
		return nil, fmt.Errorf("store: group anchors: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []grouping.Anchor{}
	for rows.Next() {
		var a grouping.Anchor
		var vec string
		if err := rows.Scan(&a.Key, &vec); err != nil {
			return nil, fmt.Errorf("store: scan group anchor: %w", err)
		}
		if err := json.Unmarshal([]byte(vec), &a.Vector); err != nil {
			return nil, fmt.Errorf("store: unmarshal anchor vector: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: group anchors: %w", err)
	}
	return out, nil
}

// SetClassGroup upserts one class_groups row under the write lock. It never
// touches finding_classes or class_decisions.
func (s *Store) SetClassGroup(ctx context.Context, g ClassGroup) error {
	vec, err := json.Marshal(g.Vector)
	if err != nil {
		return fmt.Errorf("store: marshal class vector: %w", err)
	}
	s.db.Lock()
	defer s.db.Unlock()
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO class_groups (class_key, anchor_key, similarity, threshold, model, vector, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(class_key) DO UPDATE SET
			anchor_key = excluded.anchor_key,
			similarity = excluded.similarity,
			threshold = excluded.threshold,
			model = excluded.model,
			vector = excluded.vector,
			created_at = excluded.created_at
	`, g.Key, g.Anchor, g.Similarity, g.Threshold, g.Model, string(vec), g.At); err != nil {
		return fmt.Errorf("store: set class group: %w", err)
	}
	return nil
}

// SetGroupVisibility applies visibility to every pending class of the group
// anchored at anchor, in one transaction, with one class_decisions row per
// class changed (the same actions as SetClassVisibility, detail "group
// <anchor>"). Classes already decided are left alone. It returns how many
// classes changed; a group with none pending changes nothing and writes no
// audit row. ErrUnknownClass if anchor has no group row.
func (s *Store) SetGroupVisibility(ctx context.Context, anchor, visibility, actor string, now int64) (int, error) {
	action, ok := visibilityAction(visibility)
	if !ok {
		return 0, ErrInvalidVisibility
	}
	s.db.Lock()
	defer s.db.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var one int
	err = tx.QueryRowContext(ctx,
		`SELECT 1 FROM class_groups WHERE anchor_key = ? LIMIT 1`, anchor).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrUnknownClass
	}
	if err != nil {
		return 0, fmt.Errorf("store: read class group: %w", err)
	}

	todo, err := pendingGroupClasses(ctx, tx, anchor)
	if err != nil {
		return 0, err
	}

	for _, p := range todo {
		if _, err := tx.ExecContext(ctx,
			`UPDATE finding_classes SET visibility = ? WHERE class_key = ?`, visibility, p.key); err != nil {
			return 0, fmt.Errorf("store: set class visibility: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO class_decisions (id, class_key, actor, action, detail, prompt_version, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, ulid.Make().String(), p.key, actor, action, "group "+anchor, p.pv.String, now); err != nil {
			return 0, fmt.Errorf("store: record class decision: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit group decision: %w", err)
	}
	return len(todo), nil
}

// attachGroups fills the Group* and Suggestion* fields of rows in two bounded
// queries: the rows' own group rows, then the anchors' per-visibility class
// counts. Membership is read whatever model recorded it; only the pass
// filters by model.
func (s *Store) attachGroups(ctx context.Context, rows []ClassRow) error {
	if len(rows) == 0 {
		return nil
	}
	args := make([]any, 0, len(rows))
	index := make(map[string]*ClassRow, len(rows))
	for i := range rows {
		index[rows[i].Key] = &rows[i]
		args = append(args, rows[i].Key)
	}
	in := strings.TrimSuffix(strings.Repeat("?,", len(rows)), ",")

	gr, err := s.db.QueryContext(ctx,
		`SELECT class_key, anchor_key, similarity FROM class_groups WHERE class_key IN (`+in+`)`,
		args...) // #nosec G202 -- only "?" placeholders are concatenated
	if err != nil {
		return fmt.Errorf("store: class groups: %w", err)
	}
	defer func() { _ = gr.Close() }()
	anchorSet := map[string]bool{}
	for gr.Next() {
		var key, anchor string
		var sim float64
		if err := gr.Scan(&key, &anchor, &sim); err != nil {
			return fmt.Errorf("store: scan class group: %w", err)
		}
		if r := index[key]; r != nil {
			r.GroupAnchor = anchor
			r.GroupSimilarity = sim
			anchorSet[anchor] = true
		}
	}
	if err := gr.Err(); err != nil {
		return fmt.Errorf("store: class groups: %w", err)
	}
	if len(anchorSet) == 0 {
		return nil
	}

	anchorArgs := make([]any, 0, len(anchorSet))
	for a := range anchorSet {
		anchorArgs = append(anchorArgs, a)
	}
	ain := strings.TrimSuffix(strings.Repeat("?,", len(anchorArgs)), ",")
	cr, err := s.db.QueryContext(ctx, `
		SELECT g.anchor_key, c.visibility, count(*)
		FROM class_groups g JOIN finding_classes c ON c.class_key = g.class_key
		WHERE g.anchor_key IN (`+ain+`)
		GROUP BY g.anchor_key, c.visibility
	`, anchorArgs...) // #nosec G202 -- only "?" placeholders are concatenated
	if err != nil {
		return fmt.Errorf("store: group sizes: %w", err)
	}
	defer func() { _ = cr.Close() }()
	type tally struct {
		size int
		by   map[string]int
	}
	tallies := map[string]*tally{}
	for cr.Next() {
		var anchor, vis string
		var n int
		if err := cr.Scan(&anchor, &vis, &n); err != nil {
			return fmt.Errorf("store: scan group size: %w", err)
		}
		t := tallies[anchor]
		if t == nil {
			t = &tally{by: map[string]int{}}
			tallies[anchor] = t
		}
		t.size += n
		t.by[vis] += n
	}
	if err := cr.Err(); err != nil {
		return fmt.Errorf("store: group sizes: %w", err)
	}

	for i := range rows {
		r := &rows[i]
		t := tallies[r.GroupAnchor]
		if r.GroupAnchor == "" || t == nil {
			continue
		}
		r.GroupSize = t.size
		if r.Visibility != VisibilityPending {
			continue
		}
		vis := make([]string, 0, len(t.by))
		for v := range t.by {
			vis = append(vis, v)
		}
		if sug, ok := grouping.Suggest(vis); ok {
			r.Suggestion = sug
			r.SuggestionVotes = t.by[sug]
		}
	}
	return nil
}

type pendingClass struct {
	key string
	pv  sql.NullString
}

// pendingGroupClasses lists the group's classes still awaiting a decision.
func pendingGroupClasses(ctx context.Context, tx bun.Tx, anchor string) ([]pendingClass, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT c.class_key, c.first_prompt_version
		FROM class_groups g JOIN finding_classes c ON c.class_key = g.class_key
		WHERE g.anchor_key = ? AND c.visibility = ?
		ORDER BY c.class_key
	`, anchor, VisibilityPending)
	if err != nil {
		return nil, fmt.Errorf("store: group pending classes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []pendingClass
	for rows.Next() {
		var p pendingClass
		if err := rows.Scan(&p.key, &p.pv); err != nil {
			return nil, fmt.Errorf("store: scan group class: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
