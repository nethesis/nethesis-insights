// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package logs

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// The operator review reads: the class queue behind ui/logs' /review, the
// per-prompt-version statistics behind /review/stats, and the decision trail
// behind /review/audit. The writes are in classes.go.

// reviewTitles bounds how many distinct finding titles a review row shows.
// The titles are what an operator actually recognises a class by -- the key
// is a hash -- but a class raised on forty systems can carry forty wordings
// of one problem.
const reviewTitles = 3

// ClassFilter selects ListClasses' rows. Visibility "" means every
// visibility; Key is a LIKE prefix, as on the findings page.
type ClassFilter struct {
	Visibility string
	Key        string
	Limit      int
}

// ClassRow is one class as the review queue shows it. The key is a hash, so
// what an operator recognises it by is what the model wrote: up to
// reviewTitles distinct titles across systems, and the latest finding's
// summary, suggested action, modules and evidence.
type ClassRow struct {
	Class
	Systems         int
	Findings        int
	Titles          []string
	Summary         string
	SuggestedAction string
	Modules         []string
	Evidence        []string
}

// ListClasses returns classes ranked the way the review queue wants them:
// the class raised on the most systems first, then the one with the most
// findings. Counts are derived from findings rather than stored, so they
// cannot drift from what is actually retained.
func (s *Store) ListClasses(ctx context.Context, f ClassFilter) ([]ClassRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT c.class_key, c.visibility, c.security, c.severity_override, c.doc_ref,
		       c.first_prompt_version, c.first_seen, c.last_seen,
		       (SELECT count(DISTINCT x.system_id) FROM findings x WHERE x.class_key = c.class_key) AS systems,
		       (SELECT count(*) FROM findings x WHERE x.class_key = c.class_key) AS findings
		FROM finding_classes c
		WHERE (? = '' OR c.visibility = ?)
		  AND (? = '' OR c.class_key LIKE ?)
		ORDER BY systems DESC, findings DESC, c.last_seen DESC, c.class_key
		LIMIT ?
	`, f.Visibility, f.Visibility, f.Key, likePattern(f.Key), clampLimit(f.Limit))
	if err != nil {
		return nil, fmt.Errorf("store: list classes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []ClassRow{}
	for rows.Next() {
		var r ClassRow
		var security int
		var severity, docRef, promptVersion sql.NullString
		if err := rows.Scan(&r.Key, &r.Visibility, &security, &severity, &docRef,
			&promptVersion, &r.FirstSeen, &r.LastSeen, &r.Systems, &r.Findings); err != nil {
			return nil, fmt.Errorf("store: scan class: %w", err)
		}
		r.Security = security != 0
		r.SeverityOverride = severity.String
		r.DocRef = docRef.String
		r.FirstPromptVersion = promptVersion.String
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list classes: %w", err)
	}
	if err := s.attachClassDetails(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

// attachClassDetails fills Titles, Summary, SuggestedAction, Modules and
// Evidence for rows in one query: up to reviewTitles distinct titles across
// systems, most recently seen first, and the rest from the most recently
// seen finding in the class.
func (s *Store) attachClassDetails(ctx context.Context, rows []ClassRow) error {
	if len(rows) == 0 {
		return nil
	}
	index := make(map[string]*ClassRow, len(rows))
	args := make([]any, 0, len(rows))
	for i := range rows {
		index[rows[i].Key] = &rows[i]
		args = append(args, rows[i].Key)
	}
	in := strings.TrimSuffix(strings.Repeat("?,", len(rows)), ",")

	// The IN list is built from placeholders only, never from values.
	res, err := s.db.QueryContext(ctx, `
		SELECT class_key, title, summary, suggested_action, modules, evidence
		FROM findings WHERE class_key IN (`+in+`) ORDER BY class_key, last_seen DESC, id
	`, args...) // #nosec G202 -- only "?" placeholders are concatenated
	if err != nil {
		return fmt.Errorf("store: class details: %w", err)
	}
	defer func() { _ = res.Close() }()

	filled := map[string]bool{}
	for res.Next() {
		var key, title, summary, suggestedAction, modulesJSON, evidenceJSON string
		if err := res.Scan(&key, &title, &summary, &suggestedAction, &modulesJSON, &evidenceJSON); err != nil {
			return fmt.Errorf("store: scan class detail: %w", err)
		}
		r := index[key]
		if r == nil {
			continue
		}
		if !filled[key] {
			r.Summary = summary
			r.SuggestedAction = suggestedAction
			if err := json.Unmarshal([]byte(modulesJSON), &r.Modules); err != nil {
				return fmt.Errorf("store: unmarshal class modules: %w", err)
			}
			if err := json.Unmarshal([]byte(evidenceJSON), &r.Evidence); err != nil {
				return fmt.Errorf("store: unmarshal class evidence: %w", err)
			}
			filled[key] = true
		}
		found := false
		for _, t := range r.Titles {
			if t == title {
				found = true
				break
			}
		}
		if !found && len(r.Titles) < reviewTitles {
			r.Titles = append(r.Titles, title)
		}
	}
	return res.Err()
}

// ClassStatsRow is /review/stats' row: what one prompt.Version raised and
// what operators made of it. Pending, Delivered and Internal partition
// Classes. Security overlaps them: it counts classes tagged security,
// whatever their visibility.
type ClassStatsRow struct {
	PromptVersion string
	Classes       int
	Pending       int
	Delivered     int
	Internal      int
	Security      int
}

// ClassStats groups the retained classes by the prompt version that first
// raised them, newest version first.
func (s *Store) ClassStats(ctx context.Context) ([]ClassStatsRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT coalesce(first_prompt_version, ''), count(*),
		       sum(CASE WHEN visibility = ? THEN 1 ELSE 0 END),
		       sum(CASE WHEN visibility = ? THEN 1 ELSE 0 END),
		       sum(CASE WHEN visibility = ? THEN 1 ELSE 0 END),
		       sum(security)
		FROM finding_classes GROUP BY 1 ORDER BY max(first_seen) DESC
	`, VisibilityPending, VisibilityCustomer, VisibilityOperator)
	if err != nil {
		return nil, fmt.Errorf("store: class stats: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []ClassStatsRow{}
	for rows.Next() {
		var r ClassStatsRow
		if err := rows.Scan(&r.PromptVersion, &r.Classes, &r.Pending, &r.Delivered, &r.Internal, &r.Security); err != nil {
			return nil, fmt.Errorf("store: scan class stats: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListClassDecisions returns the decision trail across every class, newest
// first, bounded by limit.
func (s *Store) ListClassDecisions(ctx context.Context, limit int) ([]ClassDecision, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT class_key, actor, action, detail, prompt_version, created_at
		FROM class_decisions ORDER BY created_at DESC, id DESC LIMIT ?
	`, clampLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("store: list class decisions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanClassDecisions(rows)
}
