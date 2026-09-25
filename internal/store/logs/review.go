// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package logs

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nethesis/nethesis-insights/internal/model"
)

// The operator review reads: the class queue behind ui/logs' /review, the
// per-prompt-version statistics behind /review/stats, and the decision trail
// behind /review/audit. The writes are in classes.go.

// reviewTitles bounds how many distinct finding titles a review row shows.
// The titles are what an operator actually recognises a class by -- the key
// is a hash -- but a class raised on forty systems can carry forty wordings
// of one problem.
const reviewTitles = 3

// severityRankSQL is a SQL CASE ranking findings.severity the same way
// model.SeverityRank does -- critical first -- built from model.Severities
// rather than spelled out a second time, so the SQL ranking and the Go one
// cannot drift apart. A severity outside model.Severities ranks last.
var severityRankSQL = buildSeverityRankSQL()

func buildSeverityRankSQL() string {
	var b strings.Builder
	b.WriteString("CASE severity")
	for i, sev := range model.Severities {
		fmt.Fprintf(&b, " WHEN '%s' THEN %d", sev, i)
	}
	fmt.Fprintf(&b, " ELSE %d END", len(model.Severities))
	return b.String()
}

// ClassFilter selects ListClasses' rows. Visibility "" means every
// visibility; Key is a LIKE prefix, as on the findings page.
type ClassFilter struct {
	Visibility string
	Key        string
	Limit      int
}

// ClassRow is one class as the review queue shows it. The key is a hash, so
// what an operator recognises it by is what the model wrote: up to
// reviewTitles distinct titles across systems, the most severe stored
// severity across the class's findings (never the model's wording -- the
// class carries no free-text severity of its own), and the latest finding's
// summary, suggested action, modules and evidence.
type ClassRow struct {
	Class
	Systems         int
	Findings        int
	Titles          []string
	Severity        string
	Summary         string
	SuggestedAction string
	Modules         []string
	Evidence        []string
}

// ListClasses returns classes ranked the way the review queue wants them:
// pending classes first -- an operator reviewing "all" must not have to
// scroll past already-decided classes to find the one still waiting -- then
// the class raised on the most systems, then the one with the most findings.
// Counts are derived from findings rather than stored, so they cannot drift
// from what is actually retained.
func (s *Store) ListClasses(ctx context.Context, f ClassFilter) ([]ClassRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT c.class_key, c.visibility, c.security, c.severity_override, c.doc_ref,
		       c.first_prompt_version, c.first_seen, c.last_seen,
		       (SELECT count(DISTINCT x.system_id) FROM findings x WHERE x.class_key = c.class_key) AS systems,
		       (SELECT count(*) FROM findings x WHERE x.class_key = c.class_key) AS findings
		FROM finding_classes c
		WHERE (? = '' OR c.visibility = ?)
		  AND (? = '' OR c.class_key LIKE ?)
		ORDER BY (c.visibility = ?) DESC, systems DESC, findings DESC, c.last_seen DESC, c.class_key
		LIMIT ?
	`, f.Visibility, f.Visibility, f.Key, likePattern(f.Key), VisibilityPending, clampLimit(f.Limit))
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

// attachClassDetails fills Titles, Severity, Summary, SuggestedAction,
// Modules and Evidence for rows in two bounded queries -- never one row per
// finding, which at fleet scale is ~100k rows for 200 classes:
//
//   - titles: one row per distinct (class_key, title), aggregated in SQL,
//     most recently seen first.
//   - detail: one row per class_key (a window function partitioned on it),
//     carrying the latest finding's summary/suggested_action/modules/evidence
//     and the whole class's most severe stored severity -- a window
//     aggregate sees every partitioned row, not just the one ROW_NUMBER
//     keeps, so both come out of a single pass.
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
	titleRows, err := s.db.QueryContext(ctx, `
		SELECT class_key, title, max(last_seen) AS ls
		FROM findings WHERE class_key IN (`+in+`)
		GROUP BY class_key, title
		ORDER BY class_key, ls DESC, title
	`, args...) // #nosec G202 -- only "?" placeholders are concatenated
	if err != nil {
		return fmt.Errorf("store: class titles: %w", err)
	}
	defer func() { _ = titleRows.Close() }()

	for titleRows.Next() {
		var key, title string
		var lastSeen int64
		if err := titleRows.Scan(&key, &title, &lastSeen); err != nil {
			return fmt.Errorf("store: scan class title: %w", err)
		}
		r := index[key]
		if r == nil || len(r.Titles) >= reviewTitles {
			continue
		}
		r.Titles = append(r.Titles, title)
	}
	if err := titleRows.Err(); err != nil {
		return fmt.Errorf("store: class titles: %w", err)
	}

	detailRows, err := s.db.QueryContext(ctx, `
		SELECT class_key, summary, suggested_action, modules, evidence, best_rank
		FROM (
			SELECT class_key, summary, suggested_action, modules, evidence,
			       ROW_NUMBER() OVER (PARTITION BY class_key ORDER BY last_seen DESC, id) AS rn,
			       MIN(`+severityRankSQL+`) OVER (PARTITION BY class_key) AS best_rank
			FROM findings WHERE class_key IN (`+in+`)
		) WHERE rn = 1
	`, args...) // #nosec G202 -- only "?" placeholders are concatenated
	if err != nil {
		return fmt.Errorf("store: class details: %w", err)
	}
	defer func() { _ = detailRows.Close() }()

	for detailRows.Next() {
		var key, summary, suggestedAction, modulesJSON, evidenceJSON string
		var bestRank int
		if err := detailRows.Scan(&key, &summary, &suggestedAction, &modulesJSON, &evidenceJSON, &bestRank); err != nil {
			return fmt.Errorf("store: scan class detail: %w", err)
		}
		r := index[key]
		if r == nil {
			continue
		}
		r.Summary = summary
		r.SuggestedAction = suggestedAction
		if bestRank >= 0 && bestRank < len(model.Severities) {
			r.Severity = model.Severities[bestRank]
		}
		if err := json.Unmarshal([]byte(modulesJSON), &r.Modules); err != nil {
			return fmt.Errorf("store: unmarshal class modules: %w", err)
		}
		if err := json.Unmarshal([]byte(evidenceJSON), &r.Evidence); err != nil {
			return fmt.Errorf("store: unmarshal class evidence: %w", err)
		}
	}
	return detailRows.Err()
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
