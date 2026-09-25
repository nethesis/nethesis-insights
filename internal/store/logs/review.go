// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package logs

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// The operator review reads: the trigger queue behind ui/logs' /review, the
// per-prompt-version statistics behind /review/stats, and the decision trail
// behind /review/audit. The writes are in triggers.go.

// reviewTitles bounds how many distinct finding titles a review row shows.
// The titles are what an operator actually recognises a trigger by -- the
// key is a hash -- but a trigger raised on forty systems can carry forty
// wordings of one problem.
const reviewTitles = 3

// TriggerFilter selects ListTriggers' rows. Visibility "" means every
// visibility; Key is a LIKE prefix, as on the findings page.
type TriggerFilter struct {
	Visibility string
	Key        string
	Limit      int
}

// TriggerRow is one root trigger as the review page shows it.
type TriggerRow struct {
	Trigger
	// Aliases counts the keys merged into this one.
	Aliases int
	// Findings counts findings under this trigger or any key merged into
	// it, fleet-wide; Titles holds up to reviewTitles of their distinct
	// titles, most recently seen first.
	Findings int
	Titles   []string
	// GateReasons are the reasons of the most recent analyses row for this
	// trigger: what made the gate fire, which the key itself cannot say.
	// Empty once every such row is past ANALYSIS_RETENTION.
	GateReasons []string
}

// ListTriggers returns root triggers -- never a key merged into another --
// ranked the way the review queue wants them: the trigger seen on the most
// systems first, then the most often seen. Bounded by f.Limit.
func (s *Store) ListTriggers(ctx context.Context, f TriggerFilter) ([]TriggerRow, error) {
	keyPattern := likePattern(f.Key)
	rows, err := s.db.QueryContext(ctx, `
		SELECT t.trigger_key, t.security, t.status, t.ignore_until, t.visibility, t.severity_override, t.doc_ref,
		       t.first_prompt_version, t.first_seen, t.last_seen, t.distinct_systems, t.count,
		       (SELECT count(*) FROM trigger_aliases a WHERE a.canonical_key = t.trigger_key),
		       (SELECT an.gate_reasons FROM analyses an WHERE an.trigger_key = t.trigger_key
		        ORDER BY an.created_at DESC LIMIT 1)
		FROM triggers t
		WHERE NOT EXISTS (SELECT 1 FROM trigger_aliases x WHERE x.alias_key = t.trigger_key)
		  AND (? = '' OR t.visibility = ?)
		  AND (? = '' OR t.trigger_key LIKE ?)
		ORDER BY t.distinct_systems DESC, t.count DESC, t.last_seen DESC, t.trigger_key
		LIMIT ?
	`, f.Visibility, f.Visibility, f.Key, keyPattern, clampLimit(f.Limit))
	if err != nil {
		return nil, fmt.Errorf("store: list triggers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []TriggerRow{}
	for rows.Next() {
		var r TriggerRow
		var security int
		var ignoreUntil sql.NullInt64
		var severity, docRef, promptVersion, reasons sql.NullString
		if err := rows.Scan(&r.Key, &security, &r.Status, &ignoreUntil, &r.Visibility, &severity, &docRef,
			&promptVersion, &r.FirstSeen, &r.LastSeen, &r.DistinctSystems, &r.Count,
			&r.Aliases, &reasons); err != nil {
			return nil, fmt.Errorf("store: scan trigger: %w", err)
		}
		r.Security = security != 0
		r.IgnoreUntil = ignoreUntil.Int64
		r.SeverityOverride = severity.String
		r.DocRef = docRef.String
		r.FirstPromptVersion = promptVersion.String
		r.GateReasons = normalizeGateReasons(reasons.String)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list triggers: %w", err)
	}
	if err := s.attachTitles(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

// attachTitles fills Findings and Titles for rows in one query, resolving
// each finding's key through the aliases so a merged key's findings count
// towards its root.
func (s *Store) attachTitles(ctx context.Context, rows []TriggerRow) error {
	if len(rows) == 0 {
		return nil
	}
	index := make(map[string]*TriggerRow, len(rows))
	args := make([]any, 0, 2*len(rows))
	for i := range rows {
		index[rows[i].Key] = &rows[i]
		args = append(args, rows[i].Key)
	}
	args = append(args, args...)
	in := strings.TrimSuffix(strings.Repeat("?,", len(rows)), ",")

	// The IN lists are built from placeholders only, never from values.
	res, err := s.db.QueryContext(ctx, `
		SELECT coalesce(a.canonical_key, f.trigger_key) AS root, f.title, count(*), max(f.last_seen) AS seen
		FROM findings f
		LEFT JOIN trigger_aliases a ON a.alias_key = f.trigger_key
		WHERE f.trigger_key IN (`+in+`) OR a.canonical_key IN (`+in+`)
		GROUP BY root, f.title
		ORDER BY root, seen DESC, f.title
	`, args...) // #nosec G202 -- only "?" placeholders are concatenated
	if err != nil {
		return fmt.Errorf("store: trigger titles: %w", err)
	}
	defer func() { _ = res.Close() }()

	for res.Next() {
		var root, title string
		var n int
		var seen int64
		if err := res.Scan(&root, &title, &n, &seen); err != nil {
			return fmt.Errorf("store: scan trigger title: %w", err)
		}
		r := index[root]
		if r == nil {
			continue
		}
		r.Findings += n
		if len(r.Titles) < reviewTitles {
			r.Titles = append(r.Titles, title)
		}
	}
	return res.Err()
}

// TriggerStatsRow is /review/stats' row: what one prompt.Version raised and
// what operators made of it. Pending, Delivered, Internal, Merged and
// Security partition Triggers -- a security trigger is delivered without
// review, so it says nothing about operator judgement and is counted apart.
// Ignored overlaps them: it counts triggers ever ignored, whatever their
// visibility.
type TriggerStatsRow struct {
	PromptVersion string
	Triggers      int
	Security      int
	Pending       int
	Delivered     int
	Internal      int
	Merged        int
	Ignored       int
}

// TriggerStats groups the retained triggers by the prompt version that
// first raised them, newest version first. Undecided triggers are pruned
// past TEMPLATE_RETENTION, so old versions lose their pending rows first.
func (s *Store) TriggerStats(ctx context.Context) ([]TriggerStatsRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT coalesce(t.first_prompt_version, ''),
		       count(*),
		       sum(t.security),
		       sum(CASE WHEN m.alias_key IS NULL AND t.security = 0 AND t.visibility = ? THEN 1 ELSE 0 END),
		       sum(CASE WHEN m.alias_key IS NULL AND t.security = 0 AND t.visibility = ? THEN 1 ELSE 0 END),
		       sum(CASE WHEN m.alias_key IS NULL AND t.security = 0 AND t.visibility = ? THEN 1 ELSE 0 END),
		       sum(CASE WHEN m.alias_key IS NOT NULL THEN 1 ELSE 0 END),
		       sum(CASE WHEN EXISTS (SELECT 1 FROM trigger_decisions d
		                             WHERE d.trigger_key = t.trigger_key AND d.action = ?) THEN 1 ELSE 0 END)
		FROM triggers t
		LEFT JOIN trigger_aliases m ON m.alias_key = t.trigger_key
		GROUP BY 1
		ORDER BY max(t.first_seen) DESC
	`, VisibilityPending, VisibilityCustomer, VisibilityOperator, ActionIgnore)
	if err != nil {
		return nil, fmt.Errorf("store: trigger stats: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []TriggerStatsRow{}
	for rows.Next() {
		var r TriggerStatsRow
		if err := rows.Scan(&r.PromptVersion, &r.Triggers, &r.Security, &r.Pending, &r.Delivered,
			&r.Internal, &r.Merged, &r.Ignored); err != nil {
			return nil, fmt.Errorf("store: scan trigger stats: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListTriggerDecisions returns the decision trail across every trigger,
// newest first, bounded by limit.
func (s *Store) ListTriggerDecisions(ctx context.Context, limit int) ([]TriggerDecision, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT trigger_key, actor, action, detail, prompt_version, created_at
		FROM trigger_decisions ORDER BY created_at DESC, id DESC LIMIT ?
	`, clampLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("store: list trigger decisions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanDecisions(rows)
}

// scanDecisions reads trigger_decisions rows in the column order both
// decision queries select.
func scanDecisions(rows *sql.Rows) ([]TriggerDecision, error) {
	out := []TriggerDecision{}
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
