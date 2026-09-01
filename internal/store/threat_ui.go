// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// Threat Shield cross-system reads for the operator UI, split out of
// threat.go for the same reason ui.go is split out of store.go: none of these
// take the write mutex, every one is bounded, and none of them is on the
// ingest or consensus path.

// ListBlocklistEntries returns the promoted entries including expired ones
// not yet swept, newest listing first -- the operator wants to see what just
// happened, whereas the feed wants a stable order.
func (s *SQLiteStore) ListBlocklistEntries(ctx context.Context, limit int) ([]BlocklistRow, error) {
	return s.queryBlocklist(ctx, `
		SELECT attacker_ip, first_listed_at, last_seen_at, expires_at,
		       distinct_systems, scenarios, listing_reason
		FROM threat_blocklist
		ORDER BY last_seen_at DESC, attacker_ip
		LIMIT ?
	`, clampLimit(limit))
}

// ListThreatEvents returns recent sanitized events, optionally filtered by
// system and by attacker address -- the "who reported this IP" question.
func (s *SQLiteStore) ListThreatEvents(ctx context.Context, systemID, attackerIP string, limit int) ([]ThreatEventRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, system_id, attacker_ip, scenario, observed_at, hit_count, metadata
		FROM threat_events
		WHERE (? = '' OR system_id = ?)
		  AND (? = '' OR attacker_ip = ?)
		ORDER BY observed_at DESC
		LIMIT ?
	`, systemID, systemID, attackerIP, attackerIP, clampLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("store: list threat events: %w", err)
	}
	defer rows.Close()

	result := []ThreatEventRow{}
	for rows.Next() {
		var (
			r        ThreatEventRow
			metadata sql.NullString
		)
		if err := rows.Scan(&r.ID, &r.SystemID, &r.AttackerIP, &r.Scenario,
			&r.ObservedAt, &r.HitCount, &metadata); err != nil {
			return nil, fmt.Errorf("store: scan threat event: %w", err)
		}
		if metadata.Valid && metadata.String != "" {
			_ = json.Unmarshal([]byte(metadata.String), &r.Metadata)
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// ThreatDailyStats returns the day/scenario rollup, newest day first.
func (s *SQLiteStore) ThreatDailyStats(ctx context.Context, limit int) ([]ThreatDailyRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT day, scenario, distinct_ips, total_hits
		FROM threat_daily_stats
		ORDER BY day DESC, scenario
		LIMIT ?
	`, clampLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("store: threat daily stats: %w", err)
	}
	defer rows.Close()

	result := []ThreatDailyRow{}
	for rows.Next() {
		var r ThreatDailyRow
		if err := rows.Scan(&r.Day, &r.Scenario, &r.DistinctIPs, &r.TotalHits); err != nil {
			return nil, fmt.Errorf("store: scan threat daily stats: %w", err)
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// ThreatIngestStats returns the per-day, per-system ingest accounting --
// what each node contributed and, more usefully, what was dropped and why.
func (s *SQLiteStore) ThreatIngestStats(ctx context.Context, limit int) ([]ThreatIngestRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT day, system_id, accepted, duplicates,
		       dropped_type, dropped_scope, dropped_origin, dropped_bad_ip,
		       dropped_private_ip, dropped_time, truncated
		FROM threat_ingest_daily
		ORDER BY day DESC, system_id
		LIMIT ?
	`, clampLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("store: threat ingest stats: %w", err)
	}
	defer rows.Close()

	result := []ThreatIngestRow{}
	for rows.Next() {
		var r ThreatIngestRow
		if err := rows.Scan(&r.Day, &r.SystemID, &r.Accepted, &r.Duplicates,
			&r.DroppedType, &r.DroppedScope, &r.DroppedOrigin, &r.DroppedBadIP,
			&r.DroppedPrivateIP, &r.DroppedTime, &r.Truncated); err != nil {
			return nil, fmt.Errorf("store: scan threat ingest stats: %w", err)
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// ThreatSystemRow is one system's aggregate contribution to Threat Shield --
// the blocklist pipeline's counterpart to store.SystemRow, which aggregates
// the log pipeline instead.
type ThreatSystemRow struct {
	SystemID          string
	FirstDay, LastDay string
	Accepted          int
	Duplicates        int
	Dropped           int
	Truncated         int
	Events            int
	DistinctIPs       int
	DistinctScenarios int
	TotalHits         int64
	LastEventAt       *int64
}

// ListThreatSystems aggregates per system_id across both Threat Shield
// tables. threat_ingest_daily is the driving table -- RecordIngestCounters
// (internal/api/threat.go) writes one row there for every POST
// /v1/threat-events regardless of outcome, so it is the complete set of
// systems that have ever reported, including ones whose every event was
// dropped or duplicate and therefore never made it into threat_events.
func (s *SQLiteStore) ListThreatSystems(ctx context.Context) ([]ThreatSystemRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		WITH ingest AS (
			SELECT system_id,
			       min(day) AS first_day, max(day) AS last_day,
			       sum(accepted) AS accepted, sum(duplicates) AS duplicates,
			       sum(dropped_type + dropped_scope + dropped_origin + dropped_bad_ip
			           + dropped_private_ip + dropped_time) AS dropped,
			       sum(truncated) AS truncated
			FROM threat_ingest_daily
			GROUP BY system_id
		), events AS (
			SELECT system_id,
			       count(*) AS events,
			       count(DISTINCT attacker_ip) AS distinct_ips,
			       count(DISTINCT scenario) AS distinct_scenarios,
			       coalesce(sum(hit_count), 0) AS total_hits,
			       max(observed_at) AS last_event_at
			FROM threat_events
			GROUP BY system_id
		)
		SELECT i.system_id, i.first_day, i.last_day, i.accepted, i.duplicates, i.dropped, i.truncated,
		       coalesce(e.events, 0), coalesce(e.distinct_ips, 0), coalesce(e.distinct_scenarios, 0),
		       coalesce(e.total_hits, 0), e.last_event_at
		FROM ingest i
		LEFT JOIN events e ON e.system_id = i.system_id
		ORDER BY i.last_day DESC, i.system_id
	`)
	if err != nil {
		return nil, fmt.Errorf("store: list threat systems: %w", err)
	}
	defer rows.Close()

	result := []ThreatSystemRow{}
	for rows.Next() {
		var r ThreatSystemRow
		var lastEventAt sql.NullInt64
		if err := rows.Scan(&r.SystemID, &r.FirstDay, &r.LastDay, &r.Accepted, &r.Duplicates, &r.Dropped, &r.Truncated,
			&r.Events, &r.DistinctIPs, &r.DistinctScenarios, &r.TotalHits, &lastEventAt); err != nil {
			return nil, fmt.Errorf("store: scan threat system row: %w", err)
		}
		if lastEventAt.Valid {
			v := lastEventAt.Int64
			r.LastEventAt = &v
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// ListThreatAllowlist returns every allowlist entry, expired ones included:
// "this used to be excluded and no longer is" is a question the operator page
// has to be able to answer.
func (s *SQLiteStore) ListThreatAllowlist(ctx context.Context) ([]AllowlistRow, error) {
	return s.queryAllowlist(ctx, `
		SELECT cidr, reason, created_by, created_at, expires_at
		FROM threat_allowlist
		ORDER BY cidr
	`)
}
