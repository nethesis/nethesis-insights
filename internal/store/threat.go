// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/oklog/ulid/v2"
)

// Threat Shield storage: ingest, consensus inputs, the promoted blocklist and
// the rollups that outlive the raw events. Write methods take the same mutex
// as the rest of the store; read methods do not.

// ThreatEventRow is one stored threat_events row.
type ThreatEventRow struct {
	ID, SystemID, AttackerIP, Scenario string
	ObservedAt                         int64
	HitCount                           int64
	Metadata                           map[string]any
}

// ThreatCandidateRow is one (attacker_ip, scenario, system_id) group inside
// the consensus window.
//
// The grouping goes all the way down to system_id deliberately. The obvious
// query -- COUNT(DISTINCT system_id) per (ip, scenario) -- cannot answer
// "how many distinct systems reported this IP at all", because per-scenario
// counts do not sum: one system reporting an IP under two scenarios would
// count twice. Aggregating the scenario list in SQL instead would need
// ARRAY_AGG / GROUP_CONCAT / STRING_AGG, none of which are portable across
// SQLite and Postgres. So the triples come back and Go folds them.
type ThreatCandidateRow struct {
	AttackerIP, Scenario, SystemID string
	Hits                           int64
	LastSeen                       int64
}

// ListingReason is the promotion evidence snapshotted into the blocklist row.
//
// Raw events expire after THREAT_EVENT_RETENTION; without this snapshot,
// "why is this IP listed?" becomes unanswerable a week later -- and that
// question gets asked by whoever's customer just got blocked.
type ListingReason struct {
	Systems       int      `json:"systems"`
	Hits          int64    `json:"hits"`
	Scenarios     []string `json:"scenarios"`
	WindowMinutes int      `json:"window_minutes"`
	MinSystems    int      `json:"min_systems"`
	Rule          string   `json:"rule"`
	DecidedAt     int64    `json:"decided_at"`
}

// BlocklistRow is one promoted entry.
type BlocklistRow struct {
	AttackerIP                           string
	FirstListedAt, LastSeenAt, ExpiresAt int64
	DistinctSystems                      int
	Scenarios                            []string
	Reason                               ListingReason
}

// AllowlistRow is one threat_allowlist row. ExpiresAt is nil for a permanent
// entry.
type AllowlistRow struct {
	CIDR, Reason, CreatedBy string
	CreatedAt               int64
	ExpiresAt               *int64
}

// EgressRow is one observed reporter source address.
type EgressRow struct {
	SystemID, SourceIP string
	UpdatedAt          int64
}

// ThreatDailyRow is one day/scenario rollup.
type ThreatDailyRow struct {
	Day, Scenario string
	DistinctIPs   int
	TotalHits     int64
}

// ThreatIngestRow is one day/system ingest accounting row.
type ThreatIngestRow struct {
	Day, SystemID string
	Accepted      int
	Duplicates    int
	model.ThreatCounters
}

// DayString formats a unix-millis instant as the UTC day key used by the
// rollup tables. Day bucketing is integer division on the millis column and
// formatting in Go, never a SQL date function -- SQLite and Postgres do not
// share one.
func DayString(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02")
}

// InsertThreatEvents stores a sanitized batch in one transaction.
//
// ON CONFLICT DO NOTHING against the (system_id, attacker_ip, scenario,
// observed_at) unique index is what makes redelivery safe: a reporter that
// retries cannot inflate hit_count, and therefore cannot manufacture its own
// contribution to consensus. Duplicates are counted, not hidden -- an edge
// retrying constantly is worth seeing in the operator UI.
func (s *SQLiteStore) InsertThreatEvents(ctx context.Context, systemID string, ev []model.ThreatEvent) (int, int, error) {
	if len(ev) == 0 {
		return 0, 0, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("store: insert threat events: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var inserted, duplicates int
	for _, e := range ev {
		metadata, err := json.Marshal(e.Metadata)
		if err != nil {
			return 0, 0, fmt.Errorf("store: marshal threat metadata: %w", err)
		}
		res, err := tx.ExecContext(ctx, `
			INSERT INTO threat_events (id, system_id, attacker_ip, scenario, observed_at, hit_count, metadata)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(system_id, attacker_ip, scenario, observed_at) DO NOTHING
		`, ulid.Make().String(), systemID, e.AttackerIP, e.Scenario, e.ObservedAt, e.HitCount, string(metadata))
		if err != nil {
			return 0, 0, fmt.Errorf("store: insert threat event: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, 0, fmt.Errorf("store: insert threat event rows: %w", err)
		}
		if n > 0 {
			inserted++
		} else {
			duplicates++
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("store: commit threat events: %w", err)
	}
	return inserted, duplicates, nil
}

// RecordSystemEgress remembers the address a reporter was last seen from.
// The union of these is an automatic promotion exclusion (spec §6).
func (s *SQLiteStore) RecordSystemEgress(ctx context.Context, systemID, sourceIP string, now int64) error {
	if systemID == "" || sourceIP == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO system_egress (system_id, source_ip, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(system_id) DO UPDATE SET
			source_ip = excluded.source_ip,
			updated_at = excluded.updated_at
	`, systemID, sourceIP, now)
	if err != nil {
		return fmt.Errorf("store: record system egress: %w", err)
	}
	return nil
}

// RecordIngestCounters accumulates one request's outcome into the day's row
// for that system.
func (s *SQLiteStore) RecordIngestCounters(ctx context.Context, day, systemID string, c model.ThreatCounters, duplicates int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO threat_ingest_daily (day, system_id, accepted, duplicates,
			dropped_type, dropped_scope, dropped_origin, dropped_bad_ip,
			dropped_private_ip, dropped_time, truncated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(day, system_id) DO UPDATE SET
			accepted = threat_ingest_daily.accepted + excluded.accepted,
			duplicates = threat_ingest_daily.duplicates + excluded.duplicates,
			dropped_type = threat_ingest_daily.dropped_type + excluded.dropped_type,
			dropped_scope = threat_ingest_daily.dropped_scope + excluded.dropped_scope,
			dropped_origin = threat_ingest_daily.dropped_origin + excluded.dropped_origin,
			dropped_bad_ip = threat_ingest_daily.dropped_bad_ip + excluded.dropped_bad_ip,
			dropped_private_ip = threat_ingest_daily.dropped_private_ip + excluded.dropped_private_ip,
			dropped_time = threat_ingest_daily.dropped_time + excluded.dropped_time,
			truncated = threat_ingest_daily.truncated + excluded.truncated
	`, day, systemID, c.Accepted, duplicates,
		c.DroppedType, c.DroppedScope, c.DroppedOrigin, c.DroppedBadIP,
		c.DroppedPrivateIP, c.DroppedTime, c.Truncated)
	if err != nil {
		return fmt.Errorf("store: record ingest counters: %w", err)
	}
	return nil
}

// ConsensusCandidates returns every (attacker_ip, scenario, system_id) triple
// observed since the given instant. See ThreatCandidateRow for why the
// grouping goes down to system_id.
func (s *SQLiteStore) ConsensusCandidates(ctx context.Context, since int64) ([]ThreatCandidateRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT attacker_ip, scenario, system_id, SUM(hit_count), MAX(observed_at)
		FROM threat_events
		WHERE observed_at >= ?
		GROUP BY attacker_ip, scenario, system_id
		ORDER BY attacker_ip, scenario, system_id
	`, since)
	if err != nil {
		return nil, fmt.Errorf("store: consensus candidates: %w", err)
	}
	defer rows.Close()

	result := []ThreatCandidateRow{}
	for rows.Next() {
		var r ThreatCandidateRow
		if err := rows.Scan(&r.AttackerIP, &r.Scenario, &r.SystemID, &r.Hits, &r.LastSeen); err != nil {
			return nil, fmt.Errorf("store: scan consensus candidate: %w", err)
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// ThreatAllowlist returns the non-expired allowlist entries. The allowlist is
// applied at promotion, not at read, so adding an entry retroactively unlists
// the address on the next consensus pass.
func (s *SQLiteStore) ThreatAllowlist(ctx context.Context, now int64) ([]AllowlistRow, error) {
	return s.queryAllowlist(ctx, `
		SELECT cidr, reason, created_by, created_at, expires_at
		FROM threat_allowlist
		WHERE expires_at IS NULL OR expires_at > ?
		ORDER BY cidr
	`, now)
}

// UpsertThreatAllowlistEntry adds or updates one allowlist entry.
//
// There is deliberately no HTTP surface for this: the design gives this
// server no admin auth plane, so entries are added out of band. The method
// exists so that "out of band" means a small supported call rather than
// hand-written SQL against a live database.
func (s *SQLiteStore) UpsertThreatAllowlistEntry(ctx context.Context, e AllowlistRow) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var expires any
	if e.ExpiresAt != nil {
		expires = *e.ExpiresAt
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO threat_allowlist (cidr, reason, created_by, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(cidr) DO UPDATE SET
			reason = excluded.reason,
			created_by = excluded.created_by,
			expires_at = excluded.expires_at
	`, e.CIDR, e.Reason, e.CreatedBy, e.CreatedAt, expires)
	if err != nil {
		return fmt.Errorf("store: upsert allowlist entry: %w", err)
	}
	return nil
}

// DeleteThreatAllowlistEntry removes one entry, reporting whether it existed.
func (s *SQLiteStore) DeleteThreatAllowlistEntry(ctx context.Context, cidr string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.ExecContext(ctx, `DELETE FROM threat_allowlist WHERE cidr = ?`, cidr)
	if err != nil {
		return false, fmt.Errorf("store: delete allowlist entry: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: delete allowlist entry rows: %w", err)
	}
	return n > 0, nil
}

func (s *SQLiteStore) queryAllowlist(ctx context.Context, query string, args ...any) ([]AllowlistRow, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: threat allowlist: %w", err)
	}
	defer rows.Close()

	result := []AllowlistRow{}
	for rows.Next() {
		var (
			r         AllowlistRow
			reason    sql.NullString
			createdBy sql.NullString
			createdAt sql.NullInt64
			expiresAt sql.NullInt64
		)
		if err := rows.Scan(&r.CIDR, &reason, &createdBy, &createdAt, &expiresAt); err != nil {
			return nil, fmt.Errorf("store: scan allowlist entry: %w", err)
		}
		r.Reason, r.CreatedBy, r.CreatedAt = reason.String, createdBy.String, createdAt.Int64
		if expiresAt.Valid {
			v := expiresAt.Int64
			r.ExpiresAt = &v
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// EgressIPs returns every observed reporter source address.
//
// There is deliberately no freshness cut-off: a node that stopped reporting
// last month still owns its WAN address, and re-listing it because the node
// went quiet is exactly the failure this exclusion exists to prevent.
func (s *SQLiteStore) EgressIPs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT source_ip FROM system_egress WHERE source_ip != ''`)
	if err != nil {
		return nil, fmt.Errorf("store: egress ips: %w", err)
	}
	defer rows.Close()

	result := []string{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, fmt.Errorf("store: scan egress ip: %w", err)
		}
		result = append(result, ip)
	}
	return result, rows.Err()
}

// UpsertBlocklistEntries promotes or refreshes entries.
//
// first_listed_at is never touched on update: it records when the fleet first
// agreed about this address, and a refresh is not a new listing.
func (s *SQLiteStore) UpsertBlocklistEntries(ctx context.Context, entries []BlocklistRow) error {
	if len(entries) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: upsert blocklist: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, e := range entries {
		scenarios, err := json.Marshal(e.Scenarios)
		if err != nil {
			return fmt.Errorf("store: marshal blocklist scenarios: %w", err)
		}
		reason, err := json.Marshal(e.Reason)
		if err != nil {
			return fmt.Errorf("store: marshal listing reason: %w", err)
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO threat_blocklist (attacker_ip, first_listed_at, last_seen_at, expires_at,
				distinct_systems, scenarios, listing_reason)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(attacker_ip) DO UPDATE SET
				last_seen_at = excluded.last_seen_at,
				expires_at = excluded.expires_at,
				distinct_systems = excluded.distinct_systems,
				scenarios = excluded.scenarios,
				listing_reason = excluded.listing_reason
		`, e.AttackerIP, e.FirstListedAt, e.LastSeenAt, e.ExpiresAt,
			e.DistinctSystems, string(scenarios), string(reason))
		if err != nil {
			return fmt.Errorf("store: upsert blocklist entry: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit blocklist: %w", err)
	}
	return nil
}

// ExpireBlocklist removes entries whose TTL has run out. A short TTL is what
// stops rented and NAT addresses lingering after reassignment (design D5).
func (s *SQLiteStore) ExpireBlocklist(ctx context.Context, now int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.ExecContext(ctx, `DELETE FROM threat_blocklist WHERE expires_at <= ?`, now)
	if err != nil {
		return 0, fmt.Errorf("store: expire blocklist: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: expire blocklist rows: %w", err)
	}
	return int(n), nil
}

// ListBlocklist returns the live entries that make up the feed, oldest
// listing first so the served order is stable across regenerations.
func (s *SQLiteStore) ListBlocklist(ctx context.Context, now int64, limit int) ([]BlocklistRow, error) {
	return s.queryBlocklist(ctx, `
		SELECT attacker_ip, first_listed_at, last_seen_at, expires_at,
		       distinct_systems, scenarios, listing_reason
		FROM threat_blocklist
		WHERE expires_at > ?
		ORDER BY first_listed_at, attacker_ip
		LIMIT ?
	`, now, clampLimit(limit))
}

func (s *SQLiteStore) queryBlocklist(ctx context.Context, query string, args ...any) ([]BlocklistRow, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list blocklist: %w", err)
	}
	defer rows.Close()

	result := []BlocklistRow{}
	for rows.Next() {
		var (
			r         BlocklistRow
			scenarios sql.NullString
			reason    sql.NullString
		)
		if err := rows.Scan(&r.AttackerIP, &r.FirstListedAt, &r.LastSeenAt, &r.ExpiresAt,
			&r.DistinctSystems, &scenarios, &reason); err != nil {
			return nil, fmt.Errorf("store: scan blocklist entry: %w", err)
		}
		// A malformed row degrades to "no detail" rather than failing the
		// whole feed or the whole page.
		if scenarios.Valid && scenarios.String != "" {
			_ = json.Unmarshal([]byte(scenarios.String), &r.Scenarios)
		}
		if reason.Valid && reason.String != "" {
			_ = json.Unmarshal([]byte(reason.String), &r.Reason)
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// RollupThreatDailyStats recomputes every UTC day present in threat_events.
//
// It recomputes rather than accumulates so that running it twice, or after a
// missed pass, converges on the right answer instead of double counting. The
// day bucket is integer division on the millis column with the label
// formatted in Go: SQLite and Postgres share no date function.
func (s *SQLiteStore) RollupThreatDailyStats(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT observed_at / ?, scenario, COUNT(DISTINCT attacker_ip), SUM(hit_count)
		FROM threat_events
		GROUP BY observed_at / ?, scenario
	`, dayMillis, dayMillis)
	if err != nil {
		return fmt.Errorf("store: rollup threat stats: %w", err)
	}
	defer rows.Close()

	type bucket struct {
		day, scenario string
		distinctIPs   int
		totalHits     int64
	}
	var buckets []bucket
	for rows.Next() {
		var (
			dayIdx int64
			b      bucket
		)
		if err := rows.Scan(&dayIdx, &b.scenario, &b.distinctIPs, &b.totalHits); err != nil {
			return fmt.Errorf("store: scan threat rollup: %w", err)
		}
		b.day = DayString(dayIdx * dayMillis)
		buckets = append(buckets, b)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store: rollup threat stats: %w", err)
	}
	if len(buckets) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: rollup threat stats: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, b := range buckets {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO threat_daily_stats (day, scenario, distinct_ips, total_hits)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(day, scenario) DO UPDATE SET
				distinct_ips = excluded.distinct_ips,
				total_hits = excluded.total_hits
		`, b.day, b.scenario, b.distinctIPs, b.totalHits)
		if err != nil {
			return fmt.Errorf("store: upsert threat daily stats: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit threat daily stats: %w", err)
	}
	return nil
}

// PruneThreatEvents drops raw events past the retention window. It must run
// after RollupThreatDailyStats, or the day being dropped loses its history.
func (s *SQLiteStore) PruneThreatEvents(ctx context.Context, olderThan int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.ExecContext(ctx, `DELETE FROM threat_events WHERE observed_at < ?`, olderThan)
	if err != nil {
		return 0, fmt.Errorf("store: prune threat events: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: prune threat events rows: %w", err)
	}
	return int(n), nil
}
