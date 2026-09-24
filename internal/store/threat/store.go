// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package threat is Threat Shield's storage: ingest, consensus inputs, the
// promoted blocklist, the allowlist and its client-facing review queue, and
// per-day ingest accounting. There is no rollup table: daily stats are read
// live from the retained raw events (see ThreatDailyStats in ui.go), so
// threat history is exactly THREAT_EVENT_RETENTION long. It is threatd's
// only store package -- a separate SQLite file from the logs and sizing
// pipelines, sharing nothing with them but the sqlitex runtime settings.
package threat

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/platform/sqlitex"
	"github.com/oklog/ulid/v2"
)

// Store is Threat Shield's SQLite-backed store: ingest, consensus inputs, the
// promoted blocklist, allowlist management and the operator UI's reads.
// Write methods take the shared write mutex (sqlitex.DB.Lock/Unlock); read
// methods do not.
type Store struct {
	db *sqlitex.DB
}

// Open opens the Threat Shield database at path with the project's standard
// SQLite runtime settings (WAL, busy_timeout, a single connection plus the
// write mutex) -- see internal/platform/sqlitex.
func Open(path string) (*Store, error) {
	db, err := sqlitex.Open(path)
	if err != nil {
		return nil, fmt.Errorf("threat: open: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// Init creates Threat Shield's tables if they do not already exist: the raw
// event stream, the promoted blocklist, the hand-maintained allowlist,
// ingest accounting, and the client-facing allowlist request queue with its
// review and audit trails.
func (s *Store) Init(ctx context.Context) error {
	s.db.Lock()
	defer s.db.Unlock()

	stmts := []string{
		// attacker_ip is always a normalized netip.Addr.String(), which is
		// what lets a portable TEXT column behave like Postgres INET: text
		// equality is address identity.
		`CREATE TABLE IF NOT EXISTS threat_events (
			id TEXT PRIMARY KEY,
			system_id TEXT,
			attacker_ip TEXT,
			scenario TEXT,
			observed_at INTEGER,
			hit_count INTEGER,
			metadata TEXT
		)`,
		// Redelivery idempotency: a reporter that retries a batch must not be
		// able to inflate hit_count and manufacture its own consensus.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_threat_events_dedup
			ON threat_events(system_id, attacker_ip, scenario, observed_at)`,
		`CREATE INDEX IF NOT EXISTS idx_threat_events_ip ON threat_events(attacker_ip, observed_at)`,
		`CREATE INDEX IF NOT EXISTS idx_threat_events_observed ON threat_events(observed_at)`,
		`CREATE TABLE IF NOT EXISTS threat_blocklist (
			attacker_ip TEXT PRIMARY KEY,
			first_listed_at INTEGER,
			last_seen_at INTEGER,
			expires_at INTEGER,
			distinct_systems INTEGER,
			scenarios TEXT,
			listing_reason TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_threat_blocklist_expires ON threat_blocklist(expires_at)`,
		`CREATE TABLE IF NOT EXISTS threat_allowlist (
			cidr TEXT PRIMARY KEY,
			reason TEXT,
			created_by TEXT,
			created_at INTEGER,
			expires_at INTEGER
		)`,
		// Ingest accounting. Without it, "this node contributes nothing and
		// here is which rule is dropping it" is answerable only from logs.
		`CREATE TABLE IF NOT EXISTS threat_ingest_daily (
			day TEXT,
			system_id TEXT,
			accepted INTEGER,
			duplicates INTEGER,
			dropped_type INTEGER,
			dropped_scope INTEGER,
			dropped_origin INTEGER,
			dropped_bad_ip INTEGER,
			dropped_private_ip INTEGER,
			dropped_time INTEGER,
			truncated INTEGER,
			PRIMARY KEY (day, system_id)
		)`,

		// --- Allowlist management ---
		//
		// threat_allowlist itself (above) is unchanged. These three tables add
		// a client-facing request queue and its audit trail on top of it, with
		// no path from a request to a live entry that does not pass through an
		// explicit admin decision -- see the "no automatic promotion" rule in
		// CLAUDE.md.
		//
		// Requests persist per (cidr, system_id) only until a decision is
		// recorded for that cidr: decideAllowlistRequest deletes every
		// request row it covers, not just the one that prompted the review
		// (see threat_allowlist_reviews below and PruneAllowlistRequests for
		// the other way a row goes, by age). "Who asked, and when" survives
		// in the audit trail instead. The counter that ranks the review
		// queue is COUNT(DISTINCT system_id) over this table, mirroring the
		// blocklist's own distinct-systems rule.
		`CREATE TABLE IF NOT EXISTS threat_allowlist_requests (
			cidr TEXT,
			system_id TEXT,
			reason TEXT,
			created_at INTEGER,
			PRIMARY KEY (cidr, system_id)
		)`,
		// The latest decision for a cidr, and nothing more: state is
		// "approved" or "rejected". It does not gate the pending queue --
		// handling a request deletes the threat_allowlist_requests rows that
		// raised it, so a later ask for the same cidr is reviewed on its own
		// merits instead of being silently swallowed by an old decision.
		// Re-reviewing an already-decided cidr overwrites the row rather than
		// erroring, since an admin may reject and then reconsider.
		`CREATE TABLE IF NOT EXISTS threat_allowlist_reviews (
			cidr TEXT PRIMARY KEY,
			state TEXT,
			decided_by TEXT,
			decided_at INTEGER,
			note TEXT
		)`,
		// Append-only, and deliberately never updated or deleted: DELETE on
		// threat_allowlist removes the very row that would otherwise hold the
		// trail, so without this table "who removed the exemption that let
		// this through" is unanswerable -- which is the question that gets
		// asked.
		`CREATE TABLE IF NOT EXISTS threat_allowlist_audit (
			id TEXT PRIMARY KEY,
			cidr TEXT,
			action TEXT,
			actor TEXT,
			at INTEGER,
			detail TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_allowlist_audit_at ON threat_allowlist_audit(at)`,
	}

	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("threat: init: %w", err)
		}
	}

	return nil
}

// defaultListLimit is applied whenever a caller passes limit <= 0. This data
// is served to an unauthenticated UI, so "no limit" is never an option.
const defaultListLimit = 200

// clampLimit applies defaultListLimit whenever the caller passed a
// non-positive value.
func clampLimit(limit int) int {
	if limit <= 0 {
		return defaultListLimit
	}
	return limit
}

const dayMillis = 86400000

// Counts is per-table row counts, for the status page.
type Counts struct {
	Events, BlocklistEntries, AllowlistEntries, PendingRequests int
}

// Counts reports per-table row counts. PendingRequests counts distinct CIDRs
// with an outstanding client request -- the review queue's size -- not the
// number of request rows, which can be many per CIDR.
func (s *Store) Counts(ctx context.Context) (Counts, error) {
	var c Counts
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM threat_events`).Scan(&c.Events); err != nil {
		return Counts{}, fmt.Errorf("threat: count events: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM threat_blocklist`).Scan(&c.BlocklistEntries); err != nil {
		return Counts{}, fmt.Errorf("threat: count blocklist entries: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM threat_allowlist`).Scan(&c.AllowlistEntries); err != nil {
		return Counts{}, fmt.Errorf("threat: count allowlist entries: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT count(DISTINCT cidr) FROM threat_allowlist_requests`).Scan(&c.PendingRequests); err != nil {
		return Counts{}, fmt.Errorf("threat: count pending requests: %w", err)
	}
	return c, nil
}

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

// ThreatDailyRow is one day/scenario aggregate, computed live from the
// retained threat_events (see ThreatDailyStats in ui.go) -- not a stored
// rollup row: there is no rollup table for this pipeline's daily stats.
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

// DayString formats a unix-millis instant as the UTC day key used by
// threat_ingest_daily and the live daily-stats query alike. Day bucketing is
// integer division on the millis column and formatting in Go, never a SQL
// date function -- SQLite and Postgres do not share one.
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
func (s *Store) InsertThreatEvents(ctx context.Context, systemID string, ev []model.ThreatEvent) (int, int, error) {
	if len(ev) == 0 {
		return 0, 0, nil
	}

	s.db.Lock()
	defer s.db.Unlock()

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

// RecordIngestCounters accumulates one request's outcome into the day's row
// for that system.
func (s *Store) RecordIngestCounters(ctx context.Context, day, systemID string, c model.ThreatCounters, duplicates int) error {
	s.db.Lock()
	defer s.db.Unlock()

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
func (s *Store) ConsensusCandidates(ctx context.Context, since int64) ([]ThreatCandidateRow, error) {
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
	defer func() { _ = rows.Close() }()

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
// applied on the consensus pass, not at read, so adding an entry retroactively
// unlists the address rather than merely hiding it from the feed: promote
// declines to add a row and the pass's unlist step deletes any live row the
// entry now covers. Applying it at read would leave the row in place, so
// deleting the entry again would silently republish the address.
func (s *Store) ThreatAllowlist(ctx context.Context, now int64) ([]AllowlistRow, error) {
	return s.queryAllowlist(ctx, `
		SELECT cidr, reason, created_by, created_at, expires_at
		FROM threat_allowlist
		WHERE expires_at IS NULL OR expires_at > ?
		ORDER BY cidr
	`, now)
}

func (s *Store) queryAllowlist(ctx context.Context, query string, args ...any) ([]AllowlistRow, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: threat allowlist: %w", err)
	}
	defer func() { _ = rows.Close() }()

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

// UpsertBlocklistEntries promotes or refreshes entries.
//
// first_listed_at is never touched on update: it records when the fleet first
// agreed about this address, and a refresh is not a new listing.
func (s *Store) UpsertBlocklistEntries(ctx context.Context, entries []BlocklistRow) error {
	if len(entries) == 0 {
		return nil
	}

	s.db.Lock()
	defer s.db.Unlock()

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
func (s *Store) ExpireBlocklist(ctx context.Context, now int64) (int, error) {
	s.db.Lock()
	defer s.db.Unlock()

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

// ListBlocklistIPs returns every live entry's address and nothing else.
//
// The consensus pass needs the whole live set to decide which rows the
// allowlist now covers, so unlike ListBlocklist this is uncapped and skips
// the JSON columns. Capping it would leave an allowlisted row in the table
// until it happened to drift inside the feed's cap, and the operator UI
// lists the table directly.
func (s *Store) ListBlocklistIPs(ctx context.Context, now int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT attacker_ip FROM threat_blocklist WHERE expires_at > ? ORDER BY attacker_ip
	`, now)
	if err != nil {
		return nil, fmt.Errorf("store: list blocklist ips: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []string{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, fmt.Errorf("store: scan blocklist ip: %w", err)
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

// DeleteBlocklistEntries removes the named entries, reporting how many rows
// went.
//
// This is how an allowlist entry unlists an address that was already
// promoted: ExpireBlocklist deletes on expires_at alone, so without this an
// exemption would take up to BLOCKLIST_TTL to take effect. One statement per
// address inside one transaction rather than an IN list, because the live
// blocklist can hold far more addresses than SQLite allows bound parameters.
func (s *Store) DeleteBlocklistEntries(ctx context.Context, ips []string) (int, error) {
	if len(ips) == 0 {
		return 0, nil
	}

	s.db.Lock()
	defer s.db.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: delete blocklist entries: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	deleted := 0
	for _, ip := range ips {
		res, err := tx.ExecContext(ctx, `DELETE FROM threat_blocklist WHERE attacker_ip = ?`, ip)
		if err != nil {
			return 0, fmt.Errorf("store: delete blocklist entry: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("store: delete blocklist entry rows: %w", err)
		}
		deleted += int(n)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit blocklist delete: %w", err)
	}
	return deleted, nil
}

// ListBlocklist returns the live entries that make up the feed, most
// recently seen first, so a cap keeps the attackers the fleet is still
// seeing. limit <= 0 means every live entry: this is the feed, and the UI
// listings' default page size must never become a silent cap on it. The
// served order is the snapshot's own (by address), not this one.
func (s *Store) ListBlocklist(ctx context.Context, now int64, limit int) ([]BlocklistRow, error) {
	if limit <= 0 {
		limit = -1 // SQLite: no limit
	}
	return s.queryBlocklist(ctx, `
		SELECT attacker_ip, first_listed_at, last_seen_at, expires_at,
		       distinct_systems, scenarios, listing_reason
		FROM threat_blocklist
		WHERE expires_at > ?
		ORDER BY last_seen_at DESC, attacker_ip
		LIMIT ?
	`, now, limit)
}

func (s *Store) queryBlocklist(ctx context.Context, query string, args ...any) ([]BlocklistRow, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list blocklist: %w", err)
	}
	defer func() { _ = rows.Close() }()

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

// PruneThreatEvents drops raw events past the retention window. Nothing
// outlives them: /stats reads the events that are left.
func (s *Store) PruneThreatEvents(ctx context.Context, olderThan int64) (int, error) {
	s.db.Lock()
	defer s.db.Unlock()

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
