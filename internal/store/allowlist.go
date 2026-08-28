// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package store

import (
	"context"
	"fmt"

	"github.com/oklog/ulid/v2"
)

// Allowlist management: the client-facing request queue and its audit
// trail, layered on top of the threat_allowlist table declared in store.go.
// There is deliberately no method here that turns a request into a
// threat_allowlist row by itself -- UpsertThreatAllowlistEntry (threat.go)
// is the only writer of that table, and every caller of it in this codebase
// is a human decision (an admin API call or an operator UI form submit).

// AllowlistReviewApproved and AllowlistReviewRejected are the only two
// values threat_allowlist_reviews.state ever takes. An absent row means
// pending; there is no third state.
const (
	AllowlistReviewApproved = "approved"
	AllowlistReviewRejected = "rejected"
)

// AllowlistRequestRow is one CIDR's aggregated pending request, ranked by
// distinct systems -- the review queue's priority signal. Distinct systems,
// not row count, exactly like blocklist consensus: the counter ranks the
// queue and never decides anything by itself (see "no automatic promotion"
// in CLAUDE.md).
type AllowlistRequestRow struct {
	CIDR                              string
	DistinctSystems                   int
	FirstRequestedAt, LastRequestedAt int64
	// Reasons is every distinct non-empty reason offered for this CIDR,
	// most-recently-seen first. It is folded in Go rather than aggregated
	// with GROUP_CONCAT/ARRAY_AGG, which are not portable across SQLite and
	// Postgres -- the same reasoning as ThreatCandidateRow.
	Reasons []string
}

// AllowlistAuditRow is one append-only audit entry.
type AllowlistAuditRow struct {
	ID, CIDR, Action, Actor, Detail string
	At                              int64
}

// UpsertAllowlistRequest records one system's ask for a CIDR and returns the
// resulting distinct-system count.
//
// Idempotent per (cidr, system_id): a system that asks again refreshes its
// reason and timestamp rather than inserting a second row, so the counter
// stays a count of systems and never of requests. A request for an already
// -allowlisted CIDR is accepted the same way -- it is a successful no-op,
// since the entry is already in effect.
func (s *SQLiteStore) UpsertAllowlistRequest(ctx context.Context, cidr, systemID, reason string, now int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO threat_allowlist_requests (cidr, system_id, reason, created_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(cidr, system_id) DO UPDATE SET
			reason = excluded.reason,
			created_at = excluded.created_at
	`, cidr, systemID, reason, now)
	if err != nil {
		return 0, fmt.Errorf("store: upsert allowlist request: %w", err)
	}

	var n int
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT system_id) FROM threat_allowlist_requests WHERE cidr = ?
	`, cidr).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count allowlist requests: %w", err)
	}
	return n, nil
}

// PendingAllowlistRequests returns every CIDR with an outstanding client
// request, ranked by distinct systems then recency -- the review queue's
// priority order.
//
// "Pending" means exactly "a threat_allowlist_requests row exists": handling
// a request deletes its rows (DeleteAllowlistRequests), so the queue holds
// only what still needs a decision. It deliberately does not consult
// threat_allowlist_reviews -- a past decision must not gag a later ask, or a
// CIDR rejected once on thin evidence could never be raised again however
// many systems went on to report it. What was asked and how it was decided
// lives in the audit trail, which is append-only.
func (s *SQLiteStore) PendingAllowlistRequests(ctx context.Context, limit int) ([]AllowlistRequestRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.cidr, r.reason, r.system_id, r.created_at
		FROM threat_allowlist_requests r
		ORDER BY r.cidr, r.created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("store: pending allowlist requests: %w", err)
	}
	defer rows.Close()

	// Folded in Go rather than aggregated in SQL for the same reason
	// ConsensusCandidates is: COUNT(DISTINCT ...) alone cannot also hand back
	// the reason list, and GROUP_CONCAT/ARRAY_AGG are not portable.
	byCIDR := map[string]*AllowlistRequestRow{}
	order := []string{}
	for rows.Next() {
		var (
			cidr, reason, systemID string
			createdAt              int64
		)
		if err := rows.Scan(&cidr, &reason, &systemID, &createdAt); err != nil {
			return nil, fmt.Errorf("store: scan pending allowlist request: %w", err)
		}
		r, ok := byCIDR[cidr]
		if !ok {
			r = &AllowlistRequestRow{CIDR: cidr, FirstRequestedAt: createdAt, LastRequestedAt: createdAt}
			byCIDR[cidr] = r
			order = append(order, cidr)
		}
		r.DistinctSystems++ // rows are already one-per-system_id because of the PRIMARY KEY
		if createdAt > r.LastRequestedAt {
			r.LastRequestedAt = createdAt
		}
		if createdAt < r.FirstRequestedAt {
			r.FirstRequestedAt = createdAt
		}
		if reason != "" && !containsString(r.Reasons, reason) {
			r.Reasons = append(r.Reasons, reason)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: pending allowlist requests: %w", err)
	}

	result := make([]AllowlistRequestRow, 0, len(order))
	for _, cidr := range order {
		result = append(result, *byCIDR[cidr])
	}
	sortAllowlistRequests(result)

	if limit = clampLimit(limit); limit < len(result) {
		result = result[:limit]
	}
	return result, nil
}

func containsString(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// sortAllowlistRequests orders by distinct systems descending, then most
// recently asked first -- the same priority order the blocklist gives its
// own consensus candidates.
func sortAllowlistRequests(rows []AllowlistRequestRow) {
	for i := 1; i < len(rows); i++ {
		for j := i; j > 0; j-- {
			a, b := rows[j-1], rows[j]
			less := b.DistinctSystems > a.DistinctSystems ||
				(b.DistinctSystems == a.DistinctSystems && b.LastRequestedAt > a.LastRequestedAt)
			if !less {
				break
			}
			rows[j-1], rows[j] = rows[j], rows[j-1]
		}
	}
}

// UpsertAllowlistReview records an approve/reject decision for a CIDR. It is
// the latest-decision record only: it does not retire anything from the
// review queue, which is emptied by DeleteAllowlistRequests instead.
//
// ON CONFLICT DO UPDATE rather than erroring on a repeat: an admin may
// reject a request and later reconsider, and the review row always
// reflects the latest decision.
func (s *SQLiteStore) UpsertAllowlistReview(ctx context.Context, cidr, state, decidedBy, note string, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO threat_allowlist_reviews (cidr, state, decided_by, decided_at, note)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(cidr) DO UPDATE SET
			state = excluded.state,
			decided_by = excluded.decided_by,
			decided_at = excluded.decided_at,
			note = excluded.note
	`, cidr, state, decidedBy, now, note)
	if err != nil {
		return fmt.Errorf("store: upsert allowlist review: %w", err)
	}
	return nil
}

// DeleteAllowlistRequests removes every client request for a CIDR and
// returns how many rows went, which is how a handled request leaves the
// review queue. It is called after the decision has been recorded, so a
// failure between the two leaves the request pending -- to be decided again
// -- rather than deleted with nothing to show for it.
//
// Deleting the asks is safe precisely because nothing is lost by it: the
// decision is in threat_allowlist_reviews and the append-only audit trail
// holds who decided what, with the note. Keeping the rows instead would let
// the table grow without bound and, worse, would need a permanent per-CIDR
// mask over the queue to hide them -- which is what silently swallowed a
// later, better-evidenced ask for the same address.
//
// A CIDR with no requests is a successful no-op returning 0: an admin may
// legitimately approve or reject an address nobody asked about.
func (s *SQLiteStore) DeleteAllowlistRequests(ctx context.Context, cidr string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.ExecContext(ctx, `DELETE FROM threat_allowlist_requests WHERE cidr = ?`, cidr)
	if err != nil {
		return 0, fmt.Errorf("store: delete allowlist requests: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: delete allowlist requests rows: %w", err)
	}
	return int(n), nil
}

// AppendAllowlistAudit appends one row to the append-only audit trail. It is
// an INSERT only -- there is no update or delete method for this table by
// design, because the whole point of the table is to survive the DELETE
// that removes the threat_allowlist row it is describing.
func (s *SQLiteStore) AppendAllowlistAudit(ctx context.Context, cidr, action, actor, detail string, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO threat_allowlist_audit (id, cidr, action, actor, at, detail)
		VALUES (?, ?, ?, ?, ?, ?)
	`, ulid.Make().String(), cidr, action, actor, now, detail)
	if err != nil {
		return fmt.Errorf("store: append allowlist audit: %w", err)
	}
	return nil
}

// ListAllowlistAudit returns the audit trail, newest first.
func (s *SQLiteStore) ListAllowlistAudit(ctx context.Context, limit int) ([]AllowlistAuditRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, cidr, action, actor, at, detail
		FROM threat_allowlist_audit
		ORDER BY at DESC
		LIMIT ?
	`, clampLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("store: list allowlist audit: %w", err)
	}
	defer rows.Close()

	result := []AllowlistAuditRow{}
	for rows.Next() {
		var r AllowlistAuditRow
		if err := rows.Scan(&r.ID, &r.CIDR, &r.Action, &r.Actor, &r.At, &r.Detail); err != nil {
			return nil, fmt.Errorf("store: scan allowlist audit: %w", err)
		}
		result = append(result, r)
	}
	return result, rows.Err()
}
