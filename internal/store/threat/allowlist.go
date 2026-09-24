// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package threat

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/oklog/ulid/v2"
	"github.com/uptrace/bun"
)

// Allowlist management: the client-facing request queue, the four operator
// actions and their audit trail, layered on top of the threat_allowlist
// table declared in store.go. No method here turns a request into a
// threat_allowlist row by itself: AddAllowlistEntry and
// ApproveAllowlistRequest are the only writers of that table, and every
// caller of either is a human decision (an operator UI form submit).

// ErrTooManyAllowlistRequests is returned when a system already has
// MaxPerSystem distinct pending CIDRs and asks about one more. It is a
// sentinel rather than a plain error so the HTTP handler can answer 429
// (the ask is well formed; the system has used up its share of the review
// queue) without matching on a message.
var ErrTooManyAllowlistRequests = errors.New("store: too many pending allowlist requests for this system")

// maxReasonsPerCIDR bounds how many distinct reasons the review queue
// carries for one CIDR. The reasons are context for a human deciding, and
// no human reads the eleventh restatement of "our scanner"; the cap is what
// keeps one popular CIDR from turning a bounded row count back into an
// unbounded one.
const maxReasonsPerCIDR = 10

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
	// Reasons is the distinct non-empty reasons offered for this CIDR,
	// most-recently-seen first and at most maxReasonsPerCIDR of them. They
	// are folded in Go rather than aggregated with GROUP_CONCAT/ARRAY_AGG,
	// which are not portable across SQLite and Postgres -- the same
	// reasoning as ThreatCandidateRow.
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
//
// maxPerSystem caps how many DISTINCT pending CIDRs one system may hold,
// and 0 means unlimited (which only tests use -- cmd/threatd always passes
// a value). The cap is checked here rather than in the handler so it is
// applied inside the same held write lock as the insert: a count read
// outside it could be raced past by concurrent requests from one reporter,
// which is exactly the caller this bound exists for. A refresh of a CIDR
// the system already asked about is never refused, because it adds no row;
// only a genuinely new CIDR can push a system over.
func (s *Store) UpsertAllowlistRequest(ctx context.Context, cidr, systemID, reason string, now int64, maxPerSystem int) (int, error) {
	s.db.Lock()
	defer s.db.Unlock()

	if maxPerSystem > 0 {
		var held int
		if err := s.db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM threat_allowlist_requests
			WHERE system_id = ? AND cidr <> ?
		`, systemID, cidr).Scan(&held); err != nil {
			return 0, fmt.Errorf("store: count allowlist requests for system: %w", err)
		}
		if held >= maxPerSystem {
			return 0, fmt.Errorf("%w: %d held, %d allowed", ErrTooManyAllowlistRequests, held, maxPerSystem)
		}
	}

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

// PendingAllowlistRequests returns the top `limit` CIDRs with an
// outstanding client request, ranked by distinct systems then recency --
// the review queue's priority order.
//
// "Pending" means exactly "a threat_allowlist_requests row exists": handling
// a request deletes its rows (decideAllowlistRequest), so the queue holds
// only what still needs a decision. It deliberately does not consult
// threat_allowlist_reviews -- a past decision must not gag a later ask, or a
// CIDR rejected once on thin evidence could never be raised again however
// many systems went on to report it. What was asked and how it was decided
// lives in the audit trail, which is append-only.
//
// Two queries, both bounded, because this table is fed by clients and is
// therefore as large as the fleet chooses to make it. The first ranks and
// limits in SQL -- COUNT/MIN/MAX only, never GROUP_CONCAT or ARRAY_AGG --
// so at most `limit` rows are read however many CIDRs exist. The second
// fetches the reasons for just those CIDRs, itself limited, because the
// reasons cannot be aggregated portably and folding every request row in Go
// is what made the old single query read the whole table.
func (s *Store) PendingAllowlistRequests(ctx context.Context, limit int) ([]AllowlistRequestRow, error) {
	limit = clampLimit(limit)

	rows, err := s.db.QueryContext(ctx, `
		SELECT cidr,
		       COUNT(DISTINCT system_id) AS systems,
		       MIN(created_at) AS first_at,
		       MAX(created_at) AS last_at
		FROM threat_allowlist_requests
		GROUP BY cidr
		ORDER BY systems DESC, last_at DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: pending allowlist requests: %w", err)
	}
	defer func() { _ = rows.Close() }()

	result := []AllowlistRequestRow{}
	for rows.Next() {
		var r AllowlistRequestRow
		if err := rows.Scan(&r.CIDR, &r.DistinctSystems, &r.FirstRequestedAt, &r.LastRequestedAt); err != nil {
			return nil, fmt.Errorf("store: scan pending allowlist request: %w", err)
		}
		result = append(result, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: pending allowlist requests: %w", err)
	}
	if len(result) == 0 {
		return result, nil
	}

	reasons, err := s.allowlistRequestReasons(ctx, result)
	if err != nil {
		return nil, err
	}
	for i := range result {
		result[i].Reasons = reasons[result[i].CIDR]
	}
	return result, nil
}

// allowlistRequestReasons loads the distinct non-empty reasons offered for
// each of the given CIDRs, most-recently-seen first and at most
// maxReasonsPerCIDR each.
func (s *Store) allowlistRequestReasons(ctx context.Context, forCIDRs []AllowlistRequestRow) (map[string][]string, error) {
	placeholders := make([]string, len(forCIDRs))
	args := make([]any, 0, len(forCIDRs)+1)
	for i, r := range forCIDRs {
		placeholders[i] = "?"
		args = append(args, r.CIDR)
	}
	// The row bound: every CIDR could in principle contribute its whole
	// fleet's worth of reasons, so the read is capped at what the per-CIDR
	// cap can consume. Ordering by created_at DESC first means the rows that
	// survive the cap are the newest.
	args = append(args, len(forCIDRs)*maxReasonsPerCIDR)

	rows, err := s.db.QueryContext(ctx, `
		SELECT cidr, reason
		FROM threat_allowlist_requests
		WHERE reason <> '' AND cidr IN (`+strings.Join(placeholders, ",")+`)
		ORDER BY created_at DESC
		LIMIT ?
	`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: allowlist request reasons: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := map[string][]string{}
	for rows.Next() {
		var cidr, reason string
		if err := rows.Scan(&cidr, &reason); err != nil {
			return nil, fmt.Errorf("store: scan allowlist request reason: %w", err)
		}
		if len(out[cidr]) >= maxReasonsPerCIDR || containsString(out[cidr], reason) {
			continue
		}
		out[cidr] = append(out[cidr], reason)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: allowlist request reasons: %w", err)
	}
	return out, nil
}

func containsString(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// The four operator actions below -- add, remove, approve, reject -- are the
// only writers of threat_allowlist, threat_allowlist_reviews and the audit
// trail, and each is one transaction: the change and the audit row that
// records it commit together or not at all. As separate calls, an audit
// insert that failed after the change had committed left an exemption added
// or removed with no record of who did it, which is the one question the
// trail exists to answer.

// AddAllowlistEntry adds or updates one entry, audited as allowlist.upsert by
// e.CreatedBy at e.CreatedAt with e.Reason as the detail.
func (s *Store) AddAllowlistEntry(ctx context.Context, e AllowlistRow) error {
	return s.allowlistTx(ctx, "add allowlist entry", func(tx bun.Tx) error {
		if err := upsertAllowlistEntry(ctx, tx, e); err != nil {
			return err
		}
		return appendAllowlistAudit(ctx, tx, e.CIDR, "allowlist.upsert", e.CreatedBy, e.Reason, e.CreatedAt)
	})
}

// RemoveAllowlistEntry deletes one entry, audited as allowlist.delete, and
// reports whether it existed. Removing an absent entry writes nothing.
func (s *Store) RemoveAllowlistEntry(ctx context.Context, cidr, actor string, now int64) (bool, error) {
	var existed bool
	err := s.allowlistTx(ctx, "remove allowlist entry", func(tx bun.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM threat_allowlist WHERE cidr = ?`, cidr)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if existed = n > 0; !existed {
			return nil
		}
		return appendAllowlistAudit(ctx, tx, cidr, "allowlist.delete", actor, "", now)
	})
	if err != nil {
		return false, err
	}
	return existed, nil
}

// ApproveAllowlistRequest creates the entry e and records the decision:
// approved by e.CreatedBy at e.CreatedAt, audited as request.approve with
// note as the detail, and every ask for e.CIDR retired from the queue.
func (s *Store) ApproveAllowlistRequest(ctx context.Context, e AllowlistRow, note string) error {
	return s.allowlistTx(ctx, "approve allowlist request", func(tx bun.Tx) error {
		if err := upsertAllowlistEntry(ctx, tx, e); err != nil {
			return err
		}
		return decideAllowlistRequest(ctx, tx, e.CIDR, AllowlistReviewApproved, "request.approve", e.CreatedBy, note, e.CreatedAt)
	})
}

// RejectAllowlistRequest records a rejection, audited as request.reject, and
// retires every ask for cidr. It creates no allowlist entry.
func (s *Store) RejectAllowlistRequest(ctx context.Context, cidr, actor, note string, now int64) error {
	return s.allowlistTx(ctx, "reject allowlist request", func(tx bun.Tx) error {
		return decideAllowlistRequest(ctx, tx, cidr, AllowlistReviewRejected, "request.reject", actor, note, now)
	})
}

// allowlistTx runs fn as one write transaction under the store's write mutex.
func (s *Store) allowlistTx(ctx context.Context, what string, fn func(bun.Tx) error) error {
	s.db.Lock()
	defer s.db.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: %s: %w", what, err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := fn(tx); err != nil {
		return fmt.Errorf("store: %s: %w", what, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit %s: %w", what, err)
	}
	return nil
}

func upsertAllowlistEntry(ctx context.Context, tx bun.Tx, e AllowlistRow) error {
	var expires any
	if e.ExpiresAt != nil {
		expires = *e.ExpiresAt
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO threat_allowlist (cidr, reason, created_by, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(cidr) DO UPDATE SET
			reason = excluded.reason,
			created_by = excluded.created_by,
			expires_at = excluded.expires_at
	`, e.CIDR, e.Reason, e.CreatedBy, e.CreatedAt, expires)
	return err
}

// decideAllowlistRequest records the latest decision for cidr, audits it, and
// retires every client ask for it -- which is how a handled request leaves
// the review queue.
//
// The review row is the latest decision only: ON CONFLICT DO UPDATE, because
// an admin may reject a request and later reconsider.
//
// Deleting the asks is safe precisely because nothing is lost by it: the
// decision is in threat_allowlist_reviews and the audit trail holds who
// decided what, with the note. Keeping the rows instead would let the table
// grow without bound and, worse, would need a permanent per-CIDR mask over
// the queue to hide them -- which is what silently swallowed a later,
// better-evidenced ask for the same address.
//
// A CIDR with no requests is fine: an admin may legitimately approve or
// reject an address nobody asked about.
func decideAllowlistRequest(ctx context.Context, tx bun.Tx, cidr, state, action, actor, note string, now int64) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO threat_allowlist_reviews (cidr, state, decided_by, decided_at, note)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(cidr) DO UPDATE SET
			state = excluded.state,
			decided_by = excluded.decided_by,
			decided_at = excluded.decided_at,
			note = excluded.note
	`, cidr, state, actor, now, note); err != nil {
		return err
	}
	if err := appendAllowlistAudit(ctx, tx, cidr, action, actor, note, now); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM threat_allowlist_requests WHERE cidr = ?`, cidr)
	return err
}

// PruneAllowlistRequests drops client requests last touched before
// olderThan and returns how many went.
//
// This is what bounds the table when nobody reviews the queue: handling a
// request deletes its rows, but an unreviewed one is otherwise permanent,
// and the queue is fed by clients. It prunes by age alone -- there is no
// state to consult, since a decided request has already been deleted -- and
// a system whose ask is dropped can simply ask again, which also re-ranks
// it as current evidence rather than a years-old one.
//
// The audit trail is deliberately NOT pruned here: it exists precisely to
// outlive the rows it describes.
func (s *Store) PruneAllowlistRequests(ctx context.Context, olderThan int64) (int, error) {
	s.db.Lock()
	defer s.db.Unlock()

	res, err := s.db.ExecContext(ctx,
		`DELETE FROM threat_allowlist_requests WHERE created_at < ?`, olderThan)
	if err != nil {
		return 0, fmt.Errorf("store: prune allowlist requests: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: prune allowlist requests rows: %w", err)
	}
	return int(n), nil
}

// appendAllowlistAudit appends one row to the append-only audit trail. It is
// an INSERT only -- there is no update or delete for this table by design,
// because the whole point of the table is to survive the DELETE that removes
// the threat_allowlist row it is describing.
func appendAllowlistAudit(ctx context.Context, tx bun.Tx, cidr, action, actor, detail string, now int64) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO threat_allowlist_audit (id, cidr, action, actor, at, detail)
		VALUES (?, ?, ?, ?, ?, ?)
	`, ulid.Make().String(), cidr, action, actor, now, detail)
	return err
}

// ListAllowlistAudit returns the audit trail, newest first.
func (s *Store) ListAllowlistAudit(ctx context.Context, limit int) ([]AllowlistAuditRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, cidr, action, actor, at, detail
		FROM threat_allowlist_audit
		ORDER BY at DESC
		LIMIT ?
	`, clampLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("store: list allowlist audit: %w", err)
	}
	defer func() { _ = rows.Close() }()

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
