// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package threat

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/oklog/ulid/v2"
)

// Allowlist management: the client-facing request queue and its audit
// trail, layered on top of the threat_allowlist table declared in store.go.
// There is deliberately no method here that turns a request into a
// threat_allowlist row by itself -- UpsertThreatAllowlistEntry (store.go)
// is the only writer of that table, and every caller of it in this codebase
// is a human decision (an admin API call or an operator UI form submit).

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
// a request deletes its rows (DeleteAllowlistRequests), so the queue holds
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

// UpsertAllowlistReview records an approve/reject decision for a CIDR. It is
// the latest-decision record only: it does not retire anything from the
// review queue, which is emptied by DeleteAllowlistRequests instead.
//
// ON CONFLICT DO UPDATE rather than erroring on a repeat: an admin may
// reject a request and later reconsider, and the review row always
// reflects the latest decision.
func (s *Store) UpsertAllowlistReview(ctx context.Context, cidr, state, decidedBy, note string, now int64) error {
	s.db.Lock()
	defer s.db.Unlock()

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
func (s *Store) DeleteAllowlistRequests(ctx context.Context, cidr string) (int, error) {
	s.db.Lock()
	defer s.db.Unlock()

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

// AppendAllowlistAudit appends one row to the append-only audit trail. It is
// an INSERT only -- there is no update or delete method for this table by
// design, because the whole point of the table is to survive the DELETE
// that removes the threat_allowlist row it is describing.
func (s *Store) AppendAllowlistAudit(ctx context.Context, cidr, action, actor, detail string, now int64) error {
	s.db.Lock()
	defer s.db.Unlock()

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
