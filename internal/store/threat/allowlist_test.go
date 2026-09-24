// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package threat

import (
	"context"
	"errors"
	"testing"
)

// Every allowlist-management read must answer empty-and-nil on a fresh
// database, mirroring TestThreatMethodsOnEmptyDatabase.
func TestAllowlistManagementMethodsOnEmptyDatabase(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if rows, err := s.PendingAllowlistRequests(ctx, 0); err != nil || len(rows) != 0 {
		t.Fatalf("PendingAllowlistRequests: %v, %d rows", err, len(rows))
	}
	if rows, err := s.ListAllowlistAudit(ctx, 0); err != nil || len(rows) != 0 {
		t.Fatalf("ListAllowlistAudit: %v, %d rows", err, len(rows))
	}
}

// The counter behind the review queue is distinct systems, not row count --
// the same rule the blocklist's own consensus uses, and for the same
// reason: it ranks the queue, it never decides anything.
func TestUpsertAllowlistRequestCountsDistinctSystems(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	n, err := s.UpsertAllowlistRequest(ctx, "203.0.113.0/24", "sys-1", "first ask", 1000, 0)
	if err != nil {
		t.Fatalf("UpsertAllowlistRequest: %v", err)
	}
	if n != 1 {
		t.Fatalf("distinct systems: got %d, want 1", n)
	}

	// The same system asking again is idempotent: it refreshes the row, it
	// does not add a second one.
	n, err = s.UpsertAllowlistRequest(ctx, "203.0.113.0/24", "sys-1", "asking again", 2000, 0)
	if err != nil {
		t.Fatalf("UpsertAllowlistRequest (repeat): %v", err)
	}
	if n != 1 {
		t.Fatalf("distinct systems after a repeat from the same system: got %d, want 1", n)
	}

	n, err = s.UpsertAllowlistRequest(ctx, "203.0.113.0/24", "sys-2", "us too", 3000, 0)
	if err != nil {
		t.Fatalf("UpsertAllowlistRequest (second system): %v", err)
	}
	if n != 2 {
		t.Fatalf("distinct systems after a second system: got %d, want 2", n)
	}
}

// This is the executable form of the plan's decision 1: there is no path
// from any number of client requests, from any number of distinct systems,
// to a live threat_allowlist entry. Only AddAllowlistEntry or
// ApproveAllowlistRequest -- which only an admin decision ever calls --
// creates one.
func TestClientRequestsNeverAutoPromoteToTheAllowlist(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const cidr = "203.0.113.0/24"

	for i, sys := range []string{"sys-1", "sys-2", "sys-3", "sys-4", "sys-5"} {
		if _, err := s.UpsertAllowlistRequest(ctx, cidr, sys, "please allowlist us", int64(1000+i), 0); err != nil {
			t.Fatalf("UpsertAllowlistRequest(%s): %v", sys, err)
		}
	}

	pending, err := s.PendingAllowlistRequests(ctx, 0)
	if err != nil {
		t.Fatalf("PendingAllowlistRequests: %v", err)
	}
	if len(pending) != 1 || pending[0].DistinctSystems != 5 {
		t.Fatalf("pending queue: got %+v, want one entry with 5 distinct systems", pending)
	}

	// However many systems asked, the CIDR must be absent from the live
	// allowlist -- both the promotion-time view and the operator/admin view.
	live, err := s.ThreatAllowlist(ctx, 9999999)
	if err != nil {
		t.Fatalf("ThreatAllowlist: %v", err)
	}
	if len(live) != 0 {
		t.Fatalf("ThreatAllowlist: got %+v, want no entries -- a request must never auto-promote", live)
	}
	all, err := s.ListThreatAllowlist(ctx)
	if err != nil {
		t.Fatalf("ListThreatAllowlist: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("ListThreatAllowlist: got %+v, want no entries -- a request must never auto-promote", all)
	}
}

// PendingAllowlistRequests ranks by distinct systems first, then recency --
// the same priority order blocklist consensus gives its own candidates.
func TestPendingAllowlistRequestsAreRankedByDistinctSystemsThenRecency(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	mustRequest := func(cidr, sys string, at int64) {
		t.Helper()
		if _, err := s.UpsertAllowlistRequest(ctx, cidr, sys, "reason for "+cidr, at, 0); err != nil {
			t.Fatalf("UpsertAllowlistRequest: %v", err)
		}
	}

	// popular: 3 distinct systems.
	mustRequest("203.0.113.0/24", "sys-1", 1000)
	mustRequest("203.0.113.0/24", "sys-2", 2000)
	mustRequest("203.0.113.0/24", "sys-3", 3000)
	// quiet: 1 system, asked more recently.
	mustRequest("198.51.100.0/24", "sys-4", 5000)

	rows, err := s.PendingAllowlistRequests(ctx, 0)
	if err != nil {
		t.Fatalf("PendingAllowlistRequests: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows: got %d, want 2", len(rows))
	}
	if rows[0].CIDR != "203.0.113.0/24" || rows[0].DistinctSystems != 3 {
		t.Fatalf("rank 0: got %+v, want the 3-system CIDR first", rows[0])
	}
	if rows[1].CIDR != "198.51.100.0/24" || rows[1].DistinctSystems != 1 {
		t.Fatalf("rank 1: got %+v", rows[1])
	}
	if rows[0].FirstRequestedAt != 1000 || rows[0].LastRequestedAt != 3000 {
		t.Fatalf("first/last requested: got %+v", rows[0])
	}
}

// Approving a request creates the entry, records the decision and retires
// every ask, and the audit row says who did it and why.
func TestApprovingARequestCreatesTheEntryAndRetiresTheAsk(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const cidr = "203.0.113.0/24"

	for _, sys := range []string{"sys-1", "sys-2"} {
		if _, err := s.UpsertAllowlistRequest(ctx, cidr, sys, "please", 1000, 0); err != nil {
			t.Fatalf("UpsertAllowlistRequest(%s): %v", sys, err)
		}
	}
	entry := AllowlistRow{CIDR: cidr, Reason: "partner scanner", CreatedBy: "alice", CreatedAt: 2000}
	if err := s.ApproveAllowlistRequest(ctx, entry, "partner scanner"); err != nil {
		t.Fatalf("ApproveAllowlistRequest: %v", err)
	}

	live, err := s.ListThreatAllowlist(ctx)
	if err != nil {
		t.Fatalf("ListThreatAllowlist: %v", err)
	}
	if len(live) != 1 || live[0].CIDR != cidr || live[0].CreatedBy != "alice" {
		t.Fatalf("allowlist: got %+v, want the approved entry by alice", live)
	}
	if pending, err := s.PendingAllowlistRequests(ctx, 0); err != nil || len(pending) != 0 {
		t.Fatalf("pending: got %+v, %v, want the handled CIDR gone", pending, err)
	}
	assertReview(t, s, cidr, AllowlistReviewApproved, "alice")
	audit, err := s.ListAllowlistAudit(ctx, 0)
	if err != nil {
		t.Fatalf("ListAllowlistAudit: %v", err)
	}
	if len(audit) != 1 || audit[0].Action != "request.approve" || audit[0].Actor != "alice" || audit[0].Detail != "partner scanner" {
		t.Fatalf("audit: got %+v, want one request.approve by alice", audit)
	}
}

// Rejecting retires the ask and records the decision, and creates nothing on
// the allowlist.
func TestRejectingARequestRetiresTheAskAndCreatesNoEntry(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const cidr = "203.0.113.0/24"

	if _, err := s.UpsertAllowlistRequest(ctx, cidr, "sys-1", "please", 1000, 0); err != nil {
		t.Fatalf("UpsertAllowlistRequest: %v", err)
	}
	if err := s.RejectAllowlistRequest(ctx, cidr, "alice", "not enough evidence", 2000); err != nil {
		t.Fatalf("RejectAllowlistRequest: %v", err)
	}

	if n := countRows(t, s, "threat_allowlist"); n != 0 {
		t.Fatalf("allowlist rows: got %d, want 0", n)
	}
	if pending, err := s.PendingAllowlistRequests(ctx, 0); err != nil || len(pending) != 0 {
		t.Fatalf("pending: got %+v, %v, want the handled CIDR gone", pending, err)
	}
	assertReview(t, s, cidr, AllowlistReviewRejected, "alice")
	audit, err := s.ListAllowlistAudit(ctx, 0)
	if err != nil {
		t.Fatalf("ListAllowlistAudit: %v", err)
	}
	if len(audit) != 1 || audit[0].Action != "request.reject" || audit[0].Detail != "not enough evidence" {
		t.Fatalf("audit: got %+v, want one request.reject", audit)
	}
}

// assertReview reads the review row directly: there is no getter for one.
func assertReview(t *testing.T, s *Store, cidr, wantState, wantBy string) {
	t.Helper()
	var state, by string
	if err := s.db.QueryRowContext(context.Background(),
		`SELECT state, decided_by FROM threat_allowlist_reviews WHERE cidr = ?`, cidr).Scan(&state, &by); err != nil {
		t.Fatalf("review row for %s: %v", cidr, err)
	}
	if state != wantState || by != wantBy {
		t.Fatalf("review: got %s by %s, want %s by %s", state, by, wantState, wantBy)
	}
}

// A past decision must not gag a later ask. A CIDR rejected once on thin
// evidence has to be reviewable again when more systems report it --
// otherwise one hasty rejection silently buries every future request for
// that address, and nobody is told.
func TestAFreshAskAfterADecisionReturnsToTheQueue(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const cidr = "203.0.113.0/24"

	if _, err := s.UpsertAllowlistRequest(ctx, cidr, "sys-1", "please", 1000, 0); err != nil {
		t.Fatalf("UpsertAllowlistRequest: %v", err)
	}
	if err := s.RejectAllowlistRequest(ctx, cidr, "alice", "not enough evidence", 2000); err != nil {
		t.Fatalf("RejectAllowlistRequest: %v", err)
	}

	if _, err := s.UpsertAllowlistRequest(ctx, cidr, "sys-2", "still want it", 3000, 0); err != nil {
		t.Fatalf("UpsertAllowlistRequest (after the rejection): %v", err)
	}
	pending, err := s.PendingAllowlistRequests(ctx, 0)
	if err != nil {
		t.Fatalf("PendingAllowlistRequests: %v", err)
	}
	if len(pending) != 1 || pending[0].CIDR != cidr {
		t.Fatalf("pending after a fresh ask: got %+v, want the CIDR reviewable again", pending)
	}
	// The new ask is counted on its own, not on top of the deleted one.
	if pending[0].DistinctSystems != 1 {
		t.Fatalf("distinct systems: got %d, want 1 -- the deleted ask must not still count",
			pending[0].DistinctSystems)
	}
	if pending[0].LastRequestedAt != 3000 {
		t.Fatalf("last requested: got %d, want 3000", pending[0].LastRequestedAt)
	}
}

// Deciding a CIDR nobody asked about succeeds: an admin may approve or
// reject an address out of band.
func TestDecidingACIDRNobodyAskedAboutSucceeds(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.RejectAllowlistRequest(ctx, "203.0.113.0/24", "alice", "", 1000); err != nil {
		t.Fatalf("RejectAllowlistRequest: %v", err)
	}
	entry := AllowlistRow{CIDR: "198.51.100.0/24", Reason: "scanner", CreatedBy: "alice", CreatedAt: 1000}
	if err := s.ApproveAllowlistRequest(ctx, entry, ""); err != nil {
		t.Fatalf("ApproveAllowlistRequest: %v", err)
	}
}

// A decision is scoped to its CIDR: handling one request must not clear the
// rest of the queue.
func TestADecisionRetiresOnlyItsCIDR(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.UpsertAllowlistRequest(ctx, "203.0.113.0/24", "sys-1", "a", 1000, 0); err != nil {
		t.Fatalf("UpsertAllowlistRequest: %v", err)
	}
	if _, err := s.UpsertAllowlistRequest(ctx, "198.51.100.0/24", "sys-1", "b", 1000, 0); err != nil {
		t.Fatalf("UpsertAllowlistRequest: %v", err)
	}
	if _, err := s.UpsertAllowlistRequest(ctx, "198.51.100.0/24", "sys-2", "b", 1100, 0); err != nil {
		t.Fatalf("UpsertAllowlistRequest: %v", err)
	}

	if err := s.RejectAllowlistRequest(ctx, "203.0.113.0/24", "alice", "", 2000); err != nil {
		t.Fatalf("RejectAllowlistRequest: %v", err)
	}

	pending, err := s.PendingAllowlistRequests(ctx, 0)
	if err != nil {
		t.Fatalf("PendingAllowlistRequests: %v", err)
	}
	if len(pending) != 1 || pending[0].CIDR != "198.51.100.0/24" || pending[0].DistinctSystems != 2 {
		t.Fatalf("pending: got %+v, want only 198.51.100.0/24 with 2 systems", pending)
	}
}

// Every ask for a CIDR goes, not just the one row that happened to be
// newest: the queue counts distinct systems, so leaving any behind would
// leave the CIDR queued at a lower count -- which reads as a fresh, weaker
// request that nobody made.
func TestADecisionRetiresEverySystemsAsk(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const cidr = "203.0.113.0/24"

	for i, sys := range []string{"sys-1", "sys-2", "sys-3"} {
		if _, err := s.UpsertAllowlistRequest(ctx, cidr, sys, "please", int64(1000+i*100), 0); err != nil {
			t.Fatalf("UpsertAllowlistRequest(%s): %v", sys, err)
		}
	}

	if err := s.RejectAllowlistRequest(ctx, cidr, "alice", "", 2000); err != nil {
		t.Fatalf("RejectAllowlistRequest: %v", err)
	}
	if n := countRows(t, s, "threat_allowlist_requests"); n != 0 {
		t.Fatalf("request rows: got %d, want 0", n)
	}
}

// A repeat review (reject, then reconsider and approve) overwrites the
// decision rather than erroring: ON CONFLICT DO UPDATE, not DO NOTHING.
func TestALaterDecisionOverwritesAPriorOne(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const cidr = "203.0.113.0/24"

	if err := s.RejectAllowlistRequest(ctx, cidr, "alice", "no", 1000); err != nil {
		t.Fatalf("RejectAllowlistRequest: %v", err)
	}
	entry := AllowlistRow{CIDR: cidr, Reason: "reconsidered", CreatedBy: "bob", CreatedAt: 2000}
	if err := s.ApproveAllowlistRequest(ctx, entry, "reconsidered"); err != nil {
		t.Fatalf("ApproveAllowlistRequest: %v", err)
	}
	assertReview(t, s, cidr, AllowlistReviewApproved, "bob")
}

// The audit trail is append-only: every action appends exactly one row, and
// nothing ever updates or deletes one -- not even the delete of the entry it
// describes.
func TestEachAllowlistActionAppendsOneAuditRow(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const cidr = "203.0.113.0/24"

	if err := s.AddAllowlistEntry(ctx, AllowlistRow{CIDR: cidr, Reason: "partner scanner", CreatedBy: "alice", CreatedAt: 1000}); err != nil {
		t.Fatalf("AddAllowlistEntry: %v", err)
	}
	existed, err := s.RemoveAllowlistEntry(ctx, cidr, "bob", 2000)
	if err != nil || !existed {
		t.Fatalf("RemoveAllowlistEntry: existed=%v err=%v", existed, err)
	}

	rows, err := s.ListAllowlistAudit(ctx, 0)
	if err != nil {
		t.Fatalf("ListAllowlistAudit: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("audit rows: got %d, want 2", len(rows))
	}
	// Newest first.
	if rows[0].Action != "allowlist.delete" || rows[0].Actor != "bob" {
		t.Fatalf("newest row: got %+v", rows[0])
	}
	if rows[1].Action != "allowlist.upsert" || rows[1].Actor != "alice" || rows[1].Detail != "partner scanner" {
		t.Fatalf("oldest row: got %+v", rows[1])
	}
	if rows[0].ID == "" || rows[0].ID == rows[1].ID {
		t.Fatalf("audit rows must each get a distinct ULID id: got %+v", rows)
	}
}

// Removing an entry that is not there reports it and records nothing: there
// was no change for the trail to describe.
func TestRemovingAnAbsentEntryWritesNothing(t *testing.T) {
	s := newTestStore(t)

	existed, err := s.RemoveAllowlistEntry(context.Background(), "203.0.113.0/24", "bob", 1000)
	if err != nil || existed {
		t.Fatalf("RemoveAllowlistEntry: existed=%v err=%v, want false, nil", existed, err)
	}
	if n := countRows(t, s, "threat_allowlist_audit"); n != 0 {
		t.Fatalf("audit rows: got %d, want 0", n)
	}
}

// A client request is a permanent row, and nothing but an admin handling
// that exact CIDR ever deleted one, so an unbounded number of distinct
// CIDRs per system was an unbounded table -- read by the review queue and
// counted by the status page. The cap is per system and counts DISTINCT
// pending CIDRs, because that is what the queue is measured in.
func TestUpsertAllowlistRequestCapsDistinctCIDRsPerSystem(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const max = 3

	for i, cidr := range []string{"203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24"} {
		if _, err := s.UpsertAllowlistRequest(ctx, cidr, "sys-1", "please", int64(1000+i), max); err != nil {
			t.Fatalf("UpsertAllowlistRequest(%s): %v", cidr, err)
		}
	}

	_, err := s.UpsertAllowlistRequest(ctx, "203.0.113.128/25", "sys-1", "one too many", 4000, max)
	if !errors.Is(err, ErrTooManyAllowlistRequests) {
		t.Fatalf("over-cap request: got %v, want ErrTooManyAllowlistRequests", err)
	}

	// A system at its cap must still be able to refresh a CIDR it already
	// asked about: the request is idempotent per (cidr, system_id), it adds
	// no row, and refusing it would make a retry look like a new ask.
	if _, err := s.UpsertAllowlistRequest(ctx, "203.0.113.0/24", "sys-1", "still want it", 5000, max); err != nil {
		t.Fatalf("refresh at the cap: %v", err)
	}

	// The cap is per system: one noisy customer must not stop another from
	// asking.
	if _, err := s.UpsertAllowlistRequest(ctx, "203.0.113.128/25", "sys-2", "us too", 6000, max); err != nil {
		t.Fatalf("second system at the same CIDR: %v", err)
	}

	rows, err := s.PendingAllowlistRequests(ctx, 0)
	if err != nil {
		t.Fatalf("PendingAllowlistRequests: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("pending CIDRs: got %d, want 4 (three from sys-1 plus sys-2's)", len(rows))
	}
}

// The retention prune is what bounds the table when nobody ever reviews the
// queue. It drops by age, not by state: a request an admin handled is
// already gone (Approve/RejectAllowlistRequest), so what is left here is only ever
// unreviewed.
func TestPruneAllowlistRequestsDropsOnlyStaleRows(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.UpsertAllowlistRequest(ctx, "203.0.113.0/24", "sys-1", "old", 1000, 0); err != nil {
		t.Fatalf("seed old: %v", err)
	}
	if _, err := s.UpsertAllowlistRequest(ctx, "198.51.100.0/24", "sys-1", "fresh", 9000, 0); err != nil {
		t.Fatalf("seed fresh: %v", err)
	}

	pruned, err := s.PruneAllowlistRequests(ctx, 5000)
	if err != nil {
		t.Fatalf("PruneAllowlistRequests: %v", err)
	}
	if pruned != 1 {
		t.Fatalf("pruned: got %d, want 1", pruned)
	}

	rows, err := s.PendingAllowlistRequests(ctx, 0)
	if err != nil {
		t.Fatalf("PendingAllowlistRequests: %v", err)
	}
	if len(rows) != 1 || rows[0].CIDR != "198.51.100.0/24" {
		t.Fatalf("after the prune: got %+v, want only the fresh request", rows)
	}
}

// The limit is the review queue's read bound, and it must select the
// top-ranked CIDRs rather than an arbitrary slice of request rows: a limit
// applied to the flat (cidr, system_id) rows would cut a CIDR's systems in
// half and mis-rank the queue.
func TestPendingAllowlistRequestsHonoursTheLimit(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// popular: 3 systems. middling: 2. Two more with 1 each.
	seed := []struct {
		cidr string
		sys  string
		at   int64
	}{
		{"203.0.113.0/24", "sys-1", 1000},
		{"203.0.113.0/24", "sys-2", 1100},
		{"203.0.113.0/24", "sys-3", 1200},
		{"198.51.100.0/24", "sys-1", 2000},
		{"198.51.100.0/24", "sys-2", 2100},
		{"192.0.2.0/24", "sys-1", 3000},
		{"203.0.113.128/25", "sys-2", 4000},
	}
	for _, sd := range seed {
		if _, err := s.UpsertAllowlistRequest(ctx, sd.cidr, sd.sys, "reason for "+sd.cidr, sd.at, 0); err != nil {
			t.Fatalf("seed %s/%s: %v", sd.cidr, sd.sys, err)
		}
	}

	rows, err := s.PendingAllowlistRequests(ctx, 2)
	if err != nil {
		t.Fatalf("PendingAllowlistRequests: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows: got %d, want 2", len(rows))
	}
	if rows[0].CIDR != "203.0.113.0/24" || rows[0].DistinctSystems != 3 {
		t.Fatalf("rank 0: got %+v, want the 3-system CIDR with all 3 counted", rows[0])
	}
	if rows[1].CIDR != "198.51.100.0/24" || rows[1].DistinctSystems != 2 {
		t.Fatalf("rank 1: got %+v, want the 2-system CIDR with both counted", rows[1])
	}
	if len(rows[0].Reasons) != 1 || rows[0].Reasons[0] != "reason for 203.0.113.0/24" {
		t.Fatalf("reasons: got %+v", rows[0].Reasons)
	}
}

// refuseAudit makes every audit insert fail: a busy or locked database at the
// worst moment, after the change and before its record.
func refuseAudit(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.db.ExecContext(context.Background(), `
		CREATE TRIGGER refuse_audit BEFORE INSERT ON threat_allowlist_audit
		BEGIN SELECT RAISE(ABORT, 'audit refused'); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
}

func countRows(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	// #nosec G202 -- table is a test constant, never input.
	if err := s.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM `+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// An allowlist action and its audit row commit together or not at all.
// Written separately, a failed audit insert left an exemption added or
// removed with no record of who did it -- the one question the trail exists
// to answer.
func TestAnAllowlistActionWhoseAuditFailsChangesNothing(t *testing.T) {
	const cidr = "203.0.113.0/24"
	entry := AllowlistRow{CIDR: cidr, Reason: "partner scanner", CreatedBy: "alice", CreatedAt: 1000}
	ctx := context.Background()

	t.Run("add", func(t *testing.T) {
		s := newTestStore(t)
		refuseAudit(t, s)
		if err := s.AddAllowlistEntry(ctx, entry); err == nil {
			t.Fatal("AddAllowlistEntry succeeded with the audit refused")
		}
		if n := countRows(t, s, "threat_allowlist"); n != 0 {
			t.Fatalf("allowlist rows: got %d, want 0", n)
		}
	})

	t.Run("remove", func(t *testing.T) {
		s := newTestStore(t)
		if err := s.AddAllowlistEntry(ctx, entry); err != nil {
			t.Fatalf("AddAllowlistEntry: %v", err)
		}
		refuseAudit(t, s)
		if _, err := s.RemoveAllowlistEntry(ctx, cidr, "bob", 2000); err == nil {
			t.Fatal("RemoveAllowlistEntry succeeded with the audit refused")
		}
		if n := countRows(t, s, "threat_allowlist"); n != 1 {
			t.Fatalf("allowlist rows: got %d, want the entry still there", n)
		}
	})

	for _, decide := range []struct {
		name string
		fn   func(*Store) error
	}{
		{"approve", func(s *Store) error { return s.ApproveAllowlistRequest(ctx, entry, "ok") }},
		{"reject", func(s *Store) error { return s.RejectAllowlistRequest(ctx, cidr, "alice", "no", 1000) }},
	} {
		t.Run(decide.name, func(t *testing.T) {
			s := newTestStore(t)
			if _, err := s.UpsertAllowlistRequest(ctx, cidr, "sys-1", "please", 500, 0); err != nil {
				t.Fatalf("UpsertAllowlistRequest: %v", err)
			}
			refuseAudit(t, s)
			if err := decide.fn(s); err == nil {
				t.Fatalf("%s succeeded with the audit refused", decide.name)
			}
			for table, want := range map[string]int{
				"threat_allowlist":          0,
				"threat_allowlist_reviews":  0,
				"threat_allowlist_requests": 1,
			} {
				if n := countRows(t, s, table); n != want {
					t.Fatalf("%s rows: got %d, want %d", table, n, want)
				}
			}
		})
	}
}
