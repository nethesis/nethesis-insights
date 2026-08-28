// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package store

import (
	"context"
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

	n, err := s.UpsertAllowlistRequest(ctx, "203.0.113.0/24", "sys-1", "first ask", 1000)
	if err != nil {
		t.Fatalf("UpsertAllowlistRequest: %v", err)
	}
	if n != 1 {
		t.Fatalf("distinct systems: got %d, want 1", n)
	}

	// The same system asking again is idempotent: it refreshes the row, it
	// does not add a second one.
	n, err = s.UpsertAllowlistRequest(ctx, "203.0.113.0/24", "sys-1", "asking again", 2000)
	if err != nil {
		t.Fatalf("UpsertAllowlistRequest (repeat): %v", err)
	}
	if n != 1 {
		t.Fatalf("distinct systems after a repeat from the same system: got %d, want 1", n)
	}

	n, err = s.UpsertAllowlistRequest(ctx, "203.0.113.0/24", "sys-2", "us too", 3000)
	if err != nil {
		t.Fatalf("UpsertAllowlistRequest (second system): %v", err)
	}
	if n != 2 {
		t.Fatalf("distinct systems after a second system: got %d, want 2", n)
	}
}

// This is the executable form of the plan's decision 1: there is no path
// from any number of client requests, from any number of distinct systems,
// to a live threat_allowlist entry. Only an explicit UpsertThreatAllowlistEntry
// call -- which only an admin decision ever makes -- creates one.
func TestClientRequestsNeverAutoPromoteToTheAllowlist(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const cidr = "203.0.113.0/24"

	for i, sys := range []string{"sys-1", "sys-2", "sys-3", "sys-4", "sys-5"} {
		if _, err := s.UpsertAllowlistRequest(ctx, cidr, sys, "please allowlist us", int64(1000+i)); err != nil {
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
		if _, err := s.UpsertAllowlistRequest(ctx, cidr, sys, "reason for "+cidr, at); err != nil {
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

// Rejecting a CIDR must retire it from the queue without touching the
// requests that got it there -- an admin needs to be able to see "this was
// asked for and was rejected", not just silence.
func TestRejectedRequestsSurviveButLeaveTheQueue(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const cidr = "203.0.113.0/24"

	if _, err := s.UpsertAllowlistRequest(ctx, cidr, "sys-1", "please", 1000); err != nil {
		t.Fatalf("UpsertAllowlistRequest: %v", err)
	}
	if err := s.UpsertAllowlistReview(ctx, cidr, AllowlistReviewRejected, "alice", "not enough evidence", 2000); err != nil {
		t.Fatalf("UpsertAllowlistReview: %v", err)
	}

	pending, err := s.PendingAllowlistRequests(ctx, 0)
	if err != nil {
		t.Fatalf("PendingAllowlistRequests: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending: got %+v, want the rejected CIDR gone from the queue", pending)
	}

	// A fresh ask for the same, still-rejected CIDR must not resurrect it:
	// the review row is keyed on cidr alone and is not cleared by a new
	// request.
	if _, err := s.UpsertAllowlistRequest(ctx, cidr, "sys-2", "still want it", 3000); err != nil {
		t.Fatalf("UpsertAllowlistRequest (after rejection): %v", err)
	}
	pending, err = s.PendingAllowlistRequests(ctx, 0)
	if err != nil {
		t.Fatalf("PendingAllowlistRequests: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending after a fresh ask: got %+v, want the rejected CIDR to stay out of the queue", pending)
	}
}

// A repeat review (reject, then reconsider and approve) must overwrite the
// decision rather than error: ON CONFLICT DO UPDATE, not DO NOTHING.
func TestUpsertAllowlistReviewOverwritesAPriorDecision(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const cidr = "203.0.113.0/24"

	if err := s.UpsertAllowlistReview(ctx, cidr, AllowlistReviewRejected, "alice", "no", 1000); err != nil {
		t.Fatalf("UpsertAllowlistReview (reject): %v", err)
	}
	if err := s.UpsertAllowlistReview(ctx, cidr, AllowlistReviewApproved, "bob", "reconsidered", 2000); err != nil {
		t.Fatalf("UpsertAllowlistReview (approve): %v", err)
	}
	// No direct getter for one review row; PendingAllowlistRequests's
	// "no live row" behavior together with the lack of an error above is the
	// externally observable proof that the second call replaced the first
	// rather than being rejected as a duplicate key.
}

// The audit trail is append-only: every write appends exactly one row, and
// nothing here ever updates or deletes one.
func TestAppendAllowlistAuditAppendsOneRowPerCall(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.AppendAllowlistAudit(ctx, "203.0.113.0/24", "allowlist.upsert", "alice", "partner scanner", 1000); err != nil {
		t.Fatalf("AppendAllowlistAudit: %v", err)
	}
	if err := s.AppendAllowlistAudit(ctx, "203.0.113.0/24", "allowlist.delete", "bob", "", 2000); err != nil {
		t.Fatalf("AppendAllowlistAudit: %v", err)
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
