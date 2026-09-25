// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package logs

import (
	"context"
	"errors"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/model"
)

// seedClassFinding stores one open finding in class on systemID.
func seedClassFinding(t *testing.T, s *Store, systemID, fingerprint, class, severity, title string, security bool, now int64) {
	t.Helper()
	f := model.Finding{SystemID: systemID, Fingerprint: fingerprint, Severity: severity, Title: title,
		Modules: []string{}, Evidence: []string{}, ClassKey: class, Security: security, PromptVersion: "p1"}
	if _, err := s.UpsertFinding(context.Background(), f, now); err != nil {
		t.Fatalf("upsert %s: %v", fingerprint, err)
	}
}

func mustDo(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func fingerprints(fs []model.Finding) map[string]model.Finding {
	out := make(map[string]model.Finding, len(fs))
	for _, f := range fs {
		out[f.Fingerprint] = f
	}
	return out
}

// Only a delivered class reaches the customer: pending (born that way) and
// internal are withheld, on every system the class appears on.
func TestOperatorOnlyFindingsNeverReachTheReadAPI(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedClassFinding(t, s, "sys1", "fp-pending", "v3:pending", "low", "p", false, 1000)
	seedClassFinding(t, s, "sys1", "fp-internal", "v3:internal", "low", "i", false, 1000)
	seedClassFinding(t, s, "sys1", "fp-delivered", "v3:delivered", "low", "d", false, 1000)
	seedClassFinding(t, s, "sys2", "fp-delivered-2", "v3:delivered", "low", "d", false, 1000)
	mustDo(t, s.SetClassVisibility(ctx, "v3:internal", VisibilityOperator, "op", 2000))
	mustDo(t, s.SetClassVisibility(ctx, "v3:delivered", VisibilityCustomer, "op", 2000))

	for sys, want := range map[string]string{"sys1": "fp-delivered", "sys2": "fp-delivered-2"} {
		got, err := s.ListFindings(ctx, sys, 0, "")
		mustDo(t, err)
		if len(got) != 1 || got[0].Fingerprint != want {
			t.Fatalf("%s: want only %s, got %+v", sys, want, got)
		}
	}
	all, err := s.ListAllFindings(ctx, "sys1", "", "", "", "", 0)
	mustDo(t, err)
	if len(all) != 3 {
		t.Fatalf("the operator must see every finding, got %d", len(all))
	}
	if v := fingerprints(all)["fp-internal"].Visibility; v != VisibilityOperator {
		t.Fatalf("operator view must carry the class visibility, got %q", v)
	}
}

func TestFindingWithoutAClassIsNeverDelivered(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedClassFinding(t, s, "sys1", "fp-none", "", "low", "n", false, 1000)
	got, err := s.ListFindings(ctx, "sys1", 0, "")
	mustDo(t, err)
	if len(got) != 0 {
		t.Fatalf("a finding with no class reached the read API: %+v", got)
	}
	var n int
	mustDo(t, s.db.QueryRowContext(ctx, `SELECT count(*) FROM finding_classes`).Scan(&n))
	if n != 0 {
		t.Fatalf("an empty class key must not create a class row, got %d", n)
	}
}

// Security is a tag, not a bypass: a security class waits like any other
// and can be kept internal.
func TestSecurityFindingsWaitForReview(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedClassFinding(t, s, "sys1", "fp-sec", "v3:sec", "high", "s", true, 1000)
	c, ok, err := s.GetClass(ctx, "v3:sec")
	mustDo(t, err)
	if !ok || c.Visibility != VisibilityPending || !c.Security {
		t.Fatalf("a security class must be born pending and tagged, got %+v", c)
	}
	got, err := s.ListFindings(ctx, "sys1", 0, "")
	mustDo(t, err)
	if len(got) != 0 {
		t.Fatal("a pending security finding reached the read API")
	}
	mustDo(t, s.SetClassVisibility(ctx, "v3:sec", VisibilityOperator, "op", 2000))
}

func TestSecurityTagReachesTheReadAPI(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedClassFinding(t, s, "sys1", "fp-a", "v3:a", "low", "a", false, 1000)
	mustDo(t, s.SetClassVisibility(ctx, "v3:a", VisibilityCustomer, "op", 2000))
	mustDo(t, s.SetClassSecurity(ctx, "v3:a", true, "op", 2000))
	got, err := s.ListFindings(ctx, "sys1", 0, "")
	mustDo(t, err)
	if len(got) != 1 || !got[0].Security {
		t.Fatalf("the operator's security tag must reach the customer, got %+v", got)
	}
}

// Recurrence must not undo the operator: the edge's classification seeds a
// new class only.
func TestSecurityTagSurvivesRecurrence(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedClassFinding(t, s, "sys1", "fp-sec", "v3:sec", "high", "s", true, 1000)
	mustDo(t, s.SetClassSecurity(ctx, "v3:sec", false, "op", 2000))
	seedClassFinding(t, s, "sys1", "fp-sec", "v3:sec", "high", "s", true, 3000)
	seedClassFinding(t, s, "sys2", "fp-sec-2", "v3:sec", "high", "s", true, 3000)
	c, _, err := s.GetClass(ctx, "v3:sec")
	mustDo(t, err)
	if c.Security {
		t.Fatal("a recurrence re-tagged a class the operator untagged")
	}
	if c.LastSeen != 3000 || c.FirstSeen != 1000 {
		t.Fatalf("first/last seen: got %d/%d", c.FirstSeen, c.LastSeen)
	}
}

// The override and the doc reference reach the customer; the stored
// severity -- the one prompt.Render prints -- does not change.
func TestSeverityOverrideIsAppliedOnlyWhenReadForTheCustomer(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedClassFinding(t, s, "sys1", "fp-a", "v3:a", "low", "a", false, 1000)
	mustDo(t, s.SetClassVisibility(ctx, "v3:a", VisibilityCustomer, "op", 2000))
	mustDo(t, s.SetClassSeverity(ctx, "v3:a", "critical", "op", 2000))
	mustDo(t, s.SetClassDocRef(ctx, "v3:a", "https://docs.example/x", "op", 2000))

	got, err := s.ListFindings(ctx, "sys1", 0, "")
	mustDo(t, err)
	if len(got) != 1 || got[0].Severity != "critical" || got[0].DocRef != "https://docs.example/x" {
		t.Fatalf("customer read: %+v", got)
	}
	open, err := s.OpenFindings(ctx, "sys1")
	mustDo(t, err)
	if len(open) != 1 || open[0].Severity != "low" || open[0].DocRef != "" || open[0].Visibility != "" {
		t.Fatalf("the prompt's input must carry no decision: %+v", open)
	}
	if err := s.SetClassSeverity(ctx, "v3:a", "urgent", "op", 2000); !errors.Is(err, ErrInvalidSeverity) {
		t.Fatalf("want ErrInvalidSeverity, got %v", err)
	}
}

func TestVisibilityNeverReturnsToPending(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedClassFinding(t, s, "sys1", "fp-a", "v3:a", "low", "a", false, 1000)
	if err := s.SetClassVisibility(ctx, "v3:a", VisibilityPending, "op", 2000); !errors.Is(err, ErrInvalidVisibility) {
		t.Fatalf("want ErrInvalidVisibility, got %v", err)
	}

	mustDo(t, s.SetClassVisibility(ctx, "v3:a", VisibilityCustomer, "op", 2000))
	// A recurrence of the delivered finding, and a new system raising the
	// same class for the first time, must not reset it back to pending --
	// UpsertFinding's ON CONFLICT for finding_classes only ever bumps
	// last_seen.
	seedClassFinding(t, s, "sys1", "fp-a", "v3:a", "low", "a", false, 3000)
	seedClassFinding(t, s, "sys2", "fp-a-2", "v3:a", "low", "a", false, 3000)

	c, ok, err := s.GetClass(ctx, "v3:a")
	mustDo(t, err)
	if !ok || c.Visibility != VisibilityCustomer {
		t.Fatalf("visibility reverted to pending on recurrence: %+v", c)
	}
}

// The queue lists pending classes first, whatever their systems/findings
// counts -- an operator reviewing "all" must not have to scroll past
// already-decided classes to find the one still waiting.
func TestListClassesRanksPendingFirst(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedClassFinding(t, s, "sys1", "fp-many-1", "v3:many", "low", "m", false, 1000)
	seedClassFinding(t, s, "sys2", "fp-many-2", "v3:many", "low", "m", false, 1000)
	seedClassFinding(t, s, "sys1", "fp-few", "v3:few", "low", "f", false, 1000)
	mustDo(t, s.SetClassVisibility(ctx, "v3:many", VisibilityCustomer, "op", 2000))

	rows, err := s.ListClasses(ctx, ClassFilter{})
	mustDo(t, err)
	if len(rows) != 2 || rows[0].Key != "v3:few" || rows[1].Key != "v3:many" {
		t.Fatalf("pending class did not rank first: %+v", rows)
	}
}

// The queue's Severity column is the most severe stored severity across the
// class's findings, not the latest finding's own severity.
func TestListClassesCarriesTheMostSevereFinding(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedClassFinding(t, s, "sys1", "fp-lo", "v3:mixed", "low", "lo", false, 1000)
	seedClassFinding(t, s, "sys2", "fp-hi", "v3:mixed", "high", "hi", false, 2000)

	rows, err := s.ListClasses(ctx, ClassFilter{})
	mustDo(t, err)
	if len(rows) != 1 || rows[0].Severity != "high" {
		t.Fatalf("want Severity=high, got %+v", rows)
	}
}

func TestDecisionOnAnUnknownClassIsRefused(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	for name, err := range map[string]error{
		"visibility": s.SetClassVisibility(ctx, "v3:nope", VisibilityCustomer, "op", 1),
		"security":   s.SetClassSecurity(ctx, "v3:nope", true, "op", 1),
		"severity":   s.SetClassSeverity(ctx, "v3:nope", "low", "op", 1),
		"doc_ref":    s.SetClassDocRef(ctx, "v3:nope", "", "op", 1),
	} {
		if !errors.Is(err, ErrUnknownClass) {
			t.Errorf("%s: want ErrUnknownClass, got %v", name, err)
		}
	}
	var n int
	mustDo(t, s.db.QueryRowContext(ctx, `SELECT count(*) FROM class_decisions`).Scan(&n))
	if n != 0 {
		t.Fatalf("a refused decision was audited: %d rows", n)
	}
}

func TestClassDecisionIsAudited(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedClassFinding(t, s, "sys1", "fp-a", "v3:a", "low", "a", false, 1000)
	mustDo(t, s.SetClassVisibility(ctx, "v3:a", VisibilityCustomer, "alice", 2000))
	mustDo(t, s.SetClassSecurity(ctx, "v3:a", true, "bob", 2001))
	mustDo(t, s.SetClassSeverity(ctx, "v3:a", "high", "carol", 2002))
	mustDo(t, s.SetClassDocRef(ctx, "v3:a", "https://d.example", "dan", 2003))
	ds, err := s.ClassDecisions(ctx, "v3:a")
	mustDo(t, err)
	want := []ClassDecision{
		{Key: "v3:a", Actor: "alice", Action: ActionDeliver, PromptVersion: "p1", CreatedAt: 2000},
		{Key: "v3:a", Actor: "bob", Action: ActionSecurity, Detail: "on", PromptVersion: "p1", CreatedAt: 2001},
		{Key: "v3:a", Actor: "carol", Action: ActionSeverity, Detail: "high", PromptVersion: "p1", CreatedAt: 2002},
		{Key: "v3:a", Actor: "dan", Action: ActionDocRef, Detail: "https://d.example", PromptVersion: "p1", CreatedAt: 2003},
	}
	if len(ds) != len(want) {
		t.Fatalf("got %d decisions, want %d: %+v", len(ds), len(want), ds)
	}
	for i := range want {
		if ds[i] != want[i] {
			t.Errorf("decision %d: got %+v, want %+v", i, ds[i], want[i])
		}
	}
}

func TestListClassesRanksBySystemsAndCarriesTheirContext(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	// v3:wide on two systems, v3:narrow on one system twice.
	seedClassFinding(t, s, "sys1", "fp-w1", "v3:wide", "low", "Wide old title", false, 1000)
	seedClassFinding(t, s, "sys2", "fp-w2", "v3:wide", "low", "Wide new title", false, 2000)
	seedClassFinding(t, s, "sys1", "fp-n1", "v3:narrow", "low", "Narrow", false, 1000)
	seedClassFinding(t, s, "sys1", "fp-n2", "v3:narrow", "low", "Narrow", false, 3000)
	mustDo(t, s.SetClassVisibility(ctx, "v3:narrow", VisibilityOperator, "op", 4000))

	rows, err := s.ListClasses(ctx, ClassFilter{})
	mustDo(t, err)
	if len(rows) != 2 || rows[0].Key != "v3:wide" || rows[0].Systems != 2 || rows[0].Findings != 2 {
		t.Fatalf("ranking: %+v", rows)
	}
	if got := rows[0].Titles; len(got) != 2 || got[0] != "Wide new title" {
		t.Fatalf("titles must be distinct, newest first: %v", got)
	}
	if rows[1].Titles[0] != "Narrow" || len(rows[1].Titles) != 1 {
		t.Fatalf("duplicate titles must collapse: %v", rows[1].Titles)
	}

	pending, err := s.ListClasses(ctx, ClassFilter{Visibility: VisibilityPending})
	mustDo(t, err)
	if len(pending) != 1 || pending[0].Key != "v3:wide" {
		t.Fatalf("visibility filter: %+v", pending)
	}
	byKey, err := s.ListClasses(ctx, ClassFilter{Key: "v3:nar"})
	mustDo(t, err)
	if len(byKey) != 1 || byKey[0].Key != "v3:narrow" {
		t.Fatalf("key prefix filter: %+v", byKey)
	}
}

func TestClassStatsPartitionsEachPromptVersion(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedClassFinding(t, s, "sys1", "fp-a", "v3:a", "low", "a", false, 1000)
	seedClassFinding(t, s, "sys1", "fp-b", "v3:b", "low", "b", true, 1000)
	seedClassFinding(t, s, "sys1", "fp-c", "v3:c", "low", "c", false, 1000)
	mustDo(t, s.SetClassVisibility(ctx, "v3:b", VisibilityCustomer, "op", 2000))
	mustDo(t, s.SetClassVisibility(ctx, "v3:c", VisibilityOperator, "op", 2000))
	rows, err := s.ClassStats(ctx)
	mustDo(t, err)
	want := ClassStatsRow{PromptVersion: "p1", Classes: 3, Pending: 1, Delivered: 1, Internal: 1, Security: 1}
	if len(rows) != 1 || rows[0] != want {
		t.Fatalf("got %+v, want %+v", rows, want)
	}
	all, err := s.ListClassDecisions(ctx, 0)
	mustDo(t, err)
	if len(all) != 2 || all[0].Key != "v3:c" {
		t.Fatalf("decisions newest first: %+v", all)
	}
}
