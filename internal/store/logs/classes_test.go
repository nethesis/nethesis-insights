// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package logs

import (
	"context"
	"errors"
	"strings"
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

	// A dismissal is undone by a new decision, never by recurrence.
	mustDo(t, s.SetClassVisibility(ctx, "v3:a", VisibilityDismissed, "op", 4000))
	seedClassFinding(t, s, "sys3", "fp-a-3", "v3:a", "low", "a", false, 5000)
	c, _, err = s.GetClass(ctx, "v3:a")
	mustDo(t, err)
	if c.Visibility != VisibilityDismissed {
		t.Fatalf("a recurrence undid a dismissal: %+v", c)
	}
	mustDo(t, s.SetClassVisibility(ctx, "v3:a", VisibilityOperator, "op", 6000))
	c, _, err = s.GetClass(ctx, "v3:a")
	mustDo(t, err)
	if c.Visibility != VisibilityOperator {
		t.Fatalf("keeping a dismissed class internal did not undo the dismissal: %+v", c)
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
	seedClassFinding(t, s, "sys1", "fp-d", "v3:d", "low", "d", false, 1000)
	mustDo(t, s.SetClassVisibility(ctx, "v3:b", VisibilityCustomer, "op", 2000))
	mustDo(t, s.SetClassVisibility(ctx, "v3:c", VisibilityOperator, "op", 2000))
	mustDo(t, s.SetClassVisibility(ctx, "v3:d", VisibilityDismissed, "op", 2001))
	rows, err := s.ClassStats(ctx)
	mustDo(t, err)
	want := ClassStatsRow{PromptVersion: "p1", Classes: 4, Pending: 1, Delivered: 1, Internal: 1, Dismissed: 1, Security: 1}
	if len(rows) != 1 || rows[0] != want {
		t.Fatalf("got %+v, want %+v", rows, want)
	}
	all, err := s.ListClassDecisions(ctx, 0)
	mustDo(t, err)
	if len(all) != 3 || all[0].Key != "v3:d" {
		t.Fatalf("decisions newest first: %+v", all)
	}
}

// A dismissed class is hidden from the customer like an internal one, on
// every system it appears on.
func TestDismissedFindingsNeverReachTheReadAPI(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedClassFinding(t, s, "sys1", "fp-a", "v3:a", "low", "a", false, 1000)
	seedClassFinding(t, s, "sys2", "fp-a-2", "v3:a", "low", "a", false, 1000)
	mustDo(t, s.SetClassVisibility(ctx, "v3:a", VisibilityCustomer, "op", 2000))
	mustDo(t, s.SetClassVisibility(ctx, "v3:a", VisibilityDismissed, "op", 3000))
	for _, sys := range []string{"sys1", "sys2"} {
		got, err := s.ListFindings(ctx, sys, 0, "")
		mustDo(t, err)
		if len(got) != 0 {
			t.Fatalf("%s: a dismissed finding reached the read API: %+v", sys, got)
		}
	}
}

// Security is a tag, not a visibility: a security class can be dismissed,
// and keeps its tag while it is.
func TestSecurityClassesCanBeDismissed(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedClassFinding(t, s, "sys1", "fp-sec", "v3:sec", "high", "s", true, 1000)
	mustDo(t, s.SetClassVisibility(ctx, "v3:sec", VisibilityDismissed, "op", 2000))
	c, _, err := s.GetClass(ctx, "v3:sec")
	mustDo(t, err)
	if c.Visibility != VisibilityDismissed || !c.Security {
		t.Fatalf("want dismissed and still tagged security, got %+v", c)
	}
	ds, err := s.ClassDecisions(ctx, "v3:sec")
	mustDo(t, err)
	if len(ds) != 1 || ds[0].Action != ActionDismiss || ds[0].Actor != "op" {
		t.Fatalf("a dismissal must be audited as dismiss: %+v", ds)
	}
}

// Hidden, not dropped: a recurrence still upserts the finding, and the
// prompt's input still lists it as known.
func TestDismissedClassKeepsItsFindings(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedClassFinding(t, s, "sys1", "fp-a", "v3:a", "low", "a", false, 1000)
	mustDo(t, s.SetClassVisibility(ctx, "v3:a", VisibilityDismissed, "op", 2000))
	out, err := s.UpsertFinding(ctx, model.Finding{SystemID: "sys1", Fingerprint: "fp-a", Severity: "low",
		Title: "a", Modules: []string{}, Evidence: []string{}, ClassKey: "v3:a", PromptVersion: "p1"}, 3000)
	mustDo(t, err)
	if out != OutcomeBumped {
		t.Fatalf("a recurrence of a dismissed finding must update it, got %q", out)
	}
	open, err := s.OpenFindings(ctx, "sys1")
	mustDo(t, err)
	if len(open) != 1 || open[0].Fingerprint != "fp-a" || open[0].OccurrenceCount != 2 || open[0].LastSeen != 3000 {
		t.Fatalf("OpenFindings must still return the dismissed finding: %+v", open)
	}
}

// A dismissed class leaves the queue: not pending, not in "all"; its own
// view and a lookup by key still find it.
func TestDismissedClassesLeaveTheQueue(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedClassFinding(t, s, "sys1", "fp-a", "v3:a", "low", "a", false, 1000)
	seedClassFinding(t, s, "sys1", "fp-b", "v3:b", "low", "b", false, 1000)
	mustDo(t, s.SetClassVisibility(ctx, "v3:a", VisibilityDismissed, "op", 2000))

	for name, f := range map[string]ClassFilter{
		"pending": {Visibility: VisibilityPending},
		"all":     {},
	} {
		rows, err := s.ListClasses(ctx, f)
		mustDo(t, err)
		if len(rows) != 1 || rows[0].Key != "v3:b" {
			t.Fatalf("%s view: want only v3:b, got %+v", name, rows)
		}
	}
	for name, f := range map[string]ClassFilter{
		"dismissed": {Visibility: VisibilityDismissed},
		"by key":    {Key: "v3:a"},
	} {
		rows, err := s.ListClasses(ctx, f)
		mustDo(t, err)
		if len(rows) != 1 || rows[0].Key != "v3:a" {
			t.Fatalf("%s: want v3:a, got %+v", name, rows)
		}
	}
}

// The operator's findings page and the systems page leave dismissed
// classes out too; a finding with no class is kept.
func TestListAllFindingsHidesDismissedClasses(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedClassFinding(t, s, "sys1", "fp-a", "v3:a", "low", "a", false, 1000)
	seedClassFinding(t, s, "sys1", "fp-b", "v3:b", "low", "b", false, 1000)
	seedClassFinding(t, s, "sys1", "fp-none", "", "low", "n", false, 1000)
	mustDo(t, s.SetClassVisibility(ctx, "v3:a", VisibilityDismissed, "op", 2000))

	all, err := s.ListAllFindings(ctx, "", "", "", "", "", 0)
	mustDo(t, err)
	got := fingerprints(all)
	if _, ok := got["fp-a"]; ok || len(got) != 2 {
		t.Fatalf("want fp-b and fp-none only, got %+v", all)
	}
	byKey, err := s.ListAllFindings(ctx, "", "", "", "v3:a", "", 0)
	mustDo(t, err)
	if len(byKey) != 0 {
		t.Fatalf("a dismissed finding is hidden even when searched for: %+v", byKey)
	}

	mustDo(t, s.UpsertSystem(ctx, System{SystemID: "sys1", FirstSeen: 1000, LastSeen: 1000}))
	systems, err := s.ListSystems(ctx)
	mustDo(t, err)
	if len(systems) != 1 || systems[0].OpenFindings != 2 || systems[0].Findings != 3 {
		t.Fatalf("want 2 open (dismissed left out) of 3 retained, got %+v", systems)
	}
}

// seedSortFixture stores three classes that each sort differently on every
// column, so a table of expected orders can tell the columns apart:
//
//	v3:a  "alpha"   [mail]     low       1 system  1 finding   last 3000  customer
//	v3:b  "Bravo"   [host]     critical  2 systems 2 findings  last 1000  pending
//	v3:c  "charlie" [web, x]   medium    1 system  3 findings  last 2000  operator
func seedSortFixture(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	seed := func(system, fp, class, severity, title string, modules []string, now int64) {
		f := model.Finding{SystemID: system, Fingerprint: fp, Severity: severity, Title: title,
			Modules: modules, Evidence: []string{}, ClassKey: class, PromptVersion: "p1"}
		if _, err := s.UpsertFinding(ctx, f, now); err != nil {
			t.Fatalf("upsert %s: %v", fp, err)
		}
	}
	seed("sys1", "fp-a", "v3:a", "low", "alpha", []string{"mail"}, 3000)
	seed("sys1", "fp-b1", "v3:b", "critical", "Bravo", []string{""}, 900)
	seed("sys2", "fp-b2", "v3:b", "critical", "Bravo", []string{""}, 1000)
	seed("sys1", "fp-c1", "v3:c", "medium", "charlie", []string{"web", "x"}, 1500)
	seed("sys1", "fp-c2", "v3:c", "medium", "charlie", []string{"web", "x"}, 1600)
	seed("sys1", "fp-c3", "v3:c", "medium", "charlie", []string{"web", "x"}, 2000)
	mustDo(t, s.SetClassVisibility(ctx, "v3:a", VisibilityCustomer, "op", 4000))
	mustDo(t, s.SetClassVisibility(ctx, "v3:c", VisibilityOperator, "op", 4000))
}

func classKeys(rows []ClassRow) string {
	keys := make([]string, len(rows))
	for i, r := range rows {
		keys[i] = r.Key
	}
	return strings.Join(keys, ",")
}

// Every column sorts in SQL, in both directions, on that column alone:
// pending-first is the default order's rule, not a column's, so v3:b (the
// only pending class) lands wherever its value puts it.
func TestListClassesSortsOnEveryColumn(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedSortFixture(t, s)

	for _, tc := range []struct {
		sort, dir, want string
	}{
		// Titles compare case-insensitively: "Bravo" is not before "alpha".
		{ClassSortTitle, SortAsc, "v3:a,v3:b,v3:c"},
		{ClassSortTitle, SortDesc, "v3:c,v3:b,v3:a"},
		// The host bucket sorts first: it is the empty module id.
		{ClassSortModule, SortAsc, "v3:b,v3:a,v3:c"},
		{ClassSortModule, SortDesc, "v3:c,v3:a,v3:b"},
		// Descending severity is most severe first.
		{ClassSortSeverity, SortDesc, "v3:b,v3:c,v3:a"},
		{ClassSortSeverity, SortAsc, "v3:a,v3:c,v3:b"},
		{ClassSortVisibility, SortAsc, "v3:a,v3:c,v3:b"},
		{ClassSortVisibility, SortDesc, "v3:b,v3:c,v3:a"},
		// v3:a and v3:c tie on one system; class_key breaks the tie.
		{ClassSortSystems, SortDesc, "v3:b,v3:a,v3:c"},
		{ClassSortSystems, SortAsc, "v3:a,v3:c,v3:b"},
		{ClassSortFindings, SortDesc, "v3:c,v3:b,v3:a"},
		{ClassSortFindings, SortAsc, "v3:a,v3:b,v3:c"},
		{ClassSortLastSeen, SortDesc, "v3:a,v3:c,v3:b"},
		{ClassSortLastSeen, SortAsc, "v3:b,v3:c,v3:a"},
	} {
		rows, err := s.ListClasses(ctx, ClassFilter{Sort: tc.sort, Dir: tc.dir})
		mustDo(t, err)
		if got := classKeys(rows); got != tc.want {
			t.Errorf("sort %s %s: got %s, want %s", tc.sort, tc.dir, got, tc.want)
		}
	}
}

// A decided class whose findings were all pruned has no title and no module;
// it sorts last in both directions rather than heading an A-to-Z sort.
func TestListClassesWithoutFindingsSortLast(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedSortFixture(t, s)
	_, err := s.db.ExecContext(ctx, `INSERT INTO finding_classes
		(class_key, visibility, security, first_seen, last_seen) VALUES (?, ?, 0, 1, 1)`,
		"v3:0", VisibilityCustomer)
	mustDo(t, err)
	for _, tc := range []struct {
		sort, dir, want string
	}{
		{ClassSortTitle, SortAsc, "v3:a,v3:b,v3:c,v3:0"},
		{ClassSortTitle, SortDesc, "v3:c,v3:b,v3:a,v3:0"},
		{ClassSortModule, SortAsc, "v3:b,v3:a,v3:c,v3:0"},
		{ClassSortModule, SortDesc, "v3:c,v3:a,v3:b,v3:0"},
	} {
		rows, err := s.ListClasses(ctx, ClassFilter{Sort: tc.sort, Dir: tc.dir})
		mustDo(t, err)
		if got := classKeys(rows); got != tc.want {
			t.Errorf("sort %s %s: got %s, want %s", tc.sort, tc.dir, got, tc.want)
		}
	}
}

// The sort runs before the limit: a one-row page sorted by findings is the
// class with the most findings in the whole queue, not the first row of the
// default order.
func TestListClassesSortsBeforeTheLimit(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedSortFixture(t, s)
	rows, err := s.ListClasses(ctx, ClassFilter{Sort: ClassSortFindings, Dir: SortDesc, Limit: 1})
	mustDo(t, err)
	if got := classKeys(rows); got != "v3:c" {
		t.Fatalf("got %s, want v3:c", got)
	}
}

// Anything but a known sort key and direction leaves the default order:
// pending first, then systems, findings, last seen.
func TestListClassesUnknownSortKeepsTheDefaultOrder(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedSortFixture(t, s)
	for _, f := range []ClassFilter{
		{},
		{Sort: "bogus", Dir: SortAsc},
		{Sort: ClassSortTitle, Dir: "sideways"},
		{Sort: ClassSortTitle},
		{Sort: "title; DROP TABLE findings", Dir: SortDesc},
	} {
		rows, err := s.ListClasses(ctx, f)
		mustDo(t, err)
		if got := classKeys(rows); got != "v3:b,v3:c,v3:a" {
			t.Errorf("%+v: got %s, want the default v3:b,v3:c,v3:a", f, got)
		}
	}
}
