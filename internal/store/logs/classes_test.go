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
