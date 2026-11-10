// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package logs

import (
	"context"
	"reflect"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/decide"
	"github.com/nethesis/nethesis-insights/internal/model"
)

func classVisibility(t *testing.T, s *Store, key string) string {
	t.Helper()
	var v string
	if err := s.db.QueryRowContext(context.Background(),
		`SELECT visibility FROM finding_classes WHERE class_key = ?`, key).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func countRows(t *testing.T, s *Store, q string, args ...any) int {
	t.Helper()
	var n int
	if err := s.db.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func appliedAsk(key, choice string) DecisionAsk {
	return DecisionAsk{Key: key, RulesVersion: "r5", Model: "m1", Result: AskApplied, Choice: choice,
		Confidence: 0.95, Usage: decide.Usage{InputTokens: 10, CachedTokens: 4, OutputTokens: 2},
		CostMicros: 7, Detail: "rules r5", At: 5000}
}

func TestRecordAppliedAskDecidesClass(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedEvidenceFinding(t, s, "a", "v3:a", nil, []string{"x"}, 1000)
	got, err := s.RecordDecisionAsk(ctx, appliedAsk("v3:a", VisibilityOperator))
	mustDo(t, err)
	if got != AskApplied || classVisibility(t, s, "v3:a") != VisibilityOperator {
		t.Fatalf("result %q vis %q", got, classVisibility(t, s, "v3:a"))
	}
	var actor, action, detail, pv string
	mustDo(t, s.db.QueryRowContext(ctx,
		`SELECT actor, action, detail, prompt_version FROM class_decisions WHERE class_key = 'v3:a'`).Scan(&actor, &action, &detail, &pv))
	if actor != ActorDecisionsAPI || action != ActionInternal || detail != "rules r5" || pv != "p1" {
		t.Fatalf("decision %q %q %q %q", actor, action, detail, pv)
	}
	if n := countRows(t, s, `SELECT count(*) FROM class_decision_asks WHERE result = 'applied' AND choice = 'operator'`); n != 1 {
		t.Fatalf("asks %d", n)
	}
}

func TestUnsureDecisionStaysPending(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedEvidenceFinding(t, s, "a", "v3:a", nil, []string{"x"}, 1000)
	a := appliedAsk("v3:a", VisibilityCustomer)
	a.Result = AskUnsure
	got, err := s.RecordDecisionAsk(ctx, a)
	mustDo(t, err)
	f := DecisionAsk{Key: "v3:a", RulesVersion: "r5", Model: "m2", Result: AskFailed}
	_, err = s.RecordDecisionAsk(ctx, f)
	mustDo(t, err)
	if got != AskUnsure || classVisibility(t, s, "v3:a") != VisibilityPending {
		t.Fatal("unsure changed the class")
	}
	if n := countRows(t, s, `SELECT count(*) FROM class_decisions`); n != 0 {
		t.Fatalf("decision rows %d", n)
	}
	if n := countRows(t, s, `SELECT count(*) FROM class_decision_asks WHERE result = 'failed' AND choice IS NULL AND confidence IS NULL`); n != 1 {
		t.Fatal("failed ask should store NULL choice and confidence")
	}
}

func TestOperatorWinsTheRace(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedEvidenceFinding(t, s, "a", "v3:a", nil, []string{"x"}, 1000)
	mustDo(t, s.SetClassVisibility(ctx, "v3:a", VisibilityDismissed, "giacomo", 2000))
	got, err := s.RecordDecisionAsk(ctx, appliedAsk("v3:a", VisibilityCustomer))
	mustDo(t, err)
	if got != AskLate || classVisibility(t, s, "v3:a") != VisibilityDismissed {
		t.Fatalf("result %q vis %q", got, classVisibility(t, s, "v3:a"))
	}
	if n := countRows(t, s, `SELECT count(*) FROM class_decisions WHERE class_key = 'v3:a'`); n != 1 {
		t.Fatalf("decision rows %d", n)
	}
	if n := countRows(t, s, `SELECT count(*) FROM class_decision_asks WHERE result = 'late'`); n != 1 {
		t.Fatal("late ask not stored")
	}
}

func TestCandidatesSkipAskedUnderSameVersionAndModel(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedEvidenceFinding(t, s, "a", "v3:a", []string{"mod"}, []string{"x"}, 1000)
	a := appliedAsk("v3:a", VisibilityCustomer)
	a.Result = AskUnsure
	_, err := s.RecordDecisionAsk(ctx, a)
	mustDo(t, err)
	for _, c := range []struct {
		v, m string
		n    int
	}{{"r5", "m1", 0}, {"r6", "m1", 1}, {"r5", "m2", 1}} {
		got, err := s.DecisionCandidates(ctx, c.v, c.m, "", 10)
		mustDo(t, err)
		if len(got) != c.n {
			t.Fatalf("%s/%s: %d candidates", c.v, c.m, len(got))
		}
	}
}

func TestCandidateCarriesDescriptionAndVector(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedEvidenceFinding(t, s, "a", "v3:a", []string{"mod"}, []string{"x"}, 1000)
	seedEvidenceFinding(t, s, "b", "v3:b", nil, []string{"y"}, 2000)
	mustDo(t, s.SetClassGroup(ctx, group("v3:a", "v3:a", "e1", 1)))
	mustDo(t, s.SetClassGroup(ctx, group("v3:b", "v3:b", "e0", 1)))
	got, err := s.DecisionCandidates(ctx, "r5", "m1", "e1", 10)
	mustDo(t, err)
	if len(got) != 2 || got[0].Key != "v3:a" || got[1].Key != "v3:b" {
		t.Fatalf("%+v", got)
	}
	if !reflect.DeepEqual(got[0].Vector, []float32{1, 0.5}) || got[1].Vector != nil {
		t.Fatalf("vectors %v / %v", got[0].Vector, got[1].Vector)
	}
	if want := decide.Describe([]string{"mod"}, []string{"x"}, "a", ""); !reflect.DeepEqual(got[0].Class, want) {
		t.Fatalf("class %+v, want %+v", got[0].Class, want)
	}
	got, err = s.DecisionCandidates(ctx, "r5", "m1", "", 1)
	mustDo(t, err)
	if len(got) != 1 || got[0].Vector != nil {
		t.Fatalf("limit or empty embed model: %+v", got)
	}
}

func TestDecidedClassIsNeverAskedAgain(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedEvidenceFinding(t, s, "a", "v3:a", nil, []string{"x"}, 1000)
	mustDo(t, s.SetClassVisibility(ctx, "v3:a", VisibilityCustomer, "giacomo", 2000))
	got, err := s.DecisionCandidates(ctx, "r9", "m9", "", 10)
	mustDo(t, err)
	if len(got) != 0 {
		t.Fatalf("decided class offered: %+v", got)
	}
}

func TestCandidatesExcludeSecurityClasses(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	f := model.Finding{SystemID: "sys1", Fingerprint: "sec", Severity: "low", Title: "t", Security: true,
		Modules: []string{}, Evidence: []string{"x"}, ClassKey: "v3:s", PromptVersion: "p1"}
	_, err := s.UpsertFinding(ctx, f, 1000)
	mustDo(t, err)
	got, err := s.DecisionCandidates(ctx, "r5", "m1", "", 10)
	mustDo(t, err)
	if len(got) != 0 {
		t.Fatalf("security class offered: %+v", got)
	}
	sec, err := s.PendingSecurityClasses(ctx)
	mustDo(t, err)
	if !reflect.DeepEqual(sec, []string{"v3:s"}) {
		t.Fatalf("security classes %v", sec)
	}
}

func TestPrecedentsExcludeAutomaticDecisions(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	for i, k := range []string{"v3:auto", "v3:person", "v3:changed", "v3:pending", "v3:unembedded"} {
		seedEvidenceFinding(t, s, k, k, nil, []string{k}, int64(1000+i))
		if k != "v3:unembedded" {
			mustDo(t, s.SetClassGroup(ctx, group(k, k, "e1", 1)))
		}
	}
	_, err := s.RecordDecisionAsk(ctx, appliedAsk("v3:auto", VisibilityCustomer))
	mustDo(t, err)
	mustDo(t, s.SetClassVisibility(ctx, "v3:person", VisibilityDismissed, "giacomo", 2000))
	_, err = s.RecordDecisionAsk(ctx, appliedAsk("v3:changed", VisibilityCustomer))
	mustDo(t, err)
	mustDo(t, s.SetClassVisibility(ctx, "v3:changed", VisibilityOperator, "giacomo", 6000))
	mustDo(t, s.SetClassVisibility(ctx, "v3:unembedded", VisibilityOperator, "giacomo", 2000))

	got, err := s.DecisionPrecedents(ctx, "e1")
	mustDo(t, err)
	dec := map[string]string{}
	for _, c := range got {
		dec[c.Class.Evidence[0]] = c.Decision
		if c.Vector == nil {
			t.Fatal("precedent without vector")
		}
	}
	want := map[string]string{"v3:person": VisibilityDismissed, "v3:changed": VisibilityOperator}
	if !reflect.DeepEqual(dec, want) {
		t.Fatalf("precedents %v, want %v", dec, want)
	}
	if got, err := s.DecisionPrecedents(ctx, ""); err != nil || got != nil {
		t.Fatalf("empty model: %v %v", got, err)
	}
}

func TestDeliverSecurityClass(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	f := model.Finding{SystemID: "sys1", Fingerprint: "sec", Severity: "low", Title: "t", Security: true,
		Modules: []string{}, Evidence: []string{"x"}, ClassKey: "v3:s", PromptVersion: "p1"}
	_, err := s.UpsertFinding(ctx, f, 1000)
	mustDo(t, err)
	ok, err := s.DeliverSecurityClass(ctx, "v3:s", 2000)
	mustDo(t, err)
	if !ok || classVisibility(t, s, "v3:s") != VisibilityCustomer {
		t.Fatal("not delivered")
	}
	var actor, detail string
	mustDo(t, s.db.QueryRowContext(ctx, `SELECT actor, detail FROM class_decisions WHERE class_key = 'v3:s'`).Scan(&actor, &detail))
	if actor != ActorSecurityRule || detail != "security tag" {
		t.Fatalf("%q %q", actor, detail)
	}
	ok, err = s.DeliverSecurityClass(ctx, "v3:s", 3000)
	mustDo(t, err)
	if ok || countRows(t, s, `SELECT count(*) FROM class_decisions`) != 1 {
		t.Fatal("second delivery should be a no-op")
	}
}

func TestPruneDecisionAsks(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedEvidenceFinding(t, s, "a", "v3:a", nil, []string{"x"}, 1000)
	for _, at := range []int64{100, 200, 900} {
		a := appliedAsk("v3:a", "")
		a.Result, a.At = AskUnsure, at
		_, err := s.RecordDecisionAsk(ctx, a)
		mustDo(t, err)
	}
	n, err := s.PruneDecisionAsks(ctx, 500)
	mustDo(t, err)
	if n != 2 || countRows(t, s, `SELECT count(*) FROM class_decision_asks`) != 1 {
		t.Fatalf("pruned %d", n)
	}
}

func TestCurrentEmbedModel(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	got, err := s.CurrentEmbedModel(ctx)
	mustDo(t, err)
	if got != "" {
		t.Fatalf("empty table gave %q", got)
	}
	mustDo(t, s.SetClassGroup(ctx, group("v3:a", "v3:a", "old", 1)))
	mustDo(t, s.SetClassGroup(ctx, group("v3:b", "v3:b", "new", 2)))
	got, err = s.CurrentEmbedModel(ctx)
	mustDo(t, err)
	if got != "new" {
		t.Fatalf("got %q", got)
	}
}
