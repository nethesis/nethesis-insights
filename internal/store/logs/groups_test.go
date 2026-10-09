// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package logs

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/grouping"
	"github.com/nethesis/nethesis-insights/internal/model"
)

func seedEvidenceFinding(t *testing.T, s *Store, fp, class string, modules, evidence []string, now int64) {
	t.Helper()
	f := model.Finding{SystemID: "sys1", Fingerprint: fp, Severity: "low", Title: fp,
		Modules: modules, Evidence: evidence, ClassKey: class, PromptVersion: "p1"}
	if _, err := s.UpsertFinding(context.Background(), f, now); err != nil {
		t.Fatal(err)
	}
}

func group(key, anchor, m string, at int64) ClassGroup {
	return ClassGroup{Key: key, Anchor: anchor, Similarity: 0.99, Threshold: 0.98, Model: m,
		Vector: []float32{1, 0.5}, At: at}
}

func TestUngroupedClasses(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedEvidenceFinding(t, s, "a-old", "v3:a", []string{"m0"}, []string{"old"}, 1000)
	seedEvidenceFinding(t, s, "a-new", "v3:a", []string{"m1"}, []string{"new"}, 2000)
	seedEvidenceFinding(t, s, "b", "v3:b", []string{}, []string{"b"}, 1500)
	seedEvidenceFinding(t, s, "c", "v3:c", []string{}, []string{"c"}, 3000)
	seedEvidenceFinding(t, s, "d", "v3:d", []string{}, []string{"d"}, 4000)
	// a class with no retained finding
	seedEvidenceFinding(t, s, "e", "v3:e", []string{}, []string{"e"}, 500)
	if _, err := s.db.ExecContext(ctx, `DELETE FROM findings WHERE class_key = 'v3:e'`); err != nil {
		t.Fatal(err)
	}
	mustDo(t, s.SetClassGroup(ctx, group("v3:b", "v3:b", "m1", 1)))  // same model: skipped
	mustDo(t, s.SetClassGroup(ctx, group("v3:c", "v3:c", "old", 1))) // other model: returned

	got, err := s.UngroupedClasses(ctx, "m1", 10)
	mustDo(t, err)
	var keys []string
	for _, e := range got {
		keys = append(keys, e.Key)
	}
	if want := []string{"v3:a", "v3:c", "v3:d"}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("keys %v, want %v", keys, want)
	}
	if !reflect.DeepEqual(got[0].Modules, []string{"m1"}) || !reflect.DeepEqual(got[0].Evidence, []string{"new"}) {
		t.Fatalf("not the latest finding's evidence: %+v", got[0])
	}
	got, err = s.UngroupedClasses(ctx, "m1", 2)
	mustDo(t, err)
	if len(got) != 2 {
		t.Fatalf("limit ignored: %d", len(got))
	}
}

func TestGroupAnchorsFiltersModelAndAnchor(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	mustDo(t, s.SetClassGroup(ctx, group("v3:a", "v3:a", "m1", 1)))
	mustDo(t, s.SetClassGroup(ctx, group("v3:b", "v3:a", "m1", 2))) // member
	mustDo(t, s.SetClassGroup(ctx, group("v3:c", "v3:c", "m2", 3))) // other model
	got, err := s.GroupAnchors(ctx, "m1")
	mustDo(t, err)
	want := []grouping.Anchor{{Key: "v3:a", Vector: []float32{1, 0.5}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
}

func TestSetClassGroupUpsertRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	g := group("v3:a", "v3:a", "m1", 1)
	g.Vector = []float32{0.25, -1, 3.5}
	mustDo(t, s.SetClassGroup(ctx, g))
	g.Model, g.Vector, g.At = "m2", []float32{9}, 2
	mustDo(t, s.SetClassGroup(ctx, g))
	got, err := s.GroupAnchors(ctx, "m2")
	mustDo(t, err)
	if len(got) != 1 || !reflect.DeepEqual(got[0].Vector, []float32{9}) {
		t.Fatalf("upsert lost: %+v", got)
	}
	if old, _ := s.GroupAnchors(ctx, "m1"); len(old) != 0 {
		t.Fatal("old model row survived the upsert")
	}
	g.Vector, g.Model = []float32{0.25, -1, 3.5}, "m1"
	mustDo(t, s.SetClassGroup(ctx, g))
	got, _ = s.GroupAnchors(ctx, "m1")
	if !reflect.DeepEqual(got[0].Vector, []float32{0.25, -1, 3.5}) {
		t.Fatalf("round trip: %v", got[0].Vector)
	}
}

func seedGroup(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	for _, k := range []string{"v3:a", "v3:b", "v3:c", "v3:x"} {
		seedClassFinding(t, s, "sys1", "fp-"+k, k, "low", "t-"+k, false, 1000)
	}
	mustDo(t, s.SetClassGroup(ctx, group("v3:a", "v3:a", "m", 1)))
	mustDo(t, s.SetClassGroup(ctx, group("v3:b", "v3:a", "m", 2)))
	mustDo(t, s.SetClassGroup(ctx, group("v3:c", "v3:a", "m", 3)))
}

func TestSetGroupVisibilityChangesOnlyPending(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedGroup(t, s)
	mustDo(t, s.SetClassVisibility(ctx, "v3:c", VisibilityOperator, "op", 1500))

	n, err := s.SetGroupVisibility(ctx, "v3:a", VisibilityDismissed, "alice", 2000)
	mustDo(t, err)
	if n != 2 {
		t.Fatalf("changed %d, want 2", n)
	}
	for key, want := range map[string]string{"v3:a": VisibilityDismissed, "v3:b": VisibilityDismissed,
		"v3:c": VisibilityOperator, "v3:x": VisibilityPending} {
		c, _, _ := s.GetClass(ctx, key)
		if c.Visibility != want {
			t.Fatalf("%s: %s, want %s", key, c.Visibility, want)
		}
	}
	ds, _ := s.ClassDecisions(ctx, "v3:b")
	if len(ds) != 1 || ds[0].Action != ActionDismiss || ds[0].Detail != "group v3:a" ||
		ds[0].Actor != "alice" || ds[0].PromptVersion != "p1" {
		t.Fatalf("audit row: %+v", ds)
	}
	if ds, _ := s.ClassDecisions(ctx, "v3:c"); len(ds) != 1 {
		t.Fatalf("decided class got an audit row: %+v", ds)
	}
	// nothing pending left: no change, no audit rows
	n, err = s.SetGroupVisibility(ctx, "v3:a", VisibilityCustomer, "alice", 3000)
	if err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if ds, _ := s.ClassDecisions(ctx, "v3:b"); len(ds) != 1 {
		t.Fatal("audit row written for a no-op")
	}
}

func TestSetGroupVisibilityRefusals(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedGroup(t, s)
	if _, err := s.SetGroupVisibility(ctx, "v3:a", VisibilityPending, "op", 1); !errors.Is(err, ErrInvalidVisibility) {
		t.Fatalf("pending: %v", err)
	}
	if _, err := s.SetGroupVisibility(ctx, "v3:nope", VisibilityCustomer, "op", 1); !errors.Is(err, ErrUnknownClass) {
		t.Fatalf("unknown anchor: %v", err)
	}
}

func TestListClassesFillsGroupFields(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedGroup(t, s)
	mustDo(t, s.SetClassVisibility(ctx, "v3:c", VisibilityCustomer, "op", 1500))

	rows, err := s.ListClasses(ctx, ClassFilter{})
	mustDo(t, err)
	by := map[string]ClassRow{}
	for _, r := range rows {
		by[r.Key] = r
	}
	b := by["v3:b"]
	if b.GroupAnchor != "v3:a" || b.GroupSize != 3 || b.GroupSimilarity != 0.99 ||
		b.Suggestion != VisibilityCustomer || b.SuggestionVotes != 1 {
		t.Fatalf("b: %+v", b)
	}
	if c := by["v3:c"]; c.Suggestion != "" || c.GroupSize != 3 {
		t.Fatalf("decided class must carry no suggestion: %+v", c)
	}
	if x := by["v3:x"]; x.GroupAnchor != "" || x.GroupSize != 0 || x.Suggestion != "" {
		t.Fatalf("ungrouped: %+v", x)
	}

	// a second, different decision makes the group ambiguous
	mustDo(t, s.SetClassVisibility(ctx, "v3:a", VisibilityDismissed, "op", 1600))
	rows, _ = s.ListClasses(ctx, ClassFilter{Key: "v3:b"})
	if len(rows) != 1 || rows[0].Suggestion != "" {
		t.Fatalf("ambiguous group suggested: %+v", rows)
	}
}

func TestListClassesGroupFilter(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedGroup(t, s)
	rows, err := s.ListClasses(ctx, ClassFilter{Group: "v3:a"})
	mustDo(t, err)
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want the 3 group members", len(rows))
	}
	for _, r := range rows {
		if r.GroupAnchor != "v3:a" {
			t.Fatalf("stray row %s", r.Key)
		}
	}
	rows, _ = s.ListClasses(ctx, ClassFilter{Group: "' OR 1=1 --"})
	if len(rows) != 0 {
		t.Fatal("group filter is not a bound parameter")
	}
}

func TestPruneClassesRemovesOrphanGroupRows(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedClassFinding(t, s, "sys1", "fp-live", "v3:live", "low", "t", false, 1000)
	mustDo(t, s.SetClassGroup(ctx, group("v3:live", "v3:live", "m", 1)))
	mustDo(t, s.SetClassGroup(ctx, group("v3:gone", "v3:live", "m", 1)))
	if _, err := s.PruneClasses(ctx, 1); err != nil {
		t.Fatal(err)
	}
	var n int
	mustDo(t, s.db.QueryRowContext(ctx, `SELECT count(*) FROM class_groups`).Scan(&n))
	if n != 1 {
		t.Fatalf("%d group rows left, want 1", n)
	}
}

// grouping is pure and cannot import the store, so it spells the visibility
// literals itself; this guards them.
func TestGroupingVisibilitiesMatchStore(t *testing.T) {
	for _, v := range []string{VisibilityCustomer, VisibilityOperator, VisibilityDismissed} {
		if got, ok := grouping.Suggest([]string{v, VisibilityPending}); !ok || got != v {
			t.Fatalf("Suggest(%q) = %q, %v", v, got, ok)
		}
	}
	if _, ok := grouping.Suggest([]string{VisibilityPending}); ok {
		t.Fatal("pending must not be a decision")
	}
	if _, ok := grouping.Suggest([]string{VisibilityCustomer, VisibilityOperator}); ok {
		t.Fatal("two decisions must not suggest")
	}
}
