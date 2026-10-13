// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package logs

import (
	"context"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/model"
)

// wordedFinding stores one open finding in class on systemID with the given
// prose, as the model would have written it for that system.
func wordedFinding(t *testing.T, s *Store, systemID, fingerprint, class string, w Wording, now int64) {
	t.Helper()
	f := model.Finding{SystemID: systemID, Fingerprint: fingerprint, Severity: "low",
		Title: w.Title, Summary: w.Summary, SuggestedAction: w.SuggestedAction,
		Modules: []string{}, Evidence: []string{}, ClassKey: class, PromptVersion: "p1"}
	if _, err := s.UpsertFinding(context.Background(), f, now); err != nil {
		t.Fatalf("upsert %s: %v", fingerprint, err)
	}
}

var (
	firstWording  = Wording{Title: "SIP authentication failures", Summary: "first summary", SuggestedAction: "first action"}
	secondWording = Wording{Title: "NethVoice proxy is seeing SIP authentication failures", Summary: "second summary", SuggestedAction: "second action"}
)

func customerFinding(t *testing.T, s *Store, systemID string) model.Finding {
	t.Helper()
	got, err := s.ListFindings(context.Background(), systemID, 0, "")
	mustDo(t, err)
	if len(got) != 1 {
		t.Fatalf("%s: want one delivered finding, got %+v", systemID, got)
	}
	return got[0]
}

func wordingOf(f model.Finding) Wording {
	return Wording{Title: f.Title, Summary: f.Summary, SuggestedAction: f.SuggestedAction}
}

// The first finding of a class words it for every customer: a later finding
// of the same class, on another system, keeps its own text in its row but
// reaches its customer in the first one's words. Recurrence never reseeds.
func TestClassWordingIsSeededFromFirstFinding(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	wordedFinding(t, s, "sys1", "fp-1", "v4:sip", firstWording, 1000)
	wordedFinding(t, s, "sys2", "fp-2", "v4:sip", secondWording, 2000)
	wordedFinding(t, s, "sys1", "fp-1", "v4:sip", secondWording, 3000) // recurrence, reworded

	c, ok, err := s.GetClass(ctx, "v4:sip")
	mustDo(t, err)
	if !ok || c.Text.Seed != firstWording || c.Text.Edited() {
		t.Fatalf("class wording must be the first finding's, unedited; got %+v", c.Text)
	}
	mustDo(t, s.SetClassVisibility(ctx, "v4:sip", VisibilityCustomer, "op", 4000))
	for _, sys := range []string{"sys1", "sys2"} {
		if got := wordingOf(customerFinding(t, s, sys)); got != firstWording {
			t.Errorf("%s: customer reads %+v, want the class wording %+v", sys, got, firstWording)
		}
	}
}

// A class from before class_texts existed has no row: the customer reads the
// finding's own text until the class's next finding seeds one.
func TestClassWithoutWordingFallsBackToTheFinding(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	wordedFinding(t, s, "sys1", "fp-1", "v4:old", firstWording, 1000)
	mustDo(t, s.SetClassVisibility(ctx, "v4:old", VisibilityCustomer, "op", 2000))
	if _, err := s.db.ExecContext(ctx, `DELETE FROM class_texts`); err != nil {
		t.Fatal(err)
	}
	if got := wordingOf(customerFinding(t, s, "sys1")); got != firstWording {
		t.Fatalf("with no class wording the customer must read the finding's own, got %+v", got)
	}

	wordedFinding(t, s, "sys2", "fp-2", "v4:old", secondWording, 3000)
	if got := wordingOf(customerFinding(t, s, "sys1")); got != secondWording {
		t.Fatalf("the next finding must seed the class wording, got %+v", got)
	}
}

// The class wording is applied in ListFindings and nowhere else: the stored
// finding keeps the model's text, OpenFindings (the prompt's input) returns
// it untouched, and the operator's ListAllFindings carries the class wording
// beside the finding's own rather than in place of it.
func TestClassWordingReachesOnlyTheReadAPI(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	wordedFinding(t, s, "sys1", "fp-1", "v4:sip", firstWording, 1000)
	wordedFinding(t, s, "sys2", "fp-2", "v4:sip", secondWording, 2000)
	edited := Wording{Title: "SIP logins are failing", Summary: "edited summary", SuggestedAction: "edited action"}
	_, err := s.UpdateClass(ctx, "v4:sip", ClassUpdate{Visibility: VisibilityCustomer, Wording: edited}, "op", 3000)
	mustDo(t, err)

	if got := wordingOf(customerFinding(t, s, "sys2")); got != edited {
		t.Fatalf("customer reads %+v, want the operator's wording %+v", got, edited)
	}
	open, err := s.OpenFindings(ctx, "sys2")
	mustDo(t, err)
	if len(open) != 1 || wordingOf(open[0]) != secondWording || open[0].ClassTitle != "" {
		t.Fatalf("OpenFindings must return the model's own text and no class wording, got %+v", open)
	}
	all, err := s.ListAllFindings(ctx, FindingFilter{System: "sys2"})
	mustDo(t, err)
	if len(all) != 1 || wordingOf(all[0]) != secondWording {
		t.Fatalf("the operator view must keep the finding's own text, got %+v", all)
	}
	if f := all[0]; f.ClassTitle != edited.Title || f.ClassSummary != edited.Summary || f.ClassSuggestedAction != edited.SuggestedAction {
		t.Fatalf("the operator view must carry the class wording beside it, got %+v", f)
	}
}

// Each changed wording field is its own audited decision; posting the
// current wording back -- as an untouched form does, whitespace and all --
// records nothing; an emptied field restores the seed and never blanks what
// the customer reads.
func TestClassWordingEditIsAudited(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	wordedFinding(t, s, "sys1", "fp-1", "v4:sip", firstWording, 1000)
	mustDo(t, s.SetClassVisibility(ctx, "v4:sip", VisibilityCustomer, "op", 1500))
	base := ClassUpdate{Visibility: VisibilityCustomer}

	// The untouched form posts the seed back.
	u := base
	u.Wording = Wording{Title: firstWording.Title + "  ", Summary: "\n" + firstWording.Summary, SuggestedAction: firstWording.SuggestedAction}
	n, err := s.UpdateClass(ctx, "v4:sip", u, "alice", 2000)
	mustDo(t, err)
	if n != 0 {
		t.Fatalf("posting the seed back changed %d fields", n)
	}

	// The title alone is edited.
	u.Wording.Title = "SIP logins are failing"
	n, err = s.UpdateClass(ctx, "v4:sip", u, "bob", 3000)
	mustDo(t, err)
	if n != 1 {
		t.Fatalf("editing the title changed %d fields, want 1", n)
	}
	if got := customerFinding(t, s, "sys1"); got.Title != "SIP logins are failing" || got.Summary != firstWording.Summary {
		t.Fatalf("customer reads %+v", got)
	}
	// The same edit again records nothing.
	n, err = s.UpdateClass(ctx, "v4:sip", u, "bob", 3500)
	mustDo(t, err)
	if n != 0 {
		t.Fatalf("an unchanged edit changed %d fields", n)
	}

	// Every field emptied: the title restores the seed (one change), the
	// others already were the seed (none), and nothing reads blank.
	u.Wording = Wording{}
	n, err = s.UpdateClass(ctx, "v4:sip", u, "carol", 4000)
	mustDo(t, err)
	if n != 1 {
		t.Fatalf("emptying the edited title changed %d fields, want 1", n)
	}
	if got := wordingOf(customerFinding(t, s, "sys1")); got != firstWording {
		t.Fatalf("an emptied wording must restore the seed, customer reads %+v", got)
	}
	c, _, err := s.GetClass(ctx, "v4:sip")
	mustDo(t, err)
	if c.Text.Edited() || c.Text.Seed != firstWording {
		t.Fatalf("class wording after restore: %+v", c.Text)
	}

	ds, err := s.ClassDecisions(ctx, "v4:sip")
	mustDo(t, err)
	want := []ClassDecision{
		{Key: "v4:sip", Actor: "op", Action: ActionDeliver, PromptVersion: "p1", CreatedAt: 1500},
		{Key: "v4:sip", Actor: "bob", Action: ActionTitle, Detail: "SIP logins are failing", PromptVersion: "p1", CreatedAt: 3000},
		{Key: "v4:sip", Actor: "carol", Action: ActionTitle, PromptVersion: "p1", CreatedAt: 4000},
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

// Every wording field changes in the fixed order, after the class's other
// decisions, each with its own audit row.
func TestClassWordingFieldsAreAuditedInOrder(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	wordedFinding(t, s, "sys1", "fp-1", "v4:sip", firstWording, 1000)
	n, err := s.UpdateClass(ctx, "v4:sip", ClassUpdate{
		Visibility: VisibilityCustomer, SeverityOverride: "high",
		Wording: Wording{Title: "t", Summary: "s", SuggestedAction: "a"},
	}, "alice", 2000)
	mustDo(t, err)
	if n != 5 {
		t.Fatalf("changed %d fields, want 5", n)
	}
	ds, err := s.ClassDecisions(ctx, "v4:sip")
	mustDo(t, err)
	var got []string
	for _, d := range ds {
		got = append(got, d.Action+"="+d.Detail)
	}
	want := []string{"deliver=", "severity=high", "title=t", "summary=s", "suggested_action=a"}
	if len(got) != len(want) {
		t.Fatalf("decisions %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("decisions %v, want %v", got, want)
		}
	}
}

// A class with no wording row yet -- it predates class_texts -- is seeded by
// the operator's first save from the finding the dialog showed, so an
// untouched form records nothing there either.
func TestClassWordingIsSeededOnTheFirstSave(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	wordedFinding(t, s, "sys1", "fp-1", "v4:old", firstWording, 1000)
	wordedFinding(t, s, "sys2", "fp-2", "v4:old", secondWording, 2000)
	if _, err := s.db.ExecContext(ctx, `DELETE FROM class_texts`); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListClasses(ctx, ClassFilter{Key: "v4:old"})
	mustDo(t, err)
	if len(rows) != 1 || rows[0].Wording != secondWording {
		t.Fatalf("the dialog must show the latest finding's text, got %+v", rows)
	}
	n, err := s.UpdateClass(ctx, "v4:old", ClassUpdate{Wording: rows[0].Wording}, "op", 3000)
	mustDo(t, err)
	if n != 0 {
		t.Fatalf("an untouched form changed %d fields", n)
	}
}

// The review queue shows and sorts by the class wording's title, not by
// whichever finding was worded last.
func TestReviewQueueShowsTheClassWording(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	wordedFinding(t, s, "sys1", "fp-1", "v4:a", Wording{Title: "zeta"}, 1000)
	wordedFinding(t, s, "sys2", "fp-2", "v4:a", Wording{Title: "alpha"}, 2000)
	wordedFinding(t, s, "sys1", "fp-3", "v4:b", Wording{Title: "mu"}, 1000)
	rows, err := s.ListClasses(ctx, ClassFilter{Sort: ClassSortTitle, Dir: SortAsc})
	mustDo(t, err)
	if got := classKeys(rows); got != "v4:b,v4:a" {
		t.Fatalf("sorted by class wording: got %s, want v4:b,v4:a", got)
	}
	if rows[1].Wording.Title != "zeta" {
		t.Fatalf("row wording = %+v, want the seed", rows[1].Wording)
	}
}

// An undecided class's wording goes with it when maint prunes the class; an
// edited one is a decision, so its class and wording stay.
func TestPruneClassesDropsTheWording(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	wordedFinding(t, s, "sys1", "fp-1", "v4:orphan", firstWording, 1000)
	wordedFinding(t, s, "sys1", "fp-2", "v4:edited", firstWording, 1000)
	_, err := s.UpdateClass(ctx, "v4:edited", ClassUpdate{Wording: Wording{Title: "edited"}}, "op", 1000)
	mustDo(t, err)
	if _, err := s.db.ExecContext(ctx, `DELETE FROM findings`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PruneClasses(ctx, 2000); err != nil {
		t.Fatal(err)
	}
	var keys []string
	rows, err := s.db.QueryContext(ctx, `SELECT class_key FROM class_texts ORDER BY class_key`)
	mustDo(t, err)
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var k string
		mustDo(t, rows.Scan(&k))
		keys = append(keys, k)
	}
	mustDo(t, rows.Err())
	if len(keys) != 1 || keys[0] != "v4:edited" {
		t.Fatalf("class_texts after prune: %v, want only v4:edited", keys)
	}
}
