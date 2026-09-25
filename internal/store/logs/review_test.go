// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package logs

import (
	"context"
	"errors"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/model"
)

// seedTrigger records one paid sighting of key on systemID.
func seedTrigger(t *testing.T, s *Store, systemID, key string, security bool, now int64) {
	t.Helper()
	sg := sighting(systemID, key, now)
	sg.Security = security
	if err := s.RecordTriggerSighting(context.Background(), sg); err != nil {
		t.Fatalf("record %s: %v", key, err)
	}
}

// seedFinding stores one open finding under key.
func seedTriggerFinding(t *testing.T, s *Store, systemID, fingerprint, key, severity, title string, now int64) {
	t.Helper()
	f := model.Finding{SystemID: systemID, Fingerprint: fingerprint, Severity: severity, Title: title,
		Modules: []string{}, Evidence: []string{}, TriggerKey: key}
	if _, err := s.UpsertFinding(context.Background(), f, now); err != nil {
		t.Fatalf("upsert %s: %v", fingerprint, err)
	}
}

func fingerprints(fs []model.Finding) map[string]model.Finding {
	out := make(map[string]model.Finding, len(fs))
	for _, f := range fs {
		out[f.Fingerprint] = f
	}
	return out
}

// Only a delivered trigger's findings reach the customer. Pending (born
// that way), internal, a key merged into an internal root and a finding
// with no trigger at all are withheld; a key merged into a delivered root
// and a security trigger are returned.
func TestOperatorOnlyFindingsNeverReachTheReadAPI(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	for _, k := range []string{"t1:pending", "t1:internal", "t1:delivered", "t1:to-internal", "t1:to-delivered"} {
		seedTrigger(t, s, "sys1", k, false, 1000)
	}
	seedTrigger(t, s, "sys1", "t1:sec", true, 1000)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.SetTriggerVisibility(ctx, "t1:internal", VisibilityOperator, "op", 2000))
	must(s.SetTriggerVisibility(ctx, "t1:delivered", VisibilityCustomer, "op", 2000))
	must(s.MergeTrigger(ctx, "t1:to-internal", "t1:internal", "op", 2000))
	must(s.MergeTrigger(ctx, "t1:to-delivered", "t1:delivered", "op", 2000))

	seedTriggerFinding(t, s, "sys1", "fp-pending", "t1:pending", "low", "p", 3000)
	seedTriggerFinding(t, s, "sys1", "fp-internal", "t1:internal", "low", "i", 3000)
	seedTriggerFinding(t, s, "sys1", "fp-delivered", "t1:delivered", "low", "d", 3000)
	seedTriggerFinding(t, s, "sys1", "fp-to-internal", "t1:to-internal", "low", "ti", 3000)
	seedTriggerFinding(t, s, "sys1", "fp-to-delivered", "t1:to-delivered", "low", "td", 3000)
	seedTriggerFinding(t, s, "sys1", "fp-sec", "t1:sec", "high", "s", 3000)
	seedTriggerFinding(t, s, "sys1", "fp-none", "", "low", "n", 3000)

	got, err := s.ListFindings(ctx, "sys1", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	byFP := fingerprints(got)
	for _, want := range []string{"fp-delivered", "fp-to-delivered", "fp-sec"} {
		if _, ok := byFP[want]; !ok {
			t.Errorf("%s was withheld from the read API", want)
		}
	}
	for _, hidden := range []string{"fp-pending", "fp-internal", "fp-to-internal", "fp-none"} {
		if _, ok := byFP[hidden]; ok {
			t.Errorf("%s reached the read API", hidden)
		}
	}

	all, err := s.ListAllFindings(ctx, "sys1", "", "", "", "", 0)
	if err != nil || len(all) != 7 {
		t.Fatalf("the operator must see every finding, got %d (%v)", len(all), err)
	}
	if v := fingerprints(all)["fp-to-internal"].Visibility; v != VisibilityOperator {
		t.Fatalf("a merged key must show its root's visibility, got %q", v)
	}
}

// The override and the doc reference reach the customer; the stored
// severity -- the one prompt.Render prints -- does not change.
func TestSeverityOverrideIsAppliedOnlyWhenReadForTheCustomer(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedTrigger(t, s, "sys1", "t1:k", false, 1000)
	seedTriggerFinding(t, s, "sys1", "fp1", "t1:k", "low", "t", 1000)
	if err := s.SetTriggerVisibility(ctx, "t1:k", VisibilityCustomer, "op", 2000); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTriggerSeverity(ctx, "t1:k", "critical", "op", 2000); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTriggerDocRef(ctx, "t1:k", "https://docs.example.org/fix", "op", 2000); err != nil {
		t.Fatal(err)
	}

	got, err := s.ListFindings(ctx, "sys1", 0, "")
	if err != nil || len(got) != 1 {
		t.Fatalf("list: %v %v", got, err)
	}
	if got[0].Severity != "critical" || got[0].DocRef != "https://docs.example.org/fix" {
		t.Fatalf("decisions not applied for the customer: %+v", got[0])
	}
	open, err := s.OpenFindings(ctx, "sys1")
	if err != nil || len(open) != 1 {
		t.Fatalf("open: %v %v", open, err)
	}
	if open[0].Severity != "low" || open[0].SeverityOverride != "" || open[0].DocRef != "" {
		t.Fatalf("a decision reached the prompt's findings: %+v", open[0])
	}

	if err := s.SetTriggerSeverity(ctx, "t1:k", "", "op", 3000); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListFindings(ctx, "sys1", 0, ""); got[0].Severity != "low" {
		t.Fatalf("clearing the override left severity %q", got[0].Severity)
	}
	if err := s.SetTriggerSeverity(ctx, "t1:k", "urgent", "op", 3000); !errors.Is(err, ErrInvalidSeverity) {
		t.Fatalf("expected ErrInvalidSeverity, got %v", err)
	}
}

// Merging always leaves every alias pointing straight at a root, so
// resolution stays one lookup; a merge between two keys that already share
// a root -- the only way to ask for a cycle -- is refused.
func TestMergeResolvesToRootAndRejectsCycles(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	for _, k := range []string{"t1:a", "t1:b", "t1:c"} {
		seedTrigger(t, s, "sys1", k, false, 1000)
	}

	if err := s.MergeTrigger(ctx, "t1:a", "t1:b", "op", 2000); err != nil {
		t.Fatal(err)
	}
	if err := s.MergeTrigger(ctx, "t1:b", "t1:c", "op", 3000); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"t1:a", "t1:b"} {
		var canonical string
		if err := s.db.QueryRowContext(ctx,
			`SELECT canonical_key FROM trigger_aliases WHERE alias_key = ?`, k).Scan(&canonical); err != nil {
			t.Fatal(err)
		}
		if canonical != "t1:c" {
			t.Fatalf("alias %s points at %s, want the root t1:c", k, canonical)
		}
		if look, _ := s.LookupTrigger(ctx, "sys1", k); look.Root != "t1:c" {
			t.Fatalf("%s resolves to %s, want t1:c", k, look.Root)
		}
	}

	for _, tc := range []struct{ key, into string }{
		{"t1:c", "t1:a"}, // into its own alias
		{"t1:a", "t1:c"}, // already merged there
		{"t1:c", "t1:c"}, // into itself
	} {
		if err := s.MergeTrigger(ctx, tc.key, tc.into, "op", 4000); !errors.Is(err, ErrMergeCycle) {
			t.Errorf("merge %s into %s: expected ErrMergeCycle, got %v", tc.key, tc.into, err)
		}
	}
	if err := s.MergeTrigger(ctx, "t1:a", "t1:nope", "op", 4000); !errors.Is(err, ErrUnknownTrigger) {
		t.Errorf("merge into an unknown key: expected ErrUnknownTrigger, got %v", err)
	}

	d, err := s.TriggerDecisions(ctx, "t1:a")
	if err != nil || len(d) != 1 || d[0].Action != ActionMerge || d[0].Detail != "t1:b" || d[0].Actor != "op" {
		t.Fatalf("merge decision not recorded as expected: %+v %v", d, err)
	}
}

// The merge and visibility halves of the security rule, on the write side.
func TestSecurityTriggersAreNeverMergedOrHiddenInTheStore(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedTrigger(t, s, "sys1", "t1:sec", true, 1000)
	seedTrigger(t, s, "sys1", "t1:sec2", true, 1000)
	seedTrigger(t, s, "sys1", "t1:plain", false, 1000)

	for _, tc := range []struct{ key, into string }{
		{"t1:sec", "t1:plain"},
		{"t1:plain", "t1:sec"},
		{"t1:sec", "t1:sec2"},
	} {
		if err := s.MergeTrigger(ctx, tc.key, tc.into, "op", 2000); !errors.Is(err, ErrSecurityTrigger) {
			t.Errorf("merge %s into %s: expected ErrSecurityTrigger, got %v", tc.key, tc.into, err)
		}
	}
	for _, v := range []string{VisibilityOperator, VisibilityCustomer} {
		if err := s.SetTriggerVisibility(ctx, "t1:sec", v, "op", 2000); !errors.Is(err, ErrSecurityTrigger) {
			t.Errorf("visibility %s on a security trigger: expected ErrSecurityTrigger, got %v", v, err)
		}
	}
	if tr := mustTrigger(t, s, "t1:sec"); tr.Visibility != VisibilityCustomer {
		t.Fatalf("refused decisions changed the trigger: %+v", tr)
	}
	if d, _ := s.TriggerDecisions(ctx, "t1:sec"); len(d) != 0 {
		t.Fatalf("refused decisions left a trail: %+v", d)
	}
	if err := s.SetTriggerVisibility(ctx, "t1:plain", VisibilityPending, "op", 2000); !errors.Is(err, ErrInvalidVisibility) {
		t.Fatalf("a trigger must never be sent back to pending, got %v", err)
	}
}

func TestEveryDecisionIsRecorded(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedTrigger(t, s, "sys1", "t1:k", false, 1000)
	seedTrigger(t, s, "sys1", "t1:root", false, 1000)

	steps := []func() error{
		func() error { return s.SetTriggerVisibility(ctx, "t1:k", VisibilityOperator, "alice", 2000) },
		func() error { return s.SetTriggerVisibility(ctx, "t1:k", VisibilityCustomer, "alice", 2001) },
		func() error { return s.IgnoreTrigger(ctx, "t1:k", 9000, "alice", 2002) },
		func() error { return s.SetTriggerSeverity(ctx, "t1:k", "high", "alice", 2003) },
		func() error { return s.SetTriggerDocRef(ctx, "t1:k", "https://x.example/d", "alice", 2004) },
		func() error { return s.MergeTrigger(ctx, "t1:k", "t1:root", "alice", 2005) },
	}
	for i, step := range steps {
		if err := step(); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	d, err := s.ListTriggerDecisions(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, x := range d {
		actions = append(actions, x.Action)
	}
	want := []string{ActionMerge, ActionDocRef, ActionSeverity, ActionIgnore, ActionDeliver, ActionInternal}
	if len(actions) != len(want) {
		t.Fatalf("actions = %v, want %v", actions, want)
	}
	for i := range want {
		if actions[i] != want[i] {
			t.Fatalf("actions = %v, want %v (newest first)", actions, want)
		}
	}
	if d[0].PromptVersion != "v3" {
		t.Fatalf("decision not stamped with the trigger's prompt version: %+v", d[0])
	}
}

// The queue lists roots only, ranked by distinct systems then count, and
// carries what an operator recognises a trigger by: its findings' titles,
// including those raised under a key merged into it, and its latest gate
// reasons.
func TestListTriggersRanksRootsAndCarriesTheirContext(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedTrigger(t, s, "sys1", "t1:wide", false, 1000)
	seedTrigger(t, s, "sys2", "t1:wide", false, 1100)
	seedTrigger(t, s, "sys1", "t1:busy", false, 1000)
	seedTrigger(t, s, "sys1", "t1:busy", false, 1200)
	seedTrigger(t, s, "sys1", "t1:busy", false, 1300)
	seedTrigger(t, s, "sys1", "t1:merged", false, 1000)
	if err := s.MergeTrigger(ctx, "t1:merged", "t1:wide", "op", 1500); err != nil {
		t.Fatal(err)
	}
	seedTriggerFinding(t, s, "sys1", "fp1", "t1:wide", "low", "disk filling", 2000)
	seedTriggerFinding(t, s, "sys2", "fp2", "t1:merged", "low", "disk almost full", 2100)

	if _, err := s.BeginAnalysis(ctx, "sys1", 100, 200, 1000); err != nil {
		t.Fatal(err)
	}
	if err := s.FinalizeAnalysis(ctx, Analysis{SystemID: "sys1", WindowStart: 100, WindowEnd: 200, Gated: true,
		GateReasons: []string{"deviation:mod1/3"}, LLMCalled: true, TriggerKey: "t1:wide"}); err != nil {
		t.Fatal(err)
	}

	rows, err := s.ListTriggers(ctx, TriggerFilter{Visibility: VisibilityPending, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Key != "t1:wide" || rows[1].Key != "t1:busy" {
		t.Fatalf("unexpected queue: %+v", rows)
	}
	wide := rows[0]
	if wide.Aliases != 1 || wide.Findings != 2 || len(wide.Titles) != 2 || wide.Titles[0] != "disk almost full" {
		t.Fatalf("root does not carry its merged key's findings: %+v", wide)
	}
	if len(wide.GateReasons) != 1 || wide.GateReasons[0] != "deviation:mod1/3" {
		t.Fatalf("gate reasons = %v", wide.GateReasons)
	}

	if err := s.SetTriggerVisibility(ctx, "t1:busy", VisibilityOperator, "op", 3000); err != nil {
		t.Fatal(err)
	}
	if rows, _ := s.ListTriggers(ctx, TriggerFilter{Visibility: VisibilityPending, Limit: 10}); len(rows) != 1 {
		t.Fatalf("a decided trigger stayed in the pending queue: %+v", rows)
	}
	if rows, _ := s.ListTriggers(ctx, TriggerFilter{Key: "t1:bu", Limit: 10}); len(rows) != 1 || rows[0].Key != "t1:busy" {
		t.Fatalf("key filter: %+v", rows)
	}
}

func TestTriggerStatsPartitionsEachPromptVersion(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	for _, k := range []string{"t1:p", "t1:d", "t1:i", "t1:m", "t1:root"} {
		seedTrigger(t, s, "sys1", k, false, 1000)
	}
	seedTrigger(t, s, "sys1", "t1:sec", true, 1000)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.SetTriggerVisibility(ctx, "t1:d", VisibilityCustomer, "op", 2000))
	must(s.SetTriggerVisibility(ctx, "t1:i", VisibilityOperator, "op", 2000))
	must(s.IgnoreTrigger(ctx, "t1:i", 9000, "op", 2000))
	must(s.MergeTrigger(ctx, "t1:m", "t1:root", "op", 2000))

	stats, err := s.TriggerStats(ctx)
	if err != nil || len(stats) != 1 {
		t.Fatalf("stats: %+v %v", stats, err)
	}
	got := stats[0]
	want := TriggerStatsRow{PromptVersion: "v3", Triggers: 6, Security: 1, Pending: 2, Delivered: 1,
		Internal: 1, Merged: 1, Ignored: 1}
	if got != want {
		t.Fatalf("stats = %+v, want %+v", got, want)
	}
}
