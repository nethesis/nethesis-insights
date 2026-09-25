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
