// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package logs

import (
	"context"
	"errors"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/model"
)

func sighting(systemID, key string, now int64) TriggerSighting {
	return TriggerSighting{SystemID: systemID, Key: key, PromptVersion: "v3", Called: true, Now: now}
}

func mustTrigger(t *testing.T, s *Store, key string) Trigger {
	t.Helper()
	tr, ok, err := s.GetTrigger(context.Background(), key)
	if err != nil || !ok {
		t.Fatalf("get trigger %q: ok=%v err=%v", key, ok, err)
	}
	return tr
}

func TestRecordTriggerSightingCountsDistinctSystems(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	for _, sg := range []TriggerSighting{
		sighting("sys1", "t1:k", 1000),
		sighting("sys1", "t1:k", 2000),
		sighting("sys2", "t1:k", 3000),
	} {
		if err := s.RecordTriggerSighting(ctx, sg); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	tr := mustTrigger(t, s, "t1:k")
	if tr.DistinctSystems != 2 || tr.Count != 3 {
		t.Fatalf("distinct_systems=%d count=%d, want 2/3", tr.DistinctSystems, tr.Count)
	}
	if tr.FirstSeen != 1000 || tr.LastSeen != 3000 || tr.FirstPromptVersion != "v3" {
		t.Fatalf("unexpected bookkeeping: %+v", tr)
	}
	if tr.Status != TriggerActive || tr.Visibility != VisibilityPending {
		t.Fatalf("a new non-security trigger must start active and pending, got %+v", tr)
	}
}

// Only a paid call moves last_called_at; a reuse or an ignored window is a
// sighting, and must not extend the reuse window it is being measured by.
func TestOnlyAPaidCallMovesLastCalledAt(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if err := s.RecordTriggerSighting(ctx, sighting("sys1", "t1:k", 1000)); err != nil {
		t.Fatal(err)
	}
	reuse := sighting("sys1", "t1:k", 5000)
	reuse.Called, reuse.Reused = false, true
	if err := s.RecordTriggerSighting(ctx, reuse); err != nil {
		t.Fatal(err)
	}
	look, err := s.LookupTrigger(ctx, "sys1", "t1:k")
	if err != nil {
		t.Fatal(err)
	}
	if !look.SystemSeen || look.LastCalledAt != 1000 {
		t.Fatalf("LastCalledAt=%d SystemSeen=%v, want 1000/true", look.LastCalledAt, look.SystemSeen)
	}
}

func TestLookupOfAnUnknownKey(t *testing.T) {
	s := newTestStore(t)
	look, err := s.LookupTrigger(context.Background(), "sys1", "t1:nope")
	if err != nil {
		t.Fatal(err)
	}
	if look.Known || look.SystemSeen || look.Root != "t1:nope" {
		t.Fatalf("unexpected lookup for an unknown key: %+v", look)
	}
}

// The lookup resolves through the alias table, so the analyzer never has to
// know a merge happened.
func TestLookupResolvesAnAliasToItsRoot(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if err := s.RecordTriggerSighting(ctx, sighting("sys1", "t1:root", 1000)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO trigger_aliases (alias_key, canonical_key, created_at) VALUES (?, ?, ?)`,
		"t1:alias", "t1:root", 1000); err != nil {
		t.Fatal(err)
	}
	look, err := s.LookupTrigger(ctx, "sys1", "t1:alias")
	if err != nil {
		t.Fatal(err)
	}
	if look.Root != "t1:root" || !look.Known || !look.SystemSeen {
		t.Fatalf("alias did not resolve to its root: %+v", look)
	}
}

// The findings a reuse depends on are the ones the LAST call raised or a
// reuse has bumped since. An older finding under the same key, left stale
// by a call that went on to raise a different one, must not block reuse
// forever.
func TestLookupCountsOnlyFindingsFromTheLastCall(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	old := model.Finding{SystemID: "sys1", Fingerprint: "fp-old", Severity: "low", Title: "t",
		Modules: []string{}, Evidence: []string{}, TriggerKey: "t1:k"}
	if _, err := s.UpsertFinding(ctx, old, 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MarkStale(ctx, "sys1", 2000); err != nil {
		t.Fatal(err)
	}
	fresh := old
	fresh.Fingerprint = "fp-new"
	if _, err := s.UpsertFinding(ctx, fresh, 5000); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordTriggerSighting(ctx, sighting("sys1", "t1:k", 5000)); err != nil {
		t.Fatal(err)
	}

	look, err := s.LookupTrigger(ctx, "sys1", "t1:k")
	if err != nil {
		t.Fatal(err)
	}
	if look.LinkedOpen != 1 || look.LinkedNotOpen != 0 {
		t.Fatalf("LinkedOpen=%d LinkedNotOpen=%d, want 1/0", look.LinkedOpen, look.LinkedNotOpen)
	}
}

func TestAReusedSightingBumpsTheLinkedOpenFindings(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	f := model.Finding{SystemID: "sys1", Fingerprint: "fp1", Severity: "high", Title: "t",
		Modules: []string{}, Evidence: []string{}, TriggerKey: "t1:k"}
	if _, err := s.UpsertFinding(ctx, f, 1000); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordTriggerSighting(ctx, sighting("sys1", "t1:k", 1000)); err != nil {
		t.Fatal(err)
	}
	reuse := sighting("sys1", "t1:k", 4000)
	reuse.Called, reuse.Reused = false, true
	if err := s.RecordTriggerSighting(ctx, reuse); err != nil {
		t.Fatal(err)
	}

	got, err := s.ListAllFindings(ctx, "sys1", "", "", "", "", 0)
	if err != nil || len(got) != 1 {
		t.Fatalf("list: %v %v", got, err)
	}
	if got[0].OccurrenceCount != 2 || got[0].LastSeen != 4000 {
		t.Fatalf("reuse did not bump the finding: %+v", got[0])
	}
}

func TestIgnoreTriggerRecordsItsDecision(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if err := s.RecordTriggerSighting(ctx, sighting("sys1", "t1:k", 1000)); err != nil {
		t.Fatal(err)
	}
	if err := s.IgnoreTrigger(ctx, "t1:k", 9000, "alice", 2000); err != nil {
		t.Fatalf("ignore: %v", err)
	}

	tr := mustTrigger(t, s, "t1:k")
	if tr.Status != TriggerIgnored || tr.IgnoreUntil != 9000 {
		t.Fatalf("trigger not ignored: %+v", tr)
	}
	look, err := s.LookupTrigger(ctx, "sys1", "t1:k")
	if err != nil || look.IgnoredUntil != 9000 {
		t.Fatalf("lookup IgnoredUntil=%d err=%v", look.IgnoredUntil, err)
	}

	decisions, err := s.TriggerDecisions(ctx, "t1:k")
	if err != nil || len(decisions) != 1 {
		t.Fatalf("decisions: %v %v", decisions, err)
	}
	d := decisions[0]
	if d.Actor != "alice" || d.Action != ActionIgnore || d.PromptVersion != "v3" || d.CreatedAt != 2000 {
		t.Fatalf("unexpected decision row: %+v", d)
	}
}

func TestIgnoreTriggerRefusesAnUnknownKeyOrAPastExpiry(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if err := s.IgnoreTrigger(ctx, "t1:nope", 9000, "alice", 2000); !errors.Is(err, ErrUnknownTrigger) {
		t.Fatalf("expected ErrUnknownTrigger, got %v", err)
	}
	if err := s.RecordTriggerSighting(ctx, sighting("sys1", "t1:k", 1000)); err != nil {
		t.Fatal(err)
	}
	if err := s.IgnoreTrigger(ctx, "t1:k", 2000, "alice", 2000); !errors.Is(err, ErrIgnoreExpiry) {
		t.Fatalf("expected ErrIgnoreExpiry, got %v", err)
	}
}

// The store half of TestSecurityTriggersAreNeverQueuedIgnoredOrMerged (the
// analyzer holds the other): a security trigger is delivered without
// review, and the one write that could silence it refuses, leaving no
// decision row behind.
func TestSecurityTriggersAreNeverQueuedOrIgnoredInTheStore(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	sg := sighting("sys1", "t1:sec", 1000)
	sg.Security = true
	if err := s.RecordTriggerSighting(ctx, sg); err != nil {
		t.Fatal(err)
	}
	tr := mustTrigger(t, s, "t1:sec")
	if !tr.Security || tr.Visibility != VisibilityCustomer {
		t.Fatalf("security trigger was queued for review: %+v", tr)
	}
	if err := s.IgnoreTrigger(ctx, "t1:sec", 9000, "alice", 2000); !errors.Is(err, ErrSecurityTrigger) {
		t.Fatalf("expected ErrSecurityTrigger, got %v", err)
	}
	if tr := mustTrigger(t, s, "t1:sec"); tr.Status != TriggerActive {
		t.Fatalf("refused ignore still changed the trigger: %+v", tr)
	}
	if d, _ := s.TriggerDecisions(ctx, "t1:sec"); len(d) != 0 {
		t.Fatalf("refused ignore left a decision row: %+v", d)
	}
}

func TestAnalysisRowCarriesItsTriggerKey(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if _, err := s.BeginAnalysis(ctx, "sys1", 100, 200, 1000); err != nil {
		t.Fatal(err)
	}
	if err := s.FinalizeAnalysis(ctx, Analysis{
		SystemID: "sys1", WindowStart: 100, WindowEnd: 200, Gated: true,
		GateReasons: []string{"deviation:mod1/3"}, SuppressedBy: "trigger_hit", TriggerKey: "t1:k",
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListAnalyses(ctx, "sys1", 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("list analyses: %v %v", rows, err)
	}
	if rows[0].TriggerKey != "t1:k" || rows[0].SuppressedBy != "trigger_hit" {
		t.Fatalf("unexpected analysis row: %+v", rows[0])
	}
}
