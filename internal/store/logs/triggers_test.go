// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package logs

import (
	"context"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/model"
)

func sighting(systemID, key string, now int64) TriggerSighting {
	return TriggerSighting{SystemID: systemID, Key: key, Called: true, Now: now}
}

// Only a paid call moves last_called_at; a reuse is a sighting, and must not
// extend the reuse window it is being measured by.
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
	look, err := newTestStore(t).LookupTrigger(context.Background(), "sys1", "t1:nope")
	if err != nil {
		t.Fatal(err)
	}
	if look != (TriggerLookup{}) {
		t.Fatalf("unexpected lookup for an unknown key: %+v", look)
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

// A reuse bumps the findings it linked (TestAReusedSightingBumpsTheLinkedOpenFindings
// above); it must bump their class's last_seen too, or a class that is still
// being reused every window looks stale to the review queue.
func TestReuseBumpsTheClassLastSeen(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	f := model.Finding{SystemID: "sys1", Fingerprint: "fp1", Severity: "high", Title: "t",
		Modules: []string{}, Evidence: []string{}, TriggerKey: "t1:k", ClassKey: "v3:cls"}
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

	c, ok, err := s.GetClass(ctx, "v3:cls")
	if err != nil || !ok {
		t.Fatalf("get class: %v %v", ok, err)
	}
	if c.LastSeen != 4000 {
		t.Fatalf("class last_seen = %d, want 4000 (bumped by the reuse)", c.LastSeen)
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
