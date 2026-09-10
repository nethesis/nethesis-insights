// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package logs

import (
	"context"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/model"
)

func TestPruneTemplatesByLastSeen(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if err := s.UpsertTemplates(ctx, "sys1", []model.Template{
		{Template: "old line", ModuleID: "m1", Count: 1, FirstSeen: 100, LastSeen: 100},
	}, 100); err != nil {
		t.Fatalf("upsert old: %v", err)
	}
	if err := s.UpsertTemplates(ctx, "sys1", []model.Template{
		{Template: "new line", ModuleID: "m1", Count: 1, FirstSeen: 900, LastSeen: 900},
	}, 900); err != nil {
		t.Fatalf("upsert new: %v", err)
	}

	n, err := s.PruneTemplates(ctx, 500)
	if err != nil {
		t.Fatalf("prune templates: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 row pruned, got %d", n)
	}

	known, err := s.KnownTemplates(ctx, "sys1")
	if err != nil {
		t.Fatalf("known templates: %v", err)
	}
	if known[model.CanonicalKey("m1", "old line")] {
		t.Fatalf("expected the old template to be gone")
	}
	if !known[model.CanonicalKey("m1", "new line")] {
		t.Fatalf("expected the new template, inside retention, to survive")
	}
}

func TestPruneFindingsSparesOpenOnes(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	open := model.Finding{
		SystemID: "sys1", Fingerprint: "fp-open", Severity: "high",
		Title: "t", Summary: "s", SuggestedAction: "a",
		Modules: []string{"m1"}, Evidence: []string{"e1"},
	}
	stale := model.Finding{
		SystemID: "sys1", Fingerprint: "fp-stale", Severity: "high",
		Title: "t", Summary: "s", SuggestedAction: "a",
		Modules: []string{"m1"}, Evidence: []string{"e1"},
	}
	if _, err := s.UpsertFinding(ctx, open, 100); err != nil {
		t.Fatalf("insert open: %v", err)
	}
	if _, err := s.UpsertFinding(ctx, stale, 100); err != nil {
		t.Fatalf("insert stale: %v", err)
	}

	// Stale both at last_seen=100 (both went stale, since both were only
	// seen once at 100), then bring fp-open back so only fp-stale is a
	// pruning candidate -- the same setup TestStaleThenRecurrenceReopens uses.
	if _, err := s.MarkStale(ctx, "sys1", 200); err != nil {
		t.Fatalf("mark stale: %v", err)
	}
	if _, err := s.UpsertFinding(ctx, open, 300); err != nil {
		t.Fatalf("reopen fp-open: %v", err)
	}

	// olderThan=250 is past fp-stale's last_seen (100, never bumped) but
	// before fp-open's (300, just reopened), so only fp-stale qualifies even
	// though both are older than fp-open by first_seen.
	n, err := s.PruneFindings(ctx, 250)
	if err != nil {
		t.Fatalf("prune findings: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 row pruned, got %d", n)
	}

	remaining, err := s.ListFindings(ctx, "sys1", 0, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(remaining) != 1 || remaining[0].Fingerprint != "fp-open" {
		t.Fatalf("expected only fp-open to remain, got %+v", remaining)
	}
}

// TestPruneFindingsNeverTouchesAnOpenFindingRegardlessOfAge pins the rule
// called out by name in the original plan (TestPruneFindingsSparesOpenOnes)
// and restated in review: an open finding is current by definition, however
// old its last_seen is, and must never be a pruning candidate -- not "not
// yet", never.
func TestPruneFindingsNeverTouchesAnOpenFindingRegardlessOfAge(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	f := model.Finding{
		SystemID: "sys1", Fingerprint: "fp-old-open", Severity: "high",
		Title: "t", Summary: "s", SuggestedAction: "a",
		Modules: []string{"m1"}, Evidence: []string{"e1"},
	}
	if _, err := s.UpsertFinding(ctx, f, 1); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// A retention cutoff far in the future would prune everything stale --
	// this finding is still open, so it must survive regardless.
	n, err := s.PruneFindings(ctx, 1_000_000_000_000)
	if err != nil {
		t.Fatalf("prune findings: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 rows pruned, got %d -- an open finding was pruned", n)
	}

	open, err := s.OpenFindings(ctx, "sys1")
	if err != nil {
		t.Fatalf("open findings: %v", err)
	}
	if len(open) != 1 {
		t.Fatalf("expected the open finding to survive, got %d open findings", len(open))
	}
}

func TestPruneAnalysesByCreatedAt(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.BeginAnalysis(ctx, "sys1", 1000, 1900, 100); err != nil {
		t.Fatalf("begin old: %v", err)
	}
	if _, err := s.BeginAnalysis(ctx, "sys1", 2000, 2900, 900); err != nil {
		t.Fatalf("begin new: %v", err)
	}

	n, err := s.PruneAnalyses(ctx, 500)
	if err != nil {
		t.Fatalf("prune analyses: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 row pruned, got %d", n)
	}
}

// TestPruneIsANoOpWhenNothingQualifies pins that an empty, or fully-current,
// store is a clean no-op: zero rows removed and no error, for all three
// tables. A maint pass runs on a fixed interval regardless of whether there
// is anything to do, so this is the common case, not the exceptional one.
func TestPruneIsANoOpWhenNothingQualifies(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if n, err := s.PruneTemplates(ctx, 0); err != nil || n != 0 {
		t.Fatalf("prune templates: n=%d err=%v, want 0, nil", n, err)
	}
	if n, err := s.PruneFindings(ctx, 0); err != nil || n != 0 {
		t.Fatalf("prune findings: n=%d err=%v, want 0, nil", n, err)
	}
	if n, err := s.PruneAnalyses(ctx, 0); err != nil || n != 0 {
		t.Fatalf("prune analyses: n=%d err=%v, want 0, nil", n, err)
	}

	// Seed one row per table that is well inside retention (created/seen at
	// "now") and confirm a cutoff before it still prunes nothing.
	if err := s.UpsertTemplates(ctx, "sys1", []model.Template{
		{Template: "line", ModuleID: "m1", Count: 1, FirstSeen: 1000, LastSeen: 1000},
	}, 1000); err != nil {
		t.Fatalf("seed template: %v", err)
	}
	if _, err := s.UpsertFinding(ctx, model.Finding{
		SystemID: "sys1", Fingerprint: "fp1", Severity: "high",
		Title: "t", Summary: "s", SuggestedAction: "a",
		Modules: []string{"m1"}, Evidence: []string{"e1"},
	}, 1000); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	if _, err := s.BeginAnalysis(ctx, "sys1", 1000, 1900, 1000); err != nil {
		t.Fatalf("seed analysis: %v", err)
	}

	if n, err := s.PruneTemplates(ctx, 500); err != nil || n != 0 {
		t.Fatalf("prune templates: n=%d err=%v, want 0, nil", n, err)
	}
	if n, err := s.PruneAnalyses(ctx, 500); err != nil || n != 0 {
		t.Fatalf("prune analyses: n=%d err=%v, want 0, nil", n, err)
	}
}

// TestPruneLoopsAcrossMultipleBatches pins the "bounded work, not one
// transaction" property described in prune.go's pruneBatchSize doc: a
// backlog larger than one batch must still be fully cleared by a single
// Prune* call, via more than one internal DELETE, not silently truncated to
// the first batch.
func TestPruneLoopsAcrossMultipleBatches(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	old := pruneBatchSize
	pruneBatchSize = 3
	t.Cleanup(func() { pruneBatchSize = old })

	const rows = 7 // more than two batches at batch size 3
	for i := 0; i < rows; i++ {
		windowStart := int64(1000 + i)
		if _, err := s.BeginAnalysis(ctx, "sys1", windowStart, windowStart+900, 100); err != nil {
			t.Fatalf("begin analysis %d: %v", i, err)
		}
	}

	n, err := s.PruneAnalyses(ctx, 500)
	if err != nil {
		t.Fatalf("prune analyses: %v", err)
	}
	if n != rows {
		t.Fatalf("expected all %d rows pruned across multiple batches, got %d", rows, n)
	}

	// Confirm nothing was left behind by a batch that returned early.
	remaining, err := s.PruneAnalyses(ctx, 500)
	if err != nil {
		t.Fatalf("second prune: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("expected nothing left to prune, got %d", remaining)
	}
}
