// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package maint

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/nethesis/nethesis-insights/internal/model"
	logsstore "github.com/nethesis/nethesis-insights/internal/store/logs"
)

// --- independence and failure handling: a fake Reader ---
//
// What is under test here is that a failure in one prune does not stop the
// others, and that each retention window is applied against its own table --
// neither of which a real store can be made to demonstrate as directly as a
// fake can. This mirrors internal/baseline's recordingReader.

type recordingReader struct {
	calls []string

	templatesErr, findingsErr, analysesErr error
	// olderThan captures what each call was asked to prune before, so a test
	// can assert Run derived it from `now` and the right Config field.
	templatesOlderThan, findingsOlderThan, analysesOlderThan int64
}

func (r *recordingReader) PruneTemplates(_ context.Context, olderThan int64) (int, error) {
	r.calls = append(r.calls, "templates")
	r.templatesOlderThan = olderThan
	return 1, r.templatesErr
}

func (r *recordingReader) PruneFindings(_ context.Context, olderThan int64) (int, error) {
	r.calls = append(r.calls, "findings")
	r.findingsOlderThan = olderThan
	return 2, r.findingsErr
}

func (r *recordingReader) PruneAnalyses(_ context.Context, olderThan int64) (int, error) {
	r.calls = append(r.calls, "analyses")
	r.analysesOlderThan = olderThan
	return 3, r.analysesErr
}

func testConfig() Config {
	return Config{
		TemplateRetention: 400 * 24 * time.Hour,
		FindingRetention:  180 * 24 * time.Hour,
		AnalysisRetention: 90 * 24 * time.Hour,
	}
}

// A prune pass has no published artifact behind it (unlike blocklist's feed
// or baseline's cohorts), so a failure anywhere must still be logged, not
// returned -- otherwise svc.RunPassLoop-shaped callers would treat every
// transient store error as "the whole pass failed" when two of the three
// tables were pruned just fine.
func TestRunAlwaysReturnsNilEvenWhenEveryPruneFails(t *testing.T) {
	r := &recordingReader{
		templatesErr: errors.New("boom"),
		findingsErr:  errors.New("boom"),
		analysesErr:  errors.New("boom"),
	}
	if err := New(r, testConfig()).Run(context.Background(), 0); err != nil {
		t.Fatalf("Run returned %v, want nil -- a prune failure must not be fatal", err)
	}
}

// A failure pruning one table must not stop the others -- the three tables
// are independent (no rollup-before-prune ordering exists for this
// pipeline, unlike Threat Shield's or fleet sizing's), so all three must
// still be attempted regardless of an earlier one's outcome.
func TestOnePruneFailingDoesNotSkipTheOthers(t *testing.T) {
	r := &recordingReader{templatesErr: errors.New("boom")}
	if err := New(r, testConfig()).Run(context.Background(), 0); err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, want := range []string{"templates", "findings", "analyses"} {
		found := false
		for _, c := range r.calls {
			if c == want {
				found = true
			}
		}
		if !found {
			t.Errorf("expected %q to be attempted despite the templates failure; calls = %v", want, r.calls)
		}
	}
}

// Each table is pruned against its own configured retention, subtracted from
// `now` -- not, say, every table sharing TemplateRetention by accident.
func TestEachTableUsesItsOwnRetention(t *testing.T) {
	r := &recordingReader{}
	cfg := testConfig()
	now := int64(1_000_000_000_000)
	if err := New(r, cfg).Run(context.Background(), now); err != nil {
		t.Fatalf("run: %v", err)
	}

	wantTemplates := now - cfg.TemplateRetention.Milliseconds()
	wantFindings := now - cfg.FindingRetention.Milliseconds()
	wantAnalyses := now - cfg.AnalysisRetention.Milliseconds()

	if r.templatesOlderThan != wantTemplates {
		t.Errorf("templates olderThan = %d, want %d", r.templatesOlderThan, wantTemplates)
	}
	if r.findingsOlderThan != wantFindings {
		t.Errorf("findings olderThan = %d, want %d", r.findingsOlderThan, wantFindings)
	}
	if r.analysesOlderThan != wantAnalyses {
		t.Errorf("analyses olderThan = %d, want %d", r.analysesOlderThan, wantAnalyses)
	}
	// The three retentions differ (400d/180d/90d), so if the cutoffs were
	// accidentally shared this would already have failed above -- but assert
	// distinctness directly too, since that IS the property under test.
	if wantTemplates == wantFindings || wantFindings == wantAnalyses {
		t.Fatalf("test fixture's retentions were not actually distinct")
	}
}

// --- end to end against a real store ---
//
// A fake proves Run's own logic; a real temp-file SQLite store proves the
// whole pass actually removes what it should and spares what it should not,
// the same reasoning internal/baseline gives for testing against SQLite
// rather than a mock.

func newTestLogsStore(t *testing.T) *logsstore.Store {
	t.Helper()
	s, err := logsstore.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestPassPrunesEachTableIndependently is the executable form of this
// package's central design choice: system_templates, findings and analyses
// are pruned on their own schedules with no ordering constraint between
// them (unlike Threat Shield's rollup-before-prune), and a run against a mix
// of eligible and ineligible rows in all three tables leaves exactly the
// expected survivors in each.
func TestPassPrunesEachTableIndependently(t *testing.T) {
	ctx := context.Background()
	s := newTestLogsStore(t)

	const day = int64(24 * 60 * 60 * 1000)
	now := 500 * day

	// system_templates: one old enough to prune, one not.
	if err := s.UpsertTemplates(ctx, "sys1", []model.Template{
		{Template: "old", ModuleID: "m1", Count: 1, FirstSeen: 10 * day, LastSeen: 10 * day},
	}, 10*day); err != nil {
		t.Fatalf("seed old template: %v", err)
	}
	if err := s.UpsertTemplates(ctx, "sys1", []model.Template{
		{Template: "recent", ModuleID: "m1", Count: 1, FirstSeen: 490 * day, LastSeen: 490 * day},
	}, 490*day); err != nil {
		t.Fatalf("seed recent template: %v", err)
	}

	// findings: an open one far in the past (must survive regardless), a
	// stale one old enough to prune, a stale one too recent to prune.
	open := model.Finding{SystemID: "sys1", Fingerprint: "fp-open", Severity: "high",
		Title: "t", Summary: "s", SuggestedAction: "a", Modules: []string{"m1"}, Evidence: []string{"e1"}}
	staleOld := model.Finding{SystemID: "sys1", Fingerprint: "fp-stale-old", Severity: "high",
		Title: "t", Summary: "s", SuggestedAction: "a", Modules: []string{"m1"}, Evidence: []string{"e1"}}
	staleRecent := model.Finding{SystemID: "sys1", Fingerprint: "fp-stale-recent", Severity: "high",
		Title: "t", Summary: "s", SuggestedAction: "a", Modules: []string{"m1"}, Evidence: []string{"e1"}}
	if _, err := s.UpsertFinding(ctx, open, 5*day); err != nil {
		t.Fatalf("seed open finding: %v", err)
	}
	if _, err := s.UpsertFinding(ctx, staleOld, 5*day); err != nil {
		t.Fatalf("seed stale-old finding: %v", err)
	}
	if _, err := s.UpsertFinding(ctx, staleRecent, 495*day); err != nil {
		t.Fatalf("seed stale-recent finding: %v", err)
	}
	// This also marks "open" stale, since MarkStale acts on every open
	// finding older than the cutoff regardless of which one the test wants
	// to keep open -- bring it back with a later last_seen, exactly as
	// TestStaleThenRecurrenceReopens does, so it is genuinely open again
	// by the time Run prunes.
	if _, err := s.MarkStale(ctx, "sys1", 496*day); err != nil {
		t.Fatalf("mark stale: %v", err)
	}
	if _, err := s.UpsertFinding(ctx, open, 498*day); err != nil {
		t.Fatalf("reopen open finding: %v", err)
	}

	// analyses: one old enough to prune, one not.
	if _, err := s.BeginAnalysis(ctx, "sys1", 10*day, 10*day+1, 10*day); err != nil {
		t.Fatalf("seed old analysis: %v", err)
	}
	if _, err := s.BeginAnalysis(ctx, "sys1", 495*day, 495*day+1, 495*day); err != nil {
		t.Fatalf("seed recent analysis: %v", err)
	}

	cfg := Config{
		TemplateRetention: 100 * 24 * time.Hour, // cutoff = now - 100d = day 400
		FindingRetention:  50 * 24 * time.Hour,  // cutoff = now - 50d  = day 450
		AnalysisRetention: 20 * 24 * time.Hour,  // cutoff = now - 20d  = day 480
	}
	if err := New(s, cfg).Run(ctx, now); err != nil {
		t.Fatalf("run: %v", err)
	}

	known, err := s.KnownTemplates(ctx, "sys1")
	if err != nil {
		t.Fatalf("known templates: %v", err)
	}
	if known[model.CanonicalKey("m1", "old")] {
		t.Error("old template survived pruning")
	}
	if !known[model.CanonicalKey("m1", "recent")] {
		t.Error("recent template was pruned")
	}

	remaining, err := s.ListFindings(ctx, "sys1", 0, "")
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	byFP := map[string]bool{}
	for _, f := range remaining {
		byFP[f.Fingerprint] = true
	}
	if !byFP["fp-open"] {
		t.Error("open finding was pruned")
	}
	if byFP["fp-stale-old"] {
		t.Error("stale-old finding survived pruning")
	}
	if !byFP["fp-stale-recent"] {
		t.Error("stale-recent finding was pruned before its retention elapsed")
	}

	analyses, err := s.ListAnalyses(ctx, "sys1", 100)
	if err != nil {
		t.Fatalf("list analyses: %v", err)
	}
	if len(analyses) != 1 || analyses[0].WindowStart != 495*day {
		t.Fatalf("expected only the recent analysis to survive, got %+v", analyses)
	}
}
