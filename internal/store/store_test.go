// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package store

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/gate"
	"github.com/nethesis/nethesis-insights/internal/model"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRecurrenceBumpsNotInserts(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	f := model.Finding{
		SystemID: "sys1", Fingerprint: "fp1", Severity: "high",
		Title: "t", Summary: "s", SuggestedAction: "a",
		Modules: []string{"m1"}, Evidence: []string{"e1"},
	}
	outcome, err := s.UpsertFinding(ctx, f, 1000)
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if outcome != OutcomeInserted {
		t.Fatalf("expected inserted, got %s", outcome)
	}

	outcome, err = s.UpsertFinding(ctx, f, 2000)
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if outcome != OutcomeBumped {
		t.Fatalf("expected bumped, got %s", outcome)
	}

	findings, err := s.ListFindings(ctx, "sys1", 0, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 row after recurrence, got %d", len(findings))
	}
	if findings[0].OccurrenceCount != 2 {
		t.Fatalf("expected occurrence_count=2, got %d", findings[0].OccurrenceCount)
	}
}

func TestStaleThenRecurrenceReopens(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	f := model.Finding{
		SystemID: "sys1", Fingerprint: "fp1", Severity: "high",
		Title: "t", Summary: "s", SuggestedAction: "a",
		Modules: []string{"m1"}, Evidence: []string{"e1"},
	}
	if _, err := s.UpsertFinding(ctx, f, 1000); err != nil {
		t.Fatalf("insert: %v", err)
	}

	n, err := s.MarkStale(ctx, "sys1", 5000)
	if err != nil {
		t.Fatalf("mark stale: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 row marked stale, got %d", n)
	}

	outcome, err := s.UpsertFinding(ctx, f, 9000)
	if err != nil {
		t.Fatalf("reopen upsert: %v", err)
	}
	if outcome != OutcomeReopened {
		t.Fatalf("expected reopened, got %s", outcome)
	}

	findings, err := s.ListFindings(ctx, "sys1", 0, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 row, got %d", len(findings))
	}
	if findings[0].ReopenedAt == nil || *findings[0].ReopenedAt != 9000 {
		t.Fatalf("expected reopened_at=9000, got %v", findings[0].ReopenedAt)
	}
	if findings[0].Status != model.StatusOpen {
		t.Fatalf("expected status open after reopen, got %s", findings[0].Status)
	}
}

func TestFirstSeenNeverMoves(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	f := model.Finding{
		SystemID: "sys1", Fingerprint: "fp1", Severity: "high",
		Title: "t", Summary: "s", SuggestedAction: "a",
		Modules: []string{"m1"}, Evidence: []string{"e1"},
	}
	if _, err := s.UpsertFinding(ctx, f, 1000); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := s.UpsertFinding(ctx, f, 5000); err != nil {
		t.Fatalf("bump: %v", err)
	}
	if _, err := s.MarkStale(ctx, "sys1", 6000); err != nil {
		t.Fatalf("mark stale: %v", err)
	}
	if _, err := s.UpsertFinding(ctx, f, 9000); err != nil {
		t.Fatalf("reopen: %v", err)
	}

	findings, err := s.ListFindings(ctx, "sys1", 0, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 row, got %d", len(findings))
	}
	if findings[0].FirstSeen != 1000 {
		t.Fatalf("expected first_seen to stay at 1000, got %d", findings[0].FirstSeen)
	}
	if findings[0].LastSeen != 9000 {
		t.Fatalf("expected last_seen to advance to 9000, got %d", findings[0].LastSeen)
	}
}

func TestUpsertSystemFirstSeenNeverMoves(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if err := s.UpsertSystem(ctx, System{SystemID: "sys1", CollectorVersion: "1.0", FirstSeen: 100, LastSeen: 100}); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if err := s.UpsertSystem(ctx, System{SystemID: "sys1", CollectorVersion: "2.0", FirstSeen: 999999, LastSeen: 200}); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	var firstSeen int64
	var lastSeen int64
	var collectorVersion string
	row := s.db.QueryRowContext(ctx, `SELECT first_seen, last_seen, collector_version FROM systems WHERE system_id = ?`, "sys1")
	if err := row.Scan(&firstSeen, &lastSeen, &collectorVersion); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if firstSeen != 100 {
		t.Fatalf("expected first_seen to stay 100, got %d", firstSeen)
	}
	if lastSeen != 200 {
		t.Fatalf("expected last_seen to update to 200, got %d", lastSeen)
	}
	if collectorVersion != "2.0" {
		t.Fatalf("expected collector_version to update to 2.0, got %s", collectorVersion)
	}
}

func TestSamplesNeverStoredInSystemTemplates(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	templates := []model.Template{
		{Template: "tpl1", Count: 5, ModuleID: "mod1", Priority: 1, Category: "info",
			Samples: []string{"SECRET-SAMPLE-LINE"}},
	}
	if err := s.UpsertTemplates(ctx, "sys1", templates, 1000); err != nil {
		t.Fatalf("upsert templates: %v", err)
	}

	rows, err := s.db.QueryContext(ctx, `SELECT * FROM system_templates`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		t.Fatalf("columns: %v", err)
	}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatalf("scan: %v", err)
		}
		for i, v := range vals {
			b, _ := json.Marshal(v)
			if str := string(b); contains(str, "SECRET-SAMPLE-LINE") {
				t.Fatalf("column %s contains sample text: %s", cols[i], str)
			}
		}
	}

	known, err := s.KnownTemplates(ctx, "sys1")
	if err != nil {
		t.Fatalf("known templates: %v", err)
	}
	// KnownTemplates is keyed by canonical key, not raw text: the gate asks
	// "have we seen this condition", not "have we seen this exact string".
	if !known[model.CanonicalKey("mod1", "tpl1")] {
		t.Fatalf("expected tpl1 to be known, got %v", known)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (func() bool {
		for i := 0; i+len(substr) <= len(s); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	})()
}

func TestBaselinesSeedThenBlend(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	digest := []model.DigestEntry{{ModuleID: "mod1", Priority: 1, Observed: 100}}
	if err := s.UpsertBaselines(ctx, "sys1", digest, 0.3); err != nil {
		t.Fatalf("seed: %v", err)
	}
	baselines, err := s.Baselines(ctx, "sys1")
	if err != nil {
		t.Fatalf("baselines: %v", err)
	}
	if v := baselines[gate.BaselineKey{ModuleID: "mod1", Priority: 1}]; v != 100 {
		t.Fatalf("expected seed to observed value 100, got %v", v)
	}

	digest2 := []model.DigestEntry{{ModuleID: "mod1", Priority: 1, Observed: 200}}
	if err := s.UpsertBaselines(ctx, "sys1", digest2, 0.3); err != nil {
		t.Fatalf("blend: %v", err)
	}
	baselines, err = s.Baselines(ctx, "sys1")
	if err != nil {
		t.Fatalf("baselines: %v", err)
	}
	want := 0.3*200 + 0.7*100
	if v := baselines[gate.BaselineKey{ModuleID: "mod1", Priority: 1}]; v != want {
		t.Fatalf("expected blended value %v, got %v", want, v)
	}
}

// A window is claimable until it COMPLETES. These two tests are the contract:
// a finished window is idempotent, an unfinished one stays retryable.
func TestCompletedWindowIsNotFreshAgain(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	fresh, err := s.BeginAnalysis(ctx, "sys1", 100, 200, 1000)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if !fresh {
		t.Fatalf("expected fresh on first begin")
	}
	if err := s.FinalizeAnalysis(ctx, Analysis{
		SystemID: "sys1", WindowStart: 100, WindowEnd: 200, Gated: true,
	}); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	fresh, err = s.BeginAnalysis(ctx, "sys1", 100, 300, 2000)
	if err != nil {
		t.Fatalf("begin dup: %v", err)
	}
	if fresh {
		t.Fatalf("a completed window must not be claimable again")
	}
}

func TestUnfinishedWindowStaysClaimable(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.BeginAnalysis(ctx, "sys1", 100, 200, 1000); err != nil {
		t.Fatalf("begin: %v", err)
	}
	// The attempt failed transiently; the row exists but is not complete.
	if err := s.RecordAttemptError(ctx, "sys1", 100, []string{"deviation"}, 42, "upstream timeout"); err != nil {
		t.Fatalf("record attempt error: %v", err)
	}

	fresh, err := s.BeginAnalysis(ctx, "sys1", 100, 200, 2000)
	if err != nil {
		t.Fatalf("begin retry: %v", err)
	}
	if !fresh {
		t.Fatalf("a window whose attempt failed must remain claimable, or the retry is lost")
	}
}
