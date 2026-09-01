// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package store

import (
	"context"
	"testing"
	"time"

	"github.com/nethesis/nethesis-insights/internal/model"
)

// --- empty database: every method returns an empty slice/zero value and a nil error ---

func TestUIMethodsOnEmptyDatabase(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	counts, err := s.Counts(ctx)
	if err != nil {
		t.Fatalf("Counts: %v", err)
	}
	if counts != (Counts{}) {
		t.Fatalf("Counts: expected all-zero, got %+v", counts)
	}

	systems, err := s.ListSystems(ctx)
	if err != nil {
		t.Fatalf("ListSystems: %v", err)
	}
	if len(systems) != 0 {
		t.Fatalf("ListSystems: expected empty, got %d", len(systems))
	}

	analyses, err := s.ListAnalyses(ctx, "", 0)
	if err != nil {
		t.Fatalf("ListAnalyses: %v", err)
	}
	if len(analyses) != 0 {
		t.Fatalf("ListAnalyses: expected empty, got %d", len(analyses))
	}

	gateRows, err := s.GateRollup(ctx)
	if err != nil {
		t.Fatalf("GateRollup: %v", err)
	}
	if len(gateRows) != 0 {
		t.Fatalf("GateRollup: expected empty, got %d", len(gateRows))
	}

	costRows, err := s.CostRollup(ctx)
	if err != nil {
		t.Fatalf("CostRollup: %v", err)
	}
	if len(costRows) != 0 {
		t.Fatalf("CostRollup: expected empty, got %d", len(costRows))
	}

	findings, err := s.ListAllFindings(ctx, "", "", "", "", 0)
	if err != nil {
		t.Fatalf("ListAllFindings: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("ListAllFindings: expected empty, got %d", len(findings))
	}

	templates, err := s.ListTemplates(ctx, "", 0)
	if err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}
	if len(templates) != 0 {
		t.Fatalf("ListTemplates: expected empty, got %d", len(templates))
	}

	baselines, err := s.ListBaselines(ctx, "")
	if err != nil {
		t.Fatalf("ListBaselines: %v", err)
	}
	if len(baselines) != 0 {
		t.Fatalf("ListBaselines: expected empty, got %d", len(baselines))
	}
}

// --- Counts ---

func TestCountsPerTable(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if err := s.UpsertSystem(ctx, System{SystemID: "sys1", FirstSeen: 100, LastSeen: 100}); err != nil {
		t.Fatalf("upsert system: %v", err)
	}
	if err := s.UpsertSystem(ctx, System{SystemID: "sys2", FirstSeen: 100, LastSeen: 100}); err != nil {
		t.Fatalf("upsert system: %v", err)
	}
	if err := s.UpsertTemplates(ctx, "sys1", []model.Template{{Template: "t1", Count: 1, ModuleID: "m1"}}, 1000); err != nil {
		t.Fatalf("upsert templates: %v", err)
	}
	if err := s.UpsertBaselines(ctx, "sys1", []model.DigestEntry{{ModuleID: "m1", Priority: 1, Observed: 10}}, 0.3); err != nil {
		t.Fatalf("upsert baselines: %v", err)
	}
	if _, err := s.UpsertFinding(ctx, model.Finding{SystemID: "sys1", Fingerprint: "fp1", Severity: "high", Title: "t", Modules: []string{"m1"}, Evidence: []string{"e1"}}, 1000); err != nil {
		t.Fatalf("upsert finding: %v", err)
	}
	if _, err := s.BeginAnalysis(ctx, "sys1", 100, 200, 1000); err != nil {
		t.Fatalf("begin analysis: %v", err)
	}

	counts, err := s.Counts(ctx)
	if err != nil {
		t.Fatalf("Counts: %v", err)
	}
	want := Counts{Systems: 2, Templates: 1, Baselines: 1, Findings: 1, Analyses: 1}
	if counts != want {
		t.Fatalf("Counts: got %+v, want %+v", counts, want)
	}
}

// --- ListSystems ---

func TestListSystemsAggregates(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if err := s.UpsertSystem(ctx, System{SystemID: "sys1", TenantID: "tenant1", CollectorVersion: "1.0", FirstSeen: 100, LastSeen: 500}); err != nil {
		t.Fatalf("upsert system: %v", err)
	}

	// Two analyses, exactly one of which called the LLM.
	if _, err := s.BeginAnalysis(ctx, "sys1", 100, 200, 1000); err != nil {
		t.Fatalf("begin 1: %v", err)
	}
	if err := s.FinalizeAnalysis(ctx, Analysis{SystemID: "sys1", WindowStart: 100, WindowEnd: 200, Gated: false, LLMCalled: false, CostMicros: 0}); err != nil {
		t.Fatalf("finalize 1: %v", err)
	}
	if _, err := s.BeginAnalysis(ctx, "sys1", 300, 400, 2000); err != nil {
		t.Fatalf("begin 2: %v", err)
	}
	if err := s.FinalizeAnalysis(ctx, Analysis{SystemID: "sys1", WindowStart: 300, WindowEnd: 400, Gated: true, LLMCalled: true, CostMicros: 500}); err != nil {
		t.Fatalf("finalize 2: %v", err)
	}

	if err := s.UpsertTemplates(ctx, "sys1", []model.Template{{Template: "t1", Count: 1, ModuleID: "m1"}}, 1000); err != nil {
		t.Fatalf("upsert templates: %v", err)
	}
	if _, err := s.UpsertFinding(ctx, model.Finding{SystemID: "sys1", Fingerprint: "fp1", Severity: "high", Title: "t", Modules: []string{"m1"}, Evidence: []string{"e1"}}, 1000); err != nil {
		t.Fatalf("upsert open finding: %v", err)
	}
	if _, err := s.UpsertFinding(ctx, model.Finding{SystemID: "sys1", Fingerprint: "fp2", Severity: "low", Title: "t2", Modules: []string{"m1"}, Evidence: []string{"e2"}}, 1000); err != nil {
		t.Fatalf("upsert finding 2: %v", err)
	}
	if _, err := s.MarkStale(ctx, "sys1", 5000); err != nil {
		t.Fatalf("mark stale: %v", err)
	}

	systems, err := s.ListSystems(ctx)
	if err != nil {
		t.Fatalf("ListSystems: %v", err)
	}
	if len(systems) != 1 {
		t.Fatalf("expected 1 system, got %d", len(systems))
	}
	r := systems[0]
	if r.SystemID != "sys1" || r.TenantID != "tenant1" || r.CollectorVersion != "1.0" {
		t.Fatalf("unexpected identity fields: %+v", r)
	}
	if r.Templates != 1 {
		t.Fatalf("expected 1 template, got %d", r.Templates)
	}
	if r.Findings != 2 {
		t.Fatalf("expected 2 findings total, got %d", r.Findings)
	}
	if r.OpenFindings != 0 {
		t.Fatalf("expected 0 open findings (both marked stale), got %d", r.OpenFindings)
	}
	if r.Windows != 2 {
		t.Fatalf("expected 2 windows, got %d", r.Windows)
	}
	if r.LLMCalls != 1 {
		t.Fatalf("expected 1 llm call, got %d", r.LLMCalls)
	}
	if r.CostMicros != 500 {
		t.Fatalf("expected cost 500, got %d", r.CostMicros)
	}
}

// --- ListAnalyses ---

func TestListAnalysesHonoursLimitAndDefaultCap(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	for i := int64(1); i <= 3; i++ {
		ws := i * 1000
		if _, err := s.BeginAnalysis(ctx, "sys1", ws, ws+100, ws); err != nil {
			t.Fatalf("begin %d: %v", i, err)
		}
		if err := s.FinalizeAnalysis(ctx, Analysis{SystemID: "sys1", WindowStart: ws, WindowEnd: ws + 100}); err != nil {
			t.Fatalf("finalize %d: %v", i, err)
		}
	}

	limited, err := s.ListAnalyses(ctx, "", 2)
	if err != nil {
		t.Fatalf("ListAnalyses limit=2: %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("expected 2 rows with limit=2, got %d", len(limited))
	}
	// Most recent window first.
	if limited[0].WindowStart != 3000 || limited[1].WindowStart != 2000 {
		t.Fatalf("expected descending window order, got %d, %d", limited[0].WindowStart, limited[1].WindowStart)
	}

	all, err := s.ListAnalyses(ctx, "", 0)
	if err != nil {
		t.Fatalf("ListAnalyses default cap: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 rows with limit<=0 (default cap), got %d", len(all))
	}
}

func TestListAnalysesGateReasonsRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.BeginAnalysis(ctx, "sys1", 100, 200, 1000); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := s.FinalizeAnalysis(ctx, Analysis{
		SystemID: "sys1", WindowStart: 100, WindowEnd: 200,
		Gated: true, GateReasons: []string{"new_template"}, LLMCalled: true,
	}); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	rows, err := s.ListAnalyses(ctx, "sys1", 0)
	if err != nil {
		t.Fatalf("ListAnalyses: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if len(rows[0].GateReasons) != 1 || rows[0].GateReasons[0] != "new_template" {
		t.Fatalf("expected [new_template], got %v", rows[0].GateReasons)
	}
	if !rows[0].Gated || !rows[0].LLMCalled || !rows[0].Completed {
		t.Fatalf("expected gated/llm_called/completed all true, got %+v", rows[0])
	}
}

// --- GateRollup ---

func TestGateRollupMergesTheThreeEmptySpellings(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	// BeginAnalysis writes gate_reasons = '' and leaves it there for an
	// unfinished window.
	if _, err := s.BeginAnalysis(ctx, "sys1", 100, 200, 1000); err != nil {
		t.Fatalf("begin bare-empty: %v", err)
	}

	// FinalizeAnalysis with a nil GateReasons slice writes 'null'.
	if _, err := s.BeginAnalysis(ctx, "sys1", 300, 400, 1000); err != nil {
		t.Fatalf("begin null: %v", err)
	}
	if err := s.FinalizeAnalysis(ctx, Analysis{SystemID: "sys1", WindowStart: 300, WindowEnd: 400, GateReasons: nil}); err != nil {
		t.Fatalf("finalize null: %v", err)
	}

	// FinalizeAnalysis with an empty (non-nil) GateReasons slice writes '[]'.
	if _, err := s.BeginAnalysis(ctx, "sys1", 500, 600, 1000); err != nil {
		t.Fatalf("begin empty-slice: %v", err)
	}
	if err := s.FinalizeAnalysis(ctx, Analysis{SystemID: "sys1", WindowStart: 500, WindowEnd: 600, GateReasons: []string{}}); err != nil {
		t.Fatalf("finalize empty-slice: %v", err)
	}

	// One row with a real reason, to prove it stays distinct.
	if _, err := s.BeginAnalysis(ctx, "sys1", 700, 800, 1000); err != nil {
		t.Fatalf("begin reasoned: %v", err)
	}
	if err := s.FinalizeAnalysis(ctx, Analysis{SystemID: "sys1", WindowStart: 700, WindowEnd: 800, Gated: true, GateReasons: []string{"new_template"}, LLMCalled: true, CostMicros: 10}); err != nil {
		t.Fatalf("finalize reasoned: %v", err)
	}

	rows, err := s.GateRollup(ctx)
	if err != nil {
		t.Fatalf("GateRollup: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 distinct rows (merged-none + reasoned), got %d: %+v", len(rows), rows)
	}

	var none, reasoned *GateRow
	for i := range rows {
		if rows[i].Reasons == nil {
			none = &rows[i]
		} else {
			reasoned = &rows[i]
		}
	}
	if none == nil {
		t.Fatalf("expected a merged nil-Reasons row, got %+v", rows)
	}
	if none.Windows != 3 {
		t.Fatalf("expected the 3 empty spellings merged into 1 row with Windows=3, got %d", none.Windows)
	}
	if reasoned == nil || reasoned.Windows != 1 || len(reasoned.Reasons) != 1 || reasoned.Reasons[0] != "new_template" {
		t.Fatalf("expected the reasoned row to stay distinct, got %+v", reasoned)
	}
	if reasoned.LLMCalls != 1 || reasoned.CostMicros != 10 {
		t.Fatalf("expected reasoned row to carry its own llm_calls/cost, got %+v", reasoned)
	}
	// Windows descending: 3 before 1.
	if rows[0].Windows < rows[1].Windows {
		t.Fatalf("expected Windows-descending order, got %+v", rows)
	}
}

// --- CostRollup ---

func TestCostRollupBucketsByUTCDay(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	day1 := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC).UnixMilli()
	day1Later := time.Date(2026, 8, 20, 20, 0, 0, 0, time.UTC).UnixMilli()
	day2 := time.Date(2026, 8, 21, 5, 0, 0, 0, time.UTC).UnixMilli()

	seed := func(windowStart, createdAt int64, tokens int) {
		if _, err := s.BeginAnalysis(ctx, "sys1", windowStart, windowStart+100, createdAt); err != nil {
			t.Fatalf("begin: %v", err)
		}
		if err := s.FinalizeAnalysis(ctx, Analysis{
			SystemID: "sys1", WindowStart: windowStart, WindowEnd: windowStart + 100,
			LLMCalled: true, Model: "gpt-4o-mini", InputTokens: tokens, CostMicros: int64(tokens),
		}); err != nil {
			t.Fatalf("finalize: %v", err)
		}
	}

	// Two analyses within the same UTC day.
	seed(1, day1, 10)
	seed(2, day1Later, 20)
	// One analysis on the next UTC day.
	seed(3, day2, 30)

	rows, err := s.CostRollup(ctx)
	if err != nil {
		t.Fatalf("CostRollup: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 day buckets, got %d: %+v", len(rows), rows)
	}

	// Ordered day DESC.
	if rows[0].Day != "2026-08-21" {
		t.Fatalf("expected first row to be 2026-08-21, got %s", rows[0].Day)
	}
	if rows[0].Windows != 1 || rows[0].InputTokens != 30 {
		t.Fatalf("expected day2 bucket windows=1 tokens=30, got %+v", rows[0])
	}
	if rows[1].Day != "2026-08-20" {
		t.Fatalf("expected second row to be 2026-08-20, got %s", rows[1].Day)
	}
	if rows[1].Windows != 2 {
		t.Fatalf("expected the two same-day analyses merged into 1 row with Windows=2, got %d", rows[1].Windows)
	}
	if rows[1].InputTokens != 30 {
		t.Fatalf("expected day1 bucket to sum tokens to 30, got %d", rows[1].InputTokens)
	}
}

func TestCostRollupFiltersOnLLMCalled(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	// Gated-out window: llm_called stays false, must not appear in the rollup.
	if _, err := s.BeginAnalysis(ctx, "sys1", 100, 200, 1000); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := s.FinalizeAnalysis(ctx, Analysis{SystemID: "sys1", WindowStart: 100, WindowEnd: 200, LLMCalled: false}); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	rows, err := s.CostRollup(ctx)
	if err != nil {
		t.Fatalf("CostRollup: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("expected 0 rows for a gated-out window, got %d", len(rows))
	}
}

// --- ListAllFindings ---

func seedFinding(t *testing.T, ctx context.Context, s *SQLiteStore, systemID, fp, severity, status string, lastSeen int64) {
	t.Helper()
	if _, err := s.UpsertFinding(ctx, model.Finding{
		SystemID: systemID, Fingerprint: fp, Severity: severity, Title: "t", Summary: "s", SuggestedAction: "a",
		Modules: []string{"m1"}, Evidence: []string{"e1"},
	}, lastSeen); err != nil {
		t.Fatalf("seed finding %s/%s: %v", systemID, fp, err)
	}
	if status == model.StatusStale {
		if _, err := s.MarkStale(ctx, systemID, lastSeen+1); err != nil {
			t.Fatalf("mark stale %s/%s: %v", systemID, fp, err)
		}
	}
}

func TestListAllFindingsFiltersAndOrder(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	seedFinding(t, ctx, s, "sys1", "fp1", "low", model.StatusOpen, 1000)
	seedFinding(t, ctx, s, "sys1", "fp2", "critical", model.StatusOpen, 2000)
	// fp4 is marked stale before fp3 is seeded: MarkStale acts on every open
	// finding in the system at call time, so seeding fp3 (which must stay
	// open) afterwards keeps it out of the sweep.
	seedFinding(t, ctx, s, "sys2", "fp4", "medium", model.StatusStale, 1500)
	seedFinding(t, ctx, s, "sys2", "fp3", "high", model.StatusOpen, 3000)

	// No filters: all 4, in model.SortFindings order (severity asc rank, then last_seen desc).
	all, err := s.ListAllFindings(ctx, "", "", "", "", 0)
	if err != nil {
		t.Fatalf("ListAllFindings: %v", err)
	}
	if len(all) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(all))
	}
	wantOrder := []string{"fp2", "fp3", "fp4", "fp1"} // critical, high, medium, low
	for i, fp := range wantOrder {
		if all[i].Fingerprint != fp {
			t.Fatalf("order[%d]: got %s, want %s (full: %+v)", i, all[i].Fingerprint, fp, all)
		}
	}

	// systemID filter.
	sys1Only, err := s.ListAllFindings(ctx, "sys1", "", "", "", 0)
	if err != nil {
		t.Fatalf("ListAllFindings systemID filter: %v", err)
	}
	if len(sys1Only) != 2 {
		t.Fatalf("expected 2 findings for sys1, got %d", len(sys1Only))
	}

	// status filter.
	staleOnly, err := s.ListAllFindings(ctx, "", model.StatusStale, "", "", 0)
	if err != nil {
		t.Fatalf("ListAllFindings status filter: %v", err)
	}
	if len(staleOnly) != 1 || staleOnly[0].Fingerprint != "fp4" {
		t.Fatalf("expected only fp4 stale, got %+v", staleOnly)
	}

	// severity filter.
	criticalOnly, err := s.ListAllFindings(ctx, "", "", "critical", "", 0)
	if err != nil {
		t.Fatalf("ListAllFindings severity filter: %v", err)
	}
	if len(criticalOnly) != 1 || criticalOnly[0].Fingerprint != "fp2" {
		t.Fatalf("expected only fp2 critical, got %+v", criticalOnly)
	}

	// idLike: a bare value (no "%") is a prefix match against id or fingerprint.
	fpPrefix, err := s.ListAllFindings(ctx, "", "", "", "fp2", 0)
	if err != nil {
		t.Fatalf("ListAllFindings idLike prefix: %v", err)
	}
	if len(fpPrefix) != 1 || fpPrefix[0].Fingerprint != "fp2" {
		t.Fatalf("expected only fp2 for idLike=fp2, got %+v", fpPrefix)
	}

	// idLike: an explicit "%" pattern is passed through, so an operator can
	// search a substring anywhere in id/fingerprint.
	fpSubstring, err := s.ListAllFindings(ctx, "", "", "", "%p3", 0)
	if err != nil {
		t.Fatalf("ListAllFindings idLike substring: %v", err)
	}
	if len(fpSubstring) != 1 || fpSubstring[0].Fingerprint != "fp3" {
		t.Fatalf("expected only fp3 for idLike=%%p3, got %+v", fpSubstring)
	}

	// idLike also matches by the finding's ULID id, not just fingerprint.
	byID, err := s.ListAllFindings(ctx, "", "", "", fpPrefix[0].ID, 0)
	if err != nil {
		t.Fatalf("ListAllFindings idLike by id: %v", err)
	}
	if len(byID) != 1 || byID[0].Fingerprint != "fp2" {
		t.Fatalf("expected only fp2 for idLike=<its id>, got %+v", byID)
	}
}

func TestListAllFindingsHonoursLimitAndDefaultCap(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	for i := 1; i <= 3; i++ {
		seedFinding(t, ctx, s, "sys1", "fp"+string(rune('0'+i)), "low", model.StatusOpen, int64(i*1000))
	}

	limited, err := s.ListAllFindings(ctx, "", "", "", "", 2)
	if err != nil {
		t.Fatalf("ListAllFindings limit=2: %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("expected 2 findings with limit=2, got %d", len(limited))
	}

	all, err := s.ListAllFindings(ctx, "", "", "", "", 0)
	if err != nil {
		t.Fatalf("ListAllFindings default cap: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 findings with limit<=0 (default cap), got %d", len(all))
	}
}

// --- ListTemplates ---

func TestListTemplatesHonoursLimitAndFilter(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if err := s.UpsertTemplates(ctx, "sys1", []model.Template{
		{Template: "t1", Count: 1, ModuleID: "m1", Priority: 1, Category: "info"},
		{Template: "t2", Count: 1, ModuleID: "m1", Priority: 1, Category: "info"},
	}, 1000); err != nil {
		t.Fatalf("upsert templates sys1: %v", err)
	}
	if err := s.UpsertTemplates(ctx, "sys2", []model.Template{
		{Template: "t3", Count: 1, ModuleID: "m1", Priority: 1, Category: "info"},
	}, 1000); err != nil {
		t.Fatalf("upsert templates sys2: %v", err)
	}

	sys1Only, err := s.ListTemplates(ctx, "sys1", 0)
	if err != nil {
		t.Fatalf("ListTemplates sys1: %v", err)
	}
	if len(sys1Only) != 2 {
		t.Fatalf("expected 2 templates for sys1, got %d", len(sys1Only))
	}

	limited, err := s.ListTemplates(ctx, "", 1)
	if err != nil {
		t.Fatalf("ListTemplates limit=1: %v", err)
	}
	if len(limited) != 1 {
		t.Fatalf("expected 1 template with limit=1, got %d", len(limited))
	}

	all, err := s.ListTemplates(ctx, "", 0)
	if err != nil {
		t.Fatalf("ListTemplates default cap: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 templates total, got %d", len(all))
	}
}

// --- ListBaselines ---

func TestListBaselinesFilter(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if err := s.UpsertBaselines(ctx, "sys1", []model.DigestEntry{{ModuleID: "m1", Priority: 1, Observed: 5}}, 0.3); err != nil {
		t.Fatalf("upsert baseline sys1: %v", err)
	}
	if err := s.UpsertBaselines(ctx, "sys2", []model.DigestEntry{{ModuleID: "m1", Priority: 1, Observed: 7}}, 0.3); err != nil {
		t.Fatalf("upsert baseline sys2: %v", err)
	}

	all, err := s.ListBaselines(ctx, "")
	if err != nil {
		t.Fatalf("ListBaselines all: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 baselines, got %d", len(all))
	}

	sys1Only, err := s.ListBaselines(ctx, "sys1")
	if err != nil {
		t.Fatalf("ListBaselines sys1: %v", err)
	}
	if len(sys1Only) != 1 || sys1Only[0].SystemID != "sys1" {
		t.Fatalf("expected only sys1 baseline, got %+v", sys1Only)
	}
}
