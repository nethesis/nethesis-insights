// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package analyzer

import (
	"context"
	"testing"
	"time"

	"github.com/nethesis/nethesis-insights/internal/llm"
	"github.com/nethesis/nethesis-insights/internal/model"
	logsstore "github.com/nethesis/nethesis-insights/internal/store/logs"
)

const (
	findingJSON = `{"window_assessment":"degraded","findings":[` +
		`{"severity":"high","title":"Surge","summary":"s","suggested_action":"a","modules":[],"evidence":["T1"]}]}`
	emptyJSON = `{"window_assessment":"nominal","findings":[]}`
	hour      = int64(time.Hour / time.Millisecond)
)

// clock is a settable now() for tests that step through time.
type clock struct{ t int64 }

func (c *clock) now() int64 { return c.t }

func reuseConfig(window time.Duration) Config {
	cfg := testConfig()
	cfg.TriggerReuseWindow = window
	return cfg
}

// deviating is a window whose only gate reason is a deviation of mod1/1,
// once tpl1 is known: the same trigger key every time it is sent.
func deviating(systemID string, start int64) model.Bundle {
	b := steadyBundle(systemID)
	b.Window = model.Window{Start: start, End: start + 100}
	b.Digest[0].Observed = 100
	b.Digest[0].Expected = f(1)
	return b
}

// seed makes tpl1 known on systemID, so later windows fire on deviation
// alone.
func seed(t *testing.T, a *Analyzer, systemID string) {
	t.Helper()
	b := steadyBundle(systemID)
	b.Window = model.Window{Start: 0, End: 50}
	if err := a.Process(context.Background(), b); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func process(t *testing.T, a *Analyzer, b model.Bundle) {
	t.Helper()
	if err := a.Process(context.Background(), b); err != nil {
		t.Fatalf("process window %d: %v", b.Window.Start, err)
	}
}

func analysisAt(t *testing.T, s *logsstore.Store, systemID string, windowStart int64) logsstore.AnalysisRow {
	t.Helper()
	rows, err := s.ListAnalyses(context.Background(), systemID, 100)
	if err != nil {
		t.Fatalf("ListAnalyses: %v", err)
	}
	var found []logsstore.AnalysisRow
	for _, r := range rows {
		if r.WindowStart == windowStart {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("window %d has %d analyses rows, want exactly 1", windowStart, len(found))
	}
	return found[0]
}

func TestReusableTriggerDoesNotCallTheLLM(t *testing.T) {
	s := newTestStore(t)
	stub := &llm.Stub{Content: findingJSON}
	c := &clock{t: 1000}
	a := New(s, stub, testBudget(s), reuseConfig(time.Hour), c.now)
	seed(t, a, "sys1")

	c.t = 2000
	process(t, a, deviating("sys1", 1000))
	calls := stub.Calls
	before, err := s.ListAllFindings(context.Background(), "sys1", "", "", "", "", 0)
	if err != nil || len(before) != 1 {
		t.Fatalf("findings: %v %v", before, err)
	}

	c.t = 3000
	process(t, a, deviating("sys1", 2000))
	if stub.Calls != calls {
		t.Fatalf("a reusable trigger called the LLM again (%d -> %d)", calls, stub.Calls)
	}

	row := analysisAt(t, s, "sys1", 2000)
	if row.SuppressedBy != SuppressedTriggerHit || row.LLMCalled || !row.Gated || row.CostMicros != 0 {
		t.Fatalf("unexpected reused analyses row: %+v", row)
	}
	if len(row.GateReasons) == 0 || row.TriggerKey == "" {
		t.Fatalf("a reused window must keep its gate reasons and trigger key: %+v", row)
	}
	if first := analysisAt(t, s, "sys1", 1000); first.TriggerKey != row.TriggerKey {
		t.Fatalf("the two windows did not share a trigger key: %q vs %q", first.TriggerKey, row.TriggerKey)
	}

	findings, err := s.ListAllFindings(context.Background(), "sys1", "", "", "", "", 0)
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings: %v %v", findings, err)
	}
	if findings[0].OccurrenceCount != before[0].OccurrenceCount+1 || findings[0].LastSeen != 3000 {
		t.Fatalf("reuse did not bump the finding once: before %d, after %+v", before[0].OccurrenceCount, findings[0])
	}
}

// A reuse bumps last_seen, so measuring the window from the finding would let
// it renew itself forever and a persistent condition would never be analysed
// again. It is measured from the last paid call.
func TestReuseWindowCountsFromTheLastPaidCall(t *testing.T) {
	s := newTestStore(t)
	stub := &llm.Stub{Content: findingJSON}
	c := &clock{t: 1000}
	a := New(s, stub, testBudget(s), reuseConfig(time.Hour), c.now)
	seed(t, a, "sys1")

	c.t = 10 * hour
	process(t, a, deviating("sys1", 1000))
	calls := stub.Calls

	c.t = 10*hour + hour/2
	process(t, a, deviating("sys1", 2000))
	if stub.Calls != calls {
		t.Fatalf("expected a reuse inside the window")
	}

	c.t = 10*hour + hour + 1
	process(t, a, deviating("sys1", 3000))
	if stub.Calls != calls+1 {
		t.Fatalf("expected a call once the window since the last paid call elapsed, calls %d -> %d", calls, stub.Calls)
	}
}

func TestStaleFindingIsNotReused(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	stub := &llm.Stub{Content: findingJSON}
	c := &clock{t: 1000}
	a := New(s, stub, testBudget(s), reuseConfig(time.Hour), c.now)
	seed(t, a, "sys1")

	c.t = 2000
	process(t, a, deviating("sys1", 1000))
	calls := stub.Calls
	if _, err := s.MarkStale(ctx, "sys1", 1<<60); err != nil {
		t.Fatal(err)
	}

	c.t = 3000
	process(t, a, deviating("sys1", 2000))
	if stub.Calls != calls+1 {
		t.Fatalf("a trigger whose finding went stale was reused instead of re-analysed")
	}
}

// A call that raised nothing is an answer too: the model looked at exactly
// this trigger and found nothing worth reporting.
func TestAnEmptyVerdictIsReused(t *testing.T) {
	s := newTestStore(t)
	stub := &llm.Stub{Content: emptyJSON}
	c := &clock{t: 1000}
	a := New(s, stub, testBudget(s), reuseConfig(time.Hour), c.now)
	seed(t, a, "sys1")

	c.t = 2000
	process(t, a, deviating("sys1", 1000))
	calls := stub.Calls
	c.t = 3000
	process(t, a, deviating("sys1", 2000))
	if stub.Calls != calls {
		t.Fatalf("an empty verdict was not reused")
	}
}

// Reuse is per system: the same trigger on a second cluster is analysed on
// that cluster.
func TestReuseDoesNotCrossSystems(t *testing.T) {
	s := newTestStore(t)
	stub := &llm.Stub{Content: findingJSON}
	c := &clock{t: 1000}
	a := New(s, stub, testBudget(s), reuseConfig(time.Hour), c.now)
	seed(t, a, "sys1")
	seed(t, a, "sys2")

	c.t = 2000
	process(t, a, deviating("sys1", 1000))
	calls := stub.Calls
	process(t, a, deviating("sys2", 1000))
	if stub.Calls != calls+1 {
		t.Fatalf("a trigger paid for on sys1 was reused on sys2")
	}
}

func TestReuseIsOffWhenTheWindowIsZero(t *testing.T) {
	s := newTestStore(t)
	stub := &llm.Stub{Content: findingJSON}
	c := &clock{t: 1000}
	a := New(s, stub, testBudget(s), reuseConfig(0), c.now)
	seed(t, a, "sys1")

	c.t = 2000
	process(t, a, deviating("sys1", 1000))
	calls := stub.Calls
	c.t = 3000
	process(t, a, deviating("sys1", 2000))
	if stub.Calls != calls+1 {
		t.Fatalf("TRIGGER_REUSE_WINDOW=0 must disable reuse")
	}
}

// Decisions change what is paid for and what is delivered, never what the
// model is told. Two deployments that differ only by decisions on the class
// behind an open finding -- hiding it, retagging its security bit, a
// severity override, a doc reference -- must render byte-identical prompts
// for the next window.
func TestDecisionsNeverReachThePrompt(t *testing.T) {
	render := func(decide bool) string {
		s := newTestStore(t)
		stub := &llm.Stub{Content: findingJSON}
		c := &clock{t: 1000}
		a := New(s, stub, testBudget(s), testConfig(), c.now)
		seed(t, a, "sys1")

		c.t = 2000
		process(t, a, deviating("sys1", 1000)) // raises the open finding
		if decide {
			findings, err := s.ListAllFindings(context.Background(), "sys1", "", "", "", "", 0)
			if err != nil || len(findings) != 1 {
				t.Fatalf("list findings: %v %v", findings, err)
			}
			key := findings[0].ClassKey
			if key == "" {
				t.Fatal("the open finding carries no class key")
			}
			ctx := context.Background()
			if err := s.SetClassVisibility(ctx, key, logsstore.VisibilityOperator, "op", 2000); err != nil {
				t.Fatal(err)
			}
			if err := s.SetClassSecurity(ctx, key, true, "op", 2000); err != nil {
				t.Fatal(err)
			}
			if err := s.SetClassSeverity(ctx, key, "critical", "op", 2000); err != nil {
				t.Fatal(err)
			}
			if err := s.SetClassDocRef(ctx, key, "https://docs.example.org/x", "op", 2000); err != nil {
				t.Fatal(err)
			}
		}

		c.t = 3000
		next := steadyBundle("sys1")
		next.Window = model.Window{Start: 2000, End: 2100}
		next.Templates = append(next.Templates,
			model.Template{Template: "<3> [svc] unrelated new line", Count: 1, ModuleID: "mod2", Priority: 3})
		process(t, a, next)
		return stub.LastRequest.UserPrompt
	}

	without, with := render(false), render(true)
	if without == "" || without != with {
		t.Fatalf("an operator decision changed the prompt:\n--- without\n%s\n--- with\n%s", without, with)
	}
}

func TestProcessReportsTriggerSuppressions(t *testing.T) {
	s := newTestStore(t)
	stub := &llm.Stub{Content: emptyJSON}
	c := &clock{t: 1000}
	a := New(s, stub, testBudget(s), reuseConfig(time.Hour), c.now)
	rec := &recordingAnalyzerMetrics{}
	a.Metrics = rec.hooks()
	seed(t, a, "sys1")

	c.t = 2000
	process(t, a, deviating("sys1", 1000))
	c.t = 3000
	process(t, a, deviating("sys1", 2000))

	if len(rec.triggerSuppressions) != 1 || rec.triggerSuppressions[0] != SuppressedTriggerHit {
		t.Fatalf("trigger suppressions = %v, want [%s]", rec.triggerSuppressions, SuppressedTriggerHit)
	}
}
