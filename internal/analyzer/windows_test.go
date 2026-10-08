// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package analyzer

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/nethesis/nethesis-insights/internal/budget"
	"github.com/nethesis/nethesis-insights/internal/llm"
	"github.com/nethesis/nethesis-insights/internal/model"
	logsstore "github.com/nethesis/nethesis-insights/internal/store/logs"
)

const (
	findingJSON = `{"window_assessment":"degraded","findings":[` +
		`{"severity":"high","title":"Surge","summary":"s","suggested_action":"a","modules":[],"evidence":["T1"]}]}`
	emptyJSON = `{"window_assessment":"nominal","findings":[]}`
	day       = int64(24 * time.Hour / time.Millisecond)
)

// clock is a settable now() for tests that step through time.
type clock struct{ t int64 }

func (c *clock) now() int64 { return c.t }

// fresh is a window that carries tpl1 and one line the system has not sent,
// so it is paid for whatever came before it.
func fresh(systemID string, start int64) model.Bundle {
	b := steadyBundle(systemID)
	b.Window = model.Window{Start: start, End: start + 100}
	b.Templates = append(b.Templates, model.Template{
		Template: fmt.Sprintf("<3> [svc] new line at %d", start), Count: 1, ModuleID: "mod2", Priority: 3,
	})
	return b
}

// seed makes tpl1 known on systemID.
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

// Decisions change what is paid for and what is delivered, never what the
// model is told. Two deployments that differ only by decisions on the class
// behind an open finding -- hiding it, dismissing it, retagging its security bit, a
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
		process(t, a, fresh("sys1", 1000)) // raises the open finding
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
			if err := s.SetClassVisibility(ctx, key, logsstore.VisibilityDismissed, "op", 2000); err != nil {
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

// Every fresh window lands in exactly one WindowResults bucket, and a
// duplicate in none: windows_total is "gated vs not gated" on the dashboard,
// so a path that forgot to count would make the split quietly wrong.
func TestProcessCountsEveryWindowOnce(t *testing.T) {
	s := newTestStore(t)
	stub := &llm.Stub{Content: emptyJSON}
	c := &clock{t: 1000}
	a := New(s, stub, testBudget(s), testConfig(), c.now)
	rec := &recordingAnalyzerMetrics{}
	a.Metrics = rec.hooks()

	seed(t, a, "sys1") // novel template
	c.t = 2000
	process(t, a, fresh("sys1", 1000)) // a new line: paid
	quiet := steadyBundle("sys1")
	quiet.Window = model.Window{Start: 3000, End: 3100}
	process(t, a, quiet)
	process(t, a, quiet) // duplicate: not counted

	want := []string{WindowCalled, WindowCalled, WindowGatedOut}
	if !slices.Equal(rec.windows, want) {
		t.Fatalf("windows = %v, want %v", rec.windows, want)
	}
}

func TestProcessCountsBudgetSuppressedWindows(t *testing.T) {
	s := newTestStore(t)
	stub := &llm.Stub{Content: emptyJSON}
	capped := budget.New(s, budget.Config{MaxCallsPerSystemPerDay: 1}, func() int64 { return 1000 })
	a := New(s, stub, capped, testConfig(), func() int64 { return 1000 })
	rec := &recordingAnalyzerMetrics{}
	a.Metrics = rec.hooks()

	seed(t, a, "sys1")
	process(t, a, fresh("sys1", 1000))

	want := []string{WindowCalled, WindowBudget}
	if !slices.Equal(rec.windows, want) {
		t.Fatalf("windows = %v, want %v", rec.windows, want)
	}
}

// The gate's two novelty refinements, end to end: a line differing from a
// known one only in an identifier is not paid for, and a known line back
// after the silence is. Both are counted, so their effect on spend is
// measured rather than assumed.
func TestNearKnownAndReturningTemplates(t *testing.T) {
	const (
		sipKnown = `<3> [kamailio] <NUM>(<PID>) ERROR: <script>: fevigort37u6sbhqkm2p9396@<IP> INVITE-<NUM> Malformed SIP request from <IP>:<PORT>`
		sipNew   = `<3> [kamailio] <NUM>(<PID>) ERROR: <script>: 16emkwe6stxzzm2az0fu6n7l@<IP> INVITE-<NUM> Malformed SIP request from <IP>:<PORT>`
	)
	s := newTestStore(t)
	stub := &llm.Stub{Content: emptyJSON}
	c := &clock{t: 1000}
	cfg := testConfig()
	cfg.Gate.Similarity = 0.9
	cfg.Gate.Silence = 8 * day
	a := New(s, stub, testBudget(s), cfg, c.now)
	rec := &recordingAnalyzerMetrics{}
	a.Metrics = rec.hooks()

	first := steadyBundle("sys1")
	first.Window = model.Window{Start: 0, End: 100}
	first.Templates = append(first.Templates, model.Template{Template: sipKnown, Count: 1, ModuleID: "nethvoice-proxy1", Priority: 3})
	process(t, a, first)
	if stub.Calls != 1 {
		t.Fatalf("the first window is always novel, got %d calls", stub.Calls)
	}

	c.t = day
	nearKnown := steadyBundle("sys1")
	nearKnown.Window = model.Window{Start: day, End: day + 100}
	nearKnown.Templates = append(nearKnown.Templates, model.Template{Template: sipNew, Count: 1, ModuleID: "nethvoice-proxy1", Priority: 3})
	process(t, a, nearKnown)
	if stub.Calls != 1 {
		t.Fatalf("a near-known line bought a call, got %d calls", stub.Calls)
	}

	c.t = 10 * day
	back := steadyBundle("sys1")
	back.Window = model.Window{Start: 10 * day, End: 10*day + 100}
	process(t, a, back)
	if stub.Calls != 2 {
		t.Fatalf("a line back after the silence must be paid for, got %d calls", stub.Calls)
	}

	if rec.templates[TemplatesNearKnown] != 1 || rec.templates[TemplatesReturning] != 1 {
		t.Fatalf("templates = %v, want one near_known and one returning", rec.templates)
	}
}
