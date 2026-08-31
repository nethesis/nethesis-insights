// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package analyzer

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/nethesis/nethesis-insights/internal/llm"
	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/store"
)

func newTestStore(t *testing.T) *store.SQLiteStore {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func testConfig() Config {
	return Config{
		Tolerance:  3.0,
		StaleAfter: 24 * time.Hour,
		EWMAAlpha:  0.3,
		Model:      "test-model",
	}
}

func steadyBundle(systemID string) model.Bundle {
	return model.Bundle{
		SchemaVersion:    model.SchemaVersion,
		SystemID:         systemID,
		CollectorVersion: "1.0",
		Window:           model.Window{Start: 100, End: 200},
		Templates: []model.Template{
			{Template: "tpl1", Count: 5, ModuleID: "mod1", Priority: 1},
		},
		Digest: []model.DigestEntry{
			{ModuleID: "mod1", Priority: 1, Observed: 5},
		},
	}
}

func TestGatedBundleNeverCallsLLM(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	stub := &llm.Stub{Content: `{"window_assessment":"nominal","findings":[]}`}
	now := func() int64 { return 1000 }
	a := New(s, stub, testConfig(), now)

	// The very first bundle for a brand-new system always has novel
	// templates, so it necessarily calls the LLM once -- use it to seed
	// known templates and baselines.
	seed := steadyBundle("sys1")
	seed.Window = model.Window{Start: 0, End: 50}
	if err := a.Process(ctx, seed); err != nil {
		t.Fatalf("seed process: %v", err)
	}
	if stub.Calls != 1 {
		t.Fatalf("expected exactly 1 llm call to seed state, got %d", stub.Calls)
	}

	// A second bundle with the same template and digest observed value
	// (now matching the seeded baseline) should be fully steady-state and
	// gated out -- no further LLM call.
	b := steadyBundle("sys1")
	if err := a.Process(ctx, b); err != nil {
		t.Fatalf("process: %v", err)
	}
	if stub.Calls != 1 {
		t.Fatalf("expected gated bundle to never call LLM, calls went from 1 to %d", stub.Calls)
	}
}

func TestDuplicateWindowSkipped(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	stub := &llm.Stub{Content: `{"window_assessment":"nominal","findings":[]}`}
	now := func() int64 { return 1000 }
	a := New(s, stub, testConfig(), now)

	b := steadyBundle("sys1")
	b.Templates[0].Template = "novel-tpl" // force a call the first time

	if err := a.Process(ctx, b); err != nil {
		t.Fatalf("first process: %v", err)
	}
	callsAfterFirst := stub.Calls

	if err := a.Process(ctx, b); err != nil {
		t.Fatalf("duplicate process: %v", err)
	}
	if stub.Calls != callsAfterFirst {
		t.Fatalf("expected duplicate window to be skipped without another llm call, calls went from %d to %d", callsAfterFirst, stub.Calls)
	}
}

func TestFindingStoredWithValidFingerprint(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	stub := &llm.Stub{
		Content: `{"window_assessment":"degraded","findings":[` +
			`{"severity":"high","title":"Disk full","summary":"disk is full","suggested_action":"clean up","modules":[],"evidence":["T1"]}` +
			`]}`,
	}
	now := func() int64 { return 1000 }
	a := New(s, stub, testConfig(), now)

	b := steadyBundle("sys1")

	if err := a.Process(ctx, b); err != nil {
		t.Fatalf("process: %v", err)
	}

	findings, err := s.ListFindings(ctx, "sys1", 0, "")
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if len(findings[0].Fingerprint) != 64 {
		t.Fatalf("expected 64-char fingerprint, got %d: %s", len(findings[0].Fingerprint), findings[0].Fingerprint)
	}
}

// TestLLMFailureLeavesTemplatesUnrecorded is the critical correctness test:
// if the LLM call fails, templates from this bundle must NOT be recorded,
// so a retry still sees them as novel and the gate fires again.
func TestLLMFailureLeavesTemplatesUnrecorded(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	stub := &llm.Stub{Err: errors.New("boom")}
	now := func() int64 { return 1000 }
	a := New(s, stub, testConfig(), now)

	b := steadyBundle("sys1")
	b.Templates[0].Template = "novel-tpl"

	err := a.Process(ctx, b)
	if err == nil {
		t.Fatalf("expected error from failed llm call")
	}

	known, err := s.KnownTemplates(ctx, "sys1")
	if err != nil {
		t.Fatalf("known templates: %v", err)
	}
	if len(known) != 0 {
		t.Fatalf("expected no templates recorded after llm failure, got %v", known)
	}
}

func TestPermanentLLMErrorWraps(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	stub := &llm.Stub{Err: &llm.HTTPError{StatusCode: 400, Body: "bad request"}}
	now := func() int64 { return 1000 }
	a := New(s, stub, testConfig(), now)

	b := steadyBundle("sys1")
	b.Templates[0].Template = "novel-tpl"

	err := a.Process(ctx, b)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, ErrPermanent) {
		t.Fatalf("expected ErrPermanent to be wrapped, got %v", err)
	}
}

func TestParseErrorWrapsPermanent(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	stub := &llm.Stub{Content: `not valid json at all`}
	now := func() int64 { return 1000 }
	a := New(s, stub, testConfig(), now)

	b := steadyBundle("sys1")
	b.Templates[0].Template = "novel-tpl"

	err := a.Process(ctx, b)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, ErrPermanent) {
		t.Fatalf("expected ErrPermanent to be wrapped for parse failure, got %v", err)
	}
}

// The model cites template identifiers, never template text. These pin the
// reason: a fingerprint built from model-authored strings picked up the
// occurrence count printed beside the template, so the same condition changed
// identity every window and was re-raised forever.

func TestIdentityIsStableWhenOnlyTheCountChanges(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	reply := `{"window_assessment":"incident","findings":[` +
		`{"severity":"high","title":"Refusals","summary":"many refusals",` +
		`"suggested_action":"look","modules":[],"evidence":["T1"]}]}`

	first := steadyBundle("sys1")
	first.Templates[0].Count = 37
	a := New(st, &llm.Stub{Content: reply, Model: "m"}, testConfig(), func() int64 { return 1000 })
	if err := a.Process(ctx, first); err != nil {
		t.Fatalf("first window: %v", err)
	}

	second := steadyBundle("sys1")
	second.Window.Start += 100000
	second.Window.End += 100000
	second.Templates[0].Count = 91
	second.Templates = append(second.Templates, model.Template{
		Template: "a brand new line <NUM>", Count: 1, ModuleID: "mod1", Priority: 3,
	})
	b := New(st, &llm.Stub{Content: reply, Model: "m"}, testConfig(), func() int64 { return 2000 })
	if err := b.Process(ctx, second); err != nil {
		t.Fatalf("second window: %v", err)
	}

	found, err := st.OpenFindings(ctx, "sys1")
	if err != nil {
		t.Fatalf("OpenFindings: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("expected the finding to deduplicate, got %d findings", len(found))
	}
	if found[0].OccurrenceCount != 2 {
		t.Fatalf("expected occurrence_count 2, got %d", found[0].OccurrenceCount)
	}
}

func TestEvidenceAndModulesAreResolvedNotTrusted(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	// The model returns a bogus module; the server must ignore it.
	reply := `{"window_assessment":"incident","findings":[` +
		`{"severity":"high","title":"X","summary":"y","suggested_action":"z",` +
		`"modules":["6"],"evidence":["T1"]}]}`
	a := New(st, &llm.Stub{Content: reply, Model: "m"}, testConfig(), func() int64 { return 1000 })
	if err := a.Process(ctx, steadyBundle("sys1")); err != nil {
		t.Fatalf("Process: %v", err)
	}
	found, _ := st.OpenFindings(ctx, "sys1")
	if len(found) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(found))
	}
	if len(found[0].Modules) != 1 || found[0].Modules[0] != "mod1" {
		t.Fatalf("modules must come from the cited template, got %v", found[0].Modules)
	}
	if len(found[0].Evidence) != 1 || found[0].Evidence[0] != "tpl1" {
		t.Fatalf("evidence must be resolved template text, got %v", found[0].Evidence)
	}
}

func TestFindingWithUnknownEvidenceIsDiscarded(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	reply := `{"window_assessment":"incident","findings":[` +
		`{"severity":"high","title":"Hallucinated","summary":"y","suggested_action":"z",` +
		`"modules":[],"evidence":["T99"]}]}`
	a := New(st, &llm.Stub{Content: reply, Model: "m"}, testConfig(), func() int64 { return 1000 })
	if err := a.Process(ctx, steadyBundle("sys1")); err != nil {
		t.Fatalf("Process: %v", err)
	}
	found, _ := st.OpenFindings(ctx, "sys1")
	if len(found) != 0 {
		t.Fatalf("a finding citing a nonexistent template must be dropped, got %d", len(found))
	}
}

// A transient LLM failure must leave the window reprocessable.
//
// Claiming the window on insert alone meant a timeout left the analyses row
// behind, so the edge's retry was rejected as a duplicate and the window could
// never be analysed again -- observed live, where a slow model produced a 503
// and the immediate retry logged "duplicate window skipped".
func TestTransientFailureLeavesTheWindowRetryable(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	bundle := steadyBundle("sys1")

	failing := &llm.Stub{Err: &llm.HTTPError{StatusCode: 503, Body: "upstream down"}}
	a := New(st, failing, testConfig(), func() int64 { return 1000 })
	if err := a.Process(ctx, bundle); err == nil {
		t.Fatal("expected the transient failure to surface")
	}

	// The retry must actually reach the LLM, not be dropped as a duplicate.
	reply := `{"window_assessment":"incident","findings":[` +
		`{"severity":"high","title":"Recovered","summary":"s","suggested_action":"a",` +
		`"modules":[],"evidence":["T1"]}]}`
	ok := &llm.Stub{Content: reply, Model: "m"}
	b := New(st, ok, testConfig(), func() int64 { return 2000 })
	if err := b.Process(ctx, bundle); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if ok.Calls != 1 {
		t.Fatalf("retry must reach the LLM, got %d calls", ok.Calls)
	}
	found, _ := st.OpenFindings(ctx, "sys1")
	if len(found) != 1 {
		t.Fatalf("expected the retry to produce the finding, got %d", len(found))
	}
}

// A genuinely completed window must still be rejected on re-delivery.
func TestCompletedWindowIsStillIdempotent(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	bundle := steadyBundle("sys1")
	stub := &llm.Stub{Content: `{"window_assessment":"nominal","findings":[]}`, Model: "m"}
	a := New(st, stub, testConfig(), func() int64 { return 1000 })

	if err := a.Process(ctx, bundle); err != nil {
		t.Fatalf("first: %v", err)
	}
	calls := stub.Calls
	if err := a.Process(ctx, bundle); err != nil {
		t.Fatalf("second: %v", err)
	}
	if stub.Calls != calls {
		t.Fatalf("a completed window must not be reprocessed, calls went %d -> %d", calls, stub.Calls)
	}
}

// A permanent failure must close the window rather than retry into the same wall.
func TestPermanentFailureClosesTheWindow(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	bundle := steadyBundle("sys1")

	bad := &llm.Stub{Err: &llm.HTTPError{StatusCode: 400, Body: "bad schema"}}
	a := New(st, bad, testConfig(), func() int64 { return 1000 })
	err := a.Process(ctx, bundle)
	if !errors.Is(err, ErrPermanent) {
		t.Fatalf("expected ErrPermanent, got %v", err)
	}

	retry := &llm.Stub{Content: `{"window_assessment":"nominal","findings":[]}`}
	b := New(st, retry, testConfig(), func() int64 { return 2000 })
	if err := b.Process(ctx, bundle); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if retry.Calls != 0 {
		t.Fatalf("a permanently failed window must not be reprocessed, got %d calls", retry.Calls)
	}
}

// The reported symptom, as a test: the same recurring condition, but the model
// cites a wider set of templates the second time because a new country code
// showed up in that window. Under fingerprint v1 this inserted a second
// finding; it must bump the first instead.
func TestRecurrenceWithADifferentCitedSetIsBumped(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	crowdBundle := func(windowStart int64, templates ...model.Template) model.Bundle {
		return model.Bundle{
			SchemaVersion:    model.SchemaVersion,
			SystemID:         "sys1",
			CollectorVersion: "1.0",
			Window:           model.Window{Start: windowStart, End: windowStart + 100},
			Templates:        templates,
			Digest:           []model.DigestEntry{{ModuleID: "crowdsec1", Priority: 3, Observed: 5}},
		}
	}
	us := model.Template{Template: "ssh-bf by ip <IP> (US/<NUM>)", Count: 9, ModuleID: "crowdsec1", Priority: 3, Category: "security"}
	de := model.Template{Template: "ssh-bf by ip <IP> (DE/<NUM>)", Count: 4, ModuleID: "crowdsec1", Priority: 3, Category: "security"}

	// First window: one template cited.
	oneCitation := `{"window_assessment":"incident","findings":[` +
		`{"severity":"high","title":"SSH Brute-Force Activity Detected","summary":"s",` +
		`"suggested_action":"a","modules":[],"evidence":["T1"]}]}`
	a := New(st, &llm.Stub{Content: oneCitation, Model: "m"}, testConfig(), func() int64 { return 1000 })
	if err := a.Process(ctx, crowdBundle(100, us)); err != nil {
		t.Fatalf("first window: %v", err)
	}

	// Second window: same condition, but a new country arrived and the model
	// cites both templates, and words the title differently.
	twoCitations := `{"window_assessment":"incident","findings":[` +
		`{"severity":"high","title":"Repeated failed SSH logins from many hosts","summary":"s",` +
		`"suggested_action":"a","modules":[],"evidence":["T1","T2"]}]}`
	b := New(st, &llm.Stub{Content: twoCitations, Model: "m"}, testConfig(), func() int64 { return 2000 })
	if err := b.Process(ctx, crowdBundle(100000, de, us)); err != nil {
		t.Fatalf("second window: %v", err)
	}

	found, err := st.OpenFindings(ctx, "sys1")
	if err != nil {
		t.Fatalf("OpenFindings: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("expected one deduplicated finding, got %d: %+v", len(found), found)
	}
	if found[0].OccurrenceCount != 2 {
		t.Fatalf("expected occurrence_count 2, got %d", found[0].OccurrenceCount)
	}
}

// A bundle emptied by module exclusion must still record an analyses row and
// must never reach the LLM. Otherwise a CrowdSec-only window would look like a
// window that never arrived.
func TestEmptyBundleAfterExclusionIsGatedNotLost(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	full := steadyBundle("sys1")
	emptied := full.ExcludeModules(map[string]bool{"mod1": true})

	stub := &llm.Stub{Content: `{"window_assessment":"nominal","findings":[]}`, Model: "m"}
	a := New(st, stub, testConfig(), func() int64 { return 1000 })
	if err := a.Process(ctx, emptied); err != nil {
		t.Fatalf("process emptied bundle: %v", err)
	}

	if stub.Calls != 0 {
		t.Fatalf("an emptied bundle reached the LLM: %d calls", stub.Calls)
	}
	rows, err := st.ListAnalyses(ctx, "sys1", 10)
	if err != nil {
		t.Fatalf("ListAnalyses: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one analyses row for the emptied window, got %d", len(rows))
	}
	if !rows[0].Gated {
		t.Fatalf("expected the emptied window to be recorded as gated: %+v", rows[0])
	}
}
