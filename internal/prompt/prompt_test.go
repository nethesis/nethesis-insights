// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package prompt

import (
	"flag"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/model"
)

func f(v float64) *float64 { return &v }

// sel is the selection these cases render under: nothing novel, nothing
// deviating, and room for every ambient template. The selection rules have
// their own cases below.
func sel() Selection {
	return Selection{MaxAmbient: 100}
}

func sampleBundle() model.Bundle {
	return model.Bundle{
		CollectorVersion: "1.2.3",
		MaskingVersion:   2,
		Window:           model.Window{Start: 100, End: 200},
		Digest: []model.DigestEntry{
			{ModuleID: "modB", Priority: 1, Observed: 10, Expected: f(5)},
			{ModuleID: "modA", Priority: 3, Observed: 20},
			{ModuleID: "modA", Priority: 1, Observed: 30, Expected: f(10)},
		},
		Templates: []model.Template{
			{Template: "tpl-z", Count: 5, ModuleID: "modA", Priority: 1, Category: "security", Samples: []string{"SECRET-SAMPLE-1"}},
			{Template: "tpl-a", Count: 2, ModuleID: "modA", Priority: 1, Samples: []string{"SECRET-SAMPLE-2"}},
			{Template: "tpl-m", Count: 1, ModuleID: "modB", Priority: 2},
		},
		Budget: model.Budget{
			MaxLines:  1000,
			LinesSeen: 500,
			LinesKept: 400,
			TruncatedModules: []model.TruncatedModule{
				{ModuleID: "modZ", Dropped: 3, Truncated: true},
				{ModuleID: "modA", Dropped: 1, Truncated: true},
			},
		},
	}
}

func sampleOpen() []model.Finding {
	return []model.Finding{
		// tpl-z and tpl-a are both in sampleBundle; "tpl-gone" is not, and
		// must be omitted rather than rendered as an identifier the model
		// could cite back at us.
		{Severity: "high", Title: "Disk almost full", Evidence: []string{"tpl-z", "tpl-gone"}},
		{Severity: "low", Title: "Minor thing", Evidence: []string{"tpl-a"}},
	}
}

func TestRenderDeterministicUnderShuffle(t *testing.T) {
	b1 := sampleBundle()
	open1 := sampleOpen()
	out1 := Render(b1, open1, sel())

	b2 := sampleBundle()
	rand.Shuffle(len(b2.Digest), func(i, j int) { b2.Digest[i], b2.Digest[j] = b2.Digest[j], b2.Digest[i] })
	rand.Shuffle(len(b2.Templates), func(i, j int) { b2.Templates[i], b2.Templates[j] = b2.Templates[j], b2.Templates[i] })
	rand.Shuffle(len(b2.Budget.TruncatedModules), func(i, j int) {
		b2.Budget.TruncatedModules[i], b2.Budget.TruncatedModules[j] = b2.Budget.TruncatedModules[j], b2.Budget.TruncatedModules[i]
	})
	open2 := sampleOpen()
	rand.Shuffle(len(open2), func(i, j int) { open2[i], open2[j] = open2[j], open2[i] })
	out2 := Render(b2, open2, sel())

	if out1 != out2 {
		t.Fatalf("Render not deterministic under shuffle:\n---1---\n%s\n---2---\n%s", out1, out2)
	}
}

func TestRenderNeverContainsSamples(t *testing.T) {
	b := sampleBundle()
	out := Render(b, nil, sel())
	if strings.Contains(out, "SECRET-SAMPLE") {
		t.Fatalf("Render output must never contain sample strings:\n%s", out)
	}
}

func TestParseAcceptsFencedResponse(t *testing.T) {
	body := "```json\n" + `{"window_assessment":"degraded","findings":[` +
		`{"severity":"high","title":"t","summary":"s","suggested_action":"a","modules":["m"],"evidence":["ev1"]}` +
		`]}` + "\n```"
	findings, assessment, err := Parse(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if assessment != "degraded" {
		t.Fatalf("expected degraded, got %s", assessment)
	}
	if len(findings) != 1 || findings[0].Title != "t" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}

func TestParseEmptyFindingsIsValid(t *testing.T) {
	body := `{"window_assessment":"nominal","findings":[]}`
	findings, assessment, err := Parse(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if assessment != "nominal" || len(findings) != 0 {
		t.Fatalf("unexpected result: %v %v", assessment, findings)
	}
}

func TestParseRejectsBadAssessment(t *testing.T) {
	body := `{"window_assessment":"bogus","findings":[]}`
	_, _, err := Parse(body)
	if err == nil || !strings.Contains(err.Error(), "assessment") {
		t.Fatalf("expected assessment error, got %v", err)
	}
}

func TestParseRejectsBadSeverity(t *testing.T) {
	body := `{"window_assessment":"nominal","findings":[` +
		`{"severity":"catastrophic","title":"t","summary":"s","suggested_action":"a","modules":["m"],"evidence":["ev1"]}` +
		`]}`
	_, _, err := Parse(body)
	if err == nil || !strings.Contains(err.Error(), "severity") {
		t.Fatalf("expected severity error, got %v", err)
	}
}

func TestParseRejectsEmptyEvidence(t *testing.T) {
	body := `{"window_assessment":"nominal","findings":[` +
		`{"severity":"low","title":"t","summary":"s","suggested_action":"a","modules":["m"],"evidence":[]}` +
		`]}`
	_, _, err := Parse(body)
	if err == nil || !strings.Contains(err.Error(), "evidence") {
		t.Fatalf("expected evidence error, got %v", err)
	}
}

func TestParseRejectsBlankTitleAndSummary(t *testing.T) {
	body := `{"window_assessment":"nominal","findings":[` +
		`{"severity":"low","title":"  ","summary":"s","suggested_action":"a","modules":["m"],"evidence":["ev1"]}` +
		`]}`
	_, _, err := Parse(body)
	if err == nil || !strings.Contains(err.Error(), "title") {
		t.Fatalf("expected title error, got %v", err)
	}

	body2 := `{"window_assessment":"nominal","findings":[` +
		`{"severity":"low","title":"t","summary":"  ","suggested_action":"a","modules":["m"],"evidence":["ev1"]}` +
		`]}`
	_, _, err = Parse(body2)
	if err == nil || !strings.Contains(err.Error(), "summary") {
		t.Fatalf("expected summary error, got %v", err)
	}
}

// The prompt is the LLM's entire input, so a change to it is a change to every
// finding raised afterwards. The golden file makes that change visible in
// review instead of silent. Regenerate deliberately with -update, never to make
// a red test go green.
var updateGolden = flag.Bool("update", false, "rewrite prompt golden files")

func TestRenderMatchesGolden(t *testing.T) {
	got := Render(sampleBundle(), sampleOpen(), sel())
	golden := filepath.Join("testdata", "render.golden")

	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}

	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run: go test ./internal/prompt/ -update): %v", err)
	}
	if got != string(want) {
		t.Fatalf("prompt does not match golden.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// The identifiers must be the ones THIS window uses, and a template the finding
// was raised from but which is absent now must not be rendered at all.
func TestRenderAlreadyKnownCitesCurrentIdentifiers(t *testing.T) {
	out := Render(sampleBundle(), sampleOpen(), sel())

	// Select orders (modA,1,tpl-a), (modA,1,tpl-z), (modB,2,tpl-m),
	// so tpl-a is T1 and tpl-z is T2.
	if !strings.Contains(out, "[high] Disk almost full\n    evidence: T2\n") {
		t.Fatalf("expected tpl-z rendered as T2 and tpl-gone omitted, got:\n%s", out)
	}
	if !strings.Contains(out, "[low] Minor thing\n    evidence: T1\n") {
		t.Fatalf("expected tpl-a rendered as T1, got:\n%s", out)
	}
	if strings.Contains(out, "tpl-gone") {
		t.Fatalf("a template absent from this window leaked into the prompt:\n%s", out)
	}
}

// A finding whose every template is gone from this window renders as a bare
// title -- never as an empty "evidence:" line, which would read as a citation
// the model could echo back.
func TestRenderAlreadyKnownOmitsEmptyEvidenceLine(t *testing.T) {
	out := Render(sampleBundle(), []model.Finding{
		{Severity: "high", Title: "Vanished", Evidence: []string{"tpl-gone"}},
	}, sel())
	if !strings.Contains(out, "[high] Vanished\n") {
		t.Fatalf("expected the title to still render, got:\n%s", out)
	}
	if strings.Contains(out, "evidence:") {
		t.Fatalf("expected no evidence line when nothing resolves, got:\n%s", out)
	}
}

// The measured waste: a real node ships 160-190 templates and the ones the
// gate actually fired on are 10-30% of them. Everything else is context, and
// context is capped.
func TestSelectKeepsWhatPaidForTheCall(t *testing.T) {
	b := model.Bundle{
		Templates: []model.Template{
			{Template: "<3> [a] novel line", Count: 1, ModuleID: "modA", Priority: 3},
			{Template: "<3> [b] security line", Count: 2, ModuleID: "modB", Priority: 3, Category: "security"},
			{Template: "<3> [c] deviating module line", Count: 3, ModuleID: "modC", Priority: 3},
			{Template: "<3> [d] loud ambient", Count: 99, ModuleID: "modD", Priority: 3},
			{Template: "<3> [e] quiet ambient", Count: 1, ModuleID: "modE", Priority: 3},
		},
	}
	s := Selection{
		Novel:            map[string]bool{model.CanonicalKey("modA", "<3> [a] novel line"): true},
		DeviatingModules: map[string]bool{"modC": true},
		MaxAmbient:       1,
	}

	var got []string
	for _, l := range Select(b, s) {
		got = append(got, l.Template.ModuleID)
	}

	// modA (novel), modB (security), modC (deviating) unconditionally, plus
	// the loudest single ambient line. modE loses the ambient slot to modD.
	want := []string{"modA", "modB", "modC", "modD"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("selected %v, want %v", got, want)
	}
}

// Ten spellings of one condition must reach the model as one line with the
// combined count, not as ten conditions to report separately.
func TestSelectCollapsesVariants(t *testing.T) {
	b := model.Bundle{
		Templates: []model.Template{
			{Template: `<3> [db] checkpoint complete: wrote <NUM> buffers (0.3%); 0 recycled`, Count: 3, ModuleID: "m", Priority: 3},
			{Template: `<3> [db] checkpoint complete: wrote <NUM> buffers (1.8%); 2 recycled`, Count: 7, ModuleID: "m", Priority: 3},
			{Template: `<3> [db] checkpoint complete: wrote <NUM> buffers (9.9%); 4 recycled`, Count: 1, ModuleID: "m", Priority: 3},
		},
	}
	lines := Select(b, Selection{MaxAmbient: 100})
	if len(lines) != 1 {
		t.Fatalf("expected one collapsed line, got %d", len(lines))
	}
	if lines[0].Variants != 3 {
		t.Fatalf("variants=%d, want 3", lines[0].Variants)
	}
	if lines[0].Template.Count != 11 {
		t.Fatalf("count=%d, want the summed 11", lines[0].Template.Count)
	}
	// The representative is the busiest variant: that is the text an operator
	// will read on the finding.
	if !strings.Contains(lines[0].Template.Template, "(1.8%)") {
		t.Fatalf("representative should be the highest-count variant, got %q", lines[0].Template.Template)
	}
}

// A collapsed line inherits the security classification of any variant.
// Losing it would make the gate's security condition unreachable from the
// prompt's side.
func TestSelectCollapsePreservesSecurityCategory(t *testing.T) {
	b := model.Bundle{
		Templates: []model.Template{
			{Template: `<3> [auth] failed for <USER> after 2 tries`, Count: 9, ModuleID: "m", Priority: 3},
			{Template: `<3> [auth] failed for <USER> after 5 tries`, Count: 1, ModuleID: "m", Priority: 3, Category: "security"},
		},
	}
	lines := Select(b, Selection{MaxAmbient: 100})
	if len(lines) != 1 || lines[0].Template.Category != "security" {
		t.Fatalf("collapse dropped the security category: %+v", lines)
	}
}

// TemplateID numbers whatever Select returns, so the two must be built from
// the same Selection or the model's citations resolve to the wrong lines.
func TestResolveEvidenceMatchesRenderedIdentifiers(t *testing.T) {
	b := sampleBundle()
	s := Selection{MaxAmbient: 1}

	out := Render(b, nil, s)
	lines := Select(b, s)

	for i, l := range lines {
		id := TemplateID(i)
		if !strings.Contains(out, "["+id+"] ") {
			t.Fatalf("%s was not rendered:\n%s", id, out)
		}
		got, err := ResolveEvidence(b, s, []string{id})
		if err != nil {
			t.Fatalf("resolve %s: %v", id, err)
		}
		if got[0].Template != l.Template.Template {
			t.Fatalf("%s resolved to %q, rendered %q", id, got[0].Template, l.Template.Template)
		}
	}

	// An identifier past the end of the shown list is a citation of something
	// the model was never given.
	if _, err := ResolveEvidence(b, s, []string{TemplateID(len(lines))}); err == nil {
		t.Fatal("expected an unknown identifier to be rejected")
	}
}

// The window header moves last so that every request shares a prefix a
// provider can cache. A volatile first line makes the cache useless.
func TestRenderStartsWithInvariantHeader(t *testing.T) {
	a := Render(sampleBundle(), nil, sel())
	b := sampleBundle()
	b.Window = model.Window{Start: 999999, End: 1000000}
	b.CollectorVersion = "9.9.9"
	out := Render(b, nil, sel())

	if !strings.HasPrefix(a, header) || !strings.HasPrefix(out, header) {
		t.Fatal("prompts must open with the invariant header")
	}
	if strings.Index(a, "WINDOW\nstart_ms=") < strings.Index(a, "TEMPLATES") {
		t.Fatal("the volatile window block must come after the stable sections")
	}
}
