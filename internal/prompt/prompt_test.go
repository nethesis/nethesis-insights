// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package prompt

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/model"
)

func f(v float64) *float64 { return &v }

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
		{Severity: "high", Title: "Disk almost full"},
		{Severity: "low", Title: "Minor thing"},
	}
}

func TestRenderDeterministicUnderShuffle(t *testing.T) {
	b1 := sampleBundle()
	open1 := sampleOpen()
	out1 := Render(b1, open1)

	b2 := sampleBundle()
	rand.Shuffle(len(b2.Digest), func(i, j int) { b2.Digest[i], b2.Digest[j] = b2.Digest[j], b2.Digest[i] })
	rand.Shuffle(len(b2.Templates), func(i, j int) { b2.Templates[i], b2.Templates[j] = b2.Templates[j], b2.Templates[i] })
	rand.Shuffle(len(b2.Budget.TruncatedModules), func(i, j int) {
		b2.Budget.TruncatedModules[i], b2.Budget.TruncatedModules[j] = b2.Budget.TruncatedModules[j], b2.Budget.TruncatedModules[i]
	})
	open2 := sampleOpen()
	rand.Shuffle(len(open2), func(i, j int) { open2[i], open2[j] = open2[j], open2[i] })
	out2 := Render(b2, open2)

	if out1 != out2 {
		t.Fatalf("Render not deterministic under shuffle:\n---1---\n%s\n---2---\n%s", out1, out2)
	}
}

func TestRenderNeverContainsSamples(t *testing.T) {
	b := sampleBundle()
	out := Render(b, nil)
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
