// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package gate

import (
	"reflect"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/model"
)

func f(v float64) *float64 { return &v }

func baseBundle() model.Bundle {
	return model.Bundle{
		Templates: []model.Template{
			{Template: "t1", ModuleID: "mod1", Priority: 3, Category: ""},
		},
		Digest: []model.DigestEntry{
			{ModuleID: "mod1", Priority: 3, Observed: 10},
		},
	}
}

func TestSteadyStateNoCall(t *testing.T) {
	b := baseBundle()
	s := SystemState{
		KnownTemplates: map[string]bool{"t1": true},
		Baselines:      map[BaselineKey]float64{{ModuleID: "mod1", Priority: 3}: 10},
	}
	d := Evaluate(b, s, 3.0)
	if d.Call {
		t.Fatalf("expected no call in steady state, got reasons %v", d.Reasons)
	}
}

func TestNewTemplateCalls(t *testing.T) {
	b := baseBundle()
	s := SystemState{
		KnownTemplates: map[string]bool{},
		Baselines:      map[BaselineKey]float64{{ModuleID: "mod1", Priority: 3}: 10},
	}
	d := Evaluate(b, s, 3.0)
	if !d.Call {
		t.Fatalf("expected call for new template")
	}
	if d.Reasons[0] != "new_templates=1" {
		t.Fatalf("expected new_templates=1, got %v", d.Reasons)
	}
}

func TestDeviationViaExpectedCalls(t *testing.T) {
	b := baseBundle()
	b.Digest[0].Expected = f(1)
	b.Digest[0].Observed = 100
	s := SystemState{
		KnownTemplates: map[string]bool{"t1": true},
		Baselines:      map[BaselineKey]float64{},
	}
	d := Evaluate(b, s, 3.0)
	if !d.Call {
		t.Fatalf("expected call for deviation, got %v", d.Reasons)
	}
}

func TestDeviationFallsBackToBaseline(t *testing.T) {
	b := baseBundle()
	b.Digest[0].Observed = 100
	b.Digest[0].Expected = nil
	s := SystemState{
		KnownTemplates: map[string]bool{"t1": true},
		Baselines:      map[BaselineKey]float64{{ModuleID: "mod1", Priority: 3}: 1},
	}
	d := Evaluate(b, s, 3.0)
	if !d.Call {
		t.Fatalf("expected call via baseline fallback, got %v", d.Reasons)
	}
}

func TestExpectedZeroNeverPanicsNoCall(t *testing.T) {
	b := baseBundle()
	b.Digest[0].Observed = 1000
	b.Digest[0].Expected = f(0)
	s := SystemState{
		KnownTemplates: map[string]bool{"t1": true},
		Baselines:      map[BaselineKey]float64{}, // also zero/missing
	}
	d := Evaluate(b, s, 3.0)
	if d.Call {
		t.Fatalf("expected no call when expected<=0, got %v", d.Reasons)
	}
}

func TestSecurityAlwaysCalls(t *testing.T) {
	b := baseBundle()
	b.Templates[0].Category = "security"
	s := SystemState{
		KnownTemplates: map[string]bool{"t1": true},
		Baselines:      map[BaselineKey]float64{{ModuleID: "mod1", Priority: 3}: 10},
	}
	d := Evaluate(b, s, 3.0)
	if !d.Call {
		t.Fatalf("expected call for security category")
	}
	if d.Reasons[0] != ReasonSecurity {
		t.Fatalf("expected security reason first, got %v", d.Reasons)
	}
}

func TestTruncationAloneNoCall(t *testing.T) {
	b := baseBundle()
	b.Budget.TruncatedModules = []model.TruncatedModule{{ModuleID: "mod1", Dropped: 5, Truncated: true}}
	s := SystemState{
		KnownTemplates: map[string]bool{"t1": true},
		Baselines:      map[BaselineKey]float64{{ModuleID: "mod1", Priority: 3}: 10},
	}
	d := Evaluate(b, s, 3.0)
	if d.Call {
		t.Fatalf("expected truncation alone to not call, got %v", d.Reasons)
	}
}

func TestTruncationPlusDeviationCalls(t *testing.T) {
	b := baseBundle()
	b.Digest[0].Observed = 100
	b.Budget.TruncatedModules = []model.TruncatedModule{{ModuleID: "mod1", Dropped: 5, Truncated: true}}
	s := SystemState{
		KnownTemplates: map[string]bool{"t1": true},
		Baselines:      map[BaselineKey]float64{{ModuleID: "mod1", Priority: 3}: 1},
	}
	d := Evaluate(b, s, 3.0)
	if !d.Call {
		t.Fatalf("expected call for truncation+deviation")
	}
	found := false
	for _, r := range d.Reasons {
		if r == "truncated_deviating:mod1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected truncated_deviating reason, got %v", d.Reasons)
	}
}

func TestSecurityOnlySuppressesNoveltyAndDeviation(t *testing.T) {
	b := baseBundle()
	b.Digest[0].Observed = 1000
	b.Digest[0].Expected = f(1)
	s := SystemState{
		KnownTemplates: map[string]bool{}, // everything novel
		Baselines:      map[BaselineKey]float64{},
		SecurityOnly:   true,
	}
	d := Evaluate(b, s, 3.0)
	if d.Call {
		t.Fatalf("expected SecurityOnly to suppress novelty/deviation, got %v", d.Reasons)
	}
}

func TestSecurityOnlyStillCallsForSecurity(t *testing.T) {
	b := baseBundle()
	b.Templates[0].Category = "security"
	s := SystemState{
		KnownTemplates: map[string]bool{},
		Baselines:      map[BaselineKey]float64{},
		SecurityOnly:   true,
	}
	d := Evaluate(b, s, 3.0)
	if !d.Call {
		t.Fatalf("expected SecurityOnly to still call for security category")
	}
	if !reflect.DeepEqual(d.Reasons, []string{ReasonSecurity}) {
		t.Fatalf("expected only security reason, got %v", d.Reasons)
	}
}

func TestReasonsDeterministicAcrossRepeats(t *testing.T) {
	b := model.Bundle{
		Templates: []model.Template{
			{Template: "t1", ModuleID: "modZ", Priority: 1},
			{Template: "t2", ModuleID: "modA", Priority: 2},
			{Template: "t3", ModuleID: "modB", Priority: 1, Category: "security"},
		},
		Digest: []model.DigestEntry{
			{ModuleID: "modZ", Priority: 1, Observed: 100},
			{ModuleID: "modA", Priority: 2, Observed: 200},
		},
		Budget: model.Budget{
			TruncatedModules: []model.TruncatedModule{
				{ModuleID: "modA", Truncated: true},
				{ModuleID: "modZ", Truncated: true},
			},
		},
	}
	s := SystemState{
		KnownTemplates: map[string]bool{},
		Baselines: map[BaselineKey]float64{
			{ModuleID: "modZ", Priority: 1}: 1,
			{ModuleID: "modA", Priority: 2}: 1,
		},
	}
	var first Decision
	for i := 0; i < 20; i++ {
		d := Evaluate(b, s, 3.0)
		if i == 0 {
			first = d
		} else if !reflect.DeepEqual(first, d) {
			t.Fatalf("non-deterministic reasons across repeats: %v vs %v", first, d)
		}
	}
}
