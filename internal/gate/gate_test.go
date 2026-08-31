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
	if d.Reasons[0] != ReasonNewTemplates {
		t.Fatalf("expected %s, got %v", ReasonNewTemplates, d.Reasons)
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

// A steady-state security template must NOT fire the gate. This is the whole
// point of the security condition being novelty-scoped: sshd auth failures
// arrive continuously on any internet-facing node, so the previous
// "any security template calls" rule made the gate a no-op -- 352 LLM calls
// out of 352 windows on the dev fleet.
func TestKnownSecurityTemplateAloneNoCall(t *testing.T) {
	b := baseBundle()
	b.Templates[0].Category = "security"
	s := SystemState{
		KnownTemplates: map[string]bool{"t1": true},
		Baselines:      map[BaselineKey]float64{{ModuleID: "mod1", Priority: 3}: 10},
	}
	d := Evaluate(b, s, 3.0)
	if d.Call {
		t.Fatalf("expected steady-state security template to not call, got %v", d.Reasons)
	}
}

func TestNewSecurityTemplateCalls(t *testing.T) {
	b := baseBundle()
	b.Templates[0].Category = "security"
	s := SystemState{
		KnownTemplates: map[string]bool{},
		Baselines:      map[BaselineKey]float64{{ModuleID: "mod1", Priority: 3}: 10},
	}
	d := Evaluate(b, s, 3.0)
	if !d.Call {
		t.Fatalf("expected call for new security template")
	}
	if d.Reasons[0] != ReasonSecurityNew {
		t.Fatalf("expected %s first, got %v", ReasonSecurityNew, d.Reasons)
	}
}

// A known security template still fires when its bucket surges -- that is the
// brute-force-spike case the security condition exists to catch.
func TestKnownSecurityTemplateSurgeCalls(t *testing.T) {
	b := baseBundle()
	b.Templates[0].Category = "security"
	b.Digest[0].Observed = 100
	s := SystemState{
		KnownTemplates: map[string]bool{"t1": true},
		Baselines:      map[BaselineKey]float64{{ModuleID: "mod1", Priority: 3}: 1},
	}
	d := Evaluate(b, s, 3.0)
	if !d.Call {
		t.Fatalf("expected call for surging security template")
	}
	found := false
	for _, r := range d.Reasons {
		if r == ReasonSecuritySurge {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected %s reason, got %v", ReasonSecuritySurge, d.Reasons)
	}
}

// A security template surging in a DIFFERENT module than the one deviating
// must not be credited with that module's surge.
func TestSecuritySurgeIsPerModule(t *testing.T) {
	b := model.Bundle{
		Templates: []model.Template{
			{Template: "t1", ModuleID: "quiet", Priority: 3, Category: "security"},
		},
		Digest: []model.DigestEntry{
			{ModuleID: "quiet", Priority: 3, Observed: 10},
			{ModuleID: "loud", Priority: 3, Observed: 100},
		},
	}
	s := SystemState{
		KnownTemplates: map[string]bool{"t1": true},
		Baselines: map[BaselineKey]float64{
			{ModuleID: "quiet", Priority: 3}: 10,
			{ModuleID: "loud", Priority: 3}:  1,
		},
	}
	d := Evaluate(b, s, 3.0)
	for _, r := range d.Reasons {
		if r == ReasonSecuritySurge {
			t.Fatalf("security_surge credited across modules: %v", d.Reasons)
		}
	}
}

// An empty bundle is what CrowdSec exclusion produces on a window that carried
// nothing else. It must gate out cleanly rather than panic or fire.
func TestEmptyBundleNoCall(t *testing.T) {
	d := Evaluate(model.Bundle{}, SystemState{
		KnownTemplates: map[string]bool{},
		Baselines:      map[BaselineKey]float64{},
	}, 3.0)
	if d.Call {
		t.Fatalf("expected empty bundle to gate out, got %v", d.Reasons)
	}
	if len(d.Reasons) != 0 {
		t.Fatalf("expected no reasons for empty bundle, got %v", d.Reasons)
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

func TestSecurityOnlyStillCallsForNewSecurity(t *testing.T) {
	b := baseBundle()
	b.Templates[0].Category = "security"
	s := SystemState{
		KnownTemplates: map[string]bool{},
		Baselines:      map[BaselineKey]float64{},
		SecurityOnly:   true,
	}
	d := Evaluate(b, s, 3.0)
	if !d.Call {
		t.Fatalf("expected SecurityOnly to still call for a new security template")
	}
	if !reflect.DeepEqual(d.Reasons, []string{ReasonSecurityNew}) {
		t.Fatalf("expected only %s, got %v", ReasonSecurityNew, d.Reasons)
	}
}

// The spend-cap degrade path (spec section 9.4) only saves money if it declines
// steady-state security traffic. Under the old unconditional rule it fired on
// ~100% of windows, making the lever a no-op.
func TestSecurityOnlyDeclinesSteadyStateSecurity(t *testing.T) {
	b := baseBundle()
	b.Templates[0].Category = "security"
	s := SystemState{
		KnownTemplates: map[string]bool{"t1": true},
		Baselines:      map[BaselineKey]float64{{ModuleID: "mod1", Priority: 3}: 10},
		SecurityOnly:   true,
	}
	d := Evaluate(b, s, 3.0)
	if d.Call {
		t.Fatalf("expected SecurityOnly to decline steady-state security, got %v", d.Reasons)
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
