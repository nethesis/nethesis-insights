// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package gate

import (
	"reflect"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/model"
)

func f(v float64) *float64 { return &v }

// testCfg keeps the thresholds these cases were written against: one novel
// template fires, and the deviation floors are effectively off. The floors and
// the novelty quorum have their own cases below, run at the production
// defaults.
func testCfg() Config {
	return Config{Tolerance: 3.0, MinExpected: 1, MinObserved: 1, MinNewTemplates: 1}
}

// knownIn builds a KnownTemplates set the way the store does: canonical keys,
// not raw template text.
func knownIn(moduleID string, templates ...string) map[string]bool {
	known := make(map[string]bool, len(templates))
	for _, t := range templates {
		known[model.CanonicalKey(moduleID, t)] = true
	}
	return known
}

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
		KnownTemplates: knownIn("mod1", "t1"),
		Baselines:      map[BaselineKey]float64{{ModuleID: "mod1", Priority: 3}: 10},
	}
	d := Evaluate(b, s, testCfg())
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
	d := Evaluate(b, s, testCfg())
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
		KnownTemplates: knownIn("mod1", "t1"),
		Baselines:      map[BaselineKey]float64{},
	}
	d := Evaluate(b, s, testCfg())
	if !d.Call {
		t.Fatalf("expected call for deviation, got %v", d.Reasons)
	}
}

func TestDeviationFallsBackToBaseline(t *testing.T) {
	b := baseBundle()
	b.Digest[0].Observed = 100
	b.Digest[0].Expected = nil
	s := SystemState{
		KnownTemplates: knownIn("mod1", "t1"),
		Baselines:      map[BaselineKey]float64{{ModuleID: "mod1", Priority: 3}: 1},
	}
	d := Evaluate(b, s, testCfg())
	if !d.Call {
		t.Fatalf("expected call via baseline fallback, got %v", d.Reasons)
	}
}

func TestExpectedZeroNeverPanicsNoCall(t *testing.T) {
	b := baseBundle()
	b.Digest[0].Observed = 1000
	b.Digest[0].Expected = f(0)
	s := SystemState{
		KnownTemplates: knownIn("mod1", "t1"),
		Baselines:      map[BaselineKey]float64{}, // also zero/missing
	}
	d := Evaluate(b, s, testCfg())
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
		KnownTemplates: knownIn("mod1", "t1"),
		Baselines:      map[BaselineKey]float64{{ModuleID: "mod1", Priority: 3}: 10},
	}
	d := Evaluate(b, s, testCfg())
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
	d := Evaluate(b, s, testCfg())
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
		KnownTemplates: knownIn("mod1", "t1"),
		Baselines:      map[BaselineKey]float64{{ModuleID: "mod1", Priority: 3}: 1},
	}
	d := Evaluate(b, s, testCfg())
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
		KnownTemplates: knownIn("quiet", "t1"),
		Baselines: map[BaselineKey]float64{
			{ModuleID: "quiet", Priority: 3}: 10,
			{ModuleID: "loud", Priority: 3}:  1,
		},
	}
	d := Evaluate(b, s, testCfg())
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
	}, testCfg())
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
		KnownTemplates: knownIn("mod1", "t1"),
		Baselines:      map[BaselineKey]float64{{ModuleID: "mod1", Priority: 3}: 10},
	}
	d := Evaluate(b, s, testCfg())
	if d.Call {
		t.Fatalf("expected truncation alone to not call, got %v", d.Reasons)
	}
}

func TestTruncationPlusDeviationCalls(t *testing.T) {
	b := baseBundle()
	b.Digest[0].Observed = 100
	b.Budget.TruncatedModules = []model.TruncatedModule{{ModuleID: "mod1", Dropped: 5, Truncated: true}}
	s := SystemState{
		KnownTemplates: knownIn("mod1", "t1"),
		Baselines:      map[BaselineKey]float64{{ModuleID: "mod1", Priority: 3}: 1},
	}
	d := Evaluate(b, s, testCfg())
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
	d := Evaluate(b, s, testCfg())
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
	d := Evaluate(b, s, testCfg())
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
		KnownTemplates: knownIn("mod1", "t1"),
		Baselines:      map[BaselineKey]float64{{ModuleID: "mod1", Priority: 3}: 10},
		SecurityOnly:   true,
	}
	d := Evaluate(b, s, testCfg())
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
		d := Evaluate(b, s, testCfg())
		if i == 0 {
			first = d
		} else if !reflect.DeepEqual(first, d) {
			t.Fatalf("non-deterministic reasons across repeats: %v vs %v", first, d)
		}
	}
}

// prodCfg is what cmd/insightsd wires by default.
func prodCfg() Config {
	return Config{Tolerance: 3.0, MinExpected: 10, MinObserved: 20, MinNewTemplates: 3}
}

// The measured failure: <host>/5 with a baseline of 2.0 lines per window fired
// the gate at 7 lines, 28 times in 24 hours, every one of them noise.
func TestDeviationFloorsTable(t *testing.T) {
	cases := []struct {
		name     string
		expected float64
		observed int64
		wantCall bool
	}{
		{name: "tiny bucket, ratio over tolerance", expected: 2, observed: 7, wantCall: false},
		{name: "tiny bucket, huge ratio, few lines", expected: 1, observed: 15, wantCall: false},
		{name: "baseline under MinExpected, plenty of lines", expected: 5, observed: 100, wantCall: false},
		{name: "at both floors but ratio under tolerance", expected: 10, observed: 25, wantCall: false},
		{name: "over both floors and over tolerance", expected: 10, observed: 40, wantCall: true},
		{name: "large bucket surging", expected: 200, observed: 900, wantCall: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := baseBundle()
			b.Digest[0].Observed = tc.observed
			b.Digest[0].Expected = f(tc.expected)
			s := SystemState{
				KnownTemplates: knownIn("mod1", "t1"),
				Baselines:      map[BaselineKey]float64{},
			}
			d := Evaluate(b, s, prodCfg())
			if d.Call != tc.wantCall {
				t.Fatalf("call=%v want %v (reasons %v)", d.Call, tc.wantCall, d.Reasons)
			}
		})
	}
}

// The floors apply to the EWMA fallback exactly as they do to edge `expected`;
// a bucket with no edge baseline must not become the cheap way past them.
func TestDeviationFloorsApplyToEWMAFallback(t *testing.T) {
	b := baseBundle()
	b.Digest[0].Observed = 7
	b.Digest[0].Expected = nil
	s := SystemState{
		KnownTemplates: knownIn("mod1", "t1"),
		Baselines:      map[BaselineKey]float64{{ModuleID: "mod1", Priority: 3}: 2},
	}
	if d := Evaluate(b, s, prodCfg()); d.Call {
		t.Fatalf("expected floors to apply to the EWMA fallback, got %v", d.Reasons)
	}
}

func TestNoveltyQuorum(t *testing.T) {
	mk := func(n int) model.Bundle {
		b := model.Bundle{}
		for i := 0; i < n; i++ {
			b.Templates = append(b.Templates, model.Template{
				Template: "<3> [svc] new line " + string(rune('a'+i)),
				ModuleID: "mod1", Priority: 3,
			})
		}
		return b
	}
	empty := SystemState{KnownTemplates: map[string]bool{}, Baselines: map[BaselineKey]float64{}}

	for _, tc := range []struct {
		n        int
		wantCall bool
	}{{1, false}, {2, false}, {3, true}, {9, true}} {
		d := Evaluate(mk(tc.n), empty, prodCfg())
		if d.Call != tc.wantCall {
			t.Fatalf("%d novel templates: call=%v want %v (%v)", tc.n, d.Call, tc.wantCall, d.Reasons)
		}
	}
}

// The quorum must never gate out a novel security template: one is the whole
// signal the security condition exists for.
func TestNoveltyQuorumNeverSuppressesNewSecurity(t *testing.T) {
	b := baseBundle()
	b.Templates[0].Category = "security"
	s := SystemState{KnownTemplates: map[string]bool{}, Baselines: map[BaselineKey]float64{}}

	d := Evaluate(b, s, prodCfg())
	if !d.Call {
		t.Fatal("a single new security template must still fire")
	}
	if !reflect.DeepEqual(d.Reasons, []string{ReasonSecurityNew}) {
		t.Fatalf("expected only %s, got %v", ReasonSecurityNew, d.Reasons)
	}
}

// Novelty counts canonical keys. Ten spellings of one leaked field are one
// condition, and the gate must not read them as a quorum.
func TestNoveltyCountsCanonicalKeysNotSpellings(t *testing.T) {
	b := model.Bundle{
		Templates: []model.Template{
			{Template: `<3> [postgres-app] LOG: checkpoint complete: wrote <NUM> buffers (0.3%); 0 recycled`, ModuleID: "mod1", Priority: 3},
			{Template: `<3> [postgres-app] LOG: checkpoint complete: wrote <NUM> buffers (1.1%); 1 recycled`, ModuleID: "mod1", Priority: 3},
			{Template: `<3> [postgres-app] LOG: checkpoint complete: wrote <NUM> buffers (2.7%); 4 recycled`, ModuleID: "mod1", Priority: 3},
		},
	}
	s := SystemState{KnownTemplates: map[string]bool{}, Baselines: map[BaselineKey]float64{}}
	if d := Evaluate(b, s, prodCfg()); d.Call {
		t.Fatalf("three spellings of one condition must not reach the quorum: %v", d.Reasons)
	}

	// And a template already known under one spelling is not novel under another.
	b2 := baseBundle()
	b2.Templates[0].Template = `<3> [postgres-app] LOG: checkpoint complete: wrote <NUM> buffers (9.9%); 7 recycled`
	s2 := SystemState{
		KnownTemplates: knownIn("mod1", `<3> [postgres-app] LOG: checkpoint complete: wrote <NUM> buffers (0.1%); 0 recycled`),
		Baselines:      map[BaselineKey]float64{},
	}
	if d := Evaluate(b2, s2, testCfg()); d.Call {
		t.Fatalf("a known line in a new spelling must not be novel: %v", d.Reasons)
	}
}
