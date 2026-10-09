// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package gate

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/model"
)

const day = int64(24 * 60 * 60 * 1000)

// windowStart is where every test window starts: far enough from zero that a
// last_seen a few weeks earlier is still positive.
const windowStart = 100 * day

// testCfg keeps the thresholds these cases were written against: one novel
// template fires, and neither novelty refinement is on. The quorum, the
// similarity check and the silence rule have their own cases below.
func testCfg() Config {
	return Config{MinNewTemplates: 1, Similarity: 1}
}

// prodCfg is the shipped defaults.
func prodCfg() Config {
	return Config{MinNewTemplates: 3, Similarity: 0.9, Silence: 8 * day}
}

// knownIn builds a KnownTemplates map the way the store does: canonical
// keys, not raw template text, each last seen just before the window.
func knownIn(moduleID string, templates ...string) map[string]int64 {
	return knownAt(windowStart-1, moduleID, templates...)
}

func knownAt(lastSeen int64, moduleID string, templates ...string) map[string]int64 {
	known := make(map[string]int64, len(templates))
	for _, t := range templates {
		known[model.CanonicalKey(moduleID, t)] = lastSeen
	}
	return known
}

func baseBundle() model.Bundle {
	return model.Bundle{
		Window: model.Window{Start: windowStart, End: windowStart + 15*60*1000},
		Templates: []model.Template{
			{Template: "t1", ModuleID: "mod1", Priority: 3, Category: ""},
		},
	}
}

func bundleOf(ts ...model.Template) model.Bundle {
	b := baseBundle()
	b.Templates = ts
	return b
}

func TestSteadyStateNoCall(t *testing.T) {
	d := Evaluate(baseBundle(), SystemState{KnownTemplates: knownIn("mod1", "t1")}, testCfg())
	if d.Call {
		t.Fatalf("expected no call in steady state, got reasons %v", d.Reasons)
	}
}

func TestNewTemplateCalls(t *testing.T) {
	d := Evaluate(baseBundle(), SystemState{KnownTemplates: map[string]int64{}}, testCfg())
	if !d.Call {
		t.Fatalf("expected call for new template")
	}
	if !reflect.DeepEqual(d.Reasons, []string{ReasonNewTemplates}) {
		t.Fatalf("expected [%s], got %v", ReasonNewTemplates, d.Reasons)
	}
}

// A security template that is already known must NOT fire. Failed SSH logins
// arrive continuously on any internet-facing node, so the previous
// "any security template calls" rule made the gate a no-op -- 352 LLM calls
// out of 352 windows on the dev fleet.
func TestKnownSecurityTemplateAloneNoCall(t *testing.T) {
	b := baseBundle()
	b.Templates[0].Category = "security"
	d := Evaluate(b, SystemState{KnownTemplates: knownIn("mod1", "t1")}, testCfg())
	if d.Call {
		t.Fatalf("expected steady-state security template to not call, got %v", d.Reasons)
	}
}

func TestNewSecurityTemplateCalls(t *testing.T) {
	b := baseBundle()
	b.Templates[0].Category = "security"
	d := Evaluate(b, SystemState{KnownTemplates: map[string]int64{}}, testCfg())
	if !d.Call {
		t.Fatalf("expected call for new security template")
	}
	if d.Reasons[0] != ReasonSecurityNew {
		t.Fatalf("expected %s first, got %v", ReasonSecurityNew, d.Reasons)
	}
}

func TestEmptyBundleNoCall(t *testing.T) {
	d := Evaluate(model.Bundle{}, SystemState{KnownTemplates: map[string]int64{}}, testCfg())
	if d.Call {
		t.Fatalf("expected no call for an empty bundle, got %v", d.Reasons)
	}
}

// Truncation is reported to the model as context, never as a reason to call.
func TestTruncationAloneNoCall(t *testing.T) {
	b := baseBundle()
	b.Budget.TruncatedModules = []model.TruncatedModule{{ModuleID: "mod1", Dropped: 1000, Truncated: true}}
	d := Evaluate(b, SystemState{KnownTemplates: knownIn("mod1", "t1")}, testCfg())
	if d.Call {
		t.Fatalf("expected truncation alone not to call, got %v", d.Reasons)
	}
}

func TestSecurityOnlySuppressesNovelty(t *testing.T) {
	d := Evaluate(baseBundle(), SystemState{KnownTemplates: map[string]int64{}, SecurityOnly: true}, testCfg())
	if d.Call {
		t.Fatalf("security-only mode must decline non-security novelty, got %v", d.Reasons)
	}
}

func TestSecurityOnlyStillCallsForNewSecurity(t *testing.T) {
	b := baseBundle()
	b.Templates[0].Category = "security"
	d := Evaluate(b, SystemState{KnownTemplates: map[string]int64{}, SecurityOnly: true}, testCfg())
	if !d.Call || !reflect.DeepEqual(d.Reasons, []string{ReasonSecurityNew}) {
		t.Fatalf("expected a security_new call in security-only mode, got call=%v %v", d.Call, d.Reasons)
	}
}

func TestSecurityOnlyDeclinesSteadyStateSecurity(t *testing.T) {
	b := baseBundle()
	b.Templates[0].Category = "security"
	d := Evaluate(b, SystemState{KnownTemplates: knownIn("mod1", "t1"), SecurityOnly: true}, testCfg())
	if d.Call {
		t.Fatalf("a known security template must not call in security-only mode, got %v", d.Reasons)
	}
}

func TestReasonsDeterministicAcrossRepeats(t *testing.T) {
	b := bundleOf(
		model.Template{Template: "z", ModuleID: "b", Priority: 3, Category: "security"},
		model.Template{Template: "a", ModuleID: "a", Priority: 3},
	)
	s := SystemState{KnownTemplates: map[string]int64{}}
	first := Evaluate(b, s, testCfg()).Reasons
	for i := 0; i < 50; i++ {
		if got := Evaluate(b, s, testCfg()).Reasons; !reflect.DeepEqual(got, first) {
			t.Fatalf("reasons changed between runs: %v vs %v", first, got)
		}
	}
	if !reflect.DeepEqual(first, []string{ReasonSecurityNew, ReasonNewTemplates}) {
		t.Fatalf("unexpected reasons %v", first)
	}
}

func TestNoveltyQuorum(t *testing.T) {
	mk := func(n int) model.Bundle {
		b := baseBundle()
		b.Templates = nil
		for i := 0; i < n; i++ {
			b.Templates = append(b.Templates, model.Template{
				Template: "<3> [svc] new line " + string(rune('a'+i)),
				ModuleID: "mod1", Priority: 3,
			})
		}
		return b
	}
	empty := SystemState{KnownTemplates: map[string]int64{}}

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
	d := Evaluate(b, SystemState{KnownTemplates: map[string]int64{}}, prodCfg())
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
	b := bundleOf(
		model.Template{Template: `<3> [postgres-app] LOG: checkpoint complete: wrote <NUM> buffers (0.3%); 0 recycled`, ModuleID: "mod1", Priority: 3},
		model.Template{Template: `<3> [postgres-app] LOG: checkpoint complete: wrote <NUM> buffers (1.1%); 1 recycled`, ModuleID: "mod1", Priority: 3},
		model.Template{Template: `<3> [postgres-app] LOG: checkpoint complete: wrote <NUM> buffers (2.7%); 4 recycled`, ModuleID: "mod1", Priority: 3},
	)
	if d := Evaluate(b, SystemState{KnownTemplates: map[string]int64{}}, prodCfg()); d.Call {
		t.Fatalf("three spellings of one condition must not reach the quorum: %v", d.Reasons)
	}

	// And a template already known under one spelling is not novel under another.
	b2 := baseBundle()
	b2.Templates[0].Template = `<3> [postgres-app] LOG: checkpoint complete: wrote <NUM> buffers (9.9%); 7 recycled`
	s2 := SystemState{KnownTemplates: knownIn("mod1", `<3> [postgres-app] LOG: checkpoint complete: wrote <NUM> buffers (0.1%); 0 recycled`)}
	if d := Evaluate(b2, s2, testCfg()); d.Call {
		t.Fatalf("a known line in a new spelling must not be novel: %v", d.Reasons)
	}
}

// A line naming its own instance is the same line on every instance: a
// nethvoice43 warning known on this system makes the nethvoice35 copy known.
func TestOwnInstanceInTextIsNotNovel(t *testing.T) {
	const warn = `<4> [agent@nethvoice] <HOST>: domain <HOST> should not be used by nethvoice%s. Invoke agent.bind_user_domains(["<HOST>"]) to fix this warning.`
	b := bundleOf(model.Template{Template: fmt.Sprintf(warn, "35"), ModuleID: "nethvoice35", Priority: 4})
	s := SystemState{KnownTemplates: knownIn("nethvoice43", fmt.Sprintf(warn, "43"))}
	if d := Evaluate(b, s, testCfg()); d.Call {
		t.Fatalf("a known line naming another instance of the same module must not be novel: %v", d.Reasons)
	}
}

const (
	sipKnown = `<3> [kamailio] <NUM>(<PID>) ERROR: <script>: fevigort37u6sbhqkm2p9396@<IP> INVITE-<NUM> Malformed SIP request from <IP>:<PORT>`
	sipNew   = `<3> [kamailio] <NUM>(<PID>) ERROR: <script>: 16emkwe6stxzzm2az0fu6n7l@<IP> INVITE-<NUM> Malformed SIP request from <IP>:<PORT>`
)

// The case the similarity check exists for: a SIP call-id the masking leaves
// literal makes every window's copy of one known line look new.
func TestNearKnownTemplateIsNotNovel(t *testing.T) {
	b := bundleOf(model.Template{Template: sipNew, ModuleID: "nethvoice-proxy6", Priority: 3})
	s := SystemState{KnownTemplates: knownIn("nethvoice-proxy2", sipKnown)}

	d := Evaluate(b, s, Config{MinNewTemplates: 1, Similarity: 0.9})
	if d.Call {
		t.Fatalf("a line differing only in an identifier must count as known: %v", d.Reasons)
	}
	if d.NearKnown != 1 || len(d.Novel) != 0 {
		t.Fatalf("want NearKnown=1 and nothing novel, got %d and %v", d.NearKnown, d.Novel)
	}
}

func TestNearKnownNeedsTheSameFamily(t *testing.T) {
	b := bundleOf(model.Template{Template: sipNew, ModuleID: "nethvoice-proxy6", Priority: 3})
	s := SystemState{KnownTemplates: knownIn("mail1", sipKnown)}

	if d := Evaluate(b, s, Config{MinNewTemplates: 1, Similarity: 0.9}); !d.Call {
		t.Fatal("a known line of another module family must not make this one known")
	}
}

// One changed word can be the whole condition. Measured on the dev fleet,
// "Failed to reconnect" and "Failed to ping" were 90% alike.
func TestNearKnownRefusesAChangedWord(t *testing.T) {
	known := `<3> [nethvoice] nethcti-middleware logs.go:<NUM>: [CRITICAL][SATELLITE-DB] Failed to ping database after <NUM> attempts`
	novel := `<3> [nethvoice] nethcti-middleware logs.go:<NUM>: [CRITICAL][SATELLITE-DB] Failed to reconnect database after <NUM> attempts`
	b := bundleOf(model.Template{Template: novel, ModuleID: "nethvoice1", Priority: 3})
	s := SystemState{KnownTemplates: knownIn("nethvoice1", known)}

	if d := Evaluate(b, s, Config{MinNewTemplates: 1, Similarity: 0.9}); !d.Call {
		t.Fatal("a line differing in a plain word must stay novel")
	}
}

// At 0.9 a line needs ten tokens before one may differ, so a short line is
// matched exactly or not at all.
func TestShortLinesNeverMatch(t *testing.T) {
	known := `<3> [svc] session abc123 opened`
	novel := `<3> [svc] session xyz789 opened`
	b := bundleOf(model.Template{Template: novel, ModuleID: "mod1", Priority: 3})
	s := SystemState{KnownTemplates: knownIn("mod1", known)}

	if d := Evaluate(b, s, Config{MinNewTemplates: 1, Similarity: 0.9}); !d.Call {
		t.Fatal("a short line with any difference must stay novel")
	}
}

func TestNearKnownNeverAppliesToSecurity(t *testing.T) {
	b := bundleOf(model.Template{Template: sipNew, ModuleID: "nethvoice-proxy1", Priority: 3, Category: "security"})
	s := SystemState{KnownTemplates: knownIn("nethvoice-proxy1", sipKnown)}

	d := Evaluate(b, s, Config{MinNewTemplates: 3, Similarity: 0.9})
	if !d.Call || d.Reasons[0] != ReasonSecurityNew {
		t.Fatalf("a new security template must always fire, got call=%v %v", d.Call, d.Reasons)
	}
}

func TestNearKnownNeverAppliesToHighPriority(t *testing.T) {
	for _, prio := range []int{0, 1, 2} {
		b := bundleOf(model.Template{Template: sipNew, ModuleID: "nethvoice-proxy1", Priority: prio})
		s := SystemState{KnownTemplates: knownIn("nethvoice-proxy1", sipKnown)}

		if d := Evaluate(b, s, Config{MinNewTemplates: 1, Similarity: 0.9}); !d.Call {
			t.Fatalf("priority %d: a critical-or-above line must stay novel", prio)
		}
	}
}

// One template sharing a key with an ineligible one is decided by the
// ineligible one: a security spelling must not be matched away because a
// plain spelling of the same key could be.
func TestIneligibleSpellingWinsTheKey(t *testing.T) {
	b := bundleOf(
		model.Template{Template: sipNew, ModuleID: "nethvoice-proxy1", Priority: 3},
		model.Template{Template: sipNew, ModuleID: "nethvoice-proxy1", Priority: 3, Category: "security"},
	)
	s := SystemState{KnownTemplates: knownIn("nethvoice-proxy1", sipKnown)}

	if d := Evaluate(b, s, Config{MinNewTemplates: 3, Similarity: 0.9}); !d.Call {
		t.Fatal("the security spelling must keep the key novel")
	}
}

func TestSimilarityOneDisablesTheCheck(t *testing.T) {
	b := bundleOf(model.Template{Template: sipNew, ModuleID: "nethvoice-proxy1", Priority: 3})
	s := SystemState{KnownTemplates: knownIn("nethvoice-proxy1", sipKnown)}

	if d := Evaluate(b, s, Config{MinNewTemplates: 1, Similarity: 1}); !d.Call {
		t.Fatal("Similarity 1 must leave every unknown template novel")
	}
}

// The case the silence rule exists for: a failure whose lines the system
// already knows, back after a quiet spell.
func TestReturningTemplateIsNovel(t *testing.T) {
	b := baseBundle()
	s := SystemState{KnownTemplates: knownAt(windowStart-9*day, "mod1", "t1")}

	d := Evaluate(b, s, Config{MinNewTemplates: 1, Similarity: 1, Silence: 8 * day})
	if !d.Call || !reflect.DeepEqual(d.Reasons, []string{ReasonNewTemplates}) {
		t.Fatalf("a template back after the silence must count as new, got call=%v %v", d.Call, d.Reasons)
	}
	if d.Returning != 1 || !d.Novel[model.CanonicalKey("mod1", "t1")] {
		t.Fatalf("want Returning=1 and the key novel, got %d and %v", d.Returning, d.Novel)
	}
}

func TestRecentTemplateIsKnown(t *testing.T) {
	b := baseBundle()
	s := SystemState{KnownTemplates: knownAt(windowStart-7*day, "mod1", "t1")}

	if d := Evaluate(b, s, Config{MinNewTemplates: 1, Similarity: 1, Silence: 8 * day}); d.Call {
		t.Fatalf("a template seen inside the silence must stay known, got %v", d.Reasons)
	}
}

func TestSilenceZeroDisablesTheRule(t *testing.T) {
	b := baseBundle()
	s := SystemState{KnownTemplates: knownAt(1, "mod1", "t1")}

	if d := Evaluate(b, s, Config{MinNewTemplates: 1, Similarity: 1}); d.Call {
		t.Fatalf("Silence 0 must keep a known template known however old, got %v", d.Reasons)
	}
}

func TestReturningSecurityTemplateFiresSecurityNew(t *testing.T) {
	b := baseBundle()
	b.Templates[0].Category = "security"
	s := SystemState{KnownTemplates: knownAt(windowStart-30*day, "mod1", "t1")}

	d := Evaluate(b, s, prodCfg())
	if !d.Call || d.Reasons[0] != ReasonSecurityNew {
		t.Fatalf("a returning security template is a new one, got call=%v %v", d.Call, d.Reasons)
	}
}

// A silent template must not make a variant of itself look known: that
// would let the variant's return slip past both rules.
func TestSimilarityIgnoresSilentTemplates(t *testing.T) {
	b := bundleOf(model.Template{Template: sipNew, ModuleID: "nethvoice-proxy1", Priority: 3})
	s := SystemState{KnownTemplates: knownAt(windowStart-30*day, "nethvoice-proxy1", sipKnown)}

	d := Evaluate(b, s, Config{MinNewTemplates: 1, Similarity: 0.9, Silence: 8 * day})
	if !d.Call || d.NearKnown != 0 {
		t.Fatalf("a variant of a silent template must be novel, got call=%v near=%d", d.Call, d.NearKnown)
	}
}

func TestPlainWord(t *testing.T) {
	for tok, want := range map[string]bool{
		"ping": true, "Error": true, "SRTP": true, "ham": true,
		"fevigort37u6sbhqkm2p9396": false, "DjhtXUVdMggltcnr": false, "iPvhcMtxdL36C": false,
		"<HEX>": false, "42": false, "x": false, "/": false,
	} {
		if got := plainWord(tok); got != want {
			t.Errorf("plainWord(%q) = %v, want %v", tok, got, want)
		}
	}
}

func TestTokenize(t *testing.T) {
	got := tokenize(`<3> [svc] id=ab12@<IP>: done`)
	want := []string{"<3>", "[", "svc", "]", "id", "=", "ab12", "@", "<IP>", ":", "done"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tokenize = %q, want %q", got, want)
	}
}
