// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package trigger

import (
	"strings"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/gate"
	"github.com/nethesis/nethesis-insights/internal/model"
)

func novel(keys ...string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[k] = true
	}
	return m
}

func decision() gate.Decision {
	return gate.Decision{
		Call:         true,
		NoveltyFired: true,
		Novel: novel(
			model.CanonicalKey("mail1", "<3> [rspamd] a"),
			model.CanonicalKey("nethvoice5", "<3> [kamailio] b"),
		),
		DeviatingBuckets: []gate.BaselineKey{{ModuleID: "nethvoice5", Priority: 3}, {ModuleID: "", Priority: 6}},
	}
}

func TestTriggerKeyIsStableUnderReordering(t *testing.T) {
	a := decision()
	b := decision()
	b.DeviatingBuckets = []gate.BaselineKey{{ModuleID: "", Priority: 6}, {ModuleID: "nethvoice5", Priority: 3}}
	if Key(a) != Key(b) {
		t.Fatalf("bucket order changed the key")
	}
	// Map iteration order is randomised per run; repeat to give it a chance.
	for i := 0; i < 50; i++ {
		if Key(decision()) != Key(a) {
			t.Fatalf("key is not deterministic over map iteration")
		}
	}
}

func TestTriggerKeyFoldsInstancesToFamilies(t *testing.T) {
	a := decision()
	b := decision()
	b.DeviatingBuckets = []gate.BaselineKey{
		{ModuleID: "nethvoice41", Priority: 3}, {ModuleID: "nethvoice7", Priority: 3}, {ModuleID: "", Priority: 6},
	}
	if Key(a) != Key(b) {
		t.Fatalf("two instances of one family deviating produced a different key than one")
	}
}

func TestTriggerKeyIsDistinct(t *testing.T) {
	base := Key(decision())
	cases := map[string]func(d *gate.Decision){
		"priority is part of a bucket": func(d *gate.Decision) {
			d.DeviatingBuckets = []gate.BaselineKey{{ModuleID: "nethvoice5", Priority: 4}, {ModuleID: "", Priority: 6}}
		},
		"a different family": func(d *gate.Decision) {
			d.DeviatingBuckets = []gate.BaselineKey{{ModuleID: "mail1", Priority: 3}, {ModuleID: "", Priority: 6}}
		},
		"a different novel set": func(d *gate.Decision) {
			d.Novel = novel(model.CanonicalKey("mail1", "<3> [rspamd] a"))
		},
		"the security bit (new)":   func(d *gate.Decision) { d.SecurityNew = true },
		"the security bit (surge)": func(d *gate.Decision) { d.SecuritySurge = true },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := decision()
			mutate(&d)
			if Key(d) == base {
				t.Fatalf("expected a distinct key")
			}
		})
	}
}

// Sub-quorum novelty did not pay for the call; left in the key, one or two
// incidental new lines made half the dev fleet's deviation windows unique.
func TestSubQuorumNoveltyIsNotPartOfTheKey(t *testing.T) {
	a := decision()
	a.NoveltyFired = false
	b := a
	b.Novel = nil
	if Key(a) != Key(b) {
		t.Fatalf("novel templates changed the key although novelty did not fire")
	}
}

func TestSecurityNewAndSurgeShareOneBit(t *testing.T) {
	a := decision()
	a.SecurityNew = true
	b := decision()
	b.SecuritySurge = true
	if Key(a) != Key(b) {
		t.Fatalf("security_new and security_surge produced different keys")
	}
	if !IsSecurity(a) || !IsSecurity(b) || IsSecurity(decision()) {
		t.Fatalf("IsSecurity disagrees with the key's security bit")
	}
}

// A separator-joined encoding would let ("ab","c") collide with ("a","bc").
func TestTriggerKeyCannotBeForgedAcrossFields(t *testing.T) {
	a := gate.Decision{NoveltyFired: true, Novel: novel("ab", "c")}
	b := gate.Decision{NoveltyFired: true, Novel: novel("a", "bc")}
	if Key(a) == Key(b) {
		t.Fatalf("length prefixes failed to separate elements")
	}
}

func TestTriggerKeyIsVersioned(t *testing.T) {
	k := Key(decision())
	if !strings.HasPrefix(k, Version+":") {
		t.Fatalf("key %q is not prefixed with %q", k, Version)
	}
}
