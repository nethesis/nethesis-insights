// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package model

import "testing"

func excludeFixture() Bundle {
	return Bundle{
		Templates: []Template{
			{Template: "keep", ModuleID: "loki1"},
			{Template: "drop", ModuleID: "crowdsec1"},
			{Template: "host", ModuleID: ""},
		},
		Digest: []DigestEntry{
			{ModuleID: "loki1", Priority: 6, Observed: 1},
			{ModuleID: "crowdsec1", Priority: 3, Observed: 2},
			{ModuleID: "", Priority: 6, Observed: 3},
		},
		Budget: Budget{
			MaxLines:  10,
			LinesSeen: 9,
			TruncatedModules: []TruncatedModule{
				{ModuleID: "loki1", Dropped: 1},
				{ModuleID: "crowdsec1", Dropped: 2},
			},
		},
	}
}

// All three collections must be filtered together. Dropping only Templates
// leaves the digest firing deviation reasons for a module the prompt never
// mentions -- a gate decision nobody can explain from the stored data.
func TestExcludeModulesFiltersAllThreeCollections(t *testing.T) {
	got := excludeFixture().ExcludeModules(map[string]bool{"crowdsec1": true})

	if len(got.Templates) != 2 {
		t.Fatalf("templates: got %d, want 2: %+v", len(got.Templates), got.Templates)
	}
	if len(got.Digest) != 2 {
		t.Fatalf("digest: got %d, want 2: %+v", len(got.Digest), got.Digest)
	}
	if len(got.Budget.TruncatedModules) != 1 {
		t.Fatalf("truncated: got %d, want 1: %+v", len(got.Budget.TruncatedModules), got.Budget.TruncatedModules)
	}
	for _, tpl := range got.Templates {
		if tpl.ModuleID == "crowdsec1" {
			t.Fatalf("excluded module survived in templates: %+v", got.Templates)
		}
	}
	// Fields outside the three filtered collections must survive untouched.
	if got.Budget.MaxLines != 10 || got.Budget.LinesSeen != 9 {
		t.Fatalf("unrelated Budget fields were clobbered: %+v", got.Budget)
	}
}

// The empty module id is the host bucket (sshd, systemd, runagent) and is where
// the security signal lives. It must never be dropped by accident.
func TestExcludeModulesKeepsHostBucket(t *testing.T) {
	got := excludeFixture().ExcludeModules(map[string]bool{"crowdsec1": true})

	found := false
	for _, tpl := range got.Templates {
		if tpl.ModuleID == "" {
			found = true
		}
	}
	if !found {
		t.Fatal("host bucket template was dropped")
	}
}

// ...but it is an ordinary module, so an explicit listing does exclude it.
func TestExcludeModulesCanExcludeHostBucketExplicitly(t *testing.T) {
	got := excludeFixture().ExcludeModules(map[string]bool{"": true})
	for _, tpl := range got.Templates {
		if tpl.ModuleID == "" {
			t.Fatalf("explicitly excluded host bucket survived: %+v", got.Templates)
		}
	}
}

func TestExcludeModulesEmptySetIsIdentity(t *testing.T) {
	in := excludeFixture()
	for _, set := range []map[string]bool{nil, {}} {
		got := in.ExcludeModules(set)
		if len(got.Templates) != 3 || len(got.Digest) != 3 || len(got.Budget.TruncatedModules) != 2 {
			t.Fatalf("empty exclusion set changed the bundle: %+v", got)
		}
	}
}

// Excluding everything is the CrowdSec-only window. It must yield an empty but
// well-formed bundle for the gate to decline, not a nil-deref.
func TestExcludeModulesCanEmptyTheBundle(t *testing.T) {
	got := excludeFixture().ExcludeModules(map[string]bool{"loki1": true, "crowdsec1": true, "": true})
	if len(got.Templates) != 0 || len(got.Digest) != 0 || len(got.Budget.TruncatedModules) != 0 {
		t.Fatalf("expected an empty bundle, got %+v", got)
	}
}

// The filter must not write through to the caller's slices: the handler logs
// the received counts after filtering.
func TestExcludeModulesDoesNotMutateInput(t *testing.T) {
	in := excludeFixture()
	_ = in.ExcludeModules(map[string]bool{"crowdsec1": true})
	if len(in.Templates) != 3 || len(in.Digest) != 3 || len(in.Budget.TruncatedModules) != 2 {
		t.Fatalf("input bundle was mutated: %+v", in)
	}
}
