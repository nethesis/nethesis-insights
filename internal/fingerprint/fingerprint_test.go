// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package fingerprint

import "testing"

func TestStableAcrossReordering(t *testing.T) {
	a := Compute("sys1", []string{"mod1", "mod2"}, []string{"ev1", "ev2"}, "cat1")
	b := Compute("sys1", []string{"mod2", "mod1"}, []string{"ev2", "ev1"}, "cat1")
	if a != b {
		t.Fatalf("expected stable fingerprint across reordering, got %s vs %s", a, b)
	}
	if len(a) != 64 {
		t.Fatalf("expected 64 hex chars, got %d: %s", len(a), a)
	}
}

func TestDistinctPerSystem(t *testing.T) {
	a := Compute("sys1", []string{"mod1"}, []string{"ev1"}, "cat1")
	b := Compute("sys2", []string{"mod1"}, []string{"ev1"}, "cat1")
	if a == b {
		t.Fatalf("expected distinct fingerprints per system, got same: %s", a)
	}
}

func TestDuplicateEvidenceCollapses(t *testing.T) {
	a := Compute("sys1", []string{"mod1"}, []string{"ev1", "ev1"}, "cat1")
	b := Compute("sys1", []string{"mod1"}, []string{"ev1"}, "cat1")
	if a != b {
		t.Fatalf("expected duplicate evidence to collapse, got %s vs %s", a, b)
	}
}

func TestNoSeparatorCollision(t *testing.T) {
	// "ab","c" must not collide with "a","bc" -- this is why we
	// length-prefix rather than join with a separator.
	a := Compute("sys1", []string{"mod1"}, []string{"ab", "c"}, "cat1")
	b := Compute("sys1", []string{"mod1"}, []string{"a", "bc"}, "cat1")
	if a == b {
		t.Fatalf("expected no collision between [ab,c] and [a,bc], got same fingerprint: %s", a)
	}
}

func TestAllHexChars(t *testing.T) {
	a := Compute("sys1", nil, nil, "")
	if len(a) != 64 {
		t.Fatalf("expected 64 chars for empty input, got %d", len(a))
	}
	for _, c := range a {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("non-hex char in fingerprint: %q", a)
		}
	}
}
