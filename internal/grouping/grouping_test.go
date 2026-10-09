// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package grouping

import (
	"math"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestText(t *testing.T) {
	tests := []struct {
		name     string
		modules  []string
		evidence []string
		want     string
	}{
		{"order and separators", []string{"a", "b"}, []string{"x", "y"}, "modules: a,b\nx\ny"},
		{"host bucket stays a module", []string{""}, []string{"x"}, "modules: \nx"},
		{"no modules", nil, []string{"x"}, "modules: \nx"},
		{"no evidence", []string{"a"}, nil, "modules: a\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Text(tc.modules, tc.evidence); got != tc.want {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestTextTruncation(t *testing.T) {
	prefix := "modules: a\n"
	exact := strings.Repeat("x", MaxChars-len(prefix))
	if got := Text([]string{"a"}, []string{exact}); len(got) != MaxChars || got != prefix+exact {
		t.Errorf("exact fit changed: len %d", len(got))
	}
	if got := Text([]string{"a"}, []string{exact + "y"}); len(got) != MaxChars || got != prefix+exact {
		t.Errorf("one over not cut to MaxChars: len %d", len(got))
	}
	// A 2-byte rune straddling the limit must be dropped whole.
	two := strings.Repeat("x", MaxChars-len(prefix)-1) + "é"
	got := Text([]string{"a"}, []string{two})
	if !utf8.ValidString(got) || len(got) != MaxChars-1 {
		t.Errorf("2-byte rune split: len %d valid %v", len(got), utf8.ValidString(got))
	}
	// 4-byte runes, every offset.
	for pad := 0; pad < 4; pad++ {
		ev := strings.Repeat("x", pad) + strings.Repeat("😀", 600)
		got := Text([]string{"a"}, []string{ev})
		if !utf8.ValidString(got) || len(got) > MaxChars || len(got) < MaxChars-3 {
			t.Errorf("pad %d: len %d valid %v", pad, len(got), utf8.ValidString(got))
		}
	}
}

func TestCosine(t *testing.T) {
	tests := []struct {
		name string
		a, b []float32
		want float64
	}{
		{"identical", []float32{1, 2, 3}, []float32{1, 2, 3}, 1},
		{"scaled", []float32{1, 2, 3}, []float32{2, 4, 6}, 1},
		{"orthogonal", []float32{1, 0}, []float32{0, 1}, 0},
		{"opposite", []float32{1, 2}, []float32{-1, -2}, -1},
		{"zero a", []float32{0, 0}, []float32{1, 1}, 0},
		{"zero b", []float32{1, 1}, []float32{0, 0}, 0},
		{"length mismatch", []float32{1, 2}, []float32{1, 2, 3}, 0},
		{"empty", nil, nil, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Cosine(tc.a, tc.b); math.Abs(got-tc.want) > 1e-6 {
				t.Errorf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestAssign(t *testing.T) {
	x := []float32{1, 0}
	near := []float32{1, 0.1} // cosine to x ~0.995
	tests := []struct {
		name      string
		v         []float32
		anchors   []Anchor
		threshold float64
		wantKey   string
		wantJoin  bool
	}{
		{"no anchors", x, nil, 0.9, "", false},
		{"above", x, []Anchor{{"a", near}}, 0.9, "a", true},
		{"at threshold", x, []Anchor{{"a", x}}, 1, "a", true},
		{"below", x, []Anchor{{"a", []float32{0, 1}}}, 0.9, "a", false},
		{"best of several", x, []Anchor{{"a", []float32{1, 1}}, {"b", near}, {"c", []float32{0, 1}}}, 0.5, "b", true},
		{"tie goes to first", x, []Anchor{{"a", x}, {"b", x}}, 0.9, "a", true},
		{"below reports best seen", x, []Anchor{{"a", []float32{0, 1}}, {"b", []float32{1, 1}}}, 0.99, "b", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, sim, joined := Assign(tc.v, tc.anchors, tc.threshold)
			if key != tc.wantKey || joined != tc.wantJoin {
				t.Errorf("got (%q,%v,%v) want (%q,%v)", key, sim, joined, tc.wantKey, tc.wantJoin)
			}
			if joined && sim < tc.threshold-1e-9 {
				t.Errorf("joined with sim %v below threshold %v", sim, tc.threshold)
			}
		})
	}
}

func TestSuggest(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want string
		ok   bool
	}{
		{"none", nil, "", false},
		{"one", []string{"customer"}, "customer", true},
		{"two different", []string{"customer", "dismissed"}, "", false},
		{"duplicates of one", []string{"operator", "operator", "operator"}, "operator", true},
		{"pending ignored", []string{"pending", "dismissed", "pending"}, "dismissed", true},
		{"only pending", []string{"pending"}, "", false},
		{"unknown ignored", []string{"bogus", "customer"}, "customer", true},
		{"unknown alone", []string{"bogus"}, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Suggest(tc.in)
			if got != tc.want || ok != tc.ok {
				t.Errorf("got (%q,%v) want (%q,%v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}
