// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package grouping is the pure core of review grouping: what a finding class
// is embedded as, how a vector joins a group, and when a group's decisions
// imply a suggestion. No I/O and no clock, like gate.
package grouping

import (
	"math"
	"strings"
	"unicode/utf8"
)

// MaxChars caps the embedded text: bge-small reads 512 tokens and
// llama-server refuses longer input instead of truncating. The cut is in
// bytes, backed up to a UTF-8 rune boundary.
const MaxChars = 1500

// Text is what a class is embedded as: its modules and cited evidence lines,
// never the model-written title or summary. An empty module (the host bucket)
// is a real module and is kept.
func Text(modules, evidence []string) string {
	s := "modules: " + strings.Join(modules, ",") + "\n" + strings.Join(evidence, "\n")
	if len(s) <= MaxChars {
		return s
	}
	cut := MaxChars
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// Cosine of two vectors of equal length; 0 if either has zero norm or the
// lengths differ.
func Cosine(a, b []float32) float64 {
	if len(a) != len(b) {
		return 0
	}
	var dot, na, nb float64
	for i := range a {
		x, y := float64(a[i]), float64(b[i])
		dot += x * y
		na += x * x
		nb += y * y
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}

// Anchor is the first class of a group; later classes are compared to it only.
type Anchor struct {
	Key    string
	Vector []float32
}

// Assign returns the anchor key with the highest cosine to v and that
// cosine, and joined=true when it is >= threshold. With no anchors, or none
// reaching threshold, joined=false (the caller makes v a new anchor) and key
// is the best anchor seen ("" if none) so the caller can log it. Ties break
// on the earlier anchor in the slice.
func Assign(v []float32, anchors []Anchor, threshold float64) (key string, sim float64, joined bool) {
	best := math.Inf(-1)
	for _, a := range anchors {
		if c := Cosine(v, a.Vector); c > best {
			best, key = c, a.Key
		}
	}
	if key == "" && len(anchors) == 0 {
		return "", 0, false
	}
	return key, best, best >= threshold
}

// Suggest returns the one decided visibility among a group's visibilities.
// Decided = "customer", "operator", "dismissed" (the literals of
// logsstore.Visibility*, which this pure package must not import; a store
// test asserts they agree). Pending, or anything else, is ignored. Exactly one
// distinct decided value gives (value, true); none or several give ("", false).
func Suggest(visibilities []string) (string, bool) {
	found := ""
	for _, v := range visibilities {
		switch v {
		case "customer", "operator", "dismissed":
		default:
			continue
		}
		if found != "" && found != v {
			return "", false
		}
		found = v
	}
	return found, found != ""
}
