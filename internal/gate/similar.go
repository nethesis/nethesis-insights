// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package gate

import (
	"strings"

	"github.com/nethesis/nethesis-insights/internal/model"
)

// Near-known templates.
//
// model.CanonicalTemplate collapses the masking leaks somebody wrote a rule
// for. The ones nobody did -- a SIP call-id, an SRS hash, a session id, a
// username an attacker tried -- make a known line look new every window, and
// on the dev fleet they were the largest single source of paid calls. Rather
// than chase each with a rule, an unknown template counts as known when a
// known one of the same module family has the same number of tokens and
// agrees on at least Config.Similarity of them, position by position, and
// every token that differs looks like an identifier rather than a word.
//
// Measured over 7 days of the dev fleet at 0.9, this skipped 28% of spend.
// The word rule is what keeps "Failed to reconnect" from matching "Failed to
// ping": of the 15,843 new templates that matched a known one at 0.9, 567
// differed in a plain word, and those are left novel.
//
// This decides novelty only. A near-known template is still recorded under
// its own canonical key, and fingerprint identity is unchanged.

// similarityEligible reports whether t may be matched by similarity at all.
// A security-classified template never is: the security condition exists to
// see every new one. Nor is anything at priority critical or above, where
// one changed word is too expensive to miss. Priority 0 (emerg, or no
// priority at all) is therefore excluded too, which errs toward paying.
func similarityEligible(t model.Template) bool {
	return t.Category != "security" && t.Priority > 2
}

// knownIndex groups the known templates of one system by module family and
// token count, the only templates a candidate can be compared with.
type knownIndex struct {
	byShape map[shape][][]string
}

type shape struct {
	family string
	tokens int
}

// newKnownIndex indexes every known template seen at or after silentBefore.
// A template silent for longer is about to count as novel when it returns,
// and must not make a variant of itself look known meanwhile.
func newKnownIndex(known map[string]int64, silentBefore int64) *knownIndex {
	idx := &knownIndex{byShape: map[shape][][]string{}}
	for key, lastSeen := range known {
		if lastSeen < silentBefore {
			continue
		}
		family, text, ok := strings.Cut(key, "\x00")
		if !ok {
			continue
		}
		toks := tokenize(text)
		k := shape{family, len(toks)}
		idx.byShape[k] = append(idx.byShape[k], toks)
	}
	return idx
}

// near reports whether the template under canonical key matches any indexed
// template at threshold.
func (idx *knownIndex) near(key string, threshold float64) bool {
	family, text, ok := strings.Cut(key, "\x00")
	if !ok {
		return false
	}
	toks := tokenize(text)
	if len(toks) == 0 {
		return false
	}
	// The mismatch budget is fixed by the length, so a short line gets none:
	// at 0.9 a line needs ten tokens before one may differ.
	allowed := int(float64(len(toks))*(1-threshold) + 1e-9)
	if allowed == 0 {
		return false
	}
	for _, other := range idx.byShape[shape{family, len(toks)}] {
		if similar(toks, other, allowed) {
			return true
		}
	}
	return false
}

// similar reports whether a and b, of equal length, differ in at most
// allowed positions, each of them an identifier on both sides.
func similar(a, b []string, allowed int) bool {
	diff := 0
	for i := range a {
		if a[i] == b[i] {
			continue
		}
		diff++
		if diff > allowed || plainWord(a[i]) || plainWord(b[i]) {
			return false
		}
	}
	return true
}

// tokenize splits a template into words and single punctuation marks. '<'
// and '>' count as word characters so a placeholder such as <NUM> is one
// token.
func tokenize(s string) []string {
	var toks []string
	start := -1
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isWordByte(c):
			if start < 0 {
				start = i
			}
		default:
			if start >= 0 {
				toks = append(toks, s[start:i])
				start = -1
			}
			if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
				toks = append(toks, s[i:i+1])
			}
		}
	}
	if start >= 0 {
		toks = append(toks, s[start:])
	}
	return toks
}

func isWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '_' || c == '<' || c == '>'
}

// plainWord reports whether tok reads as a word -- letters only, with no
// lower-to-upper change inside it -- rather than an identifier. "ping",
// "Error" and "SRTP" are words; "fevigort37u6", "DjhtXUVdMggltcnr" and
// "<HEX>" are not.
func plainWord(tok string) bool {
	if len(tok) < 2 {
		return false
	}
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		upper := c >= 'A' && c <= 'Z'
		if !upper && (c < 'a' || c > 'z') {
			return false
		}
		if upper && i > 0 && tok[i-1] >= 'a' && tok[i-1] <= 'z' {
			return false
		}
	}
	return true
}
