// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package fingerprint

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nethesis/nethesis-insights/internal/model"
)

// Normalize collapses the variable fields the edge masker leaves literal, so a
// masking leak cannot split a finding's identity.
//
// It is model.CanonicalTemplate, which is also what the gate's novelty check
// and the system_templates key use. One definition, because the three must
// agree: if novelty and identity disagreed about whether two lines are the same
// condition, a window could buy an LLM call for a template the store already
// considered known, and the finding it produced would land on a fresh
// fingerprint every time.
//
// This is applied only on the identity path; the template text stored on the
// finding and shown to the operator is never rewritten.
func Normalize(moduleID, template string) string {
	return model.CanonicalTemplate(moduleID, template)
}

// EvidenceKey derives the stable identity input from the templates a model cited.
//
// v1 hashed every cited template, so a finding's identity moved whenever the
// model cited a different subset of an unchanged condition. This returns a
// single derived key instead:
//
//  1. normalize each cited template, so a masking leak cannot split identity.
//     Every country-code variant of one scenario normalizes to the same text,
//     so citing more of them changes nothing;
//  2. key on the canonical primary template: the first of the normalized set
//     under model.LessTemplate.
//
// v4 had a layer between the two: several distinct templates sharing one
// (module_id, priority) bucket keyed on the bucket. It merged every
// multi-line finding of a module into one class -- six unrelated
// nethvoice-proxy problems on the dev fleet (media relay down, SRTP,
// malformed SIP, debug logging, Redis, SIP auth), one review decision and,
// with class wording, one title for all of them. v5 dropped it. What it
// bought -- stability when the model cites another subset of a continuing
// problem's lines -- is now kept by RefreshFindings in the logs store, which
// holds a finding open, and so listed as ALREADY KNOWN, for as long as its
// lines keep arriving.
//
// EvidenceKey is the first of EvidenceCandidates, the key a finding gets when
// none of its lines is already the primary of a class. The analyzer prefers
// an existing class's line over it; see EvidenceCandidates.
//
// The returned slice always has exactly one element, which is what Compute's
// evidence list receives.
func EvidenceKey(cited []model.Template) []string {
	candidates := EvidenceCandidates(cited)
	if len(candidates) == 0 {
		return nil
	}
	return candidates[0]
}

// EvidenceCandidates returns the evidence key each distinct normalized cited
// line would give the finding as its primary, in model.LessTemplate order and
// deduplicated: candidate 0 is EvidenceKey. Each element has exactly one
// string, ready for Compute and Class.
//
// It exists for a cross-system wobble that EvidenceKey alone cannot absorb:
// the model on one system cites {X} and on another {W, X}, W sorting first,
// and one condition lands on two classes. On the dev fleet, Kamailio
// connection failures cited tcpconn_main_timeout() on some systems and also
// handle_tcpconn_ev() (which sorts first) on others; a SIP auth failure was
// cited as the REGISTER line alone on one system and INVITE+REGISTER on the
// rest. The analyzer therefore keys a finding on the first candidate that is
// already the primary of a stored class, else on candidate 0.
//
// That choice needs the store, so it is made by the analyzer and this stays
// pure: it only lists the lines a finding could be keyed on. Every candidate
// is a line the finding actually cites, so preferring one never invents
// evidence -- it only picks which cited line names the condition.
func EvidenceCandidates(cited []model.Template) [][]string {
	if len(cited) == 0 {
		return nil
	}

	normalized := make([]model.Template, len(cited))
	copy(normalized, cited)
	for i := range normalized {
		normalized[i].Template = Normalize(normalized[i].ModuleID, normalized[i].Template)
	}

	sort.Slice(normalized, func(i, j int) bool {
		return model.LessTemplate(normalized[i], normalized[j])
	})

	out := make([][]string, 0, len(normalized))
	seen := make(map[string]bool, len(normalized))
	for _, t := range normalized {
		key := fmt.Sprintf("primary:%s/%d/%s", t.ModuleID, t.Priority, strings.TrimSpace(t.Template))
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, []string{key})
	}
	return out
}
