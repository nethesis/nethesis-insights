// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package fingerprint

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/nethesis/nethesis-insights/internal/model"
)

// The edge masker leaves two fields literal in CrowdSec-derived templates, so
// one scenario mints a new "template" per value:
//
//	ssh-time-based-bf by ip <IP> (US/<NUM>)   ... and (DE/<NUM>), (GB/<NUM>) ...
//	ban on ip <IP> for 4m                     ... and 8m, 12m, 392m ...
//
// Fixing that belongs in the collector, not here. These two rules exist so a
// masking leak cannot silently split a finding's identity while it is being
// fixed somewhere else. They are deliberately narrow: a bracketed two-letter
// uppercase country code, and a bare duration. Anything broader risks merging
// conditions that are genuinely distinct.
var (
	countryCode = regexp.MustCompile(`\(([A-Z]{2})/`)
	duration    = regexp.MustCompile(`\b\d+(ms|s|m|h|d)\b`)
)

// Normalize collapses the known masking leaks in a template. It is applied only
// on the identity path; the template text stored on the finding and shown to the
// operator is never rewritten.
func Normalize(template string) string {
	t := countryCode.ReplaceAllString(template, "(<CC>/")
	t = duration.ReplaceAllString(t, "<DUR>")
	return t
}

// EvidenceKey derives the stable identity input from the templates a model cited.
//
// v1 hashed every cited template, so a finding's identity moved whenever the
// model cited a different subset of an unchanged condition. This returns a
// single derived key instead, in three layers:
//
//  1. normalize each cited template, so a masking leak cannot split identity.
//     This alone settles the observed case: every country-code variant of one
//     scenario normalizes to the same text, so citing more of them changes
//     nothing;
//  2. if the normalized set is a single distinct template, key on it;
//  3. if it is several distinct templates that all share one
//     (module_id, priority) bucket, key on the bucket -- residual variance
//     inside a bucket the model chose to cite as one condition is noise;
//  4. otherwise key on the canonical primary template: the first of the
//     normalized set under model.LessTemplate.
//
// Layer 3 is deliberately the last resort rather than the common path. Applying
// it whenever the cited set shares a bucket would key every single-citation
// finding on its bucket alone, merging unrelated problems that happen to live in
// the same module at the same priority -- and the host bucket carries hundreds
// of distinct templates.
//
// The returned slice always has exactly one element, which is what Compute's
// evidence list receives.
func EvidenceKey(cited []model.Template) []string {
	if len(cited) == 0 {
		return nil
	}

	normalized := make([]model.Template, len(cited))
	copy(normalized, cited)
	for i := range normalized {
		normalized[i].Template = Normalize(normalized[i].Template)
	}

	sort.Slice(normalized, func(i, j int) bool {
		return model.LessTemplate(normalized[i], normalized[j])
	})

	distinct := normalized[:0:0]
	for i, t := range normalized {
		if i == 0 || t.Template != normalized[i-1].Template ||
			t.ModuleID != normalized[i-1].ModuleID || t.Priority != normalized[i-1].Priority {
			distinct = append(distinct, t)
		}
	}

	primary := distinct[0]
	if len(distinct) > 1 {
		sameBucket := true
		for _, t := range distinct[1:] {
			if t.ModuleID != primary.ModuleID || t.Priority != primary.Priority {
				sameBucket = false
				break
			}
		}
		if sameBucket {
			return []string{fmt.Sprintf("bucket:%s/%d", primary.ModuleID, primary.Priority)}
		}
	}

	return []string{fmt.Sprintf("primary:%s/%d/%s",
		primary.ModuleID, primary.Priority, strings.TrimSpace(primary.Template))}
}
