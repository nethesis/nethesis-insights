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
//  1. normalize each cited template, so a masking leak cannot split identity;
//  2. if every cited template shares one (module_id, priority) bucket, key on
//     the bucket -- residual text variance within one bucket is noise;
//  3. otherwise key on the canonical primary template: the first of the
//     normalized set under model.LessTemplate.
//
// Layer 2 is bounded on purpose. It merges only within a single bucket a model
// already chose to cite as one condition; two conditions in different modules or
// at different priorities keep distinct identities.
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

	sameBucket := true
	for _, t := range normalized[1:] {
		if t.ModuleID != normalized[0].ModuleID || t.Priority != normalized[0].Priority {
			sameBucket = false
			break
		}
	}
	if sameBucket {
		return []string{fmt.Sprintf("bucket:%s/%d", normalized[0].ModuleID, normalized[0].Priority)}
	}

	sort.Slice(normalized, func(i, j int) bool {
		return model.LessTemplate(normalized[i], normalized[j])
	})
	primary := normalized[0]
	return []string{fmt.Sprintf("primary:%s/%d/%s",
		primary.ModuleID, primary.Priority, strings.TrimSpace(primary.Template))}
}
