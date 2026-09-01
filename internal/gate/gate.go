// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package gate

import (
	"fmt"
	"sort"

	"github.com/nethesis/nethesis-insights/internal/model"
)

const (
	ReasonNewTemplates       = "new_templates"
	ReasonDeviation          = "deviation"
	ReasonSecurityNew        = "security_new"
	ReasonSecuritySurge      = "security_surge"
	ReasonTruncatedDeviating = "truncated_deviating"
)

type BaselineKey struct {
	ModuleID string
	Priority int
}

type SystemState struct {
	// KnownTemplates is keyed by model.CanonicalKey, not by raw template
	// text. The collector's masking leaks whatever it has no rule for -- a
	// percentage, a customer domain, a single-digit counter -- and every
	// leaked variant of a known line otherwise reads as novel and buys an LLM
	// call. See model.CanonicalTemplate for what is collapsed and why the
	// rules are narrow.
	KnownTemplates map[string]bool
	Baselines      map[BaselineKey]float64
	SecurityOnly   bool
}

// Config holds the gate's thresholds. They are parameters rather than
// constants because the fleet's shape is not known in advance, and they are
// grouped so that adding one does not churn every call site.
type Config struct {
	// Tolerance is the digest ratio above which a bucket is deviating.
	Tolerance float64

	// MinExpected and MinObserved are the absolute floors under the deviation
	// condition. A ratio is not evidence when the denominator is 2: measured
	// on the dev fleet, the median module_baselines ewma_rate was 3.1 lines
	// per window and 207 of 587 buckets were below 2, so a bucket that
	// normally emits two lines fired the gate at seven. The three buckets that
	// fired most often (<host>/5, metrics1/3, loki1/6) all had a baseline
	// under 5, and every one of those calls was noise.
	MinExpected float64
	MinObserved float64

	// MinNewTemplates is how many novel templates a window needs before
	// novelty alone fires. A real new condition arrives as a cluster of lines,
	// not one. A single new template that carries category=security still
	// fires unconditionally through securityNew, which is evaluated before
	// this and is deliberately not subject to the quorum.
	MinNewTemplates int
}

type Decision struct {
	Call    bool
	Reasons []string

	// Novel holds the canonical keys (model.CanonicalKey) of the templates
	// this bundle carries that the system has not sent before, and
	// DeviatingModules the modules whose volume is over tolerance.
	//
	// They are returned rather than recomputed by the caller because the
	// prompt decides which templates are worth an LLM's attention from
	// exactly these two sets: whatever paid for the call is what gets shown.
	// Recomputing them elsewhere would be a second definition of novelty, and
	// the two would eventually disagree.
	Novel            map[string]bool
	DeviatingModules map[string]bool
}

// Evaluate decides whether an LLM call is warranted for this bundle. This is
// the cost control: every reason must be deterministic (sorted) since it may
// end up in logs/metrics compared across runs.
func Evaluate(b model.Bundle, s SystemState, cfg Config) Decision {
	var reasons []string

	// Deviation is computed first because the security condition below needs
	// to know which buckets are deviating.
	deviatingModules, deviationReasons := deviations(b, s, cfg)

	// Security condition. A security-category template fires the gate when it
	// is NEW for this system, or when its bucket is deviating -- never merely
	// because it is present.
	//
	// The unconditional form this replaces made the gate a no-op on any
	// internet-facing node: failed SSH auth arrives continuously, every window
	// therefore contained a security template, and the gate called the LLM
	// 352 times out of 352 on the dev fleet. It also made the spend-cap
	// degrade path (SecurityOnly, spec section 9.4) cost exactly as much as
	// not degrading, which is the opposite of what that lever is for.
	// Novelty is computed over canonical keys, so ten spellings of one leaked
	// field count once. It is computed before the security branch because
	// both conditions ask the same question of the same set.
	novel := map[string]bool{}
	for _, t := range b.Templates {
		key := model.CanonicalKey(t.ModuleID, t.Template)
		if !s.KnownTemplates[key] {
			novel[key] = true
		}
	}

	securityNew, securitySurge := false, false
	for _, t := range b.Templates {
		if t.Category != "security" {
			continue
		}
		if novel[model.CanonicalKey(t.ModuleID, t.Template)] {
			securityNew = true
			continue
		}
		if deviatingModules[t.ModuleID] {
			securitySurge = true
		}
	}
	// Reasons are appended in constant order so the stored set is
	// deterministic; see the sort note on Decision.
	if securityNew {
		reasons = append(reasons, ReasonSecurityNew)
	}
	if securitySurge {
		reasons = append(reasons, ReasonSecuritySurge)
	}

	if s.SecurityOnly {
		return Decision{
			Call:             securityNew || securitySurge,
			Reasons:          reasons,
			Novel:            novel,
			DeviatingModules: deviatingModules,
		}
	}

	if len(novel) >= cfg.MinNewTemplates && cfg.MinNewTemplates > 0 {
		// The reason carries no count. The /gate rollup groups on the stored
		// string, and an embedded number made every window a group of one --
		// the "new_templates=3" spellings still in the database are the
		// remains of that.
		reasons = append(reasons, ReasonNewTemplates)
	}

	reasons = append(reasons, deviationReasons...)

	// Truncation alone never fires; only in combination with deviation on
	// the same module.
	truncatedModules := make([]model.TruncatedModule, len(b.Budget.TruncatedModules))
	copy(truncatedModules, b.Budget.TruncatedModules)
	sort.Slice(truncatedModules, func(i, j int) bool {
		return truncatedModules[i].ModuleID < truncatedModules[j].ModuleID
	})
	for _, tm := range truncatedModules {
		if deviatingModules[tm.ModuleID] {
			reasons = append(reasons, fmt.Sprintf("%s:%s", ReasonTruncatedDeviating, tm.ModuleID))
		}
	}

	return Decision{
		Call:             len(reasons) > 0,
		Reasons:          reasons,
		Novel:            novel,
		DeviatingModules: deviatingModules,
	}
}

// deviations returns the set of modules whose observed volume exceeds
// tolerance, plus one reason string per deviating bucket.
//
// Reasons carry the bucket but NOT the computed ratio. The ratio made every
// deviating window a group of one in the operator UI's gate rollup, which
// groups on the stored gate_reasons string -- so the page that exists to answer
// "why are we paying" answered nothing.
//
// The ratio itself is deliberately not kept anywhere: it is a property of one
// window, and the two questions it gets asked are answered better elsewhere.
// "What was unusual in this window" is in the prompt body the analyzer built
// (internal/prompt), and "what does this bucket normally do" is the /baselines
// page. Do not put it back into a reason string.
func deviations(b model.Bundle, s SystemState, cfg Config) (map[string]bool, []string) {
	deviating := map[string]bool{}
	var reasons []string

	// Sort digest entries by (ModuleID, Priority) so reason ordering is
	// deterministic regardless of input order.
	digest := make([]model.DigestEntry, len(b.Digest))
	copy(digest, b.Digest)
	sort.Slice(digest, func(i, j int) bool {
		if digest[i].ModuleID != digest[j].ModuleID {
			return digest[i].ModuleID < digest[j].ModuleID
		}
		return digest[i].Priority < digest[j].Priority
	})

	for _, e := range digest {
		var expected float64
		if e.Expected != nil && *e.Expected > 0 {
			expected = *e.Expected
		} else {
			key := BaselineKey{ModuleID: e.ModuleID, Priority: e.Priority}
			expected = s.Baselines[key]
		}
		if expected <= 0 {
			// Never divide by zero; skip entries with no usable baseline.
			continue
		}
		// Both floors are conjunctive with the ratio, and both are needed:
		// MinExpected refuses to judge a bucket too small to have a normal,
		// MinObserved refuses to call a handful of lines a surge however
		// quiet the bucket usually is.
		if expected < cfg.MinExpected || float64(e.Observed) < cfg.MinObserved {
			continue
		}
		if float64(e.Observed)/expected > cfg.Tolerance {
			reasons = append(reasons, fmt.Sprintf("%s:%s/%d", ReasonDeviation, e.ModuleID, e.Priority))
			deviating[e.ModuleID] = true
		}
	}

	return deviating, reasons
}
