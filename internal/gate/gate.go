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
	KnownTemplates map[string]bool
	Baselines      map[BaselineKey]float64
	SecurityOnly   bool
}

type Decision struct {
	Call    bool
	Reasons []string
}

// Evaluate decides whether an LLM call is warranted for this bundle. This is
// the cost control: every reason must be deterministic (sorted) since it may
// end up in logs/metrics compared across runs.
func Evaluate(b model.Bundle, s SystemState, tolerance float64) Decision {
	var reasons []string

	// Deviation is computed first because the security condition below needs
	// to know which buckets are deviating.
	deviatingModules, deviationReasons := deviations(b, s, tolerance)

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
	securityNew, securitySurge := false, false
	for _, t := range b.Templates {
		if t.Category != "security" {
			continue
		}
		if !s.KnownTemplates[t.Template] {
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
		return Decision{Call: securityNew || securitySurge, Reasons: reasons}
	}

	// New templates.
	newCount := 0
	for _, t := range b.Templates {
		if !s.KnownTemplates[t.Template] {
			newCount++
		}
	}
	if newCount > 0 {
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

	return Decision{Call: len(reasons) > 0, Reasons: reasons}
}

// deviations returns the set of modules whose observed volume exceeds
// tolerance, plus one reason string per deviating bucket.
//
// Reasons carry the bucket but NOT the computed ratio. The ratio made every
// deviating window a group of one in the operator UI's gate rollup, which
// groups on the stored gate_reasons string -- so the page that exists to answer
// "why are we paying" answered nothing. The ratio is still logged per window by
// the analyzer at debug level.
func deviations(b model.Bundle, s SystemState, tolerance float64) (map[string]bool, []string) {
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
		if float64(e.Observed)/expected > tolerance {
			reasons = append(reasons, fmt.Sprintf("%s:%s/%d", ReasonDeviation, e.ModuleID, e.Priority))
			deviating[e.ModuleID] = true
		}
	}

	return deviating, reasons
}
