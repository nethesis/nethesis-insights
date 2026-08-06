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
	ReasonSecurity           = "security_category"
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

	// Security condition is evaluated first so its reason is always first
	// when present.
	securityHit := false
	for _, t := range b.Templates {
		if t.Category == "security" {
			securityHit = true
			break
		}
	}
	if securityHit {
		reasons = append(reasons, ReasonSecurity)
	}

	if s.SecurityOnly {
		return Decision{Call: securityHit, Reasons: reasons}
	}

	// New templates.
	newCount := 0
	for _, t := range b.Templates {
		if !s.KnownTemplates[t.Template] {
			newCount++
		}
	}
	if newCount > 0 {
		reasons = append(reasons, fmt.Sprintf("%s=%d", ReasonNewTemplates, newCount))
	}

	// Deviation, tracked per module so we can cross-reference truncation.
	deviatingModules := map[string]bool{}

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
		ratio := float64(e.Observed) / expected
		if ratio > tolerance {
			reasons = append(reasons, fmt.Sprintf("%s:%s/%d=%.2f", ReasonDeviation, e.ModuleID, e.Priority, ratio))
			deviatingModules[e.ModuleID] = true
		}
	}

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
