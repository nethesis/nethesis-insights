// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package gate

import (
	"github.com/nethesis/nethesis-insights/internal/model"
)

const (
	ReasonNewTemplates = "new_templates"
	ReasonSecurityNew  = "security_new"
)

type SystemState struct {
	// KnownTemplates maps every template this system has sent, keyed by
	// model.CanonicalKey, to the unix-millis it was last seen. Keyed on the
	// canonical form, not the raw text: the collector's masking leaks
	// whatever it has no rule for -- a percentage, a customer domain, a
	// single-digit counter -- and every leaked variant of a known line
	// otherwise reads as novel and buys an LLM call. See
	// model.CanonicalTemplate for what is collapsed and why the rules are
	// narrow; Config.Similarity catches what they miss.
	KnownTemplates map[string]int64
	SecurityOnly   bool
}

// Config holds the gate's thresholds. They are parameters rather than
// constants because the fleet's shape is not known in advance, and they are
// grouped so that adding one does not churn every call site.
type Config struct {
	// MinNewTemplates is how many novel templates a window needs before
	// novelty alone fires. A real new condition arrives as a cluster of lines,
	// not one. A single new template that carries category=security still
	// fires unconditionally through securityNew, which is evaluated before
	// this and is deliberately not subject to the quorum.
	MinNewTemplates int

	// Similarity is the share of tokens an unknown template must have in
	// common, position by position, with a known one for it to count as
	// known. 1 disables the check. See nearKnown for what may differ.
	Similarity float64

	// Silence, in milliseconds, is how long a known template must have been
	// absent before the window for its return to count as novel. 0 disables
	// it. This is what replaced the volume baseline: a failure whose lines
	// the system already knows -- a backup that failed in March and again in
	// May -- is caught when it comes back, without keeping a per-bucket
	// average whose idea of "normal" was the last hour.
	Silence int64
}

type Decision struct {
	Call    bool
	Reasons []string

	// Novel holds the canonical keys (model.CanonicalKey) of the templates
	// that count as new for this system: never sent, not near a known one,
	// or back after Config.Silence.
	//
	// It is returned rather than recomputed by the caller because the
	// prompt decides which templates are worth an LLM's attention from
	// exactly this set: whatever paid for the call is what gets shown.
	// Recomputing it elsewhere would be a second definition of novelty, and
	// the two would eventually disagree.
	Novel map[string]bool

	// NearKnown counts the canonical keys Config.Similarity kept out of
	// Novel, and Returning those Config.Silence put into it. Both are
	// reported as metrics, so the two rules' effect is measured rather than
	// assumed.
	NearKnown int
	Returning int
}

// Evaluate decides whether an LLM call is warranted for this bundle. This is
// the cost control: every reason must be deterministic (constant order)
// since it may end up in logs/metrics compared across runs.
//
// The gate answers one question: did this window bring something the system
// has not shown recently. There is no volume condition. A per-bucket EWMA
// baseline used to fire on a burst of known lines; it remembered roughly the
// last hour, so a quiet night made every morning a surge, it fired in 42% of
// the dev fleet's windows, and it cost a table, five settings and three
// reasons for 8% of new findings. Config.Silence catches the part of that
// worth keeping.
func Evaluate(b model.Bundle, s SystemState, cfg Config) Decision {
	var reasons []string

	silentBefore := int64(-1 << 63)
	if cfg.Silence > 0 {
		silentBefore = b.Window.Start - cfg.Silence
	}

	// Novelty is computed over canonical keys, so ten spellings of one leaked
	// field count once. A key is decided once even when several templates
	// share it; eligible records whether any of them may be matched by
	// similarity, and one that may not wins.
	novel := map[string]bool{}
	returning := map[string]bool{}
	unknown := map[string]bool{}
	var unknownOrder []string
	for _, t := range b.Templates {
		key := model.CanonicalKey(t.ModuleID, t.Template)
		lastSeen, known := s.KnownTemplates[key]
		switch {
		case !known:
			if _, seen := unknown[key]; !seen {
				unknown[key] = true
				unknownOrder = append(unknownOrder, key)
			}
			if !similarityEligible(t) {
				unknown[key] = false
			}
		case lastSeen < silentBefore:
			novel[key] = true
			returning[key] = true
		}
	}

	nearKnown := 0
	if len(unknownOrder) > 0 {
		var idx *knownIndex
		if cfg.Similarity < 1 {
			idx = newKnownIndex(s.KnownTemplates, silentBefore)
		}
		for _, key := range unknownOrder {
			if unknown[key] && idx != nil && idx.near(key, cfg.Similarity) {
				nearKnown++
				continue
			}
			novel[key] = true
		}
	}

	// Security condition. A security-category template fires the gate when it
	// is NEW for this system -- never merely because it is present.
	//
	// The unconditional form this replaces made the gate a no-op on any
	// internet-facing node: failed SSH auth arrives continuously, every window
	// therefore contained a security template, and the gate called the LLM
	// 352 times out of 352 on the dev fleet. It also made the spend-cap
	// degrade path (SecurityOnly, spec section 9.4) cost exactly as much as
	// not degrading, which is the opposite of what that lever is for.
	securityNew := false
	for _, t := range b.Templates {
		if t.Category == "security" && novel[model.CanonicalKey(t.ModuleID, t.Template)] {
			securityNew = true
			break
		}
	}
	if securityNew {
		reasons = append(reasons, ReasonSecurityNew)
	}

	// In security-only mode (the spend cap's degrade path) only the security
	// condition may pay.
	if !s.SecurityOnly && len(novel) >= cfg.MinNewTemplates && cfg.MinNewTemplates > 0 {
		// The reason carries no count. The /gate rollup groups on the stored
		// string, and an embedded number made every window a group of one --
		// the "new_templates=3" spellings still in the database are the
		// remains of that.
		reasons = append(reasons, ReasonNewTemplates)
	}

	return Decision{
		Call:      len(reasons) > 0,
		Reasons:   reasons,
		Novel:     novel,
		NearKnown: nearKnown,
		Returning: len(returning),
	}
}
