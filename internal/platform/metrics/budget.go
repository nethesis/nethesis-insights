// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package metrics

import "github.com/prometheus/client_golang/prometheus"

// Budget holds insightsd's budget-rejection counter: how many windows were
// suppressed before the gate even ran, by the limit that stopped them (see
// internal/budget.Verdict.Suppressed). The label set is the handful of
// budget.Suppressed* constants, never a computed value -- the same rule
// CLAUDE.md states for gate reasons.
type Budget struct {
	rejections *prometheus.CounterVec
}

// NewBudget builds and registers the budget-rejection counter into reg,
// pre-creating one child at 0 per reason so the family is present before the
// first rejection -- see the package doc's "pre-create every enumerable
// child".
//
// reasons is supplied by the caller rather than restated here because the
// vocabulary belongs to internal/budget: cmd/insightsd passes
// budget.SuppressedSystemCap, which is the only value
// budget.Verdict.Suppressed is ever assigned. Note that
// budget.ReasonSpendCap is deliberately NOT one of them -- the daily spend
// cap degrades the gate to security-only (Verdict.SecurityOnly) rather than
// suppressing a window, so it never reaches this counter, and pre-creating
// it would invent a series that can never move.
func NewBudget(reg *prometheus.Registry, reasons ...string) *Budget {
	b := &Budget{
		rejections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "budget_rejections_total",
			Help: "Windows suppressed by internal/budget before the gate ran, by the limit that fired.",
		}, []string{"reason"}),
	}
	reg.MustRegister(b.rejections)
	for _, reason := range reasons {
		b.rejections.WithLabelValues(reason)
	}
	return b
}

// Rejected records one suppressed window. reason is a budget.Suppressed*
// constant (today only budget.SuppressedSystemCap).
func (b *Budget) Rejected(reason string) {
	b.rejections.WithLabelValues(reason).Inc()
}
