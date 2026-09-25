// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package metrics

import "github.com/prometheus/client_golang/prometheus"

// Trigger holds insightsd's trigger-memory counter: how many windows the
// gate fired on were answered without an LLM call, by why (see
// analyzer.SuppressedTrigger*, today just "trigger_hit"). The label is that
// closed set and nothing else -- never the trigger key, which is unbounded,
// and never system_id.
type Trigger struct {
	suppressions *prometheus.CounterVec
}

// NewTrigger builds and registers the counter into reg, pre-creating one
// child at 0 per reason. reasons comes from the caller
// (analyzer.TriggerSuppressions) because the vocabulary belongs to the
// analyzer, the same arrangement as NewBudget.
func NewTrigger(reg *Registry, reasons ...string) *Trigger {
	t := &Trigger{
		suppressions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trigger_suppressions_total",
			Help: "Windows the gate fired on that the trigger memory answered without an LLM call, by reason.",
		}, []string{"reason"}),
	}
	reg.prefixed.MustRegister(t.suppressions)
	for _, reason := range reasons {
		t.suppressions.WithLabelValues(reason)
	}
	return t
}

// Suppressed records one window answered from trigger memory.
func (t *Trigger) Suppressed(reason string) {
	t.suppressions.WithLabelValues(reason).Inc()
}
