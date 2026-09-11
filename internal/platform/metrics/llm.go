// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package metrics

import "github.com/prometheus/client_golang/prometheus"

// LLM-call outcome classes. These mirror analyzer.Process's own step order:
// a call either succeeds, fails transiently (the window stays claimable and
// the edge retries), fails permanently (the window is closed), or succeeds
// at the HTTP layer but the response fails prompt.Parse. Bounded set of
// four -- never a provider error string, which is unbounded.
const (
	LLMResultSuccess   = "success"
	LLMResultTransient = "transient"
	LLMResultPermanent = "permanent"
	LLMResultParse     = "parse"
)

// LLM holds insightsd's model-call counters: how many calls landed in each
// outcome class, and the running cost these calls billed.
type LLM struct {
	calls *prometheus.CounterVec
	cost  prometheus.Counter
}

// NewLLM builds and registers insightsd's LLM counters into reg.
//
// All four outcome children are pre-created at 0 -- see the package doc's
// "pre-create every enumerable child" note. This vocabulary is closed and
// owned here (the LLMResult* constants above), so unlike NewBudget and
// NewAuth this constructor needs no vocabulary from its caller.
func NewLLM(reg *Registry) *LLM {
	l := &LLM{
		calls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "llm_calls_total",
			Help: "LLM calls attempted, by outcome (success, transient, permanent, parse).",
		}, []string{"result"}),
		cost: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "llm_cost_micros_total",
			Help: "Total LLM spend in micro-dollars (1e-6 USD), from successful calls only.",
		}),
	}
	reg.prefixed.MustRegister(l.calls, l.cost)
	for _, result := range []string{
		LLMResultSuccess, LLMResultTransient, LLMResultPermanent, LLMResultParse,
	} {
		l.calls.WithLabelValues(result)
	}
	return l
}

// Call records one attempt. costMicros is added only for a successful call;
// every failed class bills nothing, matching the analyses ledger's own
// cost_micros = 0 on an errored attempt.
func (l *LLM) Call(result string, costMicros int64) {
	l.calls.WithLabelValues(result).Inc()
	if costMicros > 0 {
		l.cost.Add(float64(costMicros))
	}
}
