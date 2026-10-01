// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package metrics

import "github.com/prometheus/client_golang/prometheus"

// Results is a counter with one `result` label whose vocabulary belongs to
// the caller: insightsd's windows_total (what the gate decided for each
// window) and threatd's events_total (what ingest did with each decision).
// The vocabulary is passed in, never restated here, so there is no second
// copy to drift -- the same arrangement as NewTrigger and NewBudget.
type Results struct {
	counter *prometheus.CounterVec
}

// NewResults builds and registers the counter into reg, pre-creating one
// child at 0 per result.
func NewResults(reg *Registry, name, help string, results ...string) *Results {
	r := &Results{
		counter: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: name,
			Help: help,
		}, []string{"result"}),
	}
	reg.prefixed.MustRegister(r.counter)
	for _, result := range results {
		r.counter.WithLabelValues(result)
	}
	return r
}

// Inc records one occurrence of result.
func (r *Results) Inc(result string) {
	r.counter.WithLabelValues(result).Inc()
}

// Add records n occurrences of result. A non-positive n is a no-op, so a
// caller can hand over every counter of a batch without filtering zeros.
func (r *Results) Add(result string, n int) {
	if n > 0 {
		r.counter.WithLabelValues(result).Add(float64(n))
	}
}
