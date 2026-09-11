// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package metrics

import "github.com/prometheus/client_golang/prometheus"

// IngestQueueFull holds the counter for internal/platform/ingestq's ErrFull
// path -- the bounded-ingest queue threatd puts in front of its
// single-writer database. Every ErrFull also surfaces generically as
// http_requests_total{route="/v1/events",status="503"}, but this counter
// exists in addition because it names the specific, quantifiable condition
// (the queue was saturated) rather than the generic symptom (some handler
// answered 503).
type IngestQueueFull struct {
	full *prometheus.CounterVec
}

// NewIngestQueueFull builds and registers the counter into reg.
func NewIngestQueueFull(reg *prometheus.Registry) *IngestQueueFull {
	c := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ingestq_full_total",
		Help: "Publish calls that found internal/platform/ingestq.Queue saturated, by queue name.",
	}, []string{"queue"})
	reg.MustRegister(c)
	return &IngestQueueFull{full: c}
}

// Counter returns a bound increment function for one named queue, suitable
// for wiring straight into ingestq.Metrics.Full -- which takes a plain
// func() so that package needs no dependency on prometheus or this one.
//
// Binding the child here is also what pre-creates it at 0: WithLabelValues
// registers the child whether or not it is ever incremented, and callers
// call this at wiring time, so the family is present in the scrape output
// from the first scrape rather than appearing only after a queue first
// saturates. See the package doc's "pre-create every enumerable child" --
// this constructor needs no separate pre-creation pass because its only
// label value is the one being bound.
func (i *IngestQueueFull) Counter(queue string) func() {
	c := i.full.WithLabelValues(queue)
	return c.Inc
}
