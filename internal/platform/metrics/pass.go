// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Pass holds the counters shared by every periodic background pass driven
// through internal/platform/svc.RunPassLoop: threatd's blocklist consensus,
// sizingd's cohort pass, and insightsd's log-maintenance pass. The "pass"
// label is the same short name RunPassLoop already logs against ("blocklist
// consensus", "sizing cohort", "log maintenance") -- a closed set of three
// across the whole deployment, one per binary that runs a pass.
type Pass struct {
	runs        *prometheus.CounterVec
	duration    *prometheus.HistogramVec
	lastSuccess *prometheus.GaugeVec
}

// Pass-run outcomes. Closed, and owned here: Observe derives the result
// from an error rather than being handed a vocabulary.
const (
	passResultSuccess = "success"
	passResultFailure = "failure"
)

// NewPass builds and registers the pass counters into reg. *Pass satisfies
// svc.PassRecorder.
//
// passes names the background passes this process runs -- cmd/threatd
// passes "blocklist consensus", cmd/sizingd "sizing cohort", cmd/insightsd
// maint.PassName -- so that pass_runs_total's success and failure children
// are pre-created at 0 and the family is present before the first run
// finishes. Each caller passes the same string it hands svc.RunPassLoop (or,
// for insightsd, the one maint.Runner.RunLoop hands it), so there is no
// second copy to drift.
//
// pass_duration_seconds needs no pre-creation: a histogram vec child would
// export an all-zero bucket set, and a rate over an absent histogram is the
// same "no data" as one over a zero one, so there is nothing to fix.
// pass_last_success_timestamp_seconds is deliberately NOT pre-created --
// see the package doc: a zero there would read as "last succeeded at the
// Unix epoch" and fire every staleness alert on every restart.
func NewPass(reg *Registry, passes ...string) *Pass {
	p := &Pass{
		runs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pass_runs_total",
			Help: "Background pass runs, by pass name and result (success, failure).",
		}, []string{"pass", "result"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "pass_duration_seconds",
			Help:    "Background pass run duration in seconds, by pass name.",
			Buckets: prometheus.DefBuckets,
		}, []string{"pass"}),
		lastSuccess: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "pass_last_success_timestamp_seconds",
			Help: "Unix time of the last successful run of this pass.",
		}, []string{"pass"}),
	}
	reg.prefixed.MustRegister(p.runs, p.duration, p.lastSuccess)
	for _, pass := range passes {
		p.runs.WithLabelValues(pass, passResultSuccess)
		p.runs.WithLabelValues(pass, passResultFailure)
	}
	return p
}

// Observe records one pass run. now is the unix-millis clock value
// RunPassLoop drove the pass with, converted to seconds for the gauge.
func (p *Pass) Observe(pass string, err error, duration time.Duration, now int64) {
	result := passResultSuccess
	if err != nil {
		result = passResultFailure
	}
	p.runs.WithLabelValues(pass, result).Inc()
	p.duration.WithLabelValues(pass).Observe(duration.Seconds())
	if err == nil {
		p.lastSuccess.WithLabelValues(pass).Set(float64(now) / 1000)
	}
}
