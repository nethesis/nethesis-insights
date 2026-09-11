// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package metrics is the shared Prometheus wiring every binary uses: a
// per-process registry carrying the standard Go runtime/process collectors
// plus this package's typed constructors for the handful of counters,
// histograms and gauges the four binaries need.
//
// It belongs beside internal/platform/auth, httpx and sqlitex -- the
// packages every binary may import (see docs/architecture.md's package
// layering) -- because /metrics is wired the same way in all four: a fresh
// registry built once in main(), a handler mounted next to /healthz, and a
// small set of typed recorders passed down to whatever code produces the
// numbers.
//
// # Every metric defined here is prefixed with its service name
//
// NewRegistry takes the exporting container's name, and everything this
// package defines is registered through a registerer wrapped in
// "<service>_": insightsd_http_requests_total, threatd_ingestq_full_total,
// authd_cache_results_total and so on. The metric names in the constructors
// below are therefore the UNPREFIXED half of what a scrape shows -- see
// NewRegistry for why the prefix is applied once at the registry rather than
// as a Namespace on each definition, and for why the standard `go_*`,
// `process_*` and `promhttp_*` collectors deliberately keep their
// conventional unprefixed names.
//
// HARD RULE, the same class as CLAUDE.md's "gate reasons carry no computed
// values": no label here may carry a system_id (~2700 distinct values,
// customer-identifying), a raw request path, or any other unbounded or
// customer-identifying value. Every label set in this file is a small,
// closed enumeration -- a route pattern as registered on a ServeMux, an
// error class, a pass name -- never something request- or tenant-shaped.
//
// # Pre-create every enumerable child
//
// A prometheus CounterVec creates a child only on the first
// WithLabelValues call, and a family with no children is absent from the
// scrape output entirely -- no HELP, no TYPE, no series. That silently
// breaks alerting: `rate(llm_calls_total{result="permanent"}[5m]) > 0`
// evaluates against NO DATA rather than 0 on a freshly restarted process,
// so it never fires until the first permanent error has already happened --
// exactly the moment the alert was for. Dashboards show gaps instead of
// flat zero lines for the same reason.
//
// So every constructor here pre-creates the children whose label values are
// enumerable when it runs, by calling WithLabelValues and discarding the
// result: that registers the child at 0 without incrementing it. Where the
// vocabulary belongs to another package (budget's suppression reasons,
// auth's upstream outcomes, a pass's name) the constructor takes it as a
// parameter rather than restating the strings, so there is never a second
// copy to drift -- the same reason model.LessTemplate is the single
// definition of template order.
//
// Two deliberate exceptions:
//
//   - HTTP's families stay lazy. Neither `status` nor `method` is a closed
//     set, and enumerating them would invent series for combinations that
//     never occur (a 451 on /healthz, a PATCH on /metrics), which is a
//     worse lie than an absent one.
//   - Pass's last-success gauge stays absent until a pass actually
//     succeeds. Pre-creating it at 0 would read as "last succeeded at the
//     Unix epoch", making a staleness alert
//     (`time() - pass_last_success_timestamp_seconds > 3600`) fire on every
//     restart. Absent is the honest representation of "has not succeeded
//     yet".
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Registry is one process's metrics state: the raw registry a scrape is
// served from, plus the prefixed registerer every constructor in this
// package registers through.
//
// The two halves exist because only half the output is prefixed. Both
// fields are unexported and every constructor here takes a *Registry rather
// than a prometheus.Registerer, so there is no way to register one of this
// package's metrics on the unprefixed half by accident -- the only path to
// `raw` is the standard-collector registration in NewRegistry and the
// gatherer Handler serves from.
type Registry struct {
	// raw carries the standard collectors and is what Handler gathers from,
	// so a scrape returns the prefixed and unprefixed halves together.
	raw *prometheus.Registry

	// prefixed is raw wrapped in "<service>_". Everything this package
	// defines goes through it.
	prefixed prometheus.Registerer
}

// NewRegistry returns a fresh, unshared registry for one service, whose name
// is the container that exports the metrics -- "insightsd", "threatd",
// "sizingd" or "authd", matching ContainerName= in deploy/quadlet/*.container.
// Every binary builds its own -- never prometheus.DefaultRegisterer -- so
// that /metrics reflects exactly what this package and its callers
// registered, not whatever an imported dependency happens to have registered
// globally.
//
// The service prefix is applied ONCE here, by wrapping the registerer, rather
// than by giving each metric definition a Namespace: a metric added to this
// package later is prefixed automatically, whereas a per-definition Namespace
// is something a future change can silently forget, and one unprefixed family
// in an otherwise prefixed set is exactly the kind of inconsistency nobody
// notices until a dashboard query comes back empty.
//
// The standard Go runtime and process collectors are deliberately registered
// on the RAW registry, so they keep their conventional `go_*` and `process_*`
// names. Every off-the-shelf Go/Grafana dashboard and every `go_*`-based
// alert rule queries those exact names; prefixing them would buy consistency
// with this package's own metrics at the cost of breaking all of it.
// promhttp's own handler-error counter (`promhttp_*`, registered by Handler)
// is unprefixed for the same reason.
func NewRegistry(service string) *Registry {
	raw := prometheus.NewRegistry()
	raw.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return &Registry{
		raw:      raw,
		prefixed: prometheus.WrapRegistererWithPrefix(service+"_", raw),
	}
}

// Handler returns the scrape endpoint for reg, to be mounted at /metrics
// next to /healthz on each binary's existing API mux. It gathers from the
// raw registry, so one scrape carries both the prefixed families this
// package defines and the unprefixed standard collectors.
func Handler(reg *Registry) http.Handler {
	return promhttp.HandlerFor(reg.raw, promhttp.HandlerOpts{Registry: reg.raw})
}

// HTTP holds the request counter and duration histogram every binary's
// mux(es) feed through internal/platform/httpx.Logging on every request.
// Route is always the ServeMux pattern that matched (httpx.RouteLabel), not
// r.URL.Path -- a raw path is unbounded, a registered pattern is a small
// fixed set per binary.
type HTTP struct {
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// NewHTTP builds and registers the HTTP request counter/histogram pair into
// reg. *HTTP satisfies httpx.MetricsRecorder.
//
// Both families are deliberately left lazy, unlike every other constructor
// here: `route` is enumerable (the mux's registered patterns) but `status`
// and `method` are not, so pre-creating would mean inventing a series for
// every (method, route, status) triple -- a 451 on /healthz, a PATCH on
// /metrics -- almost all of which can never occur. An invented series that
// stays at 0 forever is a worse lie than an absent one. See the package doc.
func NewHTTP(reg *Registry) *HTTP {
	h := &HTTP{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total HTTP requests, by method, route and status code.",
		}, []string{"method", "route", "status"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds, by method and route.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "route"}),
	}
	reg.prefixed.MustRegister(h.requests, h.duration)
	return h
}

// Observe records one completed request. method is the HTTP verb, route the
// matched ServeMux pattern (see httpx.RouteLabel), status the response code.
func (h *HTTP) Observe(method, route string, status int, duration time.Duration) {
	h.requests.WithLabelValues(method, route, strconv.Itoa(status)).Inc()
	h.duration.WithLabelValues(method, route).Observe(duration.Seconds())
}

// RegisterQueueGauges wires depth/capacity/worker-count accessors -- already
// live, lock-free reads on *queue.Queue and *ingestq.Queue[T] -- into
// GaugeFuncs evaluated at scrape time. No bookkeeping, no polling loop: the
// gauge simply calls the accessor when Prometheus asks. name distinguishes
// the queue when a binary ever has more than one; today insightsd passes
// "bundle" and threatd passes "threat_events".
func RegisterQueueGauges(reg *Registry, name string, depth, capacity, workers func() int) {
	labels := prometheus.Labels{"queue": name}
	reg.prefixed.MustRegister(
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name:        "queue_depth",
			Help:        "Items currently buffered in the queue.",
			ConstLabels: labels,
		}, func() float64 { return float64(depth()) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name:        "queue_capacity",
			Help:        "Configured buffer size of the queue.",
			ConstLabels: labels,
		}, func() float64 { return float64(capacity()) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name:        "queue_workers",
			Help:        "Worker goroutines started for the queue.",
			ConstLabels: labels,
		}, func() float64 { return float64(workers()) }),
	)
}
