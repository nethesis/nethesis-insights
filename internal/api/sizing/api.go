// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package sizing serves fleet sizing's client API: one cluster's
// complete-UTC-day workload and performance report in, nothing served back
// to the edge (the two operator UI pages are the only consumers of what this
// stores).
//
// Authentication happens at the proxy: Traefik's forwardAuth middleware
// calls authd, and only a request it approved reaches this process. The
// Authorization header still arrives untouched, so the system identity is
// read from it here -- see httpx.SystemID, whose trusted-proxy check is what
// makes that safe.
package sizing

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/platform/httpx"
	sizingstore "github.com/nethesis/nethesis-insights/internal/store/sizing"
)

// Store is the slice of sizingstore.Store this package needs. Declared here,
// narrow, so the handler is testable with a small fake instead of the whole
// store -- the same idiom as internal/ui/sizing's Reader.
// *sizingstore.Store satisfies it.
type Store interface {
	UpsertSizingDays(ctx context.Context, systemID, reporterVersion string, days []sizingstore.SizingDayRows, now int64) (int, error)
	RecordSizingIngest(ctx context.Context, day int64, systemID, reporterVersion string, c model.SizingCounters, now int64) error
}

type server struct {
	store   Store
	trusted httpx.TrustedProxies
	cfg     Config
}

// Config carries the ingest bounds and the injectable clock. MaxNodes
// truncates rather than rejects: a report over the cap loses its tail, never
// the whole report.
type Config struct {
	MaxNodes int
	Now      func() int64
}

func defaultNow() int64 { return time.Now().UnixMilli() }

// NewServer builds sizingd's ingest API. metricsHandler is mounted at
// /metrics next to /healthz -- nil skips it, which only tests exercise. rec
// is fed every completed request's method/route/status/duration; nil is
// valid and simply skips metrics -- see httpx.MetricsRecorder.
func NewServer(st Store, trusted httpx.TrustedProxies, cfg Config, metricsHandler http.Handler, rec httpx.MetricsRecorder) http.Handler {
	if cfg.Now == nil {
		cfg.Now = defaultNow
	}
	srv := &server{store: st, trusted: trusted, cfg: cfg}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", httpx.Healthz)
	if metricsHandler != nil {
		mux.Handle("/metrics", metricsHandler)
	}
	mux.HandleFunc("/v1/reports", srv.handleReports)
	return httpx.Logging(mux, rec)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// reject answers the client and records why, so a 400 in the access log is
// always explainable without reproducing the request.
func reject(w http.ResponseWriter, r *http.Request, status int, msg string, attrs ...any) {
	slog.Debug("sizing request rejected",
		append([]any{"status", status, "reason", msg, "remote_addr", r.RemoteAddr}, attrs...)...)
	writeError(w, status, msg)
}
