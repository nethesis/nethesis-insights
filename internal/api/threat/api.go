// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package threat serves Threat Shield's client API: CrowdSec ban decisions
// in, the fleet-consensus blocklist out, and the allowlist review queue.
//
// Authentication happens at the proxy: Traefik's forwardAuth middleware
// calls authd, and only a request it approved reaches this process. The
// Authorization header still arrives untouched, so the system identity is
// read from it here -- see httpx.SystemID, whose trusted-proxy check is what
// makes that safe.
package threat

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/nethesis/nethesis-insights/internal/blocklist"
	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/platform/httpx"
)

// Store is the slice of threatstore.Store this package needs. Declared here,
// narrow, so the handlers are testable with a small fake instead of the
// whole store -- the same idiom as internal/ui's Reader/Writer.
// *threatstore.Store satisfies it.
type Store interface {
	InsertThreatEvents(ctx context.Context, systemID string, ev []model.ThreatEvent) (inserted, duplicates int, err error)
	RecordIngestCounters(ctx context.Context, day, systemID string, c model.ThreatCounters, duplicates int) error
	UpsertAllowlistRequest(ctx context.Context, cidr, systemID, reason string, now int64) (distinctSystems int, err error)
}

type server struct {
	store   Store
	snap    *blocklist.Snapshot
	trusted httpx.TrustedProxies
	cfg     Config
}

// Config carries the ingest bounds and the injectable clock. MaxDecisions
// truncates rather than rejects: a batch over the cap loses its tail, never
// the whole report.
type Config struct {
	MaxDecisions int
	Now          func() int64
}

func defaultNow() int64 { return time.Now().UnixMilli() }

func NewServer(st Store, snap *blocklist.Snapshot, trusted httpx.TrustedProxies, cfg Config) http.Handler {
	if cfg.Now == nil {
		cfg.Now = defaultNow
	}
	srv := &server{store: st, snap: snap, trusted: trusted, cfg: cfg}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", httpx.Healthz)
	mux.HandleFunc("/v1/events", srv.handleEvents)
	mux.HandleFunc("/v1/feed", srv.handleFeed)
	mux.HandleFunc("/v1/allowlist-requests", srv.handleAllowlistRequest)
	return httpx.Logging(mux)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// reject answers the client and records why, so a 400 in the access log is
// always explainable without reproducing the request.
func reject(w http.ResponseWriter, r *http.Request, status int, msg string, attrs ...any) {
	slog.Debug("threat request rejected",
		append([]any{"status", status, "reason", msg, "remote_addr", r.RemoteAddr}, attrs...)...)
	writeError(w, status, msg)
}
