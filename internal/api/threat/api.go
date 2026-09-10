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
// whole store -- the same idiom as internal/ui/threat's Reader/Writer.
// *threatstore.Store satisfies it.
type Store interface {
	InsertThreatEvents(ctx context.Context, systemID string, ev []model.ThreatEvent) (inserted, duplicates int, err error)
	RecordIngestCounters(ctx context.Context, day, systemID string, c model.ThreatCounters, duplicates int) error
	UpsertAllowlistRequest(ctx context.Context, cidr, systemID, reason string, now int64, maxPerSystem int) (distinctSystems int, err error)
}

// Work is one accepted, sanitized threat-events batch queued for storage.
// handleEvents builds it after threat.Sanitize has already run, so the
// queue only ever holds clean events -- never a raw report.
type Work struct {
	SystemID string
	Events   []model.ThreatEvent
	Counters model.ThreatCounters
	Day      string
}

// Publisher accepts an accepted batch for asynchronous storage. Ingest
// answers as soon as Publish returns: the client learns only whether the
// batch was taken, never whether it landed, because stored/duplicates are
// post-write facts that cannot survive an asynchronous ingest.
// *ingestq.Queue[Work] satisfies it.
type Publisher interface {
	Publish(w Work) error
}

// NewConsumer returns the queue's handler: the InsertThreatEvents and
// RecordIngestCounters calls handleEvents used to make directly, before this
// task put a queue between them. It is a free function rather than a method
// on server because the queue's handler must be supplied when the queue is
// constructed, and the queue itself is what NewServer takes as a
// parameter -- so cmd/threatd builds the consumer from the same Store before
// either the server or the queue exists.
//
// A crash (or a store error) between Publish returning 202 and this running
// loses the batch, genuinely and without compensation: the reporter is
// alert-driven and already advanced its watermark on the 202, so it will not
// re-send those decisions on its own. The (system_id, attacker_ip, scenario,
// observed_at) unique index only makes a *duplicate* delivery harmless; it
// does not recover a dropped one. This is judged acceptable because
// promotion needs three distinct systems observing the same address, and an
// attacker active enough to matter keeps triggering fresh alerts and fresh
// batches. Because this is the only place such a loss is ever recorded --
// the client already has its 202 -- a failure here logs system_id and the
// event count, not just the bare error, so an operator can at least tell
// whose evidence went missing.
func NewConsumer(st Store) func(context.Context, Work) error {
	return func(ctx context.Context, w Work) error {
		_, duplicates, err := st.InsertThreatEvents(ctx, w.SystemID, w.Events)
		if err != nil {
			slog.Error("insert threat events failed, batch lost",
				"system_id", w.SystemID, "events", len(w.Events), "error", err)
			return err
		}

		// Accounting failures must never lose the work item: the evidence is
		// already stored, and the counters are an operator convenience.
		if err := st.RecordIngestCounters(ctx, w.Day, w.SystemID, w.Counters, duplicates); err != nil {
			slog.Error("record ingest counters failed", "system_id", w.SystemID, "error", err)
		}
		return nil
	}
}

type server struct {
	store   Store
	queue   Publisher
	snap    *blocklist.Snapshot
	trusted httpx.TrustedProxies
	cfg     Config
}

// Config carries the ingest bounds and the injectable clock.
//
// MaxDecisions truncates rather than rejects: a batch over the cap loses
// its tail, never the whole report.
//
// MaxAllowlistRequestsPerSys is the opposite -- it refuses, with a 429 --
// because the two caps bound different things. A threat batch is evidence
// with a short retention that an attacker's next alert re-supplies, so
// dropping its tail costs nearly nothing; a client allowlist request is a
// permanent row in a queue only a human empties, so the cap has to be a
// door rather than a trim. 0 means unlimited.
type Config struct {
	MaxDecisions               int
	MaxAllowlistRequestsPerSys int
	Now                        func() int64
}

func defaultNow() int64 { return time.Now().UnixMilli() }

// NewServer builds threatd's client API. q is not optional: every deployment
// bounds ingest against the single-writer database, so cmd/threatd always
// builds one and there is no synchronous fallback path to leave untested.
func NewServer(st Store, q Publisher, snap *blocklist.Snapshot, trusted httpx.TrustedProxies, cfg Config) http.Handler {
	if cfg.Now == nil {
		cfg.Now = defaultNow
	}
	srv := &server{store: st, queue: q, snap: snap, trusted: trusted, cfg: cfg}

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
