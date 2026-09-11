// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package logs serves insightsd's client API: masked log bundles in
// (queued for asynchronous analysis, never analysed on the request goroutine),
// findings out.
//
// Authentication happens at the proxy: Traefik's forwardAuth middleware calls
// authd, and only a request it approved reaches this process. The
// Authorization header still arrives untouched, so the system identity is
// read from it here -- see httpx.SystemID, whose trusted-proxy check is what
// makes that safe.
package logs

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/platform/httpx"
)

// Publisher accepts a validated bundle for later analysis. Ingest answers as
// soon as Publish returns: the client is told whether the bundle was accepted,
// never how the analysis went. An LLM call outliving the client's timeout must
// not turn into a lost window.
type Publisher interface {
	Publish(b model.Bundle) error
}

// Store is the slice of logsstore.Store this package needs -- just the read
// path behind /v1/findings, so the handler is testable with a small fake
// instead of the whole store. *logsstore.Store satisfies it.
type Store interface {
	ListFindings(ctx context.Context, systemID string, since int64, status string) ([]model.Finding, error)
}

// Config carries the ingest-time module/service exclusion sets.
//
// excludeModules names modules dropped from every bundle before it is
// queued, and excludeServices names syslog identifiers dropped the same way.
// See model.Bundle.ExcludeModules for why this is applied here, in the
// handler, and not deeper in the pipeline: the gate, the prompt,
// system_templates and module_baselines all read from what is queued, so
// none of them can disagree about which modules are in scope.
type Config struct {
	ExcludeModules  map[string]bool
	ExcludeServices map[string]bool

	// Now is the injected clock the future-window and window-age checks read
	// -- never a direct time.Now() in validation logic, so both can be driven
	// deterministically in tests. Defaults to time.Now in NewServer, so no
	// caller has to set it.
	Now func() time.Time
}

type server struct {
	queue   Publisher
	store   Store
	trusted httpx.TrustedProxies
	cfg     Config
}

// NewServer builds insightsd's ingest and read API. metricsHandler is
// mounted at /metrics next to /healthz -- nil skips it, which only tests
// exercise; every real binary supplies internal/platform/metrics.Handler.
// rec is fed every completed request's method/route/status/duration; nil is
// valid and simply skips metrics -- see httpx.MetricsRecorder.
func NewServer(q Publisher, st Store, trusted httpx.TrustedProxies, cfg Config, metricsHandler http.Handler, rec httpx.MetricsRecorder) http.Handler {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	srv := &server{queue: q, store: st, trusted: trusted, cfg: cfg}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", httpx.Healthz)
	if metricsHandler != nil {
		mux.Handle("/metrics", metricsHandler)
	}
	mux.HandleFunc("/v1/bundles", srv.handleBundles)
	mux.HandleFunc("/v1/findings", srv.handleFindings)
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
	slog.Debug("bundle rejected",
		append([]any{"status", status, "reason", msg, "remote_addr", r.RemoteAddr}, attrs...)...)
	writeError(w, status, msg)
}

// maxCompressedBundleSize bounds what is read off the socket; maxBundleSize
// bounds the JSON the decoder sees after gunzip. Two numbers because the
// ratio between them is the whole point: 30 MiB of bundle JSON is roughly
// 3 MiB gzipped, so the raw cap leaves ample headroom for a legitimate
// bundle while refusing to stream an unbounded compressed body.
const (
	maxCompressedBundleSize = 8 << 20  // 8 MiB, compressed
	maxBundleSize           = 30 << 20 // 30 MiB, decoded
)

// The per-array ceilings. The byte caps above bound the body but not the
// work a body implies: ~700k digest entries fit inside 30 MiB of JSON and
// compress to well under 8 MiB, and each one costs UpsertBaselines a SELECT
// plus an INSERT inside a single transaction holding the process-wide write
// mutex on a one-connection database, plus a line in the prompt. So every
// repeated array is capped by count as well.
//
// All three share one number because there is no reason for them to differ:
// a real multi-module node was measured at 587 digest buckets, so 1000 is
// ample for each, and one ceiling is one thing to remember. A bundle over
// any of them is rejected rather than truncated -- unlike threat and sizing
// ingest, which truncate, because a rejected bundle is re-sent by an edge
// that still holds the window, while a silently trimmed one would make the
// gate reason about a window the server only partly received.
const (
	maxTemplates        = 1000
	maxDigestEntries    = 1000
	maxTruncatedModules = 1000
)

func (s *server) handleBundles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	authenticatedSystemID, err := httpx.SystemID(r, s.trusted)
	if err != nil {
		slog.Debug("unauthorized", "error", err, "remote_addr", r.RemoteAddr)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// The cap that matters is on the DECODED stream. A LimitReader on r.Body
	// alone bounds only the compressed bytes: gunzip is then free to expand
	// them without limit, and a few MiB of gzipped whitespace becomes
	// gigabytes of JSON fed straight to the decoder before a single field is
	// validated. So both sides are capped -- the raw body, which is what is
	// read off the socket, and the decompressed stream the decoder actually
	// reads. http.MaxBytesReader rather than io.LimitReader because it
	// reports the overrun as *http.MaxBytesError instead of silently
	// truncating into a confusing "invalid json body".
	r.Body = http.MaxBytesReader(w, r.Body, maxCompressedBundleSize)
	var reader io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(reader)
		if err != nil {
			reject(w, r, http.StatusBadRequest, "invalid gzip body", "error", err.Error())
			return
		}
		defer func() { _ = gz.Close() }()
		reader = http.MaxBytesReader(w, io.NopCloser(gz), maxBundleSize)
	}

	var b model.Bundle
	if err := json.NewDecoder(reader).Decode(&b); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			reject(w, r, http.StatusRequestEntityTooLarge, "bundle too large",
				"limit", tooBig.Limit, "content_length", r.ContentLength)
			return
		}
		reject(w, r, http.StatusBadRequest, "invalid json body",
			"error", err.Error(), "content_length", r.ContentLength)
		return
	}

	if b.SchemaVersion != model.SchemaVersion {
		reject(w, r, http.StatusBadRequest, "unsupported schema_version",
			"got", b.SchemaVersion, "want", model.SchemaVersion)
		return
	}
	if b.SystemID == "" {
		reject(w, r, http.StatusBadRequest, "system_id required")
		return
	}
	if b.SystemID != authenticatedSystemID {
		reject(w, r, http.StatusForbidden, "system_id does not match authenticated system",
			"bundle_system_id", b.SystemID, "authenticated_system_id", authenticatedSystemID)
		return
	}
	if b.Window.End <= b.Window.Start {
		reject(w, r, http.StatusBadRequest, "window.end must be greater than window.start",
			"window_start", b.Window.Start, "window_end", b.Window.End)
		return
	}

	nowMillis := s.cfg.Now().UnixMilli()
	if b.Window.End > nowMillis {
		reject(w, r, http.StatusBadRequest, "window.end is in the future",
			"window_end", b.Window.End, "now", nowMillis)
		return
	}
	// §5.4: 6 hours, not 1 -- this is the room the edge needs to retry a
	// bundle across several failed send cycles (a network blip, a server
	// restart, a queue at capacity) without the server discarding data the
	// edge eventually manages to deliver. Do not tighten this without
	// re-reading that section: a smaller window trades recovered data for no
	// benefit the spec identifies.
	const maxWindowAge = 6 * time.Hour
	if cutoff := nowMillis - maxWindowAge.Milliseconds(); b.Window.Start < cutoff {
		reject(w, r, http.StatusBadRequest, "window.start is older than the acceptance window",
			"window_start", b.Window.Start, "cutoff", cutoff)
		return
	}

	if len(b.Templates) > maxTemplates {
		reject(w, r, http.StatusBadRequest, "too many templates", "templates", len(b.Templates))
		return
	}
	if len(b.Digest) > maxDigestEntries {
		reject(w, r, http.StatusBadRequest, "too many digest entries", "digest_entries", len(b.Digest))
		return
	}
	if len(b.Budget.TruncatedModules) > maxTruncatedModules {
		reject(w, r, http.StatusBadRequest, "too many truncation records",
			"truncated_modules", len(b.Budget.TruncatedModules))
		return
	}
	for _, t := range b.Templates {
		if len(t.Samples) > 2 {
			reject(w, r, http.StatusBadRequest, "too many samples for template",
				"module_id", t.ModuleID, "samples", len(t.Samples))
			return
		}
	}

	// Strip modules that own a dedicated pipeline before anything else sees
	// the bundle. Doing it here rather than in the analyzer keeps it to one
	// place: the gate, the prompt, system_templates and module_baselines all
	// read from what is queued, so none of them can disagree about which
	// modules are in scope.
	receivedTemplates, receivedDigest := len(b.Templates), len(b.Digest)
	b = b.ExcludeModules(s.cfg.ExcludeModules)
	b = b.ExcludeServices(s.cfg.ExcludeServices)

	slog.Debug("bundle accepted for analysis",
		"system_id", b.SystemID,
		"window_start", b.Window.Start,
		"window_end", b.Window.End,
		"templates", len(b.Templates),
		"digest_entries", len(b.Digest),
		"templates_received", receivedTemplates,
		"digest_entries_received", receivedDigest,
		"collector_version", b.CollectorVersion,
		"lines_seen", b.Budget.LinesSeen,
		"lines_kept", b.Budget.LinesKept,
	)

	// Analysis is asynchronous: the only thing the client learns is whether
	// the bundle was taken. Anything else would make the edge's HTTP timeout
	// decide the fate of a window.
	if err := s.queue.Publish(b); err != nil {
		reject(w, r, http.StatusServiceUnavailable, "temporarily unavailable",
			"system_id", b.SystemID, "error", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]bool{"accepted": true})
}

func (s *server) handleFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	authenticatedSystemID, err := httpx.SystemID(r, s.trusted)
	if err != nil {
		slog.Debug("unauthorized", "error", err, "remote_addr", r.RemoteAddr)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var since int64
	if v := r.URL.Query().Get("since"); v != "" {
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid since parameter")
			return
		}
		since = parsed
	}
	status := r.URL.Query().Get("status")

	findings, err := s.store.ListFindings(r.Context(), authenticatedSystemID, since, status)
	if err != nil {
		slog.Error("list findings failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily unavailable")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string][]model.Finding{"findings": findings})
}
