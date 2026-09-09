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
	"io"
	"log/slog"
	"net/http"
	"strconv"

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
}

type server struct {
	queue   Publisher
	store   Store
	trusted httpx.TrustedProxies
	cfg     Config
}

// NewServer builds insightsd's ingest and read API.
func NewServer(q Publisher, st Store, trusted httpx.TrustedProxies, cfg Config) http.Handler {
	srv := &server{queue: q, store: st, trusted: trusted, cfg: cfg}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", httpx.Healthz)
	mux.HandleFunc("/v1/bundles", srv.handleBundles)
	mux.HandleFunc("/v1/findings", srv.handleFindings)
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
	slog.Debug("bundle rejected",
		append([]any{"status", status, "reason", msg, "remote_addr", r.RemoteAddr}, attrs...)...)
	writeError(w, status, msg)
}

const maxBundleSize = 8 << 20 // 8 MiB

func (s *server) handleBundles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	authenticatedSystemID, err := httpx.SystemID(r, s.trusted)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var reader io.Reader = io.LimitReader(r.Body, maxBundleSize)
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(reader)
		if err != nil {
			reject(w, r, http.StatusBadRequest, "invalid gzip body", "error", err.Error())
			return
		}
		defer gz.Close()
		reader = gz
	}

	var b model.Bundle
	if err := json.NewDecoder(reader).Decode(&b); err != nil {
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
	if len(b.Templates) > 1000 {
		reject(w, r, http.StatusBadRequest, "too many templates", "templates", len(b.Templates))
		return
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
