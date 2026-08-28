// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package admin serves the allowlist admin API: bearer-key authenticated
// writes to the threat_allowlist table and the request/review/audit tables
// layered on top of it, on its own listener (ADMIN_LISTEN_ADDR).
//
// It is a new, separate package rather than a few more handlers on
// internal/api's mux, deliberately: the public ingest surface and the admin
// surface must never be able to accidentally share a route table. The two
// packages share only the store.
//
// This surface is registered at all only when cmd/insightsd is given both
// ADMIN_API_KEY and a non-empty listen address -- there is never a default
// credential, so an operator who configures neither gets a plain 404
// (the listener never starts) rather than a live surface nobody meant to
// expose.
package admin

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/threat"
)

// BearerAuth validates the admin API key from an
// `Authorization: Bearer <key>` header, comparing in constant time.
//
// This is a distinct type from api.StaticAuth (HTTP Basic, edge
// credentials) on purpose: the admin plane authenticates differently from
// the edge plane, and giving it its own type is what stops the two ever
// sharing a comparison code path by accident.
type BearerAuth struct {
	Key string
}

func (a BearerAuth) valid(header string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	presented := strings.TrimPrefix(header, prefix)
	// The key is never empty here -- NewServer's caller (cmd/insightsd) never
	// constructs this package when ADMIN_API_KEY is unset -- but comparing in
	// constant time regardless costs nothing and removes any doubt.
	return subtle.ConstantTimeCompare([]byte(presented), []byte(a.Key)) == 1
}

type server struct {
	store AllowlistStore
	auth  BearerAuth
	now   func() int64
}

// NewServer builds the admin API handler. key must be non-empty; the caller
// is responsible for never calling this with an empty key (see the package
// doc comment) -- an empty key here would make BearerAuth.valid compare
// against "", which a request with no Authorization header would also
// present as, turning "no key configured" into "wide open" instead of
// "absent".
func NewServer(store AllowlistStore, key string, now func() int64) http.Handler {
	if now == nil {
		now = func() int64 { return time.Now().UnixMilli() }
	}
	srv := &server{store: store, auth: BearerAuth{Key: key}, now: now}

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/v1/allowlist", srv.handleAllowlist)
	mux.HandleFunc("/admin/v1/allowlist/requests", srv.handleRequests)
	mux.HandleFunc("/admin/v1/allowlist/requests/approve", srv.handleApprove)
	mux.HandleFunc("/admin/v1/allowlist/requests/reject", srv.handleReject)
	mux.HandleFunc("/admin/v1/allowlist/audit", srv.handleAudit)

	return &loggingHandler{next: mux}
}

// authenticate checks the bearer key. It is applied to every route,
// including reads: unlike the operator UI (which is deliberately readable
// by anyone on the network it is bound to), this listener has no
// unauthenticated half.
func (s *server) authenticate(w http.ResponseWriter, r *http.Request) bool {
	if !s.auth.valid(r.Header.Get("Authorization")) {
		writeJSONError(w, http.StatusUnauthorized, "invalid or missing admin API key")
		return false
	}
	return true
}

// actor extracts and sanitizes X-Admin-Actor. It is required, and empty, on
// every write -- a shared bearer key has no attribution of its own, so
// "the allowlist changed" is useless without "who" (see decision 3 in
// docs/plans/2026-08-28-allowlist-management.md). It is not a security
// control: anyone holding the key can claim any name.
func actor(r *http.Request) (string, bool) {
	a := threat.CleanText(r.Header.Get("X-Admin-Actor"), model.MaxAdminActorLen)
	return a, a != ""
}

func requireActor(w http.ResponseWriter, r *http.Request) (string, bool) {
	act, ok := actor(r)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "X-Admin-Actor header is required")
		return "", false
	}
	return act, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// --- logging ---
//
// Copied from internal/api and internal/ui rather than imported from
// either: this package must not depend on api (a shared route table is
// exactly what splitting it out avoids) or on ui.

type loggingHandler struct {
	next http.Handler
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// ServeHTTP logs method, path, status and duration, but NEVER the
// Authorization header (the bearer key) -- the same rule internal/api's
// logging handler follows for the edge's Basic credentials. X-Admin-Actor is
// not a secret and is safe to log; it is not logged here only because
// per-route handlers already do, once they have validated it.
func (h *loggingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	slog.Debug("admin request received",
		"method", r.Method,
		"path", r.URL.Path,
		"query", r.URL.RawQuery,
		"remote_addr", r.RemoteAddr,
		"has_authorization", r.Header.Get("Authorization") != "",
	)

	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	h.next.ServeHTTP(rec, r)

	slog.Info("admin request",
		"method", r.Method,
		"path", r.URL.Path,
		"status", rec.status,
		"duration_ms", time.Since(start).Milliseconds(),
	)
}
