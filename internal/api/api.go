// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"compress/gzip"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/store"
)

// ErrInvalidCredentials is returned by Authenticator.Validate on mismatch.
var ErrInvalidCredentials = errors.New("invalid credentials")

type Authenticator interface {
	Validate(ctx context.Context, authHeader string) (systemID string, err error)
}

// StaticAuth validates a single hardcoded system id / secret pair using
// HTTP Basic auth, comparing both sides in constant time.
type StaticAuth struct {
	SystemID string
	Secret   string
}

// Validate wraps ErrInvalidCredentials with the reason it failed. The reason
// is for debug logs only -- the HTTP response stays a bare 401 -- and it
// never carries the presented secret, only which half did not match.
func (a StaticAuth) Validate(ctx context.Context, authHeader string) (string, error) {
	const prefix = "Basic "
	if authHeader == "" {
		return "", fmt.Errorf("%w: no Authorization header", ErrInvalidCredentials)
	}
	if !strings.HasPrefix(authHeader, prefix) {
		scheme, _, _ := strings.Cut(authHeader, " ")
		return "", fmt.Errorf("%w: scheme is %q, want Basic", ErrInvalidCredentials, scheme)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, prefix))
	if err != nil {
		return "", fmt.Errorf("%w: credentials are not valid base64", ErrInvalidCredentials)
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("%w: credentials are not system_id:secret", ErrInvalidCredentials)
	}
	systemID, secret := parts[0], parts[1]

	systemMatch := subtle.ConstantTimeCompare([]byte(systemID), []byte(a.SystemID)) == 1
	secretMatch := subtle.ConstantTimeCompare([]byte(secret), []byte(a.Secret)) == 1
	switch {
	case !systemMatch && !secretMatch:
		return "", fmt.Errorf("%w: system_id %q unknown and secret mismatch", ErrInvalidCredentials, systemID)
	case !systemMatch:
		return "", fmt.Errorf("%w: system_id %q does not match the configured one", ErrInvalidCredentials, systemID)
	case !secretMatch:
		return "", fmt.Errorf("%w: secret mismatch for system_id %q", ErrInvalidCredentials, systemID)
	}
	return systemID, nil
}

// Publisher accepts a validated bundle for later analysis. Ingest answers as
// soon as Publish returns: the client is told whether the bundle was accepted,
// never how the analysis went. An LLM call outliving the client's timeout must
// not turn into a lost window.
type Publisher interface {
	Publish(b model.Bundle) error
}

type server struct {
	queue Publisher
	store store.Store
	auth  Authenticator
	mux   *http.ServeMux
}

func NewServer(q Publisher, s store.Store, auth Authenticator) http.Handler {
	srv := &server{queue: q, store: s, auth: auth}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/bundles", srv.handleBundles)
	mux.HandleFunc("/v1/findings", srv.handleFindings)
	mux.HandleFunc("/healthz", srv.handleHealthz)
	srv.mux = mux
	return &loggingHandler{next: mux}
}

// loggingHandler logs method, path, status and duration for every request,
// but NEVER the Authorization header.
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

func (h *loggingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	slog.Debug("request received",
		"method", r.Method,
		"path", r.URL.Path,
		"query", r.URL.RawQuery,
		"remote_addr", r.RemoteAddr,
		"forwarded_for", r.Header.Get("X-Forwarded-For"),
		"user_agent", r.UserAgent(),
		"content_length", r.ContentLength,
		"content_encoding", r.Header.Get("Content-Encoding"),
		"has_authorization", r.Header.Get("Authorization") != "",
	)

	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	h.next.ServeHTTP(rec, r)

	// A client that hung up mid-request is worth naming: it looks identical
	// to a server fault in the status line alone.
	if err := r.Context().Err(); err != nil {
		slog.Debug("client disconnected before the response completed",
			"method", r.Method, "path", r.URL.Path, "error", err)
	}

	slog.Info("request",
		"method", r.Method,
		"path", r.URL.Path,
		"status", rec.status,
		"duration_ms", time.Since(start).Milliseconds(),
	)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (s *server) authenticate(w http.ResponseWriter, r *http.Request) (string, bool) {
	systemID, err := s.auth.Validate(r.Context(), r.Header.Get("Authorization"))
	if err != nil {
		// The client only ever learns "invalid credentials"; the operator
		// gets the reason in the debug log.
		slog.Debug("authentication rejected",
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
			"reason", err.Error(),
		)
		writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
		return "", false
	}
	slog.Debug("authenticated", "system_id", systemID, "path", r.URL.Path)
	return systemID, true
}

// reject answers the client and records why, so a 400 in the access log is
// always explainable without reproducing the request.
func reject(w http.ResponseWriter, r *http.Request, status int, msg string, attrs ...any) {
	slog.Debug("bundle rejected",
		append([]any{"status", status, "reason", msg, "remote_addr", r.RemoteAddr}, attrs...)...)
	writeJSONError(w, status, msg)
}

const maxBundleSize = 8 << 20 // 8 MiB

func (s *server) handleBundles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	authenticatedSystemID, ok := s.authenticate(w, r)
	if !ok {
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

	slog.Debug("bundle accepted for analysis",
		"system_id", b.SystemID,
		"window_start", b.Window.Start,
		"window_end", b.Window.End,
		"templates", len(b.Templates),
		"digest_entries", len(b.Digest),
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
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	authenticatedSystemID, ok := s.authenticate(w, r)
	if !ok {
		return
	}

	var since int64
	if v := r.URL.Query().Get("since"); v != "" {
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid since parameter")
			return
		}
		since = parsed
	}
	status := r.URL.Query().Get("status")

	findings, err := s.store.ListFindings(r.Context(), authenticatedSystemID, since, status)
	if err != nil {
		slog.Error("list findings failed", "error", err)
		writeJSONError(w, http.StatusServiceUnavailable, "temporarily unavailable")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string][]model.Finding{"findings": findings})
}

func (s *server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
