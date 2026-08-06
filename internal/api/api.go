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
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nethesis/nethesis-insights/internal/analyzer"
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

func (a StaticAuth) Validate(ctx context.Context, authHeader string) (string, error) {
	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", ErrInvalidCredentials
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, prefix))
	if err != nil {
		return "", ErrInvalidCredentials
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", ErrInvalidCredentials
	}
	systemID, secret := parts[0], parts[1]

	systemMatch := subtle.ConstantTimeCompare([]byte(systemID), []byte(a.SystemID)) == 1
	secretMatch := subtle.ConstantTimeCompare([]byte(secret), []byte(a.Secret)) == 1
	if !systemMatch || !secretMatch {
		return "", ErrInvalidCredentials
	}
	return systemID, nil
}

type server struct {
	analyzer *analyzer.Analyzer
	store    store.Store
	auth     Authenticator
	mux      *http.ServeMux
}

func NewServer(a *analyzer.Analyzer, s store.Store, auth Authenticator) http.Handler {
	srv := &server{analyzer: a, store: s, auth: auth}
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
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	h.next.ServeHTTP(rec, r)
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
		writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
		return "", false
	}
	return systemID, true
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
			writeJSONError(w, http.StatusBadRequest, "invalid gzip body")
			return
		}
		defer gz.Close()
		reader = gz
	}

	var b model.Bundle
	if err := json.NewDecoder(reader).Decode(&b); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json body")
		return
	}

	if b.SchemaVersion != model.SchemaVersion {
		writeJSONError(w, http.StatusBadRequest, "unsupported schema_version")
		return
	}
	if b.SystemID == "" {
		writeJSONError(w, http.StatusBadRequest, "system_id required")
		return
	}
	if b.SystemID != authenticatedSystemID {
		writeJSONError(w, http.StatusForbidden, "system_id does not match authenticated system")
		return
	}
	if b.Window.End <= b.Window.Start {
		writeJSONError(w, http.StatusBadRequest, "window.end must be greater than window.start")
		return
	}
	if len(b.Templates) > 1000 {
		writeJSONError(w, http.StatusBadRequest, "too many templates")
		return
	}

	err := s.analyzer.Process(r.Context(), b)
	switch {
	case err == nil:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]bool{"accepted": true})
	case errors.Is(err, analyzer.ErrPermanent):
		writeJSONError(w, http.StatusUnprocessableEntity, "bundle could not be processed")
	default:
		slog.Error("bundle processing failed", "error", err)
		writeJSONError(w, http.StatusServiceUnavailable, "temporarily unavailable")
	}
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
