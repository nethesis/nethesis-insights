// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package httpx

import (
	"log/slog"
	"net/http"
	"time"
)

// statusRecorder captures the status code a handler wrote, so it can be
// logged after the fact.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Logging wraps next to log method, path, status and duration for every
// request, but NEVER the Authorization header.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		next.ServeHTTP(rec, r)

		// A client that hung up mid-request is worth naming: it looks
		// identical to a server fault in the status line alone.
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
	})
}
