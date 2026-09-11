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

// MetricsRecorder observes one completed HTTP request: method, the matched
// route (see RouteLabel -- never a raw path), the response status and how
// long it took. Declared here, narrow, so this package needs no dependency
// on prometheus; *metrics.HTTP satisfies it. A nil MetricsRecorder is valid
// and simply skips metrics -- every UI mux passes nil today, since only the
// four binaries' API muxes carry a /metrics endpoint.
type MetricsRecorder interface {
	Observe(method, route string, status int, duration time.Duration)
}

// RouteLabel is the metrics label for a request: the ServeMux pattern that
// matched (net/http populates Request.Pattern for every pattern-based
// ServeMux match, including a plain unmethod-prefixed pattern like
// "/v1/bundles"), or "unmatched" when nothing did -- a 404. Every mux in
// this codebase registers a small, fixed set of patterns, so this is always
// low-cardinality: never r.URL.Path, which an attacker or a typo can make
// unbounded.
func RouteLabel(r *http.Request) string {
	if r.Pattern != "" {
		return r.Pattern
	}
	return "unmatched"
}

// Logging wraps next to log method, path, status and duration for every
// request, but NEVER the Authorization header. When rec is non-nil, it also
// feeds it the same status/duration this logs, labeled by RouteLabel rather
// than the raw path.
func Logging(next http.Handler, rec MetricsRecorder) http.Handler {
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

		rec2 := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec2, r)
		duration := time.Since(start)

		// A client that hung up mid-request is worth naming: it looks
		// identical to a server fault in the status line alone.
		if err := r.Context().Err(); err != nil {
			slog.Debug("client disconnected before the response completed",
				"method", r.Method, "path", r.URL.Path, "error", err)
		}

		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec2.status,
			"duration_ms", duration.Milliseconds(),
		)

		if rec != nil {
			rec.Observe(r.Method, RouteLabel(r), rec2.status, duration)
		}
	})
}
