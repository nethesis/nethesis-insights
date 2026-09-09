// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/nethesis/nethesis-insights/internal/platform/auth"
	"github.com/nethesis/nethesis-insights/internal/platform/httpx"
)

// validator is the half of auth.ForwardAuth this binary uses, declared here
// so the handler tests need no network and no cache.
type validator interface {
	Validate(ctx context.Context, authHeader string) (string, error)
}

// newHandler builds authd's mux.
//
// GET /auth is Traefik's forwardAuth address. Traefik forwards the client's
// original request headers here, expects 2xx to mean "let it through", and
// passes any other status straight back to the client -- which is what keeps
// this service's 401/503 distinction visible at the edge.
func newHandler(v validator) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", httpx.Healthz)
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if header == "" {
			unauthorized(w)
			return
		}

		_, err := v.Validate(r.Context(), header)
		switch {
		case err == nil:
			w.WriteHeader(http.StatusOK)
		case errors.Is(err, auth.ErrInvalidCredentials):
			// err, not a system_id: every ErrInvalidCredentials path in
			// internal/platform/auth returns "" as the first value, so
			// logging system_id here would read as an empty id on every
			// rejection. err carries the actual reason and never the
			// secret -- every format string in that package interpolates
			// only the system id and the auth scheme.
			slog.Info("authd: rejected", "err", err, "remote_addr", r.RemoteAddr)
			unauthorized(w)
		case errors.Is(err, auth.ErrUnavailable):
			// Fail closed, but distinctly: the edge retries a 503 and gives
			// up on a 401.
			slog.Warn("authd: validator unavailable", "remote_addr", r.RemoteAddr)
			http.Error(w, "validator unavailable", http.StatusServiceUnavailable)
		default:
			slog.Error("authd: unexpected validate error", "err", err)
			http.Error(w, "validator unavailable", http.StatusServiceUnavailable)
		}
	})
	return httpx.Logging(mux)
}

// unauthorized answers without a WWW-Authenticate challenge: the client is a
// reporter with a configured credential, not a browser to prompt, and the
// challenge would only add a round trip.
func unauthorized(w http.ResponseWriter) {
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
