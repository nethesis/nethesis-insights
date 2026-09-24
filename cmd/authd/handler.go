// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"

	"github.com/nethesis/nethesis-insights/internal/platform/auth"
	"github.com/nethesis/nethesis-insights/internal/platform/httpx"
)

// validator is the half of auth.ForwardAuth this binary uses, declared here
// so the handler tests need no network and no cache. service is "" for the
// plain subscription check and a service name for an entitlement check --
// see auth.ForwardAuth.Validate.
type validator interface {
	Validate(ctx context.Context, authHeader, service string) (string, error)
}

// serviceName is the closed charset for the {service} path segment:
// lowercase alphanumerics and inner dashes, bounded in length. The segment
// becomes a path component of a request to AUTH_VALIDATE_URL, so it is
// checked here, at the only place a service name is derived from something
// outside this process, rather than trusted because the proxy is the only
// caller that can reach this port.
//
// It is a charset rule and deliberately not a list of known entitlements:
// adding one upstream should be a line of Traefik config, not a release of
// this binary. An unknown name simply fails upstream, which is the correct
// place for that verdict.
var serviceName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)

// newHandler builds authd's mux.
//
// GET /auth is Traefik's forwardAuth address. Traefik forwards the client's
// original request headers here, expects 2xx to mean "let it through", and
// passes any other status straight back to the client -- which is what keeps
// this service's 401/403/503 distinction visible at the edge.
//
// GET /auth/service/{service} is the same check plus a named entitlement:
// the proxy points a route's forwardAuth at it when a subscription alone is
// not enough to use that route. Threat Shield is the first user -- every
// subscriber reports events through /auth, but only a node carrying the
// ng-blacklist entitlement may fetch the feed or ask for an allowlist entry.
// Both routes share one cache and one upstream; only the URL and the cache
// key differ (auth.ForwardAuth.Validate).
//
// metricsHandler is mounted at /metrics next to /healthz -- nil skips it,
// which only tests exercise. rec is fed every completed request's
// method/route/status/duration; nil is valid and simply skips metrics -- see
// httpx.MetricsRecorder.
func newHandler(v validator, metricsHandler http.Handler, rec httpx.MetricsRecorder) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", httpx.Healthz)
	if metricsHandler != nil {
		mux.Handle("/metrics", metricsHandler)
	}
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		validate(w, r, v, "")
	})
	mux.HandleFunc("/auth/service/{service}", func(w http.ResponseWriter, r *http.Request) {
		service := r.PathValue("service")
		if !serviceName.MatchString(service) {
			// 404, not 400 or 401: a name this handler will not accept is
			// our own proxy configuration being wrong, not a verdict on the
			// caller's credential, and it must not cost an upstream call to
			// discover. The name is not echoed -- it would be reflected
			// straight into Traefik's access log.
			http.NotFound(w, r)
			return
		}
		validate(w, r, v, service)
	})
	return httpx.Logging(mux, rec)
}

// validate is the body both auth routes share: reject a missing header
// locally, then map the validator's verdict onto the status Traefik will
// hand back to the node.
func validate(w http.ResponseWriter, r *http.Request, v validator, service string) {
	header := r.Header.Get("Authorization")
	if header == "" {
		unauthorized(w)
		return
	}

	_, err := v.Validate(r.Context(), header, service)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusOK)
	case errors.Is(err, auth.ErrInvalidCredentials):
		// err, not a system_id: every ErrInvalidCredentials path in
		// internal/platform/auth returns "" as the first value, so
		// logging system_id here would read as an empty id on every
		// rejection. err carries the reason and never the secret --
		// no format string in that package interpolates any part of
		// the Authorization header. It once interpolated the "scheme",
		// which strings.Cut reports as the entire header when there is
		// no delimiter, and this line therefore logged live fleet
		// credentials in plaintext; auth.ParseBasic now names the
		// failure without copying header content, and
		// TestParseBasicErrorNeverCarriesTheCredential fails loudly if
		// anyone reintroduces the interpolation.
		slog.Info("authd: rejected", "err", err, "remote_addr", r.RemoteAddr)
		unauthorized(w)
	case errors.Is(err, auth.ErrForbidden):
		// Authenticated, but not entitled. 403 rather than 401 so the
		// node's administrator is pointed at the missing entitlement
		// instead of at a credential that is working perfectly -- see
		// auth.ErrForbidden. err names the service and the system_id and
		// never the secret, same rule as above.
		slog.Info("authd: not entitled", "err", err, "remote_addr", r.RemoteAddr)
		http.Error(w, "forbidden", http.StatusForbidden)
	case errors.Is(err, auth.ErrUnavailable):
		// Fail closed, but distinctly: the edge retries a 503 and gives
		// up on a 401. err names the upstream status when there was one (or
		// says there was none, for a transport error) and, for a redirect,
		// its target -- never a query string or the Authorization header --
		// so AUTH_VALIDATE_URL configured with the wrong scheme, or a
		// trailing-slash mismatch, does not read exactly like a genuine
		// outage. See internal/platform/auth's unavailableErr.
		slog.Warn("authd: validator unavailable", "err", err, "remote_addr", r.RemoteAddr)
		http.Error(w, "validator unavailable", http.StatusServiceUnavailable)
	default:
		slog.Error("authd: unexpected validate error", "err", err)
		http.Error(w, "validator unavailable", http.StatusServiceUnavailable)
	}
}

// unauthorized answers without a WWW-Authenticate challenge: the client is a
// reporter with a configured credential, not a browser to prompt, and the
// challenge would only add a round trip.
func unauthorized(w http.ResponseWriter) {
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
