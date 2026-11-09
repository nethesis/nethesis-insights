// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

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
// subscriber reports events through /auth, but only a node carrying its
// client's entitlement (ng-blacklist for NethSecurity,
// crowdsec-advanced-threat-shield for NS8 CrowdSec) may fetch the feed or ask
// for an allowlist entry.
// Both routes share one cache and one upstream; only the URL and the cache
// key differ (auth.ForwardAuth.Validate).
//
// trusted is TRUSTED_PROXY_CIDRS: the forwardAuth headers that say who was
// denied -- X-Forwarded-For, -Method, -Uri -- are believed only from it, and
// only for the denial log line (see logDenial); no answer depends on them.
//
// metricsHandler is mounted at /metrics next to /healthz -- nil skips it,
// which only tests exercise. rec is fed every completed request's
// method/route/status/duration; nil is valid and simply skips metrics -- see
// httpx.MetricsRecorder.
func newHandler(v validator, trusted httpx.TrustedProxies, metricsHandler http.Handler, rec httpx.MetricsRecorder) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", httpx.Healthz)
	if metricsHandler != nil {
		mux.Handle("/metrics", metricsHandler)
	}
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		validate(w, r, v, trusted, "")
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
		validate(w, r, v, trusted, service)
	})
	return httpx.Logging(mux, rec)
}

// validate is the body both auth routes share: reject a missing header
// locally, then map the validator's verdict onto the status Traefik will
// hand back to the node. Every 401 and 403 writes one logDenial line.
func validate(w http.ResponseWriter, r *http.Request, v validator, trusted httpx.TrustedProxies, service string) {
	header := r.Header.Get("Authorization")
	if header == "" {
		logDenial(r, trusted, outcomeUnauthorized, service, errNoHeader)
		unauthorized(w)
		return
	}

	_, err := v.Validate(r.Context(), header, service)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusOK)
	case errors.Is(err, auth.ErrInvalidCredentials):
		// err carries the reason and never the secret -- no format string
		// in internal/platform/auth interpolates any part of the
		// Authorization header beyond the system_id. It once interpolated
		// the "scheme", which strings.Cut reports as the entire header when
		// there is no delimiter, and this line therefore logged live fleet
		// credentials in plaintext; auth.ParseBasic now names the failure
		// without copying header content, and
		// TestParseBasicErrorNeverCarriesTheCredential fails loudly if
		// anyone reintroduces the interpolation.
		logDenial(r, trusted, outcomeUnauthorized, service, err)
		unauthorized(w)
	case errors.Is(err, auth.ErrForbidden):
		// Authenticated, but not entitled. 403 rather than 401 so the
		// node's administrator is pointed at the missing entitlement
		// instead of at a credential that is working perfectly -- see
		// auth.ErrForbidden.
		logDenial(r, trusted, outcomeForbidden, service, err)
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

// The outcome field of a denial line: a 401 and a 403.
const (
	outcomeUnauthorized = "invalid_credentials"
	outcomeForbidden    = "not_entitled"
)

// errNoHeader is the reason logged for a request that carried no
// Authorization header at all, which is rejected without a Validate call.
var errNoHeader = errors.New("no Authorization header")

// Bounds on the client-controlled values a denial line repeats, so a
// caller cannot make one line arbitrarily long.
const (
	maxLoggedSystemID = 128
	maxLoggedPath     = 256
)

// logDenial writes the one line every 401 and 403 produces, so "who was
// refused the feed, from where" is answerable from the journal -- it is the
// only record: authd owns no store, and a denied request never reaches the
// pipeline behind Traefik. scripts/feed-denials.sh reads these lines, so
// the message and the field names are an interface.
//
// The identity is the Basic username and nothing else of the Authorization
// header -- auth.ParseBasic's secret is discarded on the spot. On a 403 the
// credential was genuine, so it is logged as system_id; on a 401 it is
// whatever the caller typed and is logged as claimed_system_id, empty when
// the header could not be parsed at all. Either is capped and quoted by
// slog, so a hostile username cannot forge another field or another line.
//
// method, path and client_addr come from the headers Traefik's forwardAuth
// sends -- X-Forwarded-Method, X-Forwarded-Uri and X-Forwarded-For, the
// last of which Traefik sets to the connection it accepted -- and are
// believed only when the request came from TRUSTED_PROXY_CIDRS; otherwise
// method and path are empty and client_addr is RemoteAddr. path drops the
// query string: nothing denied here needs it, and a query is where a
// misconfigured client would put a token.
func logDenial(r *http.Request, trusted httpx.TrustedProxies, outcome, service string, err error) {
	var claimed string
	if id, _, perr := auth.ParseBasic(r.Header.Get("Authorization")); perr == nil {
		claimed = truncate(id, maxLoggedSystemID)
	}
	idKey := "claimed_system_id"
	if outcome == outcomeForbidden {
		idKey = "system_id"
	}

	var method, path string
	if trusted.Contains(r.RemoteAddr) {
		method = truncate(r.Header.Get("X-Forwarded-Method"), 16)
		path, _, _ = strings.Cut(r.Header.Get("X-Forwarded-Uri"), "?")
		path = truncate(path, maxLoggedPath)
	}

	slog.Info("authd: denied",
		"outcome", outcome,
		idKey, claimed,
		"service", service,
		"method", method,
		"path", path,
		"client_addr", httpx.ClientIP(r, trusted),
		"err", err)
}

// truncate cuts s to at most n bytes on a rune boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// unauthorized answers without a WWW-Authenticate challenge: the client is a
// reporter with a configured credential, not a browser to prompt, and the
// challenge would only add a round trip.
func unauthorized(w http.ResponseWriter) {
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
