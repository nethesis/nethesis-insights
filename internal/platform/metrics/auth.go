// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package metrics

import "github.com/prometheus/client_golang/prometheus"

// Auth holds authd's forward-auth counters: how often a validation outcome
// came from cache versus the upstream validator, and what the upstream
// answered when it was called. Upstream failures ("unavailable") are what
// the admin guide's "AUTH_VALIDATE_URL unreachable" case looks like here;
// the 503 it produces on /auth is also visible generically through
// authd_http_requests_total{route="/auth",status="503"} via the same Logging
// hook every other binary gets, so there is no separate 503 counter here.
//
// The names below carry no "auth_" of their own: only authd registers these,
// and the registry already prefixes them with its service name, so they
// scrape as authd_cache_results_total and authd_upstream_results_total
// rather than the stuttering authd_auth_*.
type Auth struct {
	cache    *prometheus.CounterVec
	upstream *prometheus.CounterVec
}

// Cache-lookup outcomes. Closed, and owned here rather than by
// internal/platform/auth, because CacheHit/CacheMiss below are this
// package's own API rather than a vocabulary auth hands over.
const (
	authCacheHit  = "hit"
	authCacheMiss = "miss"
)

// NewAuth builds and registers authd's cache/upstream counters into reg,
// pre-creating every child at 0 so both families are present before the
// first request -- see the package doc's "pre-create every enumerable
// child".
//
// upstreamResults is supplied by the caller rather than restated here
// because that vocabulary belongs to internal/platform/auth: cmd/authd
// passes auth.UpstreamValid, auth.UpstreamInvalid and
// auth.UpstreamUnavailable, the same three constants it wires into
// ForwardAuth.Metrics.Upstream, so the two can never disagree.
func NewAuth(reg *Registry, upstreamResults ...string) *Auth {
	a := &Auth{
		cache: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cache_results_total",
			Help: "Forward-auth cache lookups, by result (hit, miss).",
		}, []string{"result"}),
		upstream: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "upstream_results_total",
			Help: "Upstream validator calls, by result (valid, invalid, unavailable).",
		}, []string{"result"}),
	}
	reg.prefixed.MustRegister(a.cache, a.upstream)
	a.cache.WithLabelValues(authCacheHit)
	a.cache.WithLabelValues(authCacheMiss)
	for _, result := range upstreamResults {
		a.upstream.WithLabelValues(result)
	}
	return a
}

// CacheHit records a fresh cached outcome that answered Validate without an
// upstream call.
func (a *Auth) CacheHit() { a.cache.WithLabelValues(authCacheHit).Inc() }

// CacheMiss records a lookup that fell through to the upstream validator --
// no entry, or a stale one only usable as an outage fallback.
func (a *Auth) CacheMiss() { a.cache.WithLabelValues(authCacheMiss).Inc() }

// Upstream records what the upstream validator answered: "valid",
// "invalid" or "unavailable" -- auth.outcome's three values, spelled out
// here rather than importing that unexported type.
func (a *Auth) Upstream(result string) { a.upstream.WithLabelValues(result).Inc() }
