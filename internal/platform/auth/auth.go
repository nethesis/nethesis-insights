// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package auth validates edge credentials by forwarding them to an external
// validator -- the Traefik forwardAuth pattern (design spec §4). The server
// never stores or verifies secrets itself; it only ever holds a cache of
// pepper-hashed outcomes, in memory, never persisted.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ErrInvalidCredentials is returned by Validate on a definitive reject --
// malformed header, wrong secret, unknown system_id -- as opposed to the
// validator being unreachable, which returns ErrUnavailable instead so the
// caller can answer 503 rather than a false 401.
var ErrInvalidCredentials = errors.New("invalid credentials")

// ErrUnavailable is returned when the validator could not be reached (or
// answered unexpectedly) and there is no cached outcome, stale or fresh, to
// fall back on. Callers must answer 503: an ingestion gap the edge retries
// is recoverable, a false reject is not (spec §4, "fail closed").
var ErrUnavailable = errors.New("validator unavailable")

// ErrForbidden is returned when the validator answered 403: the credential
// is genuine, but it does not carry the entitlement the requested service
// needs. It is deliberately distinct from ErrInvalidCredentials -- the two
// send an administrator to opposite places, one to buy an entitlement and
// one to fix a credential, and collapsing them into a single 401 makes a
// missing entitlement look exactly like a typo in a password that is fine.
var ErrForbidden = errors.New("not entitled")

const (
	defaultPositiveTTL = 5 * time.Minute
	defaultNegativeTTL = 30 * time.Second
	defaultTimeout     = 5 * time.Second
)

// Upstream outcome labels, exported so a caller wiring Metrics.Upstream (a
// plain func(string), to keep this package free of a prometheus dependency)
// has a fixed vocabulary to switch on instead of guessing the internal
// outcome type's spelling.
const (
	UpstreamValid       = "valid"
	UpstreamInvalid     = "invalid"
	UpstreamForbidden   = "forbidden"
	UpstreamUnavailable = "unavailable"
)

// Metrics is the optional counter set Validate reports against: one call per
// cache lookup (CacheHit or CacheMiss, mutually exclusive) and, on a miss,
// one call to Upstream naming what the validator answered. A nil field (or
// a nil *Metrics, the zero value of ForwardAuth.Metrics) is skipped, so
// every existing caller and test is unaffected by adding this.
// *metrics.Auth supplies all three.
type Metrics struct {
	CacheHit  func()
	CacheMiss func()
	Upstream  func(result string)
}

func (m *Metrics) cacheHit() {
	if m != nil && m.CacheHit != nil {
		m.CacheHit()
	}
}

func (m *Metrics) cacheMiss() {
	if m != nil && m.CacheMiss != nil {
		m.CacheMiss()
	}
}

func (m *Metrics) upstream(result string) {
	if m != nil && m.Upstream != nil {
		m.Upstream(result)
	}
}

// ForwardAuth validates HTTP Basic credentials by forwarding the
// Authorization header verbatim to a validator URL and caching the
// outcome. Caching is mandatory, not an optimization: at fleet scale,
// uncached validation would be one call per bundle for credentials that
// essentially never change (spec §4).
type ForwardAuth struct {
	PositiveTTL time.Duration
	NegativeTTL time.Duration

	// MaxPositiveEntries and MaxNegativeEntries bound the outcome cache.
	// Unbounded, every distinct wrong credential is a permanent entry and
	// the process grows until it is killed. See cache for why the two are
	// counted separately.
	MaxPositiveEntries int
	MaxNegativeEntries int

	// Metrics is optional and nil-safe on every call; see Metrics' doc. Set
	// directly after New, before the first Validate call.
	Metrics *Metrics

	pepper string
	fwd    *forwarder
	cache  *cache
	now    func() time.Time
}

// New returns a ForwardAuth that validates against validateURL.
//
// pepper is the HMAC key for cache keys -- a secret, from AUTH_PEPPER --
// so the cache (in-memory only, but defense in depth) cannot be used to
// reconstruct which credentials are valid.
//
// now is injected so tests can control TTL expiry deterministically.
func New(validateURL, pepper string, timeout time.Duration, now func() time.Time) *ForwardAuth {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &ForwardAuth{
		PositiveTTL:        defaultPositiveTTL,
		NegativeTTL:        defaultNegativeTTL,
		MaxPositiveEntries: defaultMaxPositiveEntries,
		MaxNegativeEntries: defaultMaxNegativeEntries,
		pepper:             pepper,
		fwd:                &forwarder{url: validateURL, client: newValidatorClient(timeout)},
		cache:              newCache(now, 0, 0),
		now:                now,
	}
}

// Validate has the same signature as authd's own narrow validator interface
// (cmd/authd/handler.go), so a *ForwardAuth drops straight into authd's
// handler, which is tested against a fake implementing that interface
// instead of a real ForwardAuth.
//
// service selects what is being checked. Empty means the plain subscription
// check against the configured URL -- does this system_id/secret belong to a
// subscriber at all -- which is what every ingest route uses. A non-empty
// service additionally asks whether that subscriber carries a named
// entitlement, by calling <base>/service/<name>; "ng-blacklist" is the
// Threat Shield feed's. The caller supplies it; this package never guesses
// one from a path.
func (a *ForwardAuth) Validate(ctx context.Context, authHeader, service string) (string, error) {
	systemID, secret, err := ParseBasic(authHeader)
	if err != nil {
		return "", err
	}
	key := a.cacheKey(service, systemID, secret)
	a.cache.setLimits(a.MaxPositiveEntries, a.MaxNegativeEntries)

	if e, fresh, found := a.cache.get(key); found && fresh {
		a.Metrics.cacheHit()
		return outcomeFromEntry(e, systemID, service)
	}
	a.Metrics.cacheMiss()

	switch a.fwd.check(ctx, a.validateURL(service), authHeader) {
	case outcomeValid:
		a.Metrics.upstream(UpstreamValid)
		a.cache.set(key, entry{ok: true, systemID: systemID, expiresAt: a.now().Add(a.PositiveTTL)})
		return systemID, nil

	case outcomeInvalid:
		a.Metrics.upstream(UpstreamInvalid)
		a.cache.set(key, entry{ok: false, expiresAt: a.now().Add(a.NegativeTTL)})
		return "", fmt.Errorf("%w: validator rejected system_id %q", ErrInvalidCredentials, systemID)

	case outcomeForbidden:
		a.Metrics.upstream(UpstreamForbidden)
		// Cached on the negative TTL like any other reject, and in the same
		// tier: an unentitled system can be minted as freely as a wrong
		// password can, so it must not be able to evict positives.
		a.cache.set(key, entry{ok: false, forbidden: true, expiresAt: a.now().Add(a.NegativeTTL)})
		return "", fmt.Errorf("%w: system_id %q lacks the %q entitlement", ErrForbidden, systemID, service)

	default: // outcomeUnavailable
		a.Metrics.upstream(UpstreamUnavailable)
		if e, _, found := a.cache.get(key); found {
			// Stale beats unavailable: see the cache's doc comment.
			return outcomeFromEntry(e, systemID, service)
		}
		return "", fmt.Errorf("%w: system_id %q", ErrUnavailable, systemID)
	}
}

// outcomeFromEntry replays a cached verdict, preserving which negative it
// was. The distinction has to survive the outage fallback too: a validator
// hiccup is not a reason to report an unentitled system as having a bad
// credential, any more than it is a reason to let it through.
func outcomeFromEntry(e entry, systemID, service string) (string, error) {
	switch {
	case e.ok:
		return e.systemID, nil
	case e.forbidden:
		return "", fmt.Errorf("%w: cached, system_id %q lacks the %q entitlement", ErrForbidden, systemID, service)
	default:
		return "", fmt.Errorf("%w: cached rejection for system_id %q", ErrInvalidCredentials, systemID)
	}
}

// cacheKey derives the outcome-cache key for one credential checked against
// one service.
//
// Folding service in is not a refinement, it is the correctness of the whole
// per-service split. A node posts threat events (checked against the base
// URL) minutes before it polls the blocklist feed; keyed on the credential
// alone, that base positive would answer the feed's entitlement check out of
// cache and the entitlement would never be checked for any node that also
// reports. The mirror holds too: one service's entitlement would unlock
// every other one.
//
// service goes in first, NUL-separated, and the separator is unforgeable
// here rather than merely unlikely: cmd/authd admits only [a-z0-9-] service
// names, so no service name can contain the delimiter or the ":" that
// separates the two credential halves.
func (a *ForwardAuth) cacheKey(service, systemID, secret string) string {
	mac := hmac.New(sha256.New, []byte(a.pepper))
	mac.Write([]byte(service + "\x00" + systemID + ":" + secret))
	return hex.EncodeToString(mac.Sum(nil))
}

// ParseBasic extracts system_id/secret from a "Basic ..." Authorization
// header without judging them -- that verdict belongs to the validator.
func ParseBasic(authHeader string) (systemID, secret string, err error) {
	const prefix = "Basic "
	if authHeader == "" {
		return "", "", fmt.Errorf("%w: no Authorization header", ErrInvalidCredentials)
	}
	if !strings.HasPrefix(authHeader, prefix) {
		// No header content is interpolated, not even the "scheme". This
		// error is logged at slog.Info by cmd/authd -- the default level --
		// and a credential must never reach a log line. The tempting
		// strings.Cut(authHeader, " ") is exactly what broke that rule:
		// Cut returns the WHOLE string as the first value when the
		// separator is absent, so a reporter sending its credential with
		// no scheme, or with a tab where the space belongs, wrote its live
		// fleet secret into journald on every request.
		//
		// The delimiter is reported instead, because it is derived rather
		// than copied: it separates "sent a Bearer token" from "sent bare
		// base64", which is the whole diagnostic value the scheme had.
		if !strings.Contains(authHeader, " ") {
			return "", "", fmt.Errorf("%w: Authorization header has no scheme delimiter, want Basic", ErrInvalidCredentials)
		}
		return "", "", fmt.Errorf("%w: Authorization scheme is not Basic", ErrInvalidCredentials)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, prefix))
	if err != nil {
		return "", "", fmt.Errorf("%w: credentials are not valid base64", ErrInvalidCredentials)
	}
	systemID, secret, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return "", "", fmt.Errorf("%w: credentials are not system_id:secret", ErrInvalidCredentials)
	}
	return systemID, secret, nil
}

// validateURL is the configured base for the plain subscription check, or
// <base>/service/<name> for an entitlement.
//
// PathEscape is belt to cmd/authd's braces: the only caller that derives a
// service name from a request path already rejects anything outside
// [a-z0-9-], but this package builds an outbound URL and must not be the
// place where a "../" in some future caller's argument turns into a request
// to a different upstream endpoint. TrimSuffix covers a base configured with
// a trailing slash, which would otherwise produce a doubled separator that
// some routers 404 -- degrading every entitlement check to "unavailable",
// and so 503-ing the feed for the whole fleet.
func (a *ForwardAuth) validateURL(service string) string {
	if service == "" {
		return a.fwd.url
	}
	return strings.TrimSuffix(a.fwd.url, "/") + "/service/" + url.PathEscape(service)
}
