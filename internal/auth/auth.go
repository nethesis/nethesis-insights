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
	"net/http"
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

const (
	defaultPositiveTTL = 5 * time.Minute
	defaultNegativeTTL = 30 * time.Second
	defaultTimeout     = 5 * time.Second
)

// ForwardAuth validates HTTP Basic credentials by forwarding the
// Authorization header verbatim to a validator URL and caching the
// outcome. Caching is mandatory, not an optimization: at fleet scale,
// uncached validation would be one call per bundle for credentials that
// essentially never change (spec §4).
type ForwardAuth struct {
	PositiveTTL time.Duration
	NegativeTTL time.Duration

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
		PositiveTTL: defaultPositiveTTL,
		NegativeTTL: defaultNegativeTTL,
		pepper:      pepper,
		fwd:         &forwarder{url: validateURL, client: &http.Client{Timeout: timeout}},
		cache:       newCache(now),
		now:         now,
	}
}

// Validate has the same signature as api.Authenticator so it drops into
// api.NewServer without this package importing api.
func (a *ForwardAuth) Validate(ctx context.Context, authHeader string) (string, error) {
	systemID, secret, err := parseBasic(authHeader)
	if err != nil {
		return "", err
	}
	key := a.cacheKey(systemID, secret)

	if e, fresh, found := a.cache.get(key); found && fresh {
		return outcomeFromEntry(e, systemID)
	}

	switch a.fwd.check(ctx, authHeader) {
	case outcomeValid:
		a.cache.set(key, entry{ok: true, systemID: systemID, expiresAt: a.now().Add(a.PositiveTTL)})
		return systemID, nil

	case outcomeInvalid:
		a.cache.set(key, entry{ok: false, expiresAt: a.now().Add(a.NegativeTTL)})
		return "", fmt.Errorf("%w: validator rejected system_id %q", ErrInvalidCredentials, systemID)

	default: // outcomeUnavailable
		if e, _, found := a.cache.get(key); found {
			// Stale beats unavailable: see the cache's doc comment.
			return outcomeFromEntry(e, systemID)
		}
		return "", fmt.Errorf("%w: system_id %q", ErrUnavailable, systemID)
	}
}

func outcomeFromEntry(e entry, systemID string) (string, error) {
	if e.ok {
		return e.systemID, nil
	}
	return "", fmt.Errorf("%w: cached rejection for system_id %q", ErrInvalidCredentials, systemID)
}

func (a *ForwardAuth) cacheKey(systemID, secret string) string {
	mac := hmac.New(sha256.New, []byte(a.pepper))
	mac.Write([]byte(systemID + ":" + secret))
	return hex.EncodeToString(mac.Sum(nil))
}

// parseBasic extracts system_id/secret from a "Basic ..." Authorization
// header without judging them -- that verdict belongs to the validator.
func parseBasic(authHeader string) (systemID, secret string, err error) {
	const prefix = "Basic "
	if authHeader == "" {
		return "", "", fmt.Errorf("%w: no Authorization header", ErrInvalidCredentials)
	}
	if !strings.HasPrefix(authHeader, prefix) {
		scheme, _, _ := strings.Cut(authHeader, " ")
		return "", "", fmt.Errorf("%w: scheme is %q, want Basic", ErrInvalidCredentials, scheme)
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
