// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"context"
	"io"
	"net/http"
	"time"
)

// outcome is what the remote validator answered for one Authorization
// header. It is deliberately not a bool: "unavailable" must not collapse
// into "invalid", or a validator hiccup would reject every edge in the
// fleet instead of falling back to cache (spec §4, "fail closed").
type outcome int

const (
	outcomeValid outcome = iota
	outcomeInvalid
	outcomeForbidden
	outcomeUnavailable
)

// forwarder calls the external validator with the Authorization header
// forwarded verbatim -- the Traefik forwardAuth pattern (spec §4). It never
// parses, decodes or re-encodes the credential itself.
//
// url is the base validator URL. check takes the URL to call as an argument
// rather than reading this field, because one ForwardAuth serves both the
// plain subscription check and every per-service entitlement check from a
// single cache -- see ForwardAuth.validateURL.
type forwarder struct {
	url    string
	client *http.Client
}

// newValidatorClient never follows a redirect: the 3xx itself reaches check,
// which scores it unavailable. Go's default policy would follow it and score
// whatever the target answered -- a login or maintenance page's 200 then
// validates any credential at all, and caches it.
func newValidatorClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (f *forwarder) check(ctx context.Context, validateURL, authHeader string) outcome {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, validateURL, nil)
	if err != nil {
		return outcomeUnavailable
	}
	req.Header.Set("Authorization", authHeader)

	resp, err := f.client.Do(req)
	if err != nil {
		return outcomeUnavailable
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return outcomeValid
	case http.StatusUnauthorized:
		return outcomeInvalid
	case http.StatusForbidden:
		// Authenticated, but not entitled to what was asked for. Kept apart
		// from 401 all the way to the node: see ErrForbidden.
		return outcomeForbidden
	default:
		// Anything else -- 5xx, an unexpected 2xx/3xx/4xx -- is the
		// validator misbehaving, not a verdict on these credentials.
		return outcomeUnavailable
	}
}
