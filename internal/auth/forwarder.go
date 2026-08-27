// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"context"
	"io"
	"net/http"
)

// outcome is what the remote validator answered for one Authorization
// header. It is deliberately not a bool: "unavailable" must not collapse
// into "invalid", or a validator hiccup would reject every edge in the
// fleet instead of falling back to cache (spec §4, "fail closed").
type outcome int

const (
	outcomeValid outcome = iota
	outcomeInvalid
	outcomeUnavailable
)

// forwarder calls the external validator with the Authorization header
// forwarded verbatim -- the Traefik forwardAuth pattern (spec §4). It never
// parses, decodes or re-encodes the credential itself.
type forwarder struct {
	url    string
	client *http.Client
}

func (f *forwarder) check(ctx context.Context, authHeader string) outcome {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
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
	case http.StatusUnauthorized, http.StatusForbidden:
		return outcomeInvalid
	default:
		// Anything else -- 5xx, an unexpected 2xx/3xx/4xx -- is the
		// validator misbehaving, not a verdict on these credentials.
		return outcomeUnavailable
	}
}
