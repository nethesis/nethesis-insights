// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"context"
	"io"
	"net/http"
	"net/url"
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

// checkResult is what check learned about one upstream call: the scored
// outcome, unchanged in vocabulary, plus enough about the raw HTTP answer to
// explain an outcomeUnavailable that no cache can paper over. status is 0
// when the transport call itself failed (no response at all); location is
// set only for a 3xx and never carries a query string, an Authorization
// header or any credential -- see redirectTarget.
type checkResult struct {
	outcome  outcome
	status   int
	location string
}

func (f *forwarder) check(ctx context.Context, validateURL, authHeader string) checkResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, validateURL, nil)
	if err != nil {
		return checkResult{outcome: outcomeUnavailable}
	}
	req.Header.Set("Authorization", authHeader)

	resp, err := f.client.Do(req)
	if err != nil {
		return checkResult{outcome: outcomeUnavailable}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return checkResult{outcome: outcomeValid}
	case http.StatusUnauthorized:
		return checkResult{outcome: outcomeInvalid}
	case http.StatusForbidden:
		// Authenticated, but not entitled to what was asked for. Kept apart
		// from 401 all the way to the node: see ErrForbidden.
		return checkResult{outcome: outcomeForbidden}
	default:
		// Anything else -- 5xx, an unexpected 2xx/3xx/4xx -- is the
		// validator misbehaving, not a verdict on these credentials. A 3xx
		// additionally carries where it pointed: AUTH_VALIDATE_URL
		// configured as http:// where upstream wants https://, or a
		// trailing-slash mismatch, is scored exactly the same as a genuine
		// outage here, and the caller's log line needs this to tell them
		// apart.
		result := checkResult{outcome: outcomeUnavailable, status: resp.StatusCode}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			result.location = redirectTarget(resp)
		}
		return result
	}
}

// redirectTarget names a 3xx's Location header with its userinfo, query
// string and fragment stripped -- any of them can carry a credential, a
// session token or a one-time code -- and without ever following the
// redirect (see newValidatorClient). "" if there is no Location header or it
// does not parse as a URL.
func redirectTarget(resp *http.Response) string {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return ""
	}
	u, err := url.Parse(loc)
	if err != nil {
		return ""
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}
