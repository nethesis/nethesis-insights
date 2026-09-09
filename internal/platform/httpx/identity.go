// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package httpx

import (
	"errors"
	"net/http"
)

// ErrUntrustedProxy is returned when a request that must have come through
// the proxy did not. The credential on such a request has not been validated
// by anybody, so its username is not an identity.
var ErrUntrustedProxy = errors.New("httpx: request did not arrive from a trusted proxy")

// ErrNoCredential is returned when the request carries no usable HTTP Basic
// credential to read a system_id from.
var ErrNoCredential = errors.New("httpx: no credential")

// SystemID reads the system identity off a request the proxy has already
// authenticated via its forwardAuth middleware.
//
// The credential is NOT verified here -- authd did that, and this process
// holds no secret to verify it against. What makes the username trustworthy
// is that the request reached us from the proxy: the trusted-proxy check is
// the security boundary, not a formality. The proxy forwards the original
// Authorization header untouched, which is why the identity is still
// available without the proxy having to inject a header of its own.
func SystemID(r *http.Request, t TrustedProxies) (string, error) {
	if !t.Contains(r.RemoteAddr) {
		return "", ErrUntrustedProxy
	}
	user, _, ok := r.BasicAuth()
	if !ok || user == "" {
		return "", ErrNoCredential
	}
	return user, nil
}
