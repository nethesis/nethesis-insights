// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/platform/auth"
	"github.com/nethesis/nethesis-insights/internal/platform/metrics"
)

type fakeValidator struct {
	systemID string
	err      error
	calls    int
}

func (f *fakeValidator) Validate(ctx context.Context, authHeader string) (string, error) {
	f.calls++
	return f.systemID, f.err
}

// /metrics is mounted next to /healthz. See the equivalent api/logs test for
// why this drives a request through an unrelated route first.
func TestMetricsEndpointExposesRequestCounters(t *testing.T) {
	reg := metrics.NewRegistry("authd")
	rec := metrics.NewHTTP(reg)
	h := newHandler(&fakeValidator{systemID: "sys-1"}, metrics.Handler(reg), rec)

	hr := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	hw := httptest.NewRecorder()
	h.ServeHTTP(hw, hr)

	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	for _, want := range []string{
		"go_goroutines",
		`authd_http_requests_total{method="GET",route="/healthz",status="200"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape body missing %q\nbody:\n%s", want, body)
		}
	}
}

// Traefik forwards the auth server's status when it is not 2xx, so these
// three statuses are the whole contract. 503 must stay distinct from 401:
// an ingestion gap the edge retries is recoverable, a false reject is not.
func TestAuthEndpointStatuses(t *testing.T) {
	cases := []struct {
		name string
		v    *fakeValidator
		want int
	}{
		{"valid", &fakeValidator{systemID: "sys-1"}, http.StatusOK},
		{"invalid", &fakeValidator{err: auth.ErrInvalidCredentials}, http.StatusUnauthorized},
		{"validator unavailable", &fakeValidator{err: auth.ErrUnavailable}, http.StatusServiceUnavailable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHandler(tc.v, nil, nil)
			r := httptest.NewRequest(http.MethodGet, "/auth", nil)
			r.SetBasicAuth("sys-1", "secret")
			w := httptest.NewRecorder()

			h.ServeHTTP(w, r)

			if w.Code != tc.want {
				t.Errorf("status = %d, want %d", w.Code, tc.want)
			}
			if tc.v.calls != 1 {
				t.Errorf("validator calls = %d, want 1", tc.v.calls)
			}
		})
	}
}

// A request with no Authorization header must be rejected without calling
// the validator: there is nothing to validate, and forwarding an empty
// header upstream would spend a request to learn that.
func TestAuthEndpointRejectsAMissingHeaderWithoutCallingTheValidator(t *testing.T) {
	v := &fakeValidator{systemID: "sys-1"}
	h := newHandler(v, nil, nil)
	r := httptest.NewRequest(http.MethodGet, "/auth", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if v.calls != 0 {
		t.Errorf("validator calls = %d, want 0", v.calls)
	}
}

// The response body must never echo the credential, and the header must
// never be reflected back into a response Traefik will log.
func TestAuthEndpointNeverEchoesTheCredential(t *testing.T) {
	h := newHandler(&fakeValidator{err: auth.ErrInvalidCredentials}, nil, nil)
	r := httptest.NewRequest(http.MethodGet, "/auth", nil)
	r.SetBasicAuth("sys-1", "hunter2")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	// The likeliest form of this leak is not the literal secret but the
	// base64-encoded Authorization value landing in a diagnostic message,
	// so check for both.
	encoded := strings.TrimPrefix(r.Header.Get("Authorization"), "Basic ")
	body := w.Body.String()
	if strings.Contains(body, "hunter2") {
		t.Errorf("response body leaked the secret: %q", body)
	}
	if strings.Contains(body, encoded) {
		t.Errorf("response body leaked the encoded credential: %q", body)
	}
}

// The switch in newHandler recognizes exactly three outcomes from the
// validator (nil, ErrInvalidCredentials, ErrUnavailable); anything else --
// an error this package does not know how to interpret -- must fail closed
// through the default branch, the same 503 as ErrUnavailable, rather than
// being treated as success or leaking an internal error to the caller.
func TestAuthEndpointFailsClosedOnAnUnrecognizedValidatorError(t *testing.T) {
	v := &fakeValidator{err: errors.New("boom: this is not one of the sentinel errors")}
	h := newHandler(v, nil, nil)
	r := httptest.NewRequest(http.MethodGet, "/auth", nil)
	r.SetBasicAuth("sys-1", "secret")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d (fail closed on an unrecognized error)", w.Code, http.StatusServiceUnavailable)
	}
}

// unauthorized deliberately sends a bare 401 with no WWW-Authenticate
// challenge: Traefik passes this status straight back to the caller of
// /v1/bundles etc, which is a reporter with a configured credential, not a
// browser to prompt -- a challenge header would only cost a round trip (see
// the doc comment on unauthorized in handler.go). Assert the absence
// explicitly on both paths that produce a 401, so nobody "fixes" this into a
// spec-compliant challenge by reflex.
func TestAuthEndpoint401OmitsWWWAuthenticate(t *testing.T) {
	cases := []struct {
		name    string
		v       *fakeValidator
		setAuth bool
	}{
		{name: "missing Authorization header", v: &fakeValidator{systemID: "sys-1"}, setAuth: false},
		{name: "invalid credential", v: &fakeValidator{err: auth.ErrInvalidCredentials}, setAuth: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHandler(tc.v, nil, nil)
			r := httptest.NewRequest(http.MethodGet, "/auth", nil)
			if tc.setAuth {
				r.SetBasicAuth("sys-1", "secret")
			}
			w := httptest.NewRecorder()

			h.ServeHTTP(w, r)

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", w.Code)
			}
			if got := w.Header().Get("WWW-Authenticate"); got != "" {
				t.Errorf("WWW-Authenticate = %q, want it absent from a 401 to a reporter", got)
			}
		})
	}
}
