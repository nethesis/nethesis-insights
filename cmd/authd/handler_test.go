// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/platform/auth"
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
			h := newHandler(tc.v)
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
	h := newHandler(v)
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
	h := newHandler(&fakeValidator{err: auth.ErrInvalidCredentials})
	r := httptest.NewRequest(http.MethodGet, "/auth", nil)
	r.SetBasicAuth("sys-1", "hunter2")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if body := w.Body.String(); strings.Contains(body, "hunter2") {
		t.Errorf("response body leaked the secret: %q", body)
	}
}
