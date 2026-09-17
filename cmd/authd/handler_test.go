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
	services []string // the service argument of every call, in order
}

func (f *fakeValidator) Validate(ctx context.Context, authHeader, service string) (string, error) {
	f.calls++
	f.services = append(f.services, service)
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

// /auth checks a subscription; /auth/service/<name> additionally checks a
// named entitlement. The handler's only job on the second route is to hand
// the path segment to the validator -- it never decides what a service means
// or which ones exist, so a new entitlement is one line of proxy config and
// no release of this binary.
func TestServiceRoutePassesTheServiceNameToTheValidator(t *testing.T) {
	v := &fakeValidator{systemID: "sys-1"}
	h := newHandler(v, nil, nil)

	for _, path := range []string{"/auth", "/auth/service/ng-blacklist"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.SetBasicAuth("sys-1", "secret")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", path, w.Code)
		}
	}

	want := []string{"", "ng-blacklist"}
	if len(v.services) != len(want) || v.services[0] != want[0] || v.services[1] != want[1] {
		t.Fatalf("validator called with services %q, want %q", v.services, want)
	}
}

// The service name lands in an outbound URL path, so the charset is closed:
// [a-z0-9-], not starting or ending with a dash, and bounded in length.
// Anything else is a proxy misconfiguration rather than a verdict on the
// caller's credential, so it is a 404 and the validator is never called --
// spending an upstream request to learn that our own config is wrong.
func TestServiceRouteRejectsAMalformedServiceName(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"empty", "/auth/service/"},
		{"uppercase", "/auth/service/NG-Blacklist"},
		{"underscore", "/auth/service/ng_blacklist"},
		{"leading dash", "/auth/service/-ng-blacklist"},
		{"trailing dash", "/auth/service/ng-blacklist-"},
		{"dot", "/auth/service/ng.blacklist"},
		{"traversal", "/auth/service/..%2F..%2Fadmin"},
		{"extra segment", "/auth/service/ng-blacklist/extra"},
		{"too long", "/auth/service/" + strings.Repeat("a", 65)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := &fakeValidator{systemID: "sys-1"}
			h := newHandler(v, nil, nil)
			r := httptest.NewRequest(http.MethodGet, tc.path, nil)
			r.SetBasicAuth("sys-1", "secret")
			w := httptest.NewRecorder()

			h.ServeHTTP(w, r)

			if w.Code != http.StatusNotFound {
				t.Errorf("status = %d, want 404", w.Code)
			}
			if v.calls != 0 {
				t.Errorf("validator calls = %d, want 0", v.calls)
			}
		})
	}
}

// Traefik passes this status straight back to the node, so a subscriber
// without the Threat Shield entitlement gets a 403 on the feed and not the
// 401 a wrong password gets. The two send an administrator to different
// places, which is the whole reason auth.ErrForbidden exists.
func TestForbiddenAnswers403(t *testing.T) {
	for _, path := range []string{"/auth", "/auth/service/ng-blacklist"} {
		t.Run(path, func(t *testing.T) {
			h := newHandler(&fakeValidator{err: auth.ErrForbidden}, nil, nil)
			r := httptest.NewRequest(http.MethodGet, path, nil)
			r.SetBasicAuth("sys-1", "secret")
			w := httptest.NewRecorder()

			h.ServeHTTP(w, r)

			if w.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", w.Code)
			}
		})
	}
}

// A missing Authorization header is rejected locally on the service route
// too, for the same reason it is on /auth: there is nothing to validate.
func TestServiceRouteRejectsAMissingHeaderWithoutCallingTheValidator(t *testing.T) {
	v := &fakeValidator{systemID: "sys-1"}
	h := newHandler(v, nil, nil)
	r := httptest.NewRequest(http.MethodGet, "/auth/service/ng-blacklist", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if v.calls != 0 {
		t.Errorf("validator calls = %d, want 0", v.calls)
	}
}

// The metrics route label comes from the matched ServeMux pattern, never the
// request path (httpx.RouteLabel), so the service route contributes one
// bounded label however many entitlements exist -- and
// authd_http_requests_total{route="/auth/service/{service}",status="403"} is
// how "how much of the fleet lacks an entitlement" is answered without a
// per-service counter.
func TestServiceRouteMetricsLabelIsThePatternNotThePath(t *testing.T) {
	reg := metrics.NewRegistry("authd")
	rec := metrics.NewHTTP(reg)
	h := newHandler(&fakeValidator{systemID: "sys-1"}, metrics.Handler(reg), rec)

	r := httptest.NewRequest(http.MethodGet, "/auth/service/ng-blacklist", nil)
	r.SetBasicAuth("sys-1", "secret")
	h.ServeHTTP(httptest.NewRecorder(), r)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	const want = `authd_http_requests_total{method="GET",route="/auth/service/{service}",status="200"} 1`
	if !strings.Contains(w.Body.String(), want) {
		t.Errorf("scrape body missing %q\nbody:\n%s", want, w.Body.String())
	}
}
