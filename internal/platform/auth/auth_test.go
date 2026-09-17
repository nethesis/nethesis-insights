// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func basicHeader(systemID, secret string) string {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth(systemID, secret)
	return req.Header.Get("Authorization")
}

// validator is a stub external validator. status is read on every call, so
// a test can flip it mid-run to simulate the validator going down.
type validator struct {
	status int32
	calls  int32
}

func (v *validator) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&v.calls, 1)
		// The header must be forwarded verbatim, not re-derived.
		if r.Header.Get("Authorization") == "" {
			t.Error("validator received no Authorization header")
		}
		w.WriteHeader(int(atomic.LoadInt32(&v.status)))
	}))
}

func newAuth(t *testing.T, url string, now func() time.Time) *ForwardAuth {
	t.Helper()
	return New(url, "test-pepper", time.Second, now)
}

func TestValidCredentialsAreCachedNotReverified(t *testing.T) {
	v := &validator{status: http.StatusOK}
	srv := v.server(t)
	defer srv.Close()

	a := newAuth(t, srv.URL, time.Now)
	hdr := basicHeader("sys-1", "secret")

	for i := 0; i < 3; i++ {
		systemID, err := a.Validate(context.Background(), hdr, "")
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
		if systemID != "sys-1" {
			t.Fatalf("call %d: got system_id %q, want sys-1", i, systemID)
		}
	}
	if got := atomic.LoadInt32(&v.calls); got != 1 {
		t.Fatalf("validator called %d times, want 1 (the rest should be cache hits)", got)
	}
}

// A nil Metrics (the zero value) must not panic anywhere in Validate --
// every existing caller and test predates this field.
func TestValidateWithNoMetricsDoesNotPanic(t *testing.T) {
	v := &validator{status: http.StatusOK}
	srv := v.server(t)
	defer srv.Close()

	a := newAuth(t, srv.URL, time.Now)
	if _, err := a.Validate(context.Background(), basicHeader("sys-1", "secret"), ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// The first Validate call for a credential is a cache miss followed by an
// upstream call; every later call for the same credential is a cache hit
// with no upstream call at all.
func TestValidateReportsCacheHitsMissesAndUpstreamResult(t *testing.T) {
	v := &validator{status: http.StatusOK}
	srv := v.server(t)
	defer srv.Close()

	a := newAuth(t, srv.URL, time.Now)
	var hits, misses int
	var upstreamResults []string
	a.Metrics = &Metrics{
		CacheHit:  func() { hits++ },
		CacheMiss: func() { misses++ },
		Upstream:  func(result string) { upstreamResults = append(upstreamResults, result) },
	}

	hdr := basicHeader("sys-1", "secret")
	if _, err := a.Validate(context.Background(), hdr, ""); err != nil {
		t.Fatalf("call 1: unexpected error: %v", err)
	}
	if hits != 0 || misses != 1 {
		t.Fatalf("after the first call: hits=%d misses=%d, want 0 1", hits, misses)
	}
	if len(upstreamResults) != 1 || upstreamResults[0] != UpstreamValid {
		t.Fatalf("upstream results = %v, want [%q]", upstreamResults, UpstreamValid)
	}

	if _, err := a.Validate(context.Background(), hdr, ""); err != nil {
		t.Fatalf("call 2: unexpected error: %v", err)
	}
	if hits != 1 || misses != 1 {
		t.Fatalf("after the second (cached) call: hits=%d misses=%d, want 1 1", hits, misses)
	}
	if len(upstreamResults) != 1 {
		t.Fatalf("upstream called again on a cache hit: %v", upstreamResults)
	}
}

func TestInvalidCredentialsAreCachedAndRejected(t *testing.T) {
	v := &validator{status: http.StatusUnauthorized}
	srv := v.server(t)
	defer srv.Close()

	a := newAuth(t, srv.URL, time.Now)
	hdr := basicHeader("sys-1", "wrong")

	for i := 0; i < 2; i++ {
		_, err := a.Validate(context.Background(), hdr, "")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("call %d: error %v, want ErrInvalidCredentials", i, err)
		}
	}
	if got := atomic.LoadInt32(&v.calls); got != 1 {
		t.Fatalf("validator called %d times, want 1", got)
	}
}

func TestUnavailableWithNoCacheFailsClosed(t *testing.T) {
	// Point at an address nothing listens on.
	a := newAuth(t, "http://127.0.0.1:0", time.Now)

	_, err := a.Validate(context.Background(), basicHeader("sys-1", "secret"), "")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error %v, want ErrUnavailable", err)
	}
}

func TestUnavailableFallsBackToStaleCache(t *testing.T) {
	v := &validator{status: http.StatusOK}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&v.calls, 1)
		w.WriteHeader(int(atomic.LoadInt32(&v.status)))
	}))
	defer srv.Close()

	now := time.Now()
	clock := func() time.Time { return now }
	a := newAuth(t, srv.URL, clock)
	hdr := basicHeader("sys-1", "secret")

	systemID, err := a.Validate(context.Background(), hdr, "")
	if err != nil || systemID != "sys-1" {
		t.Fatalf("priming call: systemID=%q err=%v", systemID, err)
	}

	// Expire the cache entry, then take the validator down.
	now = now.Add(a.PositiveTTL + time.Second)
	srv.Close()

	systemID, err = a.Validate(context.Background(), hdr, "")
	if err != nil {
		t.Fatalf("expected the stale cache entry to serve this request, got error: %v", err)
	}
	if systemID != "sys-1" {
		t.Fatalf("got system_id %q, want sys-1", systemID)
	}
}

func TestMalformedHeaderNeverReachesTheValidator(t *testing.T) {
	v := &validator{status: http.StatusOK}
	srv := v.server(t)
	defer srv.Close()

	a := newAuth(t, srv.URL, time.Now)

	cases := []struct {
		name string
		hdr  string
	}{
		{"empty", ""},
		{"wrong scheme", "Bearer abc123"},
		{"not base64", "Basic not-base64!!"},
		{"no colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("no-colon-here"))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := a.Validate(context.Background(), tc.hdr, "")
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("error %v, want ErrInvalidCredentials", err)
			}
		})
	}
	if got := atomic.LoadInt32(&v.calls); got != 0 {
		t.Fatalf("validator called %d times, want 0 -- malformed headers must be rejected locally", got)
	}
}

// ParseBasic's error is logged at slog.Info by cmd/authd -- the default
// level -- so it must be safe to log whatever the header contains. AGENTS.md
// makes this a rule: a credential is never logged. A header with no
// delimiter at all is the case that broke it, because strings.Cut hands back
// the WHOLE string when the separator is absent, so an interpolated "scheme"
// was the live fleet credential.
func TestParseBasicErrorNeverCarriesTheCredential(t *testing.T) {
	const secret = "sup3r-s3cret-fleet-token"
	creds := base64.StdEncoding.EncodeToString([]byte("sys-1:" + secret))

	cases := []struct {
		name string
		hdr  string
	}{
		{"no space at all", creds},
		{"tab instead of space", "Basic\t" + creds},
		{"empty scheme", " " + creds},
		{"lowercase scheme", "basic " + creds},
		{"wrong scheme", "Bearer " + creds},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ParseBasic(tc.hdr)
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("error %v, want ErrInvalidCredentials", err)
			}
			msg := err.Error()
			for _, leak := range []string{secret, creds, tc.hdr} {
				if strings.Contains(msg, leak) {
					t.Fatalf("error %q leaks %q -- ParseBasic must never interpolate header content", msg, leak)
				}
			}
		})
	}
}

func TestCacheKeyDependsOnTheFullCredential(t *testing.T) {
	a := newAuth(t, "http://unused.invalid", time.Now)
	k1 := a.cacheKey("", "sys-1", "secret-a")
	k2 := a.cacheKey("", "sys-1", "secret-b")
	k3 := a.cacheKey("", "sys-2", "secret-a")
	if k1 == k2 || k1 == k3 || k2 == k3 {
		t.Fatalf("cache keys collided: %q %q %q", k1, k2, k3)
	}
}

// pathRecordingValidator is a stub validator that answers per request path,
// so a test can assert which URL Validate actually called -- the base
// validator or a per-service one -- and give the two different verdicts.
type pathRecordingValidator struct {
	mu     sync.Mutex
	paths  []string
	status func(path string) int
}

func (p *pathRecordingValidator) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.paths = append(p.paths, r.URL.Path)
		p.mu.Unlock()
		w.WriteHeader(p.status(r.URL.Path))
	}))
}

func (p *pathRecordingValidator) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.paths...)
}

// An empty service is the plain subscription check and hits the configured
// URL unchanged; a named one hits <base>/service/<name>, the shape
// my.nethesis.it publishes entitlements at.
func TestServiceValidationCallsTheServiceURL(t *testing.T) {
	v := &pathRecordingValidator{status: func(string) int { return http.StatusOK }}
	srv := v.server(t)
	defer srv.Close()

	a := newAuth(t, srv.URL+"/auth", time.Now)
	hdr := basicHeader("sys-1", "secret")

	if _, err := a.Validate(context.Background(), hdr, ""); err != nil {
		t.Fatalf("base validation: unexpected error: %v", err)
	}
	if _, err := a.Validate(context.Background(), hdr, "ng-blacklist"); err != nil {
		t.Fatalf("service validation: unexpected error: %v", err)
	}

	want := []string{"/auth", "/auth/service/ng-blacklist"}
	got := v.seen()
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("validator called on %v, want %v", got, want)
	}
}

// The load-bearing case for the whole per-service split. A node posts threat
// events (validated against the base URL) minutes before it polls the feed;
// if the cache key ignored the service, the base positive would answer the
// entitlement check from cache and the entitlement would never be checked at
// all -- the feature would silently no-op for every node that also reports.
func TestABaseCachedPositiveDoesNotSatisfyAServiceCheck(t *testing.T) {
	v := &pathRecordingValidator{status: func(path string) int {
		if strings.HasPrefix(path, "/auth/service/") {
			return http.StatusForbidden // subscribed, but not entitled
		}
		return http.StatusOK
	}}
	srv := v.server(t)
	defer srv.Close()

	a := newAuth(t, srv.URL+"/auth", time.Now)
	hdr := basicHeader("sys-1", "secret")

	if _, err := a.Validate(context.Background(), hdr, ""); err != nil {
		t.Fatalf("base validation: unexpected error: %v", err)
	}
	_, err := a.Validate(context.Background(), hdr, "ng-blacklist")
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("error %v, want ErrForbidden -- a base positive must not be cached under a service key", err)
	}
}

// And the mirror: an entitlement for one service must not answer for
// another, or one entitlement would unlock every future one.
func TestAServiceCachedPositiveDoesNotSatisfyAnotherService(t *testing.T) {
	v := &pathRecordingValidator{status: func(path string) int {
		if path == "/auth/service/ng-blacklist" {
			return http.StatusOK
		}
		return http.StatusForbidden
	}}
	srv := v.server(t)
	defer srv.Close()

	a := newAuth(t, srv.URL+"/auth", time.Now)
	hdr := basicHeader("sys-1", "secret")

	if _, err := a.Validate(context.Background(), hdr, "ng-blacklist"); err != nil {
		t.Fatalf("entitled service: unexpected error: %v", err)
	}
	_, err := a.Validate(context.Background(), hdr, "some-other-service")
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("error %v, want ErrForbidden -- one service's entitlement must not answer for another", err)
	}
}

// "Authenticated, but not entitled" is a different fact from "wrong
// credential", and the whole point of keeping it distinct is that the node's
// administrator is told to buy the entitlement rather than sent to check
// credentials that are fine. It is cached like any other negative outcome.
func TestForbiddenIsDistinctFromInvalidAndIsCached(t *testing.T) {
	v := &pathRecordingValidator{status: func(string) int { return http.StatusForbidden }}
	srv := v.server(t)
	defer srv.Close()

	a := newAuth(t, srv.URL+"/auth", time.Now)
	var upstreamResults []string
	a.Metrics = &Metrics{Upstream: func(result string) { upstreamResults = append(upstreamResults, result) }}
	hdr := basicHeader("sys-1", "secret")

	for i := 0; i < 2; i++ {
		_, err := a.Validate(context.Background(), hdr, "ng-blacklist")
		if !errors.Is(err, ErrForbidden) {
			t.Fatalf("call %d: error %v, want ErrForbidden", i, err)
		}
		if errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("call %d: ErrForbidden must not also match ErrInvalidCredentials", i)
		}
	}
	if got := len(v.seen()); got != 1 {
		t.Fatalf("validator called %d times, want 1 (the second must be a cache hit)", got)
	}
	if len(upstreamResults) != 1 || upstreamResults[0] != UpstreamForbidden {
		t.Fatalf("upstream results = %v, want [%q]", upstreamResults, UpstreamForbidden)
	}
}

// The outage fallback must preserve which negative it is: a validator
// hiccup is not a reason to promote an unentitled node to entitled, nor to
// report it as a bad credential.
func TestUnavailableFallsBackToAStaleForbiddenEntry(t *testing.T) {
	v := &pathRecordingValidator{status: func(string) int { return http.StatusForbidden }}
	srv := v.server(t)

	now := time.Now()
	clock := func() time.Time { return now }
	a := newAuth(t, srv.URL+"/auth", clock)
	hdr := basicHeader("sys-1", "secret")

	if _, err := a.Validate(context.Background(), hdr, "ng-blacklist"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("priming call: error %v, want ErrForbidden", err)
	}

	now = now.Add(a.NegativeTTL + time.Second)
	srv.Close()

	_, err := a.Validate(context.Background(), hdr, "ng-blacklist")
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("error %v, want the stale ErrForbidden entry to answer", err)
	}
}

func TestCacheKeyDependsOnTheService(t *testing.T) {
	a := newAuth(t, "http://unused.invalid", time.Now)
	base := a.cacheKey("", "sys-1", "secret")
	svc := a.cacheKey("ng-blacklist", "sys-1", "secret")
	other := a.cacheKey("other", "sys-1", "secret")
	if base == svc || base == other || svc == other {
		t.Fatalf("cache keys collided across services: %q %q %q", base, svc, other)
	}
}

// A validator URL configured with a trailing slash must not produce
// "<base>//service/<name>" -- some routers 404 that, which would degrade
// every entitlement check to "unavailable" and 503 the whole feed.
func TestServiceURLToleratesATrailingSlashOnTheBase(t *testing.T) {
	v := &pathRecordingValidator{status: func(string) int { return http.StatusOK }}
	srv := v.server(t)
	defer srv.Close()

	a := newAuth(t, srv.URL+"/auth/", time.Now)
	if _, err := a.Validate(context.Background(), basicHeader("sys-1", "secret"), "ng-blacklist"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := v.seen(); len(got) != 1 || got[0] != "/auth/service/ng-blacklist" {
		t.Fatalf("validator called on %v, want [/auth/service/ng-blacklist]", got)
	}
}
