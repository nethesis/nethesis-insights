// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
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
		systemID, err := a.Validate(context.Background(), hdr)
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

func TestInvalidCredentialsAreCachedAndRejected(t *testing.T) {
	v := &validator{status: http.StatusUnauthorized}
	srv := v.server(t)
	defer srv.Close()

	a := newAuth(t, srv.URL, time.Now)
	hdr := basicHeader("sys-1", "wrong")

	for i := 0; i < 2; i++ {
		_, err := a.Validate(context.Background(), hdr)
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

	_, err := a.Validate(context.Background(), basicHeader("sys-1", "secret"))
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

	systemID, err := a.Validate(context.Background(), hdr)
	if err != nil || systemID != "sys-1" {
		t.Fatalf("priming call: systemID=%q err=%v", systemID, err)
	}

	// Expire the cache entry, then take the validator down.
	now = now.Add(a.PositiveTTL + time.Second)
	srv.Close()

	systemID, err = a.Validate(context.Background(), hdr)
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
			_, err := a.Validate(context.Background(), tc.hdr)
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("error %v, want ErrInvalidCredentials", err)
			}
		})
	}
	if got := atomic.LoadInt32(&v.calls); got != 0 {
		t.Fatalf("validator called %d times, want 0 -- malformed headers must be rejected locally", got)
	}
}

func TestCacheKeyDependsOnTheFullCredential(t *testing.T) {
	a := newAuth(t, "http://unused.invalid", time.Now)
	k1 := a.cacheKey("sys-1", "secret-a")
	k2 := a.cacheKey("sys-1", "secret-b")
	k3 := a.cacheKey("sys-2", "secret-a")
	if k1 == k2 || k1 == k3 || k2 == k3 {
		t.Fatalf("cache keys collided: %q %q %q", k1, k2, k3)
	}
}
