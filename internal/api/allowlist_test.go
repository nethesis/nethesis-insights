// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/store"
)

// newAllowlistTestStore builds a real, temp-file SQLite store. The
// client-facing allowlist-request handler is tested against the real store
// package (rather than a hand-rolled fake of the whole store.Store
// interface) for the same reason blocklist and analyzer are: the
// idempotency and distinct-system counting live in the SQL, not in a mock
// that would just reimplement it.
func newAllowlistTestStore(t *testing.T) *store.SQLiteStore {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func allowlistServer(st store.Store) http.Handler {
	return NewServer(&fakePublisher{}, st,
		StaticAuth{SystemID: testSystemID, Secret: testSecret},
		ThreatConfig{
			Store:        &fakeThreatStore{},
			Feed:         &fakeFeed{},
			MaxDecisions: 500,
			Now:          func() int64 { return threatNow },
		}, SizingConfig{}, nil, nil)
}

func postAllowlistRequest(t *testing.T, h http.Handler, body string, withAuth bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/allowlist-requests", strings.NewReader(body))
	if withAuth {
		req.SetBasicAuth(testSystemID, testSecret)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAllowlistRequestIsAccepted(t *testing.T) {
	h := allowlistServer(newAllowlistTestStore(t))
	rec := postAllowlistRequest(t, h, `{"cidr":"203.0.113.0/24","reason":"partner's vulnerability scanner"}`, true)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"accepted":true`) || !strings.Contains(rec.Body.String(), `"requests":1`) {
		t.Fatalf("body: got %s", rec.Body.String())
	}
}

// Idempotent per (cidr, system_id): the same authenticated system asking
// twice counts once, mirroring the blocklist's own distinct-system rule.
func TestAllowlistRequestIsIdempotentPerSystem(t *testing.T) {
	h := allowlistServer(newAllowlistTestStore(t))

	first := postAllowlistRequest(t, h, `{"cidr":"203.0.113.0/24","reason":"first ask"}`, true)
	second := postAllowlistRequest(t, h, `{"cidr":"203.0.113.0/24","reason":"asking again"}`, true)

	if !strings.Contains(first.Body.String(), `"requests":1`) {
		t.Fatalf("first request: got %s, want requests:1", first.Body.String())
	}
	if !strings.Contains(second.Body.String(), `"requests":1`) {
		t.Fatalf("second request from the same system: got %s, want requests:1 (idempotent)", second.Body.String())
	}
}

// A bare address normalizes to /32 before it is stored, matching the admin
// path's normalization.
func TestAllowlistRequestNormalizesABareAddress(t *testing.T) {
	st := newAllowlistTestStore(t)
	h := allowlistServer(st)

	rec := postAllowlistRequest(t, h, `{"cidr":"203.0.113.7","reason":"x"}`, true)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202", rec.Code)
	}

	pending, err := st.PendingAllowlistRequests(context.Background(), 0)
	if err != nil {
		t.Fatalf("PendingAllowlistRequests: %v", err)
	}
	if len(pending) != 1 || pending[0].CIDR != "203.0.113.7/32" {
		t.Fatalf("pending: got %+v, want 203.0.113.7/32", pending)
	}
}

// The over-broad-prefix guardrail does NOT apply to a request -- it is a
// review queue, not a promotion, and a human decides at approval time.
func TestAllowlistRequestAcceptsAnOverBroadCIDR(t *testing.T) {
	h := allowlistServer(newAllowlistTestStore(t))
	rec := postAllowlistRequest(t, h, `{"cidr":"0.0.0.0/0","reason":"please"}`, true)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestAllowlistRequestRejectsGarbage(t *testing.T) {
	h := allowlistServer(newAllowlistTestStore(t))
	rec := postAllowlistRequest(t, h, `{"cidr":"not-a-cidr","reason":"x"}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", rec.Code)
	}
}

func TestAllowlistRequestRequiresAuthentication(t *testing.T) {
	h := allowlistServer(newAllowlistTestStore(t))
	rec := postAllowlistRequest(t, h, `{"cidr":"203.0.113.0/24","reason":"x"}`, false)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
}

func TestAllowlistRequestRejectsWrongMethod(t *testing.T) {
	h := allowlistServer(newAllowlistTestStore(t))
	req := httptest.NewRequest(http.MethodGet, "/v1/allowlist-requests", nil)
	req.SetBasicAuth(testSystemID, testSecret)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d, want 405", rec.Code)
	}
}

// The route is part of the Threat Shield surface: the zero ThreatConfig
// leaves it off exactly like /v1/threat-events and /v1/blocklist.
func TestAllowlistRequestRouteIsAbsentWhenThreatShieldIsUnconfigured(t *testing.T) {
	h := testServer(&fakePublisher{})
	req := httptest.NewRequest(http.MethodPost, "/v1/allowlist-requests", strings.NewReader(`{}`))
	req.SetBasicAuth(testSystemID, testSecret)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d, want 404", rec.Code)
	}
}

// This is the executable form of "no automatic promotion" at the API
// boundary: however many distinct systems request a CIDR through this
// endpoint, it must never appear in the live allowlist. The one
// StaticAuth-authenticated call exercises the real HTTP path; the rest use
// the store directly to simulate other systems, since StaticAuth only ever
// accepts a single configured credential.
func TestAllowlistRequestsNeverAutoPromote(t *testing.T) {
	st := newAllowlistTestStore(t)
	h := allowlistServer(st)
	const cidr = "203.0.113.0/24"

	rec := postAllowlistRequest(t, h, `{"cidr":"`+cidr+`","reason":"please"}`, true)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202", rec.Code)
	}
	for _, sys := range []string{"sys-b", "sys-c", "sys-d", "sys-e"} {
		if _, err := st.UpsertAllowlistRequest(context.Background(), cidr, sys, "please", threatNow); err != nil {
			t.Fatalf("UpsertAllowlistRequest(%s): %v", sys, err)
		}
	}

	pending, err := st.PendingAllowlistRequests(context.Background(), 0)
	if err != nil {
		t.Fatalf("PendingAllowlistRequests: %v", err)
	}
	if len(pending) != 1 || pending[0].DistinctSystems != 5 {
		t.Fatalf("pending queue: got %+v, want one CIDR with 5 distinct systems", pending)
	}

	entries, err := st.ListThreatAllowlist(context.Background())
	if err != nil {
		t.Fatalf("ListThreatAllowlist: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("ListThreatAllowlist: got %+v, want no entries -- requests must never auto-promote", entries)
	}
}
