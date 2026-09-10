// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package threat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	threatstore "github.com/nethesis/nethesis-insights/internal/store/threat"
)

// newAllowlistTestStore builds a real, temp-file SQLite store. The
// client-facing allowlist-request handler is tested against the real store
// package (rather than a hand-rolled fake of the whole Store interface) for
// the same reason blocklist and analyzer are: the idempotency and
// distinct-system counting live in the SQL, not in a mock that would just
// reimplement it.
func newAllowlistTestStore(t *testing.T) *threatstore.Store {
	t.Helper()
	s, err := threatstore.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func allowlistServer(st Store) http.Handler {
	// No queue and no blocklist snapshot: these tests exercise only
	// /v1/allowlist-requests, which touches neither.
	return NewServer(st, nil, nil, trustedProxy, Config{
		MaxDecisions: 500,
		Now:          func() int64 { return threatNow },
	})
}

func postAllowlistRequest(t *testing.T, h http.Handler, body string, withAuth bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/allowlist-requests", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
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

// The over-broad-prefix guardrail applies to a request too. There is no
// override at approval time any more, so a prefix this wide could never
// become an entry -- queueing it would only put a row in front of an admin
// that they have no way to say yes to.
func TestAllowlistRequestRejectsAnOverBroadCIDR(t *testing.T) {
	h := allowlistServer(newAllowlistTestStore(t))
	for _, cidr := range []string{"0.0.0.0/0", "203.0.113.0/16", "2001:db8::/32", "::ffff:0.0.0.0/96"} {
		rec := postAllowlistRequest(t, h, `{"cidr":"`+cidr+`","reason":"please"}`, true)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d, want 400 (body %s)", cidr, rec.Code, rec.Body.String())
		}
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
	req.RemoteAddr = "127.0.0.1:12345"
	req.SetBasicAuth(testSystemID, testSecret)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d, want 405", rec.Code)
	}
}

// This is the executable form of "no automatic promotion" at the API
// boundary: however many distinct systems request a CIDR through this
// endpoint, it must never appear in the live allowlist. The one
// HTTP-authenticated call exercises the real path; the rest use the store
// directly to simulate other systems.
func TestAllowlistRequestsNeverAutoPromote(t *testing.T) {
	st := newAllowlistTestStore(t)
	h := allowlistServer(st)
	const cidr = "203.0.113.0/24"

	rec := postAllowlistRequest(t, h, `{"cidr":"`+cidr+`","reason":"please"}`, true)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202", rec.Code)
	}
	for _, sys := range []string{"sys-b", "sys-c", "sys-d", "sys-e"} {
		if _, err := st.UpsertAllowlistRequest(context.Background(), cidr, sys, "please", threatNow, 0); err != nil {
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

// The per-system cap is enforced at ingest, like every other bound in this
// pipeline: a client request is a permanent row, so an uncapped one is an
// uncapped table. 429 rather than 400 -- the request is well formed, the
// system has simply used up its share of the review queue -- and the
// existing rows are untouched.
func TestAllowlistRequestRefusesASystemPastItsCap(t *testing.T) {
	st := newAllowlistTestStore(t)
	h := NewServer(st, nil, nil, trustedProxy, Config{
		MaxDecisions:               500,
		MaxAllowlistRequestsPerSys: 2,
		Now:                        func() int64 { return threatNow },
	})

	for _, cidr := range []string{"203.0.113.0/24", "198.51.100.0/24"} {
		rec := postAllowlistRequest(t, h, `{"cidr":"`+cidr+`","reason":"please"}`, true)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("%s: status %d, want 202 (body %s)", cidr, rec.Code, rec.Body.String())
		}
	}

	rec := postAllowlistRequest(t, h, `{"cidr":"192.0.2.0/24","reason":"one too many"}`, true)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-cap status: got %d, want 429 (body %s)", rec.Code, rec.Body.String())
	}

	// Refreshing a CIDR already asked about is still accepted at the cap:
	// it adds no row.
	again := postAllowlistRequest(t, h, `{"cidr":"203.0.113.0/24","reason":"still want it"}`, true)
	if again.Code != http.StatusAccepted {
		t.Fatalf("refresh at the cap: got %d, want 202 (body %s)", again.Code, again.Body.String())
	}

	pending, err := st.PendingAllowlistRequests(context.Background(), 0)
	if err != nil {
		t.Fatalf("PendingAllowlistRequests: %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("pending CIDRs: got %d, want 2 -- the refused request must store nothing", len(pending))
	}
}
