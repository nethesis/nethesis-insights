// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/store"
)

// fakeWriter records the writes the UI asked for, so each test can assert on
// the actor that was attributed as well as on the effect.
type fakeWriter struct {
	upserted []store.AllowlistRow
	deleted  []string
	reviews  []review
	audit    []auditCall
	err      error
}

type review struct{ cidr, state, decidedBy, note string }

type auditCall struct{ cidr, action, actor, detail string }

func (f *fakeWriter) UpsertThreatAllowlistEntry(_ context.Context, e store.AllowlistRow) error {
	if f.err != nil {
		return f.err
	}
	f.upserted = append(f.upserted, e)
	return nil
}

func (f *fakeWriter) DeleteThreatAllowlistEntry(_ context.Context, cidr string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	f.deleted = append(f.deleted, cidr)
	return true, nil
}

func (f *fakeWriter) UpsertAllowlistReview(_ context.Context, cidr, state, decidedBy, note string, _ int64) error {
	if f.err != nil {
		return f.err
	}
	f.reviews = append(f.reviews, review{cidr, state, decidedBy, note})
	return nil
}

func (f *fakeWriter) AppendAllowlistAudit(_ context.Context, cidr, action, actor, detail string, _ int64) error {
	if f.err != nil {
		return f.err
	}
	f.audit = append(f.audit, auditCall{cidr, action, actor, detail})
	return nil
}

const testAdminKey = "dev-admin-key"

// writeReq builds a same-origin form POST, the shape a browser submitting one
// of the UI's own forms produces.
func writeReq(path string, form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Origin", "http://"+req.Host)
	return req
}

func do(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

var writePaths = []string{
	"/blocklist/allowlist",
	"/blocklist/allowlist/delete",
	"/allowlist-requests/approve",
	"/allowlist-requests/reject",
}

// With no admin key configured the dashboard is exactly the read-only page it
// has always been: the write routes are not merely unauthorized, they do not
// exist as writes at all.
func TestWriteRoutesAreNotReachableWithoutAnAdminKey(t *testing.T) {
	w := &fakeWriter{}
	h := newTestServerWithFeed(t, threatReader(), nil, nil) // no writer, no key

	for _, p := range writePaths {
		rec := do(h, writeReq(p, url.Values{"cidr": {"203.0.113.0/24"}}))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s with no admin key: got %d, want 405", p, rec.Code)
		}
	}
	if len(w.upserted) != 0 || len(w.deleted) != 0 {
		t.Fatal("a write reached the store with no admin key configured")
	}
}

func TestWriteRoutesRequireTheAdminKey(t *testing.T) {
	w := &fakeWriter{}
	h := newWriteTestServer(t, threatReader(), nil, nil, w, testAdminKey)

	t.Run("no credential", func(t *testing.T) {
		rec := do(h, writeReq("/blocklist/allowlist", url.Values{"cidr": {"203.0.113.0/24"}}))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status: got %d, want 401", rec.Code)
		}
		if rec.Header().Get("WWW-Authenticate") == "" {
			t.Fatal("no WWW-Authenticate header, so the browser will never prompt")
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		req := writeReq("/blocklist/allowlist", url.Values{"cidr": {"203.0.113.0/24"}})
		req.SetBasicAuth("alice", "not-the-key")
		if rec := do(h, req); rec.Code != http.StatusUnauthorized {
			t.Fatalf("status: got %d, want 401", rec.Code)
		}
	})

	if len(w.upserted) != 0 {
		t.Fatalf("an unauthenticated write reached the store: %+v", w.upserted)
	}
}

// The Basic username is the actor. It is the whole reason the UI needs no
// separate actor field.
func TestWriteRecordsTheBasicUsernameAsTheActor(t *testing.T) {
	w := &fakeWriter{}
	h := newWriteTestServer(t, threatReader(), nil, nil, w, testAdminKey)

	req := writeReq("/blocklist/allowlist", url.Values{
		"cidr":   {"203.0.113.0/24"},
		"reason": {"partner scanner"},
	})
	req.SetBasicAuth("alice", testAdminKey)

	rec := do(h, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status: got %d, want 303 (body %s)", rec.Code, rec.Body.String())
	}
	if len(w.upserted) != 1 {
		t.Fatalf("upserted: %+v", w.upserted)
	}
	if got := w.upserted[0]; got.CIDR != "203.0.113.0/24" || got.CreatedBy != "alice" || got.Reason != "partner scanner" {
		t.Fatalf("upserted row: %+v", got)
	}
	if len(w.audit) != 1 || w.audit[0].actor != "alice" {
		t.Fatalf("audit: %+v, want exactly one row attributed to alice", w.audit)
	}
}

// An empty username would produce an audit trail attributed to nobody, which
// is the one thing the actor exists to prevent.
func TestWriteRejectsAnEmptyActor(t *testing.T) {
	w := &fakeWriter{}
	h := newWriteTestServer(t, threatReader(), nil, nil, w, testAdminKey)

	req := writeReq("/blocklist/allowlist", url.Values{"cidr": {"203.0.113.0/24"}})
	req.SetBasicAuth("", testAdminKey)

	if rec := do(h, req); rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", rec.Code)
	}
	if len(w.upserted) != 0 {
		t.Fatal("a write with no actor reached the store")
	}
}

// The write routes authenticate with HTTP Basic, and a browser replays a
// cached Basic credential automatically on every later request to the same
// origin -- including a form POST from an unrelated site the operator visits
// afterwards. Without this guard any page could add an attacker's address to
// the fleet allowlist silently and permanently, which is exactly the harm the
// no-automatic-promotion rule exists to prevent.
func TestWriteRefusesCrossSiteRequests(t *testing.T) {
	cases := []struct {
		name          string
		secFetchSite  string
		origin        string
		wantForbidden bool
	}{
		{name: "cross-site form post", secFetchSite: "cross-site", origin: "http://evil.example", wantForbidden: true},
		{name: "same-site but not same-origin", secFetchSite: "same-site", origin: "http://evil.example", wantForbidden: true},
		{name: "mismatched origin alone", origin: "http://evil.example", wantForbidden: true},
		{name: "same-origin", secFetchSite: "same-origin", origin: "SELF"},
		{name: "address bar navigation", secFetchSite: "none"},
		// A non-browser client carries no ambient credential to abuse, so
		// refusing it would break the scripted path without closing anything.
		{name: "no browser headers at all (curl)"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &fakeWriter{}
			h := newWriteTestServer(t, threatReader(), nil, nil, w, testAdminKey)

			req := httptest.NewRequest(http.MethodPost, "/blocklist/allowlist",
				strings.NewReader(url.Values{"cidr": {"203.0.113.0/24"}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.secFetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.secFetchSite)
			}
			switch tc.origin {
			case "":
			case "SELF":
				req.Header.Set("Origin", "http://"+req.Host)
			default:
				req.Header.Set("Origin", tc.origin)
			}
			req.SetBasicAuth("alice", testAdminKey)

			rec := do(h, req)

			if tc.wantForbidden {
				if rec.Code != http.StatusForbidden {
					t.Fatalf("status: got %d, want 403", rec.Code)
				}
				if len(w.upserted) != 0 {
					t.Fatalf("a cross-site write reached the store: %+v", w.upserted)
				}
				return
			}
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("status: got %d, want 303 (body %s)", rec.Code, rec.Body.String())
			}
			if len(w.upserted) != 1 {
				t.Fatalf("upserted: %+v, want the write to go through", w.upserted)
			}
		})
	}
}

// A forged cross-site request must be refused outright, never answered with
// a 401 that would prompt the operator for a password on somebody else's form.
func TestCrossSiteWriteIsRefusedBeforeTheCredentialIsChecked(t *testing.T) {
	w := &fakeWriter{}
	h := newWriteTestServer(t, threatReader(), nil, nil, w, testAdminKey)

	req := httptest.NewRequest(http.MethodPost, "/blocklist/allowlist",
		strings.NewReader(url.Values{"cidr": {"203.0.113.0/24"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	// Deliberately no credential: the answer must still be 403, not 401.

	rec := do(h, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") != "" {
		t.Fatal("a forged cross-site form must never make the browser prompt for a password")
	}
}

func TestApproveAndRejectRecordTheReviewAndAudit(t *testing.T) {
	for _, tc := range []struct {
		path, wantState, wantAction string
	}{
		{"/allowlist-requests/approve", "approved", "request.approve"},
		{"/allowlist-requests/reject", "rejected", "request.reject"},
	} {
		t.Run(tc.wantState, func(t *testing.T) {
			w := &fakeWriter{}
			h := newWriteTestServer(t, threatReader(), nil, nil, w, testAdminKey)

			req := writeReq(tc.path, url.Values{"cidr": {"203.0.113.0/24"}, "note": {"looks fine"}})
			req.SetBasicAuth("bob", testAdminKey)

			rec := do(h, req)

			if rec.Code != http.StatusSeeOther {
				t.Fatalf("status: got %d, want 303 (body %s)", rec.Code, rec.Body.String())
			}
			if len(w.reviews) != 1 {
				t.Fatalf("reviews: %+v", w.reviews)
			}
			got := w.reviews[0]
			if got.state != tc.wantState || got.decidedBy != "bob" || got.cidr != "203.0.113.0/24" {
				t.Fatalf("review: %+v", got)
			}
			if len(w.audit) == 0 || w.audit[len(w.audit)-1].actor != "bob" {
				t.Fatalf("audit: %+v", w.audit)
			}
		})
	}
}

// Approving is the ONLY path from a client request to an allowlist entry.
// Rejecting must never create one.
func TestRejectingARequestNeverCreatesAnAllowlistEntry(t *testing.T) {
	w := &fakeWriter{}
	h := newWriteTestServer(t, threatReader(), nil, nil, w, testAdminKey)

	req := writeReq("/allowlist-requests/reject", url.Values{"cidr": {"203.0.113.0/24"}})
	req.SetBasicAuth("bob", testAdminKey)
	do(h, req)

	if len(w.upserted) != 0 {
		t.Fatalf("rejecting created an allowlist entry: %+v", w.upserted)
	}
}

// Turning writes on must not change the read surface at all: every page still
// answers GET with no credential whatsoever.
func TestEnablingWritesLeavesEveryGETUnauthenticated(t *testing.T) {
	h := newWriteTestServer(t, threatReader(), nil, nil, &fakeWriter{}, testAdminKey)

	for _, rt := range routes {
		rec := get(t, h, rt.path)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s with writes enabled: got %d, want 200", rt.path, rec.Code)
		}
	}
}

// A GET to a write-only path is still a 404 from the read dispatcher, not a
// half-open write surface.
func TestGetOnAWriteOnlyPathIsNotFound(t *testing.T) {
	h := newWriteTestServer(t, threatReader(), nil, nil, &fakeWriter{}, testAdminKey)

	for _, p := range writePaths {
		if rec := get(t, h, p); rec.Code != http.StatusNotFound {
			t.Fatalf("GET %s: got %d, want 404", p, rec.Code)
		}
	}
}

// The prefix guardrail has to hold at the UI too, not only in the admin API:
// 0.0.0.0/0 on the allowlist silently disables the entire feed.
func TestWriteEnforcesThePrefixGuardrail(t *testing.T) {
	w := &fakeWriter{}
	h := newWriteTestServer(t, threatReader(), nil, nil, w, testAdminKey)

	req := writeReq("/blocklist/allowlist", url.Values{"cidr": {"0.0.0.0/0"}})
	req.SetBasicAuth("alice", testAdminKey)

	if rec := do(h, req); rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", rec.Code)
	}
	if len(w.upserted) != 0 {
		t.Fatalf("an over-broad prefix was written: %+v", w.upserted)
	}

	// ... and goes through when the operator says force.
	forced := writeReq("/blocklist/allowlist", url.Values{"cidr": {"0.0.0.0/0"}, "force": {"1"}})
	forced.SetBasicAuth("alice", testAdminKey)
	if rec := do(h, forced); rec.Code != http.StatusSeeOther {
		t.Fatalf("forced status: got %d, want 303", rec.Code)
	}
	if len(w.upserted) != 1 {
		t.Fatalf("forced write did not land: %+v", w.upserted)
	}
}
