// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/store"
)

const testAdminKey = "s3cret-admin-key"

var adminNow = int64(1700000000000)

// fakeStore is an in-package stand-in for AllowlistStore.
type fakeStore struct {
	entries  []store.AllowlistRow
	pending  []store.AllowlistRequestRow
	audit    []store.AllowlistAuditRow
	upserts  []store.AllowlistRow
	deletes  []string
	reviews  []reviewCall
	auditErr error
	err      error // when set, every method that can fail returns this
}

type reviewCall struct {
	cidr, state, decidedBy, note string
}

func (f *fakeStore) ListThreatAllowlist(context.Context) ([]store.AllowlistRow, error) {
	return f.entries, f.err
}

func (f *fakeStore) UpsertThreatAllowlistEntry(_ context.Context, e store.AllowlistRow) error {
	if f.err != nil {
		return f.err
	}
	f.upserts = append(f.upserts, e)
	f.entries = append(f.entries, e)
	return nil
}

func (f *fakeStore) DeleteThreatAllowlistEntry(_ context.Context, cidr string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	for i, e := range f.entries {
		if e.CIDR == cidr {
			f.entries = append(f.entries[:i], f.entries[i+1:]...)
			f.deletes = append(f.deletes, cidr)
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeStore) PendingAllowlistRequests(context.Context, int) ([]store.AllowlistRequestRow, error) {
	return f.pending, f.err
}

func (f *fakeStore) UpsertAllowlistReview(_ context.Context, cidr, state, decidedBy, note string, _ int64) error {
	if f.err != nil {
		return f.err
	}
	f.reviews = append(f.reviews, reviewCall{cidr, state, decidedBy, note})
	return nil
}

func (f *fakeStore) AppendAllowlistAudit(_ context.Context, cidr, action, actor, detail string, at int64) error {
	if f.auditErr != nil {
		return f.auditErr
	}
	f.audit = append(f.audit, store.AllowlistAuditRow{CIDR: cidr, Action: action, Actor: actor, Detail: detail, At: at})
	return nil
}

func (f *fakeStore) ListAllowlistAudit(context.Context, int) ([]store.AllowlistAuditRow, error) {
	return f.audit, f.err
}

func testServer(st AllowlistStore) http.Handler {
	return NewServer(st, testAdminKey, func() int64 { return adminNow })
}

func doReq(t *testing.T, h http.Handler, method, target, body string, bearer bool, actor string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if bearer {
		req.Header.Set("Authorization", "Bearer "+testAdminKey)
	}
	if actor != "" {
		req.Header.Set("X-Admin-Actor", actor)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Every route on this listener requires the bearer key, reads included:
// unlike the operator UI, there is no unauthenticated half here.
func TestAdminRoutesRequireTheBearerKey(t *testing.T) {
	h := testServer(&fakeStore{})
	routes := []struct{ method, path string }{
		{http.MethodGet, "/admin/v1/allowlist"},
		{http.MethodPost, "/admin/v1/allowlist"},
		{http.MethodDelete, "/admin/v1/allowlist?cidr=203.0.113.0/24"},
		{http.MethodGet, "/admin/v1/allowlist/requests"},
		{http.MethodPost, "/admin/v1/allowlist/requests/approve"},
		{http.MethodPost, "/admin/v1/allowlist/requests/reject"},
		{http.MethodGet, "/admin/v1/allowlist/audit"},
	}
	for _, rt := range routes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			rec := doReq(t, h, rt.method, rt.path, "", false, "alice")
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("no bearer key: got %d, want 401", rec.Code)
			}
		})
	}
}

func TestAdminRejectsAWrongBearerKey(t *testing.T) {
	h := testServer(&fakeStore{})
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/allowlist", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key: got %d, want 401", rec.Code)
	}
}

// X-Admin-Actor is required on every write; a missing or empty one is 400,
// never silently accepted as an anonymous write.
func TestAdminWritesRequireAnActor(t *testing.T) {
	h := testServer(&fakeStore{})
	writes := []struct {
		method, path, body string
	}{
		{http.MethodPost, "/admin/v1/allowlist", `{"cidr":"203.0.113.0/24","reason":"x"}`},
		{http.MethodDelete, "/admin/v1/allowlist?cidr=203.0.113.0/24", ""},
		{http.MethodPost, "/admin/v1/allowlist/requests/approve", `{"cidr":"203.0.113.0/24"}`},
		{http.MethodPost, "/admin/v1/allowlist/requests/reject", `{"cidr":"203.0.113.0/24"}`},
	}
	for _, w := range writes {
		t.Run(w.method+" "+w.path, func(t *testing.T) {
			rec := doReq(t, h, w.method, w.path, w.body, true, "")
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("missing actor: got %d, want 400 (body %s)", rec.Code, rec.Body.String())
			}
		})
	}
}

// Reads never require an actor -- only writes carry attribution.
func TestAdminReadsDoNotRequireAnActor(t *testing.T) {
	h := testServer(&fakeStore{})
	reads := []string{"/admin/v1/allowlist", "/admin/v1/allowlist/requests", "/admin/v1/allowlist/audit"}
	for _, path := range reads {
		rec := doReq(t, h, http.MethodGet, path, "", true, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s without an actor: got %d, want 200", path, rec.Code)
		}
	}
}

// POST of an already-present CIDR is 200, never an error -- the plan is
// explicit that this must not behave like a naive REST conflict.
func TestAddAllowlistIsIdempotent(t *testing.T) {
	st := &fakeStore{}
	h := testServer(st)

	for i := 0; i < 2; i++ {
		rec := doReq(t, h, http.MethodPost, "/admin/v1/allowlist",
			`{"cidr":"203.0.113.0/24","reason":"partner scanner"}`, true, "alice")
		if rec.Code != http.StatusOK {
			t.Fatalf("attempt %d: got %d, want 200 (body %s)", i, rec.Code, rec.Body.String())
		}
	}
	if len(st.upserts) != 2 {
		t.Fatalf("upserts: got %d, want 2 (both attempts must reach the store)", len(st.upserts))
	}
	if len(st.audit) != 2 {
		t.Fatalf("audit rows: got %d, want one per write", len(st.audit))
	}
}

// A bare address normalizes to /32 before it reaches the store.
func TestAddAllowlistNormalizesABareAddress(t *testing.T) {
	st := &fakeStore{}
	h := testServer(st)
	rec := doReq(t, h, http.MethodPost, "/admin/v1/allowlist", `{"cidr":"203.0.113.7","reason":"x"}`, true, "alice")
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if len(st.upserts) != 1 || st.upserts[0].CIDR != "203.0.113.7/32" {
		t.Fatalf("stored entry: got %+v, want 203.0.113.7/32", st.upserts)
	}
}

// A prefix wider than the guardrail floor is rejected without force, and
// accepted with it -- 0.0.0.0/0 would otherwise silently disable the feed.
func TestAddAllowlistEnforcesTheOverBroadGuardrail(t *testing.T) {
	st := &fakeStore{}
	h := testServer(st)

	rec := doReq(t, h, http.MethodPost, "/admin/v1/allowlist", `{"cidr":"0.0.0.0/0","reason":"oops"}`, true, "alice")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("without force: got %d, want 400", rec.Code)
	}
	if len(st.upserts) != 0 {
		t.Fatal("an over-broad prefix reached the store without force")
	}

	rec = doReq(t, h, http.MethodPost, "/admin/v1/allowlist", `{"cidr":"0.0.0.0/0","reason":"oops","force":true}`, true, "alice")
	if rec.Code != http.StatusOK {
		t.Fatalf("with force: got %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if len(st.upserts) != 1 {
		t.Fatal("force did not let the entry through")
	}
}

// DELETE of a missing entry is 404; DELETE of a present one is 200 and
// appends exactly one audit row.
func TestDeleteAllowlist(t *testing.T) {
	st := &fakeStore{entries: []store.AllowlistRow{{CIDR: "203.0.113.0/24", CreatedAt: 1}}}
	h := testServer(st)

	rec := doReq(t, h, http.MethodDelete, "/admin/v1/allowlist?cidr=198.51.100.0/24", "", true, "alice")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing entry: got %d, want 404", rec.Code)
	}

	rec = doReq(t, h, http.MethodDelete, "/admin/v1/allowlist?cidr=203.0.113.0/24", "", true, "alice")
	if rec.Code != http.StatusOK {
		t.Fatalf("present entry: got %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if len(st.deletes) != 1 || len(st.audit) != 1 || st.audit[0].Action != "allowlist.delete" {
		t.Fatalf("delete/audit bookkeeping: deletes=%v audit=%+v", st.deletes, st.audit)
	}
}

// The CIDR travels in the query string, never a path segment.
func TestDeleteAllowlistRequiresTheCIDRQueryParameter(t *testing.T) {
	h := testServer(&fakeStore{})
	rec := doReq(t, h, http.MethodDelete, "/admin/v1/allowlist", "", true, "alice")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", rec.Code)
	}
}

// GET /admin/v1/allowlist/requests serves the ranked pending queue.
func TestListPendingRequests(t *testing.T) {
	st := &fakeStore{pending: []store.AllowlistRequestRow{
		{CIDR: "203.0.113.0/24", DistinctSystems: 5, Reasons: []string{"partner scanner"}},
	}}
	h := testServer(st)
	rec := doReq(t, h, http.MethodGet, "/admin/v1/allowlist/requests", "", true, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "203.0.113.0/24") || !strings.Contains(rec.Body.String(), "partner scanner") {
		t.Fatalf("body missing the pending request: %s", rec.Body.String())
	}
}

// Approving is the only path in this codebase that turns a request into a
// live entry -- this is the executable form of "no automatic promotion".
func TestApproveCreatesTheEntryAndRetiresTheRequest(t *testing.T) {
	st := &fakeStore{}
	h := testServer(st)

	rec := doReq(t, h, http.MethodPost, "/admin/v1/allowlist/requests/approve",
		`{"cidr":"203.0.113.0/24","note":"confirmed with the customer"}`, true, "alice")
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if len(st.upserts) != 1 || st.upserts[0].CIDR != "203.0.113.0/24" || st.upserts[0].CreatedBy != "alice" {
		t.Fatalf("upserted entry: got %+v", st.upserts)
	}
	if len(st.reviews) != 1 || st.reviews[0].state != store.AllowlistReviewApproved || st.reviews[0].decidedBy != "alice" {
		t.Fatalf("review: got %+v", st.reviews)
	}
	if len(st.audit) != 1 || st.audit[0].Action != "request.approve" || st.audit[0].Actor != "alice" {
		t.Fatalf("audit: got %+v", st.audit)
	}
}

// Approving an over-broad CIDR is guarded exactly like a direct POST.
func TestApproveEnforcesTheOverBroadGuardrail(t *testing.T) {
	st := &fakeStore{}
	h := testServer(st)
	rec := doReq(t, h, http.MethodPost, "/admin/v1/allowlist/requests/approve",
		`{"cidr":"0.0.0.0/0"}`, true, "alice")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", rec.Code)
	}
	if len(st.upserts) != 0 {
		t.Fatal("an over-broad approval reached the store without force")
	}
}

// Rejecting creates no entry at all.
func TestRejectCreatesNoEntry(t *testing.T) {
	st := &fakeStore{}
	h := testServer(st)

	rec := doReq(t, h, http.MethodPost, "/admin/v1/allowlist/requests/reject",
		`{"cidr":"203.0.113.0/24","note":"not enough evidence"}`, true, "alice")
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if len(st.upserts) != 0 {
		t.Fatal("a rejection must never create an allowlist entry")
	}
	if len(st.reviews) != 1 || st.reviews[0].state != store.AllowlistReviewRejected {
		t.Fatalf("review: got %+v", st.reviews)
	}
	if len(st.audit) != 1 || st.audit[0].Action != "request.reject" {
		t.Fatalf("audit: got %+v", st.audit)
	}
}

func TestAuditEndpointListsRows(t *testing.T) {
	st := &fakeStore{audit: []store.AllowlistAuditRow{{ID: "01AUDIT", CIDR: "203.0.113.0/24", Action: "allowlist.upsert", Actor: "alice", At: 1}}}
	h := testServer(st)
	rec := doReq(t, h, http.MethodGet, "/admin/v1/allowlist/audit", "", true, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "01AUDIT") {
		t.Fatalf("body missing the audit row: %s", rec.Body.String())
	}
}

// A store failure is a 503, never a silently swallowed error.
func TestAdminAnswers503WhenTheStoreFails(t *testing.T) {
	st := &fakeStore{err: errors.New("disk on fire")}
	h := testServer(st)
	for _, path := range []string{"/admin/v1/allowlist", "/admin/v1/allowlist/requests", "/admin/v1/allowlist/audit"} {
		rec := doReq(t, h, http.MethodGet, path, "", true, "")
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: got %d, want 503", path, rec.Code)
		}
	}
}

// A failed audit append must not fail the write it is describing: the
// mutation already happened, and losing the trail is a lesser failure than
// reporting a successful write as an error.
func TestAWriteSucceedsEvenWhenTheAuditAppendFails(t *testing.T) {
	st := &fakeStore{auditErr: errors.New("disk on fire")}
	h := testServer(st)
	rec := doReq(t, h, http.MethodPost, "/admin/v1/allowlist", `{"cidr":"203.0.113.0/24","reason":"x"}`, true, "alice")
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 despite the audit failure (body %s)", rec.Code, rec.Body.String())
	}
}

func TestAdminRejectsWrongMethod(t *testing.T) {
	h := testServer(&fakeStore{})
	rec := doReq(t, h, http.MethodPut, "/admin/v1/allowlist", "", true, "alice")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d, want 405", rec.Code)
	}
}
