// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package logs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	logsstore "github.com/nethesis/nethesis-insights/internal/store/logs"
	"github.com/nethesis/nethesis-insights/internal/ui/chrome"
)

// fakeWriter records each decision the UI asked the store for, with its
// actor. The store's own tests cover the transaction and the audit row.
type fakeWriter struct {
	calls []string // "method key value actor"
	err   error
}

func (f *fakeWriter) record(parts ...string) error {
	if f.err != nil {
		return f.err
	}
	f.calls = append(f.calls, strings.Join(parts, " "))
	return nil
}

func (f *fakeWriter) SetClassVisibility(_ context.Context, key, visibility, actor string, _ int64) error {
	return f.record("visibility", key, visibility, actor)
}

func (f *fakeWriter) SetClassSecurity(_ context.Context, key string, security bool, actor string, _ int64) error {
	v := "off"
	if security {
		v = "on"
	}
	return f.record("security", key, v, actor)
}

func (f *fakeWriter) SetClassSeverity(_ context.Context, key, severity, actor string, _ int64) error {
	return f.record("severity", key, severity, actor)
}

func (f *fakeWriter) SetClassDocRef(_ context.Context, key, docRef, actor string, _ int64) error {
	return f.record("doc_ref", key, docRef, actor)
}

const testAdminKey = "dev-admin-key"

func newWriteTestServer(t *testing.T, r Reader, w Writer) http.Handler {
	t.Helper()
	h, err := NewServer(r, w, nil, chrome.Config{Info: testInfo(), AdminKey: testAdminKey})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return h
}

// writeReq builds an authenticated same-origin form POST, the shape a
// browser submitting one of the page's own forms produces.
func writeReq(path string, form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Origin", "http://"+req.Host)
	req.SetBasicAuth("alice", testAdminKey)
	return req
}

func do(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func reviewPaths() []string {
	var out []string
	for p := range writableRoutes {
		out = append(out, p)
	}
	return out
}

// Without ADMIN_API_KEY the review routes do not exist as writes, and the
// queue renders no form.
func TestReviewRoutesAreNotReachableWithoutAnAdminKey(t *testing.T) {
	w := &fakeWriter{}
	h, err := NewServer(seededReader(), w, nil, chrome.Config{Info: testInfo()})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range reviewPaths() {
		if rec := do(h, writeReq(p, url.Values{"key": {"v3:aaaa"}})); rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s with no admin key: got %d, want 405", p, rec.Code)
		}
	}
	if len(w.calls) != 0 {
		t.Fatalf("a decision reached the store with no admin key: %v", w.calls)
	}
	body := get(t, h, "/review").Body.String()
	if strings.Contains(body, `method="post"`) || !strings.Contains(body, "Read-only") {
		t.Fatal("the queue rendered decision forms without an admin key")
	}
}

func TestReviewWritesAreAuthenticatedAndSameOrigin(t *testing.T) {
	w := &fakeWriter{}
	h := newWriteTestServer(t, seededReader(), w)
	form := url.Values{"key": {"v3:aaaa"}}

	wrong := writeReq("/review/deliver", form)
	wrong.SetBasicAuth("alice", "not-the-key")
	if rec := do(h, wrong); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key: got %d, want 401", rec.Code)
	}

	forged := writeReq("/review/deliver", form)
	forged.Header.Set("Sec-Fetch-Site", "cross-site")
	forged.Header.Set("Origin", "https://evil.example")
	if rec := do(h, forged); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site: got %d, want 403", rec.Code)
	}

	head := writeReq("/review/deliver?key=v3:aaaa", nil)
	head.Method = http.MethodHead
	if rec := do(h, head); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("HEAD: got %d, want 405", rec.Code)
	}
	if len(w.calls) != 0 {
		t.Fatalf("a refused write reached the store: %v", w.calls)
	}
}

func TestReviewDecisionsReachTheStoreWithTheActor(t *testing.T) {
	for _, tc := range []struct {
		path string
		form url.Values
		want string
	}{
		{"/review/deliver", url.Values{"key": {"v3:aaaa"}}, "visibility v3:aaaa customer alice"},
		{"/review/internal", url.Values{"key": {"v3:aaaa"}}, "visibility v3:aaaa operator alice"},
		{"/review/security", url.Values{"key": {"v3:aaaa"}, "security": {"on"}}, "security v3:aaaa on alice"},
		{"/review/security", url.Values{"key": {"v3:aaaa"}, "security": {"off"}}, "security v3:aaaa off alice"},
		{"/review/severity", url.Values{"key": {"v3:aaaa"}, "severity": {"high"}}, "severity v3:aaaa high alice"},
		{"/review/severity", url.Values{"key": {"v3:aaaa"}, "severity": {""}}, "severity v3:aaaa  alice"},
		{"/review/doc-ref", url.Values{"key": {"v3:aaaa"}, "doc_ref": {"https://docs.example.org/fix"}}, "doc_ref v3:aaaa https://docs.example.org/fix alice"},
		{"/review/doc-ref", url.Values{"key": {"v3:aaaa"}, "doc_ref": {""}}, "doc_ref v3:aaaa  alice"},
	} {
		w := &fakeWriter{}
		h := newWriteTestServer(t, seededReader(), w)
		form := tc.form
		form.Set("view", "all")
		rec := do(h, writeReq(tc.path, form))
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("POST %s: got %d (%s), want 303", tc.path, rec.Code, rec.Body.String())
		}
		if loc := rec.Header().Get("Location"); loc != "/review?view=all" {
			t.Fatalf("POST %s redirected to %q", tc.path, loc)
		}
		if len(w.calls) != 1 || w.calls[0] != tc.want {
			t.Fatalf("POST %s: store calls %q, want %q", tc.path, w.calls, tc.want)
		}
	}
}

// Parameters come from the body only; a value in the query string is not a
// decision anyone submitted.
func TestReviewIgnoresQueryStringParameters(t *testing.T) {
	w := &fakeWriter{}
	h := newWriteTestServer(t, seededReader(), w)
	if rec := do(h, writeReq("/review/deliver?key=v3:aaaa", nil)); rec.Code != http.StatusBadRequest {
		t.Fatalf("key in the query string: got %d, want 400", rec.Code)
	}
	if len(w.calls) != 0 {
		t.Fatalf("store called: %v", w.calls)
	}
}

func TestReviewRejectsBadInput(t *testing.T) {
	for _, tc := range []struct {
		path string
		form url.Values
	}{
		{"/review/deliver", url.Values{}},
		{"/review/deliver", url.Values{"key": {strings.Repeat("k", maxClassKeyLen+1)}}},
		{"/review/security", url.Values{"key": {"v3:aaaa"}, "security": {"maybe"}}},
		{"/review/security", url.Values{"key": {"v3:aaaa"}, "security": {""}}},
		{"/review/severity", url.Values{"key": {"v3:aaaa"}, "severity": {"urgent"}}},
		{"/review/doc-ref", url.Values{"key": {"v3:aaaa"}, "doc_ref": {"javascript:alert(1)"}}},
		{"/review/doc-ref", url.Values{"key": {"v3:aaaa"}, "doc_ref": {"docs/fix.md"}}},
	} {
		w := &fakeWriter{}
		h := newWriteTestServer(t, seededReader(), w)
		if rec := do(h, writeReq(tc.path, tc.form)); rec.Code != http.StatusBadRequest {
			t.Errorf("POST %s %v: got %d, want 400", tc.path, tc.form, rec.Code)
		}
		if len(w.calls) != 0 {
			t.Errorf("POST %s %v reached the store: %v", tc.path, tc.form, w.calls)
		}
	}
}

func TestReviewMapsStoreRefusals(t *testing.T) {
	for err, want := range map[error]int{
		logsstore.ErrUnknownClass:      http.StatusNotFound,
		logsstore.ErrInvalidVisibility: http.StatusBadRequest,
		logsstore.ErrInvalidSeverity:   http.StatusBadRequest,
	} {
		h := newWriteTestServer(t, seededReader(), &fakeWriter{err: err})
		if rec := do(h, writeReq("/review/deliver", url.Values{"key": {"v3:aaaa"}})); rec.Code != want {
			t.Errorf("%v: got %d, want %d", err, rec.Code, want)
		}
	}
}

// A stale tab posting to a removed route must reach no store method.
func TestReviewHasNoIgnoreOrMergeRoute(t *testing.T) {
	w := &fakeWriter{}
	h := newWriteTestServer(t, seededReader(), w)
	for _, path := range []string{"/review/ignore", "/review/merge"} {
		rec := do(h, writeReq(path, url.Values{"key": {"v3:aaaa"}}))
		if rec.Code >= 200 && rec.Code < 400 {
			t.Errorf("POST %s: got %d, want a refusal", path, rec.Code)
		}
	}
	if len(w.calls) != 0 {
		t.Fatalf("a removed route reached the store: %v", w.calls)
	}
}

// The queue opens on pending classes; a link to one class (from a finding or
// the audit trail) finds it whatever it was decided.
func TestReviewQueueDefaultsToPending(t *testing.T) {
	r := seededReader()
	h := newTestServer(t, r, nil)

	body := get(t, h, "/review").Body.String()
	if r.classSeen.Visibility != logsstore.VisibilityPending {
		t.Fatalf("default view filtered on %q, want pending", r.classSeen.Visibility)
	}
	if !strings.Contains(body, "disk filling on mail") || strings.Contains(body, "sshd failing repeatedly") {
		t.Fatal("the pending queue shows the wrong classes")
	}

	get(t, h, "/review?key=v3:bbbb")
	if r.classSeen.Visibility != "" || r.classSeen.Key != "v3:bbbb" {
		t.Fatalf("a key link filtered on %+v, want every visibility", r.classSeen)
	}
	get(t, h, "/review?view=bogus")
	if r.classSeen.Visibility != logsstore.VisibilityPending {
		t.Fatalf("an unknown view filtered on %q, want pending", r.classSeen.Visibility)
	}
}

// A security class gets the same decision forms as any other.
func TestReviewOffersEveryDecisionForASecurityClass(t *testing.T) {
	r := seededReader()
	r.classes = []logsstore.ClassRow{
		{Class: logsstore.Class{Key: "v3:s", Visibility: logsstore.VisibilityPending, Security: true}},
	}
	body := get(t, newWriteTestServer(t, r, &fakeWriter{}), "/review?view=all").Body.String()
	for _, path := range []string{"/review/deliver", "/review/internal", "/review/security", "/review/severity", "/review/doc-ref"} {
		if !strings.Contains(body, path) {
			t.Errorf("a security class was not offered %s", path)
		}
	}
}

// Clicking a finding opens its detail in a modal <dialog> -- opened by an
// invoker button, not a script -- rather than expanding the row in place,
// which made a wide table wider. It closes from the header cross, a Close
// button at the bottom, and a click anywhere outside the article (the
// dialog-dismiss button behind it); Escape is native to a modal dialog.
func TestFindingDetailOpensInADialog(t *testing.T) {
	body := get(t, newTestServer(t, seededReader(), nil), "/").Body.String()
	id := "finding-01FINDINGID0000000000000000"
	for _, want := range []string{
		`commandfor="` + id + `" command="show-modal"`,
		`<dialog id="` + id + `"`,
		`rel="prev" commandfor="` + id + `" command="close"`,
		`class="secondary" commandfor="` + id + `" command="close">Close</button>`,
		`class="dialog-dismiss" tabindex="-1" aria-hidden="true" commandfor="` + id + `" command="close"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("findings page lacks %s", want)
		}
	}
	if strings.Contains(body, "<details>") {
		t.Error("findings rows still expand in place")
	}
}
