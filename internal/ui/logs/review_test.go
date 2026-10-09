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

func (f *fakeWriter) SetGroupVisibility(_ context.Context, anchor, visibility, actor string, _ int64) (int, error) {
	return 2, f.record("group", anchor, visibility, actor)
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
	form := url.Values{"key": {"v3:aaaa"}, "anchor": {"v3:aaaa"}, "visibility": {"customer"}}

	for _, p := range reviewPaths() {
		wrong := writeReq(p, form)
		wrong.SetBasicAuth("alice", "not-the-key")
		if rec := do(h, wrong); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s wrong key: got %d, want 401", p, rec.Code)
		}

		forged := writeReq(p, form)
		forged.Header.Set("Sec-Fetch-Site", "cross-site")
		forged.Header.Set("Origin", "https://evil.example")
		if rec := do(h, forged); rec.Code != http.StatusForbidden {
			t.Fatalf("%s cross-site: got %d, want 403", p, rec.Code)
		}

		head := writeReq(p+"?key=v3:aaaa", nil)
		head.Method = http.MethodHead
		if rec := do(h, head); rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s HEAD: got %d, want 405", p, rec.Code)
		}
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
		{"/review/dismiss", url.Values{"key": {"v3:aaaa"}}, "visibility v3:aaaa dismissed alice"},
		{"/review/group", url.Values{"anchor": {"v3:aaaa"}, "visibility": {"customer"}}, "group v3:aaaa customer alice"},
		{"/review/group", url.Values{"anchor": {"v3:aaaa"}, "visibility": {"dismissed"}}, "group v3:aaaa dismissed alice"},
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
		{"/review/group", url.Values{"anchor": {"v3:aaaa"}, "visibility": {"pending"}}},
		{"/review/group", url.Values{"anchor": {"v3:aaaa"}, "visibility": {"bogus"}}},
		{"/review/group", url.Values{"anchor": {"v3:aaaa"}}},
		{"/review/group", url.Values{"visibility": {"customer"}}},
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

// A path added to writableRoutes with no case in handleDecision's switch
// must not silently redirect as if it had done something -- it must 404.
func TestUnhandledWritableRouteIsNotFound(t *testing.T) {
	writableRoutes["/review/bogus"] = true
	defer delete(writableRoutes, "/review/bogus")

	w := &fakeWriter{}
	h := newWriteTestServer(t, seededReader(), w)
	rec := do(h, writeReq("/review/bogus", url.Values{"key": {"v3:aaaa"}}))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", rec.Code)
	}
	if len(w.calls) != 0 {
		t.Fatalf("an unhandled writable route reached the store: %v", w.calls)
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

// The queue table and the class dialog must both show what the AI's own
// severity was -- not just an override, which most classes never get.
func TestReviewShowsTheAIsSeverity(t *testing.T) {
	r := seededReader()
	r.classes = []logsstore.ClassRow{
		{Class: logsstore.Class{Key: "v3:aaaa", Visibility: logsstore.VisibilityPending}, Severity: "high"},
	}
	body := get(t, newTestServer(t, r, nil), "/review?view=all").Body.String()
	if !strings.Contains(body, `data-severity="high"`) {
		t.Fatalf("review queue did not show the AI's severity: %s", body)
	}
	if !strings.Contains(body, "AI severity") {
		t.Fatalf("class dialog is missing the AI severity label: %s", body)
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
	for _, path := range []string{"/review/deliver", "/review/internal", "/review/dismiss", "/review/security", "/review/severity", "/review/doc-ref"} {
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

// Dismissing a class that groups several log lines hides every later
// conclusion drawn from its bucket, so the form says so; a one-line class
// carries no such warning.
func TestReviewWarnsBeforeDismissingABucketClass(t *testing.T) {
	r := seededReader()
	r.classes = []logsstore.ClassRow{
		{Class: logsstore.Class{Key: "v3:bucket", Visibility: logsstore.VisibilityPending}, Evidence: []string{"a", "b"}},
	}
	const warning = "groups several different"
	if body := get(t, newWriteTestServer(t, r, &fakeWriter{}), "/review").Body.String(); !strings.Contains(body, warning) {
		t.Fatal("no warning before dismissing a multi-line class")
	}
	r.classes[0].Evidence = []string{"a"}
	if body := get(t, newWriteTestServer(t, r, &fakeWriter{}), "/review").Body.String(); strings.Contains(body, warning) {
		t.Fatal("a one-line class carries the bucket warning")
	}
}

// The dismissed view is where a dismissal is undone, so it must exist and
// filter on the stored visibility.
func TestReviewHasADismissedView(t *testing.T) {
	r := seededReader()
	get(t, newTestServer(t, r, nil), "/review?view=dismissed")
	if r.classSeen.Visibility != logsstore.VisibilityDismissed {
		t.Fatalf("dismissed view filtered on %q", r.classSeen.Visibility)
	}
}

// Every column header is a plain link that sorts the queue, carrying the
// current view and key; the active column flips direction and says which
// way it is sorted, the others sort in their own default direction.
func TestReviewHeadersSortTheQueue(t *testing.T) {
	r := seededReader()
	h := newTestServer(t, r, nil)
	body := get(t, h, "/review?view=all&key=v3:a&sort=systems&dir=desc").Body.String()
	if r.classSeen.Sort != logsstore.ClassSortSystems || r.classSeen.Dir != logsstore.SortDesc {
		t.Fatalf("the store was asked for %+v, want systems desc", r.classSeen)
	}
	for _, want := range []string{
		// The active column flips, and is marked.
		`<th scope="col" class="num" aria-sort="descending"><a href="/review?dir=asc&amp;key=v3%3Aa&amp;sort=systems&amp;view=all">Systems</a> <span aria-hidden="true">▼</span></th>`,
		// Text sorts A to Z first; numbers, dates and severity most first.
		`<th scope="col"><a href="/review?dir=asc&amp;key=v3%3Aa&amp;sort=class&amp;view=all">Class</a></th>`,
		`<a href="/review?dir=asc&amp;key=v3%3Aa&amp;sort=module&amp;view=all">Module</a>`,
		`<a href="/review?dir=desc&amp;key=v3%3Aa&amp;sort=severity&amp;view=all">Severity</a>`,
		`<a href="/review?dir=asc&amp;key=v3%3Aa&amp;sort=visibility&amp;view=all">Visibility</a>`,
		`<a href="/review?dir=desc&amp;key=v3%3Aa&amp;sort=findings&amp;view=all">Findings</a>`,
		`<a href="/review?dir=desc&amp;key=v3%3Aa&amp;sort=last_seen&amp;view=all">Last seen</a>`,
		// The filter form keeps the sort.
		`<input type="hidden" name="sort" value="systems"><input type="hidden" name="dir" value="desc">`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("review page lacks %s", want)
		}
	}
	if n := strings.Count(body, "aria-sort="); n != 1 {
		t.Errorf("%d columns marked sorted, want 1", n)
	}

	body = get(t, h, "/review?sort=systems&dir=asc").Body.String()
	if !strings.Contains(body, `aria-sort="ascending"><a href="/review?dir=desc&amp;sort=systems&amp;view=pending">Systems</a> <span aria-hidden="true">▲</span>`) {
		t.Error("an ascending column does not flip to descending")
	}
}

func TestReviewSanitizesTheSort(t *testing.T) {
	for _, tc := range []struct {
		query, sort, dir string
	}{
		{"", "", ""},
		{"sort=bogus&dir=asc", "", ""},
		{"sort=title;DROP&dir=desc", "", ""},
		{"sort=severity", logsstore.ClassSortSeverity, logsstore.SortDesc},
		{"sort=class&dir=sideways", logsstore.ClassSortTitle, logsstore.SortAsc},
		{"sort=last_seen&dir=asc", logsstore.ClassSortLastSeen, logsstore.SortAsc},
	} {
		r := seededReader()
		body := get(t, newTestServer(t, r, nil), "/review?"+tc.query).Body.String()
		if r.classSeen.Sort != tc.sort || r.classSeen.Dir != tc.dir {
			t.Errorf("%q: store asked for %q %q, want %q %q", tc.query, r.classSeen.Sort, r.classSeen.Dir, tc.sort, tc.dir)
		}
		if tc.sort == "" && strings.Contains(body, "aria-sort=") {
			t.Errorf("%q: a column is marked sorted in the default order", tc.query)
		}
	}
}

// The Module column shows the latest finding's first module, the host
// bucket by name, and how many more the dialog lists.
func TestReviewShowsTheModuleColumn(t *testing.T) {
	r := seededReader()
	r.classes = []logsstore.ClassRow{
		{Class: logsstore.Class{Key: "v3:host", Visibility: logsstore.VisibilityPending}, Modules: []string{""}},
		{Class: logsstore.Class{Key: "v3:many", Visibility: logsstore.VisibilityPending}, Modules: []string{"mail1", "sshd", "web"}},
		{Class: logsstore.Class{Key: "v3:none", Visibility: logsstore.VisibilityPending}},
	}
	body := get(t, newTestServer(t, r, nil), "/review").Body.String()
	for _, want := range []string{
		`<td class="mono">(host)</td>`,
		`<td class="mono">mail1 +2</td>`,
		`<td class="mono">&mdash;</td>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("review page lacks %s", want)
		}
	}
	r.classes = nil
	if body := get(t, newTestServer(t, r, nil), "/review").Body.String(); !strings.Contains(body, `<td colspan="7">`) {
		t.Error("the empty row does not span the Module column")
	}
}

// The class name is left to CSS to cut, so the whole title is in the button
// and in its tooltip; with no title the tooltip is the key.
func TestReviewClassNameIsNotPreTruncated(t *testing.T) {
	long := strings.Repeat("disk filling ", 10)
	r := seededReader()
	r.classes = []logsstore.ClassRow{
		{Class: logsstore.Class{Key: "v3:long", Visibility: logsstore.VisibilityPending}, Titles: []string{long}},
		{Class: logsstore.Class{Key: "v3:untitled", Visibility: logsstore.VisibilityPending}},
	}
	body := get(t, newTestServer(t, r, nil), "/review").Body.String()
	if !strings.Contains(body, `class="linklike" title="`+long+`" commandfor="class-v3:long" command="show-modal"><span>`+long+`</span></button>`) {
		t.Error("the class title was cut before CSS could ellipsize it")
	}
	if !strings.Contains(body, `class="linklike" title="v3:untitled"`) {
		t.Error("an untitled class does not fall back to its key")
	}
}

// A decision returns to the sort order it was taken from, re-validated.
func TestReviewDecisionKeepsTheSort(t *testing.T) {
	for _, tc := range []struct {
		sort, dir, want string
	}{
		{"severity", "asc", "/review?dir=asc&key=v3%3Aaa&sort=severity&view=all"},
		{"findings", "sideways", "/review?dir=desc&key=v3%3Aaa&sort=findings&view=all"},
		{"bogus", "asc", "/review?key=v3%3Aaa&view=all"},
		{"", "", "/review?key=v3%3Aaa&view=all"},
	} {
		h := newWriteTestServer(t, seededReader(), &fakeWriter{})
		form := url.Values{"key": {"v3:aaaa"}, "view": {"all"}, "filter": {"v3:aa"}, "sort": {tc.sort}, "dir": {tc.dir}}
		rec := do(h, writeReq("/review/deliver", form))
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("got %d, want 303", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != tc.want {
			t.Errorf("sort %q %q redirected to %q, want %q", tc.sort, tc.dir, loc, tc.want)
		}
	}
}

// Every decision form carries the sort back, or the redirect could not --
// and so does the filter form.
func TestReviewDecisionFormsCarryTheSort(t *testing.T) {
	body := get(t, newWriteTestServer(t, seededReader(), &fakeWriter{}), "/review?sort=module&dir=desc").Body.String()
	forms := strings.Count(body, `method="post"`) + strings.Count(body, `method="get"`)
	if forms < 2 {
		t.Fatal("no decision forms rendered")
	}
	for _, want := range []string{
		`<input type="hidden" name="sort" value="module">`,
		`<input type="hidden" name="dir" value="desc">`,
	} {
		if n := strings.Count(body, want); n != forms {
			t.Errorf("%d of %d forms carry %s", n, forms, want)
		}
	}
}

func groupedReader() *fakeReader {
	r := seededReader()
	r.classes = append([]logsstore.ClassRow(nil), r.classes...)
	for i := range r.classes {
		r.classes[i].GroupAnchor, r.classes[i].GroupSize = "v3:anchor", 3
	}
	return r
}

func TestReviewShowsGroupLinkAndSuggestion(t *testing.T) {
	r := groupedReader()
	for i := range r.classes {
		if r.classes[i].Visibility == logsstore.VisibilityPending {
			r.classes[i].Suggestion, r.classes[i].SuggestionVotes = logsstore.VisibilityDismissed, 2
		}
	}
	body := get(t, newWriteTestServer(t, r, &fakeWriter{}), "/review?view=all").Body.String()
	for _, want := range []string{
		`group of 3`, `?group=v3%3aanchor`, `Suggested: Dismiss`, `2 similar class(es) decided`,
		`class="suggested"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// only the dismiss button of a pending row is marked, and decided rows
	// carry no suggestion text
	if n := strings.Count(body, "Suggested: "); n != 1 {
		t.Errorf("%d suggestion lines, want 1 (one pending row)", n)
	}
	if n := strings.Count(body, `class="suggested"`); n != 1 {
		t.Errorf("%d marked buttons, want 1", n)
	}
}

func TestReviewWithoutSuggestionOrGroupShowsNeither(t *testing.T) {
	body := get(t, newWriteTestServer(t, seededReader(), &fakeWriter{}), "/review?view=all").Body.String()
	for _, bad := range []string{"group of", "Suggested:", `class="suggested"`} {
		if strings.Contains(body, bad) {
			t.Errorf("page shows %q with no group", bad)
		}
	}
}

func TestReviewGroupViewFiltersAndOffersGroupForms(t *testing.T) {
	r := groupedReader()
	h := newWriteTestServer(t, r, &fakeWriter{})
	body := get(t, h, "/review?group=v3:anchor").Body.String()
	if r.classSeen.Group != "v3:anchor" || r.classSeen.Visibility != "" {
		t.Fatalf("group link filtered on %+v, want group with every visibility", r.classSeen)
	}
	for _, want := range []string{`action="/review/group"`, `name="anchor" value="v3:anchor"`, `name="visibility" value="customer"`, `Deliver all pending`} {
		if !strings.Contains(body, want) {
			t.Errorf("group view lacks %q", want)
		}
	}
	if strings.Contains(get(t, h, "/review").Body.String(), `action="/review/group"`) {
		t.Error("the plain queue offers group forms")
	}
	get(t, h, "/review?group=v3:anchor&view=pending")
	if r.classSeen.Visibility != logsstore.VisibilityPending {
		t.Errorf("explicit view ignored: %+v", r.classSeen)
	}
	ro := get(t, newTestServer(t, groupedReader(), nil), "/review?group=v3:anchor").Body.String()
	if strings.Contains(ro, `/review/group`) {
		t.Error("read-only server offers group forms")
	}
}

func TestReviewGroupDecisionKeepsTheGroupFilter(t *testing.T) {
	h := newWriteTestServer(t, seededReader(), &fakeWriter{})
	form := url.Values{"anchor": {"v3:anchor"}, "visibility": {"operator"}, "group": {"v3:anchor"}, "view": {"all"}}
	rec := do(h, writeReq("/review/group", form))
	if loc := rec.Header().Get("Location"); rec.Code != http.StatusSeeOther || loc != "/review?group=v3%3Aanchor&view=all" {
		t.Fatalf("got %d %q", rec.Code, loc)
	}
}
