// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package logs

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/platform/httpx"
)

type fakePublisher struct {
	published []model.Bundle
	err       error
}

func (f *fakePublisher) Publish(b model.Bundle) error {
	if f.err != nil {
		return f.err
	}
	f.published = append(f.published, b)
	return nil
}

// fakeStore backs /v1/findings. Nothing here exercises it beyond
// construction, but NewServer takes one Store for both routes.
type fakeStore struct {
	findings []model.Finding
	err      error
}

func (f *fakeStore) ListFindings(_ context.Context, _ string, _ int64, _ string) ([]model.Finding, error) {
	return f.findings, f.err
}

// The credential is never verified in this process -- authd and the
// trusted-proxy check are the whole boundary -- so any non-empty pair works
// here; it exists only to exercise HTTP Basic's wire format.
const (
	testSystemID = "sys1"
	testSecret   = "whatever"
)

// trustedProxy is the loopback prefix every test builds its trusted set from,
// matching httptest.NewRequest's need for an explicit RemoteAddr.
var trustedProxy = mustTrust("127.0.0.0/8")

func mustTrust(cidr string) httpx.TrustedProxies {
	t, err := httpx.ParseTrustedProxies(cidr)
	if err != nil {
		panic(err)
	}
	return t
}

// testNow is the fixed instant every test's clock reads, so window-age and
// future-window assertions do not depend on wall-clock time (and so a valid
// bundle's Window{1000, 2000} -- ancient by any real clock -- does not
// spuriously fail the 6-hour-age rule).
var testNow = time.UnixMilli(1_700_000_000_000)

func fixedClock() time.Time { return testNow }

// testWindow is comfortably inside the acceptance window: in the past, but
// well within 6 hours of testNow.
var testWindow = model.Window{
	Start: testNow.Add(-2 * time.Minute).UnixMilli(),
	End:   testNow.Add(-1 * time.Minute).UnixMilli(),
}

func testServer(p Publisher) http.Handler {
	return NewServer(p, &fakeStore{}, trustedProxy, Config{Now: fixedClock})
}

func validBundle() string {
	return bundleWithWindow(testWindow)
}

func bundleWithWindow(win model.Window) string {
	b, _ := json.Marshal(model.Bundle{
		SchemaVersion: model.SchemaVersion,
		SystemID:      testSystemID,
		Window:        win,
	})
	return string(b)
}

func postBundle(t *testing.T, h http.Handler, body string, withAuth bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/bundles", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345" // the trusted proxy
	if withAuth {
		req.SetBasicAuth(testSystemID, testSecret)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// The whole point of the queue: ingest must answer without waiting for -- or
// even starting -- the analysis.
func TestIngestAcceptsWithoutRunningTheAnalysis(t *testing.T) {
	pub := &fakePublisher{}
	rec := postBundle(t, testServer(pub), validBundle(), true)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want %d (body %s)", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	var got map[string]bool
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if !got["accepted"] {
		t.Fatalf("body: got %s, want accepted=true", rec.Body.String())
	}
	if len(pub.published) != 1 {
		t.Fatalf("published %d bundles, want 1", len(pub.published))
	}
}

// A saturated queue is the one case where the client must be told to come
// back: the bundle was NOT accepted.
func TestIngestReports503WhenThePublisherRefuses(t *testing.T) {
	pub := &fakePublisher{err: errors.New("queue: full")}
	rec := postBundle(t, testServer(pub), validBundle(), true)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestIngestRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{"invalid json", `{"schema_version":`, http.StatusBadRequest},
		{"wrong schema version", `{"schema_version":99,"system_id":"sys1","window":{"start":1,"end":2}}`, http.StatusBadRequest},
		{"missing system_id", `{"schema_version":1,"window":{"start":1,"end":2}}`, http.StatusBadRequest},
		{"foreign system_id", `{"schema_version":1,"system_id":"other","window":{"start":1,"end":2}}`, http.StatusForbidden},
		{"empty window", `{"schema_version":1,"system_id":"sys1","window":{"start":2,"end":2}}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub := &fakePublisher{}
			rec := postBundle(t, testServer(pub), tc.body, true)
			if rec.Code != tc.want {
				t.Fatalf("status: got %d, want %d (body %s)", rec.Code, tc.want, rec.Body.String())
			}
			if len(pub.published) != 0 {
				t.Fatal("a rejected bundle reached the queue")
			}
		})
	}
}

func TestIngestRequiresCredentials(t *testing.T) {
	pub := &fakePublisher{}
	rec := postBundle(t, testServer(pub), validBundle(), false)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if len(pub.published) != 0 {
		t.Fatal("an unauthenticated bundle reached the queue")
	}
}

// The credential is not verified in this process, so the trusted-proxy check
// is the entire boundary: a direct connection must not be able to name a
// system_id.
func TestIngestRefusesARequestThatDidNotComeThroughTheProxy(t *testing.T) {
	pub := &fakePublisher{}
	h := NewServer(pub, &fakeStore{}, trustedProxy, Config{})

	r := httptest.NewRequest(http.MethodPost, "/v1/bundles", strings.NewReader(validBundle()))
	r.RemoteAddr = "203.0.113.7:4444"
	r.SetBasicAuth(testSystemID, testSecret)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if len(pub.published) != 0 {
		t.Fatalf("a direct request published %d bundles", len(pub.published))
	}
}

// Exclusion happens at ingest, before the queue, so that the gate, the prompt,
// system_templates and module_baselines all read the same filtered bundle and
// cannot disagree about which modules are in scope.
func TestIngestExcludesConfiguredModules(t *testing.T) {
	pub := &fakePublisher{}
	h := NewServer(pub, &fakeStore{}, trustedProxy, Config{
		ExcludeModules: map[string]bool{"crowdsec1": true},
		Now:            fixedClock,
	})

	body, err := json.Marshal(model.Bundle{
		SchemaVersion: model.SchemaVersion,
		SystemID:      testSystemID,
		Window:        testWindow,
		Templates: []model.Template{
			{Template: "keep", ModuleID: "loki1"},
			{Template: "drop", ModuleID: "crowdsec1"},
		},
		Digest: []model.DigestEntry{
			{ModuleID: "loki1", Priority: 6, Observed: 1},
			{ModuleID: "crowdsec1", Priority: 3, Observed: 2},
		},
		Budget: model.Budget{TruncatedModules: []model.TruncatedModule{{ModuleID: "crowdsec1", Dropped: 1}}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if rec := postBundle(t, h, string(body), true); rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want %d (body %s)", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	if len(pub.published) != 1 {
		t.Fatalf("expected one published bundle, got %d", len(pub.published))
	}

	got := pub.published[0]
	if len(got.Templates) != 1 || got.Templates[0].ModuleID != "loki1" {
		t.Fatalf("excluded module survived in templates: %+v", got.Templates)
	}
	if len(got.Digest) != 1 || got.Digest[0].ModuleID != "loki1" {
		t.Fatalf("excluded module survived in digest: %+v", got.Digest)
	}
	if len(got.Budget.TruncatedModules) != 0 {
		t.Fatalf("excluded module survived in truncated_modules: %+v", got.Budget.TruncatedModules)
	}
}

// With no exclusion configured the bundle must reach the queue untouched --
// including the crowdsec1 content the default configuration would strip.
func TestIngestWithoutExclusionPassesEverything(t *testing.T) {
	pub := &fakePublisher{}
	body, err := json.Marshal(model.Bundle{
		SchemaVersion: model.SchemaVersion,
		SystemID:      testSystemID,
		Window:        testWindow,
		Templates: []model.Template{
			{Template: "keep", ModuleID: "loki1"},
			{Template: "also-keep", ModuleID: "crowdsec1"},
		},
		Digest: []model.DigestEntry{{ModuleID: "crowdsec1", Priority: 3, Observed: 2}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if rec := postBundle(t, testServer(pub), string(body), true); rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d (body %s)", rec.Code, rec.Body.String())
	}
	if len(pub.published) != 1 {
		t.Fatalf("expected one published bundle, got %d", len(pub.published))
	}
	if len(pub.published[0].Templates) != 2 || len(pub.published[0].Digest) != 1 {
		t.Fatalf("bundle was filtered with no exclusion configured: %+v", pub.published[0])
	}
}

// Host records name their unit, which is the only service dimension on the
// wire -- module_id is "" for all of them. Excluding by service is what stops a
// co-located deployment analysing its own log output.
func TestIngestExcludesConfiguredServices(t *testing.T) {
	pub := &fakePublisher{}
	h := NewServer(pub, &fakeStore{}, trustedProxy, Config{
		ExcludeServices: map[string]bool{"insights": true},
		Now:             fixedClock,
	})

	body, err := json.Marshal(model.Bundle{
		SchemaVersion: model.SchemaVersion,
		SystemID:      testSystemID,
		Window:        testWindow,
		Templates: []model.Template{
			{Template: `<3> [insights] msg="gate decision"`, ModuleID: ""},
			{Template: `<6> [sshd-session] Received disconnect from <IP>`, ModuleID: "", Category: "security"},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if rec := postBundle(t, h, string(body), true); rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d (body %s)", rec.Code, rec.Body.String())
	}
	got := pub.published[0]
	if len(got.Templates) != 1 {
		t.Fatalf("expected 1 template to survive, got %+v", got.Templates)
	}
	if model.ServiceTag(got.Templates[0].Template) != "sshd-session" {
		t.Fatalf("wrong template survived: %+v", got.Templates)
	}
}

// A gzip bomb must be refused by size, not decompressed into memory. Before
// the decoded-side cap existed, the limiter sat on r.Body only: a few KiB of
// gzipped whitespace expanded without limit and the decoder consumed all of
// it. The body here is ~35 MiB of JSON whitespace, which gzips to a few tens
// of KiB -- so it sails past any compressed-side cap and can only be stopped
// after gunzip.
func TestBundleGzipBombIsRejectedBySize(t *testing.T) {
	var body bytes.Buffer
	gz := gzip.NewWriter(&body)
	if _, err := gz.Write([]byte(`{"schema_version":1,`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Whitespace is valid JSON filler, so the decoder keeps reading rather
	// than failing early on a syntax error -- which is what makes this a
	// size test and not a parser test.
	filler := bytes.Repeat([]byte(" "), 1<<20)
	for range 35 {
		if _, err := gz.Write(filler); err != nil {
			t.Fatalf("write filler: %v", err)
		}
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if body.Len() > maxCompressedBundleSize {
		t.Fatalf("compressed body is %d bytes, over the raw cap -- the test would "+
			"pass for the wrong reason", body.Len())
	}

	pub := &fakePublisher{}
	h := NewServer(pub, &fakeStore{}, trustedProxy, Config{})

	r := httptest.NewRequest(http.MethodPost, "/v1/bundles", bytes.NewReader(body.Bytes()))
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Content-Encoding", "gzip")
	r.SetBasicAuth(testSystemID, testSecret)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d -- an unbounded gunzip is a memory-exhaustion "+
			"path for any node with a valid credential", w.Code, http.StatusRequestEntityTooLarge)
	}
	if len(pub.published) != 0 {
		t.Fatalf("published %d bundles, want 0", len(pub.published))
	}
}

// The raw cap still applies to a body that is not compressed at all.
func TestOversizedUncompressedBundleIsRejectedBySize(t *testing.T) {
	pub := &fakePublisher{}
	h := NewServer(pub, &fakeStore{}, trustedProxy, Config{})

	big := strings.NewReader(`{"schema_version":1,` + strings.Repeat(" ", maxCompressedBundleSize+1))
	r := httptest.NewRequest(http.MethodPost, "/v1/bundles", big)
	r.RemoteAddr = "127.0.0.1:12345"
	r.SetBasicAuth(testSystemID, testSecret)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
	}
}

// §5.4: "window in the future" is checked on window.end, since that is what
// tells whether any part of a claimed-complete window has not happened yet.
func TestIngestRejectsWindowInTheFuture(t *testing.T) {
	cases := []struct {
		name string
		end  int64
		want int
	}{
		{"ends exactly now", testNow.UnixMilli(), http.StatusAccepted},
		{"ends one millisecond in the future", testNow.UnixMilli() + 1, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub := &fakePublisher{}
			win := model.Window{Start: tc.end - 1000, End: tc.end}
			rec := postBundle(t, testServer(pub), bundleWithWindow(win), true)
			if rec.Code != tc.want {
				t.Fatalf("status: got %d, want %d (body %s)", rec.Code, tc.want, rec.Body.String())
			}
			gotPublished := len(pub.published) != 0
			wantPublished := tc.want == http.StatusAccepted
			if gotPublished != wantPublished {
				t.Fatalf("published = %v, want %v", gotPublished, wantPublished)
			}
		})
	}
}

// §5.4: window.start older than 6 hours is rejected. That 6 hours -- not 1 --
// is deliberate: it is the room the edge needs to retry a bundle across
// several failed send cycles (a network blip, a server restart, a queue at
// capacity) without the server discarding data the edge eventually manages
// to deliver. This test's job is to catch a future "tightening" of that
// number as much as to prove the rule exists.
func TestIngestRejectsWindowOlderThan6Hours(t *testing.T) {
	cutoff := testNow.Add(-6 * time.Hour).UnixMilli()
	cases := []struct {
		name  string
		start int64
		want  int
	}{
		{"starts exactly at the 6-hour edge", cutoff, http.StatusAccepted},
		{"starts one millisecond past the 6-hour edge", cutoff - 1, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub := &fakePublisher{}
			win := model.Window{Start: tc.start, End: tc.start + 1000}
			rec := postBundle(t, testServer(pub), bundleWithWindow(win), true)
			if rec.Code != tc.want {
				t.Fatalf("status: got %d, want %d (body %s)", rec.Code, tc.want, rec.Body.String())
			}
			gotPublished := len(pub.published) != 0
			wantPublished := tc.want == http.StatusAccepted
			if gotPublished != wantPublished {
				t.Fatalf("published = %v, want %v", gotPublished, wantPublished)
			}
		})
	}
}

// §5.4: at most 2 samples per template.
func TestIngestRejectsTooManySamplesPerTemplate(t *testing.T) {
	cases := []struct {
		name    string
		samples []string
		want    int
	}{
		{"exactly 2 samples", []string{"sample one", "sample two"}, http.StatusAccepted},
		{"3 samples", []string{"sample one", "sample two", "sample three"}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub := &fakePublisher{}
			body, err := json.Marshal(model.Bundle{
				SchemaVersion: model.SchemaVersion,
				SystemID:      testSystemID,
				Window:        testWindow,
				Templates: []model.Template{
					{Template: "tmpl", ModuleID: "loki1", Samples: tc.samples},
				},
			})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			rec := postBundle(t, testServer(pub), string(body), true)
			if rec.Code != tc.want {
				t.Fatalf("status: got %d, want %d (body %s)", rec.Code, tc.want, rec.Body.String())
			}
			gotPublished := len(pub.published) != 0
			wantPublished := tc.want == http.StatusAccepted
			if gotPublished != wantPublished {
				t.Fatalf("published = %v, want %v", gotPublished, wantPublished)
			}
		})
	}
}
