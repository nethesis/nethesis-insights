// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nethesis/nethesis-insights/internal/model"
)

var threatNow = time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC).UnixMilli()

// fakeThreatStore records what the handler asked it to store.
type fakeThreatStore struct {
	events     []model.ThreatEvent
	systemID   string
	counters   model.ThreatCounters
	duplicates int
	day        string
	insertErr  error
	countErr   error
}

func (f *fakeThreatStore) InsertThreatEvents(_ context.Context, systemID string, ev []model.ThreatEvent) (int, int, error) {
	if f.insertErr != nil {
		return 0, 0, f.insertErr
	}
	f.systemID = systemID
	f.events = append(f.events, ev...)
	return len(ev), 0, nil
}

func (f *fakeThreatStore) RecordIngestCounters(_ context.Context, day, _ string, c model.ThreatCounters, duplicates int) error {
	f.day = day
	f.counters = c
	f.duplicates = duplicates
	return f.countErr
}

// fakeFeed is a fixed snapshot.
type fakeFeed struct {
	ready bool
	body  []byte
	gz    []byte
	etag  string
}

func (f *fakeFeed) Ready() bool        { return f.ready }
func (f *fakeFeed) Body() []byte       { return f.body }
func (f *fakeFeed) Gzip() []byte       { return f.gz }
func (f *fakeFeed) ETag() string       { return f.etag }
func (f *fakeFeed) GeneratedAt() int64 { return threatNow }

func readyFeed(t *testing.T, body string) *fakeFeed {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(body)); err != nil {
		t.Fatalf("gzip: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return &fakeFeed{ready: true, body: []byte(body), gz: buf.Bytes(), etag: `"sha256-abc"`}
}

func threatServer(st ThreatStore, feed Feed) http.Handler {
	return NewServer(&fakePublisher{}, nil,
		StaticAuth{SystemID: testSystemID, Secret: testSecret},
		ThreatConfig{
			Store:        st,
			Feed:         feed,
			MaxDecisions: 500,
			Now:          func() int64 { return threatNow },
		}, SizingConfig{}, nil, nil)
}

func decision(ip, scenario, origin string) model.Decision {
	return model.Decision{
		Value: ip, Scope: "Ip", Type: "ban", Scenario: scenario, Origin: origin,
		Duration: "4h", CreatedAt: "2026-08-28T09:59:00Z",
	}
}

func postThreat(t *testing.T, h http.Handler, body string, withAuth bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/threat-events", strings.NewReader(body))
	req.RemoteAddr = "198.51.100.5:44321"
	if withAuth {
		req.SetBasicAuth(testSystemID, testSecret)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func reportBody(t *testing.T, systemID string, ds ...model.Decision) string {
	t.Helper()
	b, err := json.Marshal(model.ThreatReport{
		SchemaVersion: model.ThreatSchemaVersion,
		SystemID:      systemID,
		Decisions:     ds,
	})
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	return string(b)
}

func TestThreatIngestStoresSanitizedEvents(t *testing.T) {
	st := &fakeThreatStore{}
	body := reportBody(t, testSystemID, decision("203.0.113.7", "crowdsecurity/ssh-bf", "crowdsec"))

	rec := postThreat(t, threatServer(st, &fakeFeed{}), body, true)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202 (body %s)", rec.Code, rec.Body.String())
	}
	var got threatIngestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !got.Accepted || got.Stored != 1 || got.Dropped.Accepted != 1 {
		t.Fatalf("response: %+v", got)
	}
	if len(st.events) != 1 || st.events[0].AttackerIP != "203.0.113.7" {
		t.Fatalf("stored events: %+v", st.events)
	}
	if st.systemID != testSystemID {
		t.Fatalf("system id: got %q, want the authenticated one", st.systemID)
	}
	if st.day != "2026-08-28" {
		t.Fatalf("counter day: got %q", st.day)
	}
}

// The reporter is identified by its credential; the body's system_id is
// optional and only ever cross-checked.
func TestThreatIngestAcceptsAnOmittedSystemID(t *testing.T) {
	st := &fakeThreatStore{}
	rec := postThreat(t, threatServer(st, &fakeFeed{}),
		reportBody(t, "", decision("203.0.113.7", "crowdsecurity/ssh-bf", "crowdsec")), true)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202", rec.Code)
	}
	if st.systemID != testSystemID {
		t.Fatalf("system id: got %q, want %q", st.systemID, testSystemID)
	}
}

func TestThreatIngestRejectsAForeignSystemID(t *testing.T) {
	st := &fakeThreatStore{}
	rec := postThreat(t, threatServer(st, &fakeFeed{}),
		reportBody(t, "someone-else", decision("203.0.113.7", "crowdsecurity/ssh-bf", "crowdsec")), true)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403", rec.Code)
	}
	if len(st.events) != 0 {
		t.Fatalf("a foreign report was stored: %+v", st.events)
	}
}

func TestThreatIngestRequiresAuthentication(t *testing.T) {
	st := &fakeThreatStore{}
	rec := postThreat(t, threatServer(st, &fakeFeed{}),
		reportBody(t, testSystemID, decision("203.0.113.7", "crowdsecurity/ssh-bf", "crowdsec")), false)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
	if len(st.events) != 0 {
		t.Fatal("an unauthenticated report reached the store")
	}
}

func TestThreatIngestRejectsBadRequests(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{"invalid json", "{not json", http.StatusBadRequest},
		{"wrong schema version", `{"schema_version":99,"decisions":[]}`, http.StatusBadRequest},
		{"missing schema version", `{"decisions":[]}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := &fakeThreatStore{}
			rec := postThreat(t, threatServer(st, &fakeFeed{}), tc.body, true)
			if rec.Code != tc.want {
				t.Fatalf("status: got %d, want %d", rec.Code, tc.want)
			}
			if len(st.events) != 0 {
				t.Fatalf("rejected body still stored: %+v", st.events)
			}
		})
	}
}

func TestThreatIngestRejectsWrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/threat-events", nil)
	req.SetBasicAuth(testSystemID, testSecret)
	rec := httptest.NewRecorder()
	threatServer(&fakeThreatStore{}, &fakeFeed{}).ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d, want 405", rec.Code)
	}
}

// Fail-open on content: one bad decision must not cost the batch.
func TestThreatIngestKeepsTheBatchWhenOneDecisionIsMalformed(t *testing.T) {
	st := &fakeThreatStore{}
	body := reportBody(t, testSystemID,
		decision("10.0.0.5", "crowdsecurity/ssh-bf", "crowdsec"),
		decision("203.0.113.7", "crowdsecurity/ssh-bf", "CAPI"),
		decision("bogus", "crowdsecurity/ssh-bf", "crowdsec"),
		decision("203.0.113.9", "crowdsecurity/ssh-bf", "crowdsec"),
	)

	rec := postThreat(t, threatServer(st, &fakeFeed{}), body, true)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202", rec.Code)
	}
	if len(st.events) != 1 || st.events[0].AttackerIP != "203.0.113.9" {
		t.Fatalf("stored: %+v, want only 203.0.113.9", st.events)
	}
	var got threatIngestResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Dropped.DroppedPrivateIP != 1 || got.Dropped.DroppedOrigin != 1 || got.Dropped.DroppedBadIP != 1 {
		t.Fatalf("dropped counters: %+v", got.Dropped)
	}
}

// A scenario the server has never seen is stored, not dropped: there is no
// allowlist, so a third-party or hand-written collection still contributes.
func TestThreatIngestAcceptsAnUnfamiliarScenario(t *testing.T) {
	st := &fakeThreatStore{}
	rec := postThreat(t, threatServer(st, &fakeFeed{}),
		reportBody(t, testSystemID,
			decision("203.0.113.7", "LePresidente/http-generic-401-bf", "crowdsec")), true)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202", rec.Code)
	}
	if len(st.events) != 1 {
		t.Fatalf("stored: %+v, want the event kept", st.events)
	}
	if st.events[0].Scenario != "LePresidente/http-generic-401-bf" {
		t.Fatalf("scenario: got %q", st.events[0].Scenario)
	}
}

// The reporter-own-address check must key off the real connection, never a
// client-controlled header: otherwise an authenticated edge could spoof its
// way past it and get any address dropped as "its own".
func TestThreatIngestIgnoresXForwardedFor(t *testing.T) {
	st := &fakeThreatStore{}
	req := httptest.NewRequest(http.MethodPost, "/v1/threat-events",
		strings.NewReader(reportBody(t, testSystemID, decision("203.0.113.7", "crowdsecurity/ssh-bf", "crowdsec"))))
	req.RemoteAddr = "198.51.100.5:44321"
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.SetBasicAuth(testSystemID, testSecret)
	rec := httptest.NewRecorder()

	threatServer(st, &fakeFeed{}).ServeHTTP(rec, req)

	// The spoofed address must not be excluded by the forged header.
	if len(st.events) != 1 || st.events[0].AttackerIP != "203.0.113.7" {
		t.Fatalf("stored: %+v, want the header not to have excluded 203.0.113.7", st.events)
	}
}

// A node banning its own address is a misconfiguration; it must not become a
// fleet-wide outage.
func TestThreatIngestDropsTheReportersOwnAddress(t *testing.T) {
	st := &fakeThreatStore{}
	rec := postThreat(t, threatServer(st, &fakeFeed{}),
		reportBody(t, testSystemID, decision("198.51.100.5", "crowdsecurity/ssh-bf", "crowdsec")), true)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202", rec.Code)
	}
	if len(st.events) != 0 {
		t.Fatalf("the reporter's own address was stored: %+v", st.events)
	}
}

func TestThreatIngestAcceptsGzip(t *testing.T) {
	st := &fakeThreatStore{}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(reportBody(t, testSystemID, decision("203.0.113.7", "crowdsecurity/ssh-bf", "crowdsec"))))
	_ = zw.Close()

	req := httptest.NewRequest(http.MethodPost, "/v1/threat-events", bytes.NewReader(buf.Bytes()))
	req.Header.Set("Content-Encoding", "gzip")
	req.RemoteAddr = "198.51.100.5:44321"
	req.SetBasicAuth(testSystemID, testSecret)
	rec := httptest.NewRecorder()
	threatServer(st, &fakeFeed{}).ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202 (body %s)", rec.Code, rec.Body.String())
	}
	if len(st.events) != 1 {
		t.Fatalf("stored: %+v", st.events)
	}
}

func TestThreatIngestAnswers503WhenTheStoreFails(t *testing.T) {
	st := &fakeThreatStore{insertErr: errors.New("disk on fire")}
	rec := postThreat(t, threatServer(st, &fakeFeed{}),
		reportBody(t, testSystemID, decision("203.0.113.7", "crowdsecurity/ssh-bf", "crowdsec")), true)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d, want 503", rec.Code)
	}
}

// Accounting is an operator convenience; the evidence is already stored, so
// its failure must not cost the reporter its 202 (and therefore its
// watermark).
func TestThreatIngestSucceedsWhenAccountingFails(t *testing.T) {
	st := &fakeThreatStore{countErr: errors.New("nope")}
	rec := postThreat(t, threatServer(st, &fakeFeed{}),
		reportBody(t, testSystemID, decision("203.0.113.7", "crowdsecurity/ssh-bf", "crowdsec")), true)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202", rec.Code)
	}
	if len(st.events) != 1 {
		t.Fatalf("stored: %+v", st.events)
	}
}

// --- feed ---

func getBlocklist(t *testing.T, h http.Handler, withAuth bool, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/blocklist", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if withAuth {
		req.SetBasicAuth(testSystemID, testSecret)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const testFeedBody = "# nethesis threat shield v1\n# generated: x  entries: 1  rule: y\n203.0.113.7\n"

func TestBlocklistServesThePlainTextFeed(t *testing.T) {
	feed := readyFeed(t, testFeedBody)
	rec := getBlocklist(t, threatServer(&fakeThreatStore{}, feed), true, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Fatalf("content-type: got %q", ct)
	}
	if rec.Header().Get("ETag") != feed.etag {
		t.Fatalf("etag: got %q, want %q", rec.Header().Get("ETag"), feed.etag)
	}
	if rec.Header().Get("Cache-Control") != "max-age=900" {
		t.Fatalf("cache-control: got %q", rec.Header().Get("Cache-Control"))
	}
	if rec.Body.String() != testFeedBody {
		t.Fatalf("body: got %q", rec.Body.String())
	}
}

func TestBlocklistRequiresAuthentication(t *testing.T) {
	rec := getBlocklist(t, threatServer(&fakeThreatStore{}, readyFeed(t, testFeedBody)), false, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
}

// At a five-minute regeneration cadence, 304 is the normal answer.
func TestBlocklistAnswers304OnAMatchingETag(t *testing.T) {
	feed := readyFeed(t, testFeedBody)
	h := threatServer(&fakeThreatStore{}, feed)

	for _, header := range []string{feed.etag, `W/` + feed.etag, `"other", ` + feed.etag, "*"} {
		rec := getBlocklist(t, h, true, map[string]string{"If-None-Match": header})
		if rec.Code != http.StatusNotModified {
			t.Fatalf("If-None-Match %q: got %d, want 304", header, rec.Code)
		}
		if rec.Body.Len() != 0 {
			t.Fatalf("If-None-Match %q: 304 carried a body", header)
		}
	}

	rec := getBlocklist(t, h, true, map[string]string{"If-None-Match": `"stale"`})
	if rec.Code != http.StatusOK {
		t.Fatalf("stale etag: got %d, want 200", rec.Code)
	}
}

func TestBlocklistServesGzipWhenAccepted(t *testing.T) {
	feed := readyFeed(t, testFeedBody)
	rec := getBlocklist(t, threatServer(&fakeThreatStore{}, feed), true,
		map[string]string{"Accept-Encoding": "gzip, deflate"})

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("content-encoding: got %q", rec.Header().Get("Content-Encoding"))
	}
	zr, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	got, _ := io.ReadAll(zr)
	if string(got) != testFeedBody {
		t.Fatalf("decompressed body: %q", got)
	}
}

// An empty body would mean "no threats" to every client that imports it,
// which silently disables protection.
func TestBlocklistRefusesBeforeTheFirstGeneration(t *testing.T) {
	rec := getBlocklist(t, threatServer(&fakeThreatStore{}, &fakeFeed{ready: false}), true, nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d, want 503", rec.Code)
	}
}

func TestBlocklistRejectsWrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/blocklist", nil)
	req.SetBasicAuth(testSystemID, testSecret)
	rec := httptest.NewRecorder()
	threatServer(&fakeThreatStore{}, readyFeed(t, testFeedBody)).ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d, want 405", rec.Code)
	}
}

// The zero ThreatConfig leaves the pipeline off entirely, which is what the
// bundle-only tests rely on.
func TestThreatRoutesAreAbsentWhenUnconfigured(t *testing.T) {
	h := testServer(&fakePublisher{})
	for _, path := range []string{"/v1/threat-events", "/v1/blocklist"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.SetBasicAuth(testSystemID, testSecret)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: got %d, want 404", path, rec.Code)
		}
	}
}
