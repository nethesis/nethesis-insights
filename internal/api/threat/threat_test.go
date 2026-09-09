// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package threat

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

	"github.com/nethesis/nethesis-insights/internal/blocklist"
	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/platform/httpx"
	threatstore "github.com/nethesis/nethesis-insights/internal/store/threat"
	"github.com/nethesis/nethesis-insights/internal/threat"
)

// The credential is never verified in this process -- authd and the
// trusted-proxy check are the whole boundary -- so any non-empty pair works
// here; it exists only to exercise HTTP Basic's wire format.
const (
	testSystemID = "sys-edge-1"
	testSecret   = "whatever"
)

var threatNow = time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC).UnixMilli()

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

// fakeThreatStore records what the handler asked it to store. It implements
// the whole Store interface -- ingest and the allowlist request queue --
// because NewServer takes one Store for both.
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

func (f *fakeThreatStore) UpsertAllowlistRequest(context.Context, string, string, string, int64) (int, error) {
	return 0, nil
}

func threatServer(st Store, snap *blocklist.Snapshot) http.Handler {
	return NewServer(st, snap, trustedProxy, Config{
		MaxDecisions: 500,
		Now:          func() int64 { return threatNow },
	})
}

func decision(ip, scenario, origin string) model.Decision {
	return model.Decision{
		Value: ip, Scope: "Ip", Type: "ban", Scenario: scenario, Origin: origin,
		Duration: "4h", CreatedAt: "2026-08-28T09:59:00Z",
	}
}

func postThreat(t *testing.T, h http.Handler, body string, withAuth bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345" // the trusted proxy
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

	rec := postThreat(t, threatServer(st, nil), body, true)

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
	rec := postThreat(t, threatServer(st, nil),
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
	rec := postThreat(t, threatServer(st, nil),
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
	rec := postThreat(t, threatServer(st, nil),
		reportBody(t, testSystemID, decision("203.0.113.7", "crowdsecurity/ssh-bf", "crowdsec")), false)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
	if len(st.events) != 0 {
		t.Fatal("an unauthenticated report reached the store")
	}
}

// The credential is not verified in this process, so the trusted-proxy check
// is the entire boundary: a direct connection must not be able to name a
// system_id.
func TestIngestRefusesARequestThatDidNotComeThroughTheProxy(t *testing.T) {
	st := &fakeThreatStore{}
	h := NewServer(st, nil, trustedProxy, Config{MaxDecisions: threat.DefaultMaxDecisions})

	r := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(`{"decisions":[]}`))
	r.RemoteAddr = "203.0.113.7:4444"
	r.SetBasicAuth("someone-elses-system", "whatever")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if n := len(st.events); n != 0 {
		t.Fatalf("a direct request stored %d events", n)
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
			rec := postThreat(t, threatServer(st, nil), tc.body, true)
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
	req := httptest.NewRequest(http.MethodGet, "/v1/events", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.SetBasicAuth(testSystemID, testSecret)
	rec := httptest.NewRecorder()
	threatServer(&fakeThreatStore{}, nil).ServeHTTP(rec, req)

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

	rec := postThreat(t, threatServer(st, nil), body, true)

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
	rec := postThreat(t, threatServer(st, nil),
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

// This is the executable form of the reversal: behind the trusted proxy,
// RemoteAddr is always Traefik's own address, so the reporter-own-address
// check must key off X-Forwarded-For (via httpx.ClientIP), which is what
// makes it possible for the check to fire at all.
func TestThreatIngestDropsTheReportersOwnAddress(t *testing.T) {
	st := &fakeThreatStore{}
	req := httptest.NewRequest(http.MethodPost, "/v1/events",
		strings.NewReader(reportBody(t, testSystemID, decision("198.51.100.5", "crowdsecurity/ssh-bf", "crowdsec"))))
	req.RemoteAddr = "127.0.0.1:12345" // the trusted proxy
	req.Header.Set("X-Forwarded-For", "198.51.100.5")
	req.SetBasicAuth(testSystemID, testSecret)
	rec := httptest.NewRecorder()

	threatServer(st, nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202", rec.Code)
	}
	if len(st.events) != 0 {
		t.Fatalf("the reporter's own address was stored: %+v", st.events)
	}
}

// A forged X-Forwarded-For from a connection that is NOT the trusted proxy
// must never be consulted -- httpx.SystemID already refuses such a request
// outright (TestIngestRefusesARequestThatDidNotComeThroughTheProxy), so a
// direct connection cannot use a header to pose as coming through Traefik.
func TestThreatIngestFromAnUntrustedConnectionIsRejectedRegardlessOfXForwardedFor(t *testing.T) {
	st := &fakeThreatStore{}
	req := httptest.NewRequest(http.MethodPost, "/v1/events",
		strings.NewReader(reportBody(t, testSystemID, decision("203.0.113.7", "crowdsecurity/ssh-bf", "crowdsec"))))
	req.RemoteAddr = "198.51.100.5:44321" // not a trusted proxy
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.SetBasicAuth(testSystemID, testSecret)
	rec := httptest.NewRecorder()

	threatServer(st, nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
	if len(st.events) != 0 {
		t.Fatal("an unauthenticated report reached the store")
	}
}

func TestThreatIngestAcceptsGzip(t *testing.T) {
	st := &fakeThreatStore{}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(reportBody(t, testSystemID, decision("203.0.113.7", "crowdsecurity/ssh-bf", "crowdsec"))))
	_ = zw.Close()

	req := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(buf.Bytes()))
	req.Header.Set("Content-Encoding", "gzip")
	req.RemoteAddr = "127.0.0.1:12345"
	req.SetBasicAuth(testSystemID, testSecret)
	rec := httptest.NewRecorder()
	threatServer(st, nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202 (body %s)", rec.Code, rec.Body.String())
	}
	if len(st.events) != 1 {
		t.Fatalf("stored: %+v", st.events)
	}
}

func TestThreatIngestAnswers503WhenTheStoreFails(t *testing.T) {
	st := &fakeThreatStore{insertErr: errors.New("disk on fire")}
	rec := postThreat(t, threatServer(st, nil),
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
	rec := postThreat(t, threatServer(st, nil),
		reportBody(t, testSystemID, decision("203.0.113.7", "crowdsecurity/ssh-bf", "crowdsec")), true)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202", rec.Code)
	}
	if len(st.events) != 1 {
		t.Fatalf("stored: %+v", st.events)
	}
}

// --- feed ---

// generatedSnapshot builds and generates a real *blocklist.Snapshot with one
// entry, so tests exercise the concrete type NewServer actually takes rather
// than a faked interface.
func generatedSnapshot(t *testing.T, ip string, at int64) *blocklist.Snapshot {
	t.Helper()
	snap := blocklist.NewSnapshot()
	rule := blocklist.Rule{MinSystems: 3, Window: time.Hour, TTL: 24 * time.Hour}
	rows := []threatstore.BlocklistRow{{AttackerIP: ip, DistinctSystems: 3}}
	if err := snap.Generate(rows, rule, 0, at); err != nil {
		t.Fatalf("generate snapshot: %v", err)
	}
	return snap
}

func getBlocklist(t *testing.T, h http.Handler, withAuth bool, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/feed", nil)
	req.RemoteAddr = "127.0.0.1:12345"
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

func TestBlocklistServesThePlainTextFeed(t *testing.T) {
	snap := generatedSnapshot(t, "203.0.113.7", threatNow)
	rec := getBlocklist(t, threatServer(&fakeThreatStore{}, snap), true, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Fatalf("content-type: got %q", ct)
	}
	if rec.Header().Get("ETag") != snap.ETag() {
		t.Fatalf("etag: got %q, want %q", rec.Header().Get("ETag"), snap.ETag())
	}
	if rec.Header().Get("Cache-Control") != "max-age=900" {
		t.Fatalf("cache-control: got %q", rec.Header().Get("Cache-Control"))
	}
	if rec.Body.String() != string(snap.Body()) {
		t.Fatalf("body: got %q, want %q", rec.Body.String(), string(snap.Body()))
	}
}

func TestBlocklistRequiresAuthentication(t *testing.T) {
	snap := generatedSnapshot(t, "203.0.113.7", threatNow)
	rec := getBlocklist(t, threatServer(&fakeThreatStore{}, snap), false, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
}

// At a five-minute regeneration cadence, 304 is the normal answer.
func TestBlocklistAnswers304OnAMatchingETag(t *testing.T) {
	snap := generatedSnapshot(t, "203.0.113.7", threatNow)
	h := threatServer(&fakeThreatStore{}, snap)

	for _, header := range []string{snap.ETag(), `W/` + snap.ETag(), `"other", ` + snap.ETag(), "*"} {
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
	snap := generatedSnapshot(t, "203.0.113.7", threatNow)
	rec := getBlocklist(t, threatServer(&fakeThreatStore{}, snap), true,
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
	if string(got) != string(snap.Body()) {
		t.Fatalf("decompressed body: %q, want %q", got, snap.Body())
	}
}

// An empty body would mean "no threats" to every client that imports it,
// which silently disables protection.
func TestBlocklistRefusesBeforeTheFirstGeneration(t *testing.T) {
	rec := getBlocklist(t, threatServer(&fakeThreatStore{}, blocklist.NewSnapshot()), true, nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d, want 503", rec.Code)
	}
}

// A nil snapshot (the pipeline wired with no feed at all, as in some of the
// ingest-only tests above) must behave exactly like one that has never
// generated -- not panic.
func TestBlocklistRefusesWithNoSnapshotWired(t *testing.T) {
	rec := getBlocklist(t, threatServer(&fakeThreatStore{}, nil), true, nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d, want 503", rec.Code)
	}
}

func TestBlocklistRejectsWrongMethod(t *testing.T) {
	snap := generatedSnapshot(t, "203.0.113.7", threatNow)
	req := httptest.NewRequest(http.MethodPost, "/v1/feed", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.SetBasicAuth(testSystemID, testSecret)
	rec := httptest.NewRecorder()
	threatServer(&fakeThreatStore{}, snap).ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d, want 405", rec.Code)
	}
}
