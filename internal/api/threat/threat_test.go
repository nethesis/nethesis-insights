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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nethesis/nethesis-insights/internal/blocklist"
	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/platform/httpx"
	"github.com/nethesis/nethesis-insights/internal/platform/ingestq"
	"github.com/nethesis/nethesis-insights/internal/platform/metrics"
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

func (f *fakeThreatStore) UpsertAllowlistRequest(context.Context, string, string, string, int64, int) (int, error) {
	return 0, nil
}

// fakeQueue stands in for the ingest queue at the HTTP layer: handleEvents
// must never touch the store directly any more, only Publish a Work item, so
// these tests assert against what was published rather than what was
// stored. The consumer that turns a published Work into store calls --
// NewConsumer -- is tested on its own below, against fakeThreatStore.
type fakeQueue struct {
	published []Work
	err       error
}

func (q *fakeQueue) Publish(w Work) error {
	if q.err != nil {
		return q.err
	}
	q.published = append(q.published, w)
	return nil
}

func threatServer(st Store, q Publisher, snap *blocklist.Snapshot) http.Handler {
	return NewServer(st, q, snap, trustedProxy, Config{
		MaxDecisions: 500,
		Now:          func() int64 { return threatNow },
	}, nil, nil)
}

// /metrics is mounted next to /healthz. See the equivalent logs-package test
// for why this drives a request through an unrelated route first.
func TestMetricsEndpointExposesRequestCounters(t *testing.T) {
	reg := metrics.NewRegistry("threatd")
	rec := metrics.NewHTTP(reg)
	h := NewServer(&fakeThreatStore{}, &fakeQueue{}, nil, trustedProxy, Config{MaxDecisions: 500}, metrics.Handler(reg), rec)

	hr := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	hw := httptest.NewRecorder()
	h.ServeHTTP(hw, hr)

	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	for _, want := range []string{
		"go_goroutines",
		`threatd_http_requests_total{method="GET",route="/healthz",status="200"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape body missing %q\nbody:\n%s", want, body)
		}
	}
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

// The handler answers 202 as soon as the batch is queued, before anything
// reaches the store: sanitizing (and therefore the drop counters) happens
// synchronously, but the write is the queue's job.
func TestThreatIngestQueuesSanitizedEventsAndAnswersBeforeAnyWrite(t *testing.T) {
	st := &fakeThreatStore{}
	q := &fakeQueue{}
	body := reportBody(t, testSystemID, decision("203.0.113.7", "crowdsecurity/ssh-bf", "crowdsec"))

	rec := postThreat(t, threatServer(st, q, nil), body, true)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202 (body %s)", rec.Code, rec.Body.String())
	}
	var got threatIngestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !got.Accepted || got.Dropped.Accepted != 1 {
		t.Fatalf("response: %+v", got)
	}
	// Nothing reached the store: handleEvents publishes and returns, it
	// never calls InsertThreatEvents itself any more.
	if len(st.events) != 0 {
		t.Fatalf("the store was written synchronously: %+v", st.events)
	}
	if len(q.published) != 1 || q.published[0].Events[0].AttackerIP != "203.0.113.7" {
		t.Fatalf("published work: %+v", q.published)
	}
	if q.published[0].SystemID != testSystemID {
		t.Fatalf("system id: got %q, want the authenticated one", q.published[0].SystemID)
	}
	if q.published[0].Day != "2026-08-28" {
		t.Fatalf("work day: got %q", q.published[0].Day)
	}
}

// A queue at capacity must answer 503 and store nothing, exactly like the
// bundle queue -- the caller retries.
func TestThreatIngestAnswers503WhenTheQueueIsFull(t *testing.T) {
	st := &fakeThreatStore{}
	q := &fakeQueue{err: ingestq.ErrFull}
	rec := postThreat(t, threatServer(st, q, nil),
		reportBody(t, testSystemID, decision("203.0.113.7", "crowdsecurity/ssh-bf", "crowdsec")), true)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d, want 503 (body %s)", rec.Code, rec.Body.String())
	}
	if len(st.events) != 0 {
		t.Fatalf("a rejected batch reached the store: %+v", st.events)
	}
}

// A batch every decision of which is dropped by threat.Sanitize still has
// counters worth recording: RecordIngestCounters (now run by the consumer)
// is what keeps a reporter whose every event is rejected visible on
// /systems -- exactly the "why is this node contributing nothing" case that
// page exists for -- so it must still be enqueued, carrying a nil/empty
// Events slice InsertThreatEvents no-ops on.
func TestThreatIngestWithEveryDecisionDroppedStillEnqueuesForCounters(t *testing.T) {
	st := &fakeThreatStore{}
	q := &fakeQueue{}
	rec := postThreat(t, threatServer(st, q, nil),
		reportBody(t, testSystemID, decision("10.0.0.5", "crowdsecurity/ssh-bf", "crowdsec")), true)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202 (body %s)", rec.Code, rec.Body.String())
	}
	var got threatIngestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Dropped.DroppedPrivateIP != 1 {
		t.Fatalf("dropped counters: %+v", got.Dropped)
	}
	if len(q.published) != 1 {
		t.Fatalf("a fully-dropped batch was not enqueued: %+v", q.published)
	}
	if len(q.published[0].Events) != 0 {
		t.Fatalf("a fully-dropped batch enqueued events: %+v", q.published[0].Events)
	}
	if q.published[0].Counters.DroppedPrivateIP != 1 {
		t.Fatalf("enqueued counters: %+v", q.published[0].Counters)
	}
	if len(st.events) != 0 {
		t.Fatalf("a fully-dropped batch reached the store synchronously: %+v", st.events)
	}
}

// A report with no decisions at all has nothing to write and nothing to
// count, so it is the one case that skips the queue entirely.
func TestThreatIngestWithNoDecisionsNeverEnqueues(t *testing.T) {
	q := &fakeQueue{}
	rec := postThreat(t, threatServer(&fakeThreatStore{}, q, nil),
		reportBody(t, testSystemID), true)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202 (body %s)", rec.Code, rec.Body.String())
	}
	if len(q.published) != 0 {
		t.Fatalf("an empty report was enqueued: %+v", q.published)
	}
}

// The reporter is identified by its credential; the body's system_id is
// optional and only ever cross-checked.
func TestThreatIngestAcceptsAnOmittedSystemID(t *testing.T) {
	q := &fakeQueue{}
	rec := postThreat(t, threatServer(&fakeThreatStore{}, q, nil),
		reportBody(t, "", decision("203.0.113.7", "crowdsecurity/ssh-bf", "crowdsec")), true)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202", rec.Code)
	}
	if len(q.published) != 1 || q.published[0].SystemID != testSystemID {
		t.Fatalf("published work: %+v, want system id %q", q.published, testSystemID)
	}
}

func TestThreatIngestRejectsAForeignSystemID(t *testing.T) {
	q := &fakeQueue{}
	rec := postThreat(t, threatServer(&fakeThreatStore{}, q, nil),
		reportBody(t, "someone-else", decision("203.0.113.7", "crowdsecurity/ssh-bf", "crowdsec")), true)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403", rec.Code)
	}
	if len(q.published) != 0 {
		t.Fatalf("a foreign report was enqueued: %+v", q.published)
	}
}

func TestThreatIngestRequiresAuthentication(t *testing.T) {
	q := &fakeQueue{}
	rec := postThreat(t, threatServer(&fakeThreatStore{}, q, nil),
		reportBody(t, testSystemID, decision("203.0.113.7", "crowdsecurity/ssh-bf", "crowdsec")), false)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
	if len(q.published) != 0 {
		t.Fatal("an unauthenticated report was enqueued")
	}
}

// The credential is not verified in this process, so the trusted-proxy check
// is the entire boundary: a direct connection must not be able to name a
// system_id.
func TestIngestRefusesARequestThatDidNotComeThroughTheProxy(t *testing.T) {
	q := &fakeQueue{}
	h := NewServer(&fakeThreatStore{}, q, nil, trustedProxy, Config{MaxDecisions: threat.DefaultMaxDecisions}, nil, nil)

	r := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(`{"decisions":[]}`))
	r.RemoteAddr = "203.0.113.7:4444"
	r.SetBasicAuth("someone-elses-system", "whatever")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if n := len(q.published); n != 0 {
		t.Fatalf("a direct request enqueued %d work items", n)
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
			q := &fakeQueue{}
			rec := postThreat(t, threatServer(&fakeThreatStore{}, q, nil), tc.body, true)
			if rec.Code != tc.want {
				t.Fatalf("status: got %d, want %d", rec.Code, tc.want)
			}
			if len(q.published) != 0 {
				t.Fatalf("rejected body still enqueued: %+v", q.published)
			}
		})
	}
}

func TestThreatIngestRejectsWrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/events", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.SetBasicAuth(testSystemID, testSecret)
	rec := httptest.NewRecorder()
	threatServer(&fakeThreatStore{}, &fakeQueue{}, nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d, want 405", rec.Code)
	}
}

// Fail-open on content: one bad decision must not cost the batch.
func TestThreatIngestKeepsTheBatchWhenOneDecisionIsMalformed(t *testing.T) {
	q := &fakeQueue{}
	body := reportBody(t, testSystemID,
		decision("10.0.0.5", "crowdsecurity/ssh-bf", "crowdsec"),
		decision("203.0.113.7", "crowdsecurity/ssh-bf", "CAPI"),
		decision("bogus", "crowdsecurity/ssh-bf", "crowdsec"),
		decision("203.0.113.9", "crowdsecurity/ssh-bf", "crowdsec"),
	)

	rec := postThreat(t, threatServer(&fakeThreatStore{}, q, nil), body, true)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202", rec.Code)
	}
	if len(q.published) != 1 || len(q.published[0].Events) != 1 || q.published[0].Events[0].AttackerIP != "203.0.113.9" {
		t.Fatalf("published: %+v, want only 203.0.113.9", q.published)
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
	q := &fakeQueue{}
	rec := postThreat(t, threatServer(&fakeThreatStore{}, q, nil),
		reportBody(t, testSystemID,
			decision("203.0.113.7", "LePresidente/http-generic-401-bf", "crowdsec")), true)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202", rec.Code)
	}
	if len(q.published) != 1 || len(q.published[0].Events) != 1 {
		t.Fatalf("published: %+v, want the event kept", q.published)
	}
	if q.published[0].Events[0].Scenario != "LePresidente/http-generic-401-bf" {
		t.Fatalf("scenario: got %q", q.published[0].Events[0].Scenario)
	}
}

// This is the executable form of the reversal: behind the trusted proxy,
// RemoteAddr is always Traefik's own address, so the reporter-own-address
// check must key off X-Forwarded-For (via httpx.ClientIP), which is what
// makes it possible for the check to fire at all.
func TestThreatIngestDropsTheReportersOwnAddress(t *testing.T) {
	q := &fakeQueue{}
	req := httptest.NewRequest(http.MethodPost, "/v1/events",
		strings.NewReader(reportBody(t, testSystemID, decision("198.51.100.5", "crowdsecurity/ssh-bf", "crowdsec"))))
	req.RemoteAddr = "127.0.0.1:12345" // the trusted proxy
	req.Header.Set("X-Forwarded-For", "198.51.100.5")
	req.SetBasicAuth(testSystemID, testSecret)
	rec := httptest.NewRecorder()

	threatServer(&fakeThreatStore{}, q, nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202", rec.Code)
	}
	// The batch is still enqueued -- for its drop counters, not for an
	// event -- so /systems can show why this reporter contributed nothing.
	if len(q.published) != 1 || len(q.published[0].Events) != 0 {
		t.Fatalf("published work: %+v, want one item with no events", q.published)
	}
	if q.published[0].Counters.DroppedPrivateIP != 1 {
		t.Fatalf("the reporter's own address was not counted as dropped: %+v", q.published[0].Counters)
	}
}

// A forged X-Forwarded-For from a connection that is NOT the trusted proxy
// must never be consulted -- httpx.SystemID already refuses such a request
// outright (TestIngestRefusesARequestThatDidNotComeThroughTheProxy), so a
// direct connection cannot use a header to pose as coming through Traefik.
func TestThreatIngestFromAnUntrustedConnectionIsRejectedRegardlessOfXForwardedFor(t *testing.T) {
	q := &fakeQueue{}
	req := httptest.NewRequest(http.MethodPost, "/v1/events",
		strings.NewReader(reportBody(t, testSystemID, decision("203.0.113.7", "crowdsecurity/ssh-bf", "crowdsec"))))
	req.RemoteAddr = "198.51.100.5:44321" // not a trusted proxy
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.SetBasicAuth(testSystemID, testSecret)
	rec := httptest.NewRecorder()

	threatServer(&fakeThreatStore{}, q, nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
	if len(q.published) != 0 {
		t.Fatal("an unauthenticated report was enqueued")
	}
}

func TestThreatIngestAcceptsGzip(t *testing.T) {
	q := &fakeQueue{}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(reportBody(t, testSystemID, decision("203.0.113.7", "crowdsecurity/ssh-bf", "crowdsec"))))
	_ = zw.Close()

	req := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(buf.Bytes()))
	req.Header.Set("Content-Encoding", "gzip")
	req.RemoteAddr = "127.0.0.1:12345"
	req.SetBasicAuth(testSystemID, testSecret)
	rec := httptest.NewRecorder()
	threatServer(&fakeThreatStore{}, q, nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202 (body %s)", rec.Code, rec.Body.String())
	}
	if len(q.published) != 1 {
		t.Fatalf("published: %+v", q.published)
	}
}

// --- the queue's consumer: NewConsumer ---
//
// These replace what used to be handler-level assertions (store errors,
// accounting failures) now that InsertThreatEvents and RecordIngestCounters
// no longer run on the request goroutine at all -- they run here, in the
// function the queue calls, once per accepted Work item.

func TestConsumerStoresEventsAndRecordsCounters(t *testing.T) {
	st := &fakeThreatStore{}
	consume := NewConsumer(st)

	err := consume(context.Background(), Work{
		SystemID: testSystemID,
		Events:   []model.ThreatEvent{{AttackerIP: "203.0.113.7", Scenario: "crowdsecurity/ssh-bf"}},
		Counters: model.ThreatCounters{Accepted: 1},
		Day:      "2026-08-28",
	})
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if len(st.events) != 1 || st.events[0].AttackerIP != "203.0.113.7" {
		t.Fatalf("stored events: %+v", st.events)
	}
	if st.systemID != testSystemID {
		t.Fatalf("system id: got %q, want %q", st.systemID, testSystemID)
	}
	if st.day != "2026-08-28" {
		t.Fatalf("counter day: got %q", st.day)
	}
}

// A Work item with no events at all (every decision was dropped) must still
// record its counters: InsertThreatEvents no-ops on an empty slice, but
// RecordIngestCounters is what keeps the reporter visible on /systems.
func TestConsumerRecordsCountersEvenWithNoEvents(t *testing.T) {
	st := &fakeThreatStore{}
	consume := NewConsumer(st)

	err := consume(context.Background(), Work{
		SystemID: testSystemID,
		Counters: model.ThreatCounters{DroppedPrivateIP: 1},
		Day:      "2026-08-28",
	})
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if len(st.events) != 0 {
		t.Fatalf("stored events for an empty batch: %+v", st.events)
	}
	if st.counters.DroppedPrivateIP != 1 {
		t.Fatalf("recorded counters: %+v", st.counters)
	}
	if st.day != "2026-08-28" {
		t.Fatalf("counter day: got %q", st.day)
	}
}

// A store failure on the insert itself is a real failure: nothing was
// written, so the consumer must report it. There is no recovery path -- the
// reporter already has its 202 and will not re-send these decisions on its
// own -- so returning the error is what lets ingestq log it (with the
// system_id NewConsumer adds) as the one and only record of the loss.
func TestConsumerReturnsErrorWhenInsertFails(t *testing.T) {
	st := &fakeThreatStore{insertErr: errors.New("disk on fire")}
	consume := NewConsumer(st)

	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(old)

	err := consume(context.Background(), Work{
		SystemID: testSystemID,
		Events:   []model.ThreatEvent{{AttackerIP: "203.0.113.7", Scenario: "crowdsecurity/ssh-bf"}},
	})
	if err == nil {
		t.Fatal("consume: got nil error, want the insert failure")
	}
	// The client already has its 202: this log line is the only remaining
	// trace of whose evidence was just dropped, so it must name the system.
	if !strings.Contains(logs.String(), "system_id="+testSystemID) {
		t.Fatalf("log output missing system_id: %s", logs.String())
	}
	if !strings.Contains(logs.String(), "events=1") {
		t.Fatalf("log output missing event count: %s", logs.String())
	}
}

// Accounting is an operator convenience; the evidence is already stored, so
// its failure must not fail the work item -- there is nothing left to retry
// usefully, and the queue would just log a success as a failure.
func TestConsumerSucceedsWhenAccountingFails(t *testing.T) {
	st := &fakeThreatStore{countErr: errors.New("nope")}
	consume := NewConsumer(st)

	err := consume(context.Background(), Work{
		SystemID: testSystemID,
		Events:   []model.ThreatEvent{{AttackerIP: "203.0.113.7", Scenario: "crowdsecurity/ssh-bf"}},
	})
	if err != nil {
		t.Fatalf("consume: got %v, want nil (accounting failures are logged, not propagated)", err)
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
	rec := getBlocklist(t, threatServer(&fakeThreatStore{}, nil, snap), true, nil)

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
	rec := getBlocklist(t, threatServer(&fakeThreatStore{}, nil, snap), false, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
}

// At a five-minute regeneration cadence, 304 is the normal answer.
func TestBlocklistAnswers304OnAMatchingETag(t *testing.T) {
	snap := generatedSnapshot(t, "203.0.113.7", threatNow)
	h := threatServer(&fakeThreatStore{}, nil, snap)

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
	rec := getBlocklist(t, threatServer(&fakeThreatStore{}, nil, snap), true,
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
	rec := getBlocklist(t, threatServer(&fakeThreatStore{}, nil, blocklist.NewSnapshot()), true, nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d, want 503", rec.Code)
	}
}

// A nil snapshot (the pipeline wired with no feed at all, as in some of the
// ingest-only tests above) must behave exactly like one that has never
// generated -- not panic.
func TestBlocklistRefusesWithNoSnapshotWired(t *testing.T) {
	rec := getBlocklist(t, threatServer(&fakeThreatStore{}, nil, nil), true, nil)
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
	threatServer(&fakeThreatStore{}, nil, snap).ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d, want 405", rec.Code)
	}
}

// A gzip bomb must be refused by size rather than decompressed into memory.
// The limiter used to sit on r.Body only, bounding the compressed bytes while
// gunzip expanded them without limit; ~12 MiB of gzipped JSON whitespace
// costs a few tens of KiB on the wire and is stopped only by the cap on the
// decoded stream.
func TestThreatIngestGzipBombIsRejectedBySize(t *testing.T) {
	var body bytes.Buffer
	gz := gzip.NewWriter(&body)
	if _, err := gz.Write([]byte(`{"schema_version":1,`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Whitespace is valid JSON filler, so the decoder keeps reading instead
	// of failing early on a syntax error -- this is a size test, not a
	// parser test.
	filler := bytes.Repeat([]byte(" "), 1<<20)
	for range 12 {
		if _, err := gz.Write(filler); err != nil {
			t.Fatalf("write filler: %v", err)
		}
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(body.Bytes()))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Encoding", "gzip")
	req.SetBasicAuth(testSystemID, testSecret)
	rec := httptest.NewRecorder()
	threatServer(&fakeThreatStore{}, &fakeQueue{}, nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 -- an unbounded gunzip is a memory-exhaustion "+
			"path for any reporter with a valid credential", rec.Code)
	}
}
