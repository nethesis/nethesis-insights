// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/sizing"
	"github.com/nethesis/nethesis-insights/internal/store"
)

// sizingNow is fixed so the day-window rules are not clock sensitive.
var sizingNow = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC).UnixMilli()

type fakeSizingStore struct {
	days      []store.SizingDayRows
	counters  model.SizingCounters
	counterD  int64
	reporter  string
	upserts   int
	ingests   int
	upsertErr error
}

func (f *fakeSizingStore) UpsertSizingDays(_ context.Context, systemID, reporterVersion string, days []store.SizingDayRows, now int64) (int, error) {
	if f.upsertErr != nil {
		return 0, f.upsertErr
	}
	f.upserts++
	f.days = days
	f.reporter = reporterVersion
	stored := 0
	for _, d := range days {
		stored += len(d.Nodes)
	}
	return stored, nil
}

func (f *fakeSizingStore) RecordSizingIngest(_ context.Context, day int64, systemID, reporterVersion string, c model.SizingCounters, now int64) error {
	f.ingests++
	f.counterD = day
	f.counters.Add(c)
	return nil
}

func sizingServer(st SizingStore) http.Handler {
	return NewServer(&fakePublisher{}, nil,
		StaticAuth{SystemID: testSystemID, Secret: testSecret},
		ThreatConfig{}, SizingConfig{
			Store: st,
			Now:   func() int64 { return sizingNow },
		}, nil, nil)
}

func postSizing(t *testing.T, h http.Handler, body string, withAuth bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/sizing-reports", strings.NewReader(body))
	if withAuth {
		req.SetBasicAuth(testSystemID, testSecret)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func validReport(day string) string {
	return fmt.Sprintf(`{"schema_version":1,"reporter_version":"1.0.0","days":[
		{"day":%q,"nodes":[
			{"node_id":1,"metrics_present":true,"sample_coverage":0.99,
			 "hardware":{"cpu_cores":4,"mem_total_bytes":8589934592},
			 "resources":{"ram_util_p95":0.41,"ram_used_bytes_p95":3300000000},
			 "stress":{"iowait_busy_frac":0.01,"oom_kills":0},
			 "modules":[{"family":"mail","instances":1,"facts_ok":1,
			             "workload":{"mailboxes":210}}]}],
		 "cluster":{"user_domains":[{"total_users":210}]}}]}`, day)
}

func TestSizingIngestAcceptsAndScores(t *testing.T) {
	st := &fakeSizingStore{}
	rec := postSizing(t, sizingServer(st), validReport("2026-09-01"), true)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body.String())
	}
	var resp sizingIngestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Accepted || resp.StoredDays != 1 || resp.StoredNodes != 1 {
		t.Fatalf("response = %+v", resp)
	}
	if resp.Dropped.AcceptedNodes != 1 || resp.Dropped.AcceptedMetrics == 0 {
		t.Errorf("counters = %+v", resp.Dropped)
	}

	// The score is computed HERE, on the server, and never on the edge:
	// scoring at the edge would make every node an uncoordinated second
	// implementation of the formula.
	if len(st.days) != 1 || len(st.days[0].Nodes) != 1 {
		t.Fatalf("stored days = %#v", st.days)
	}
	node := st.days[0].Nodes[0]
	if node.PressureVersion != sizing.PressureVersion {
		t.Errorf("pressure_version = %d, want %d", node.PressureVersion, sizing.PressureVersion)
	}
	if node.Pressure == nil {
		t.Error("a fully measured node must carry a pressure")
	}
	if st.days[0].ClusterWorkload["total_users"] != 210 {
		t.Errorf("cluster workload = %#v", st.days[0].ClusterWorkload)
	}
	if st.reporter != "1.0.0" {
		t.Errorf("reporter version = %q", st.reporter)
	}
}

func TestSizingIngestRequiresAuth(t *testing.T) {
	st := &fakeSizingStore{}
	if rec := postSizing(t, sizingServer(st), validReport("2026-09-01"), false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if st.upserts != 0 {
		t.Error("an unauthenticated report reached the store")
	}
}

func TestSizingIngestRejectsWrongSchemaVersion(t *testing.T) {
	body := `{"schema_version":99,"days":[]}`
	if rec := postSizing(t, sizingServer(&fakeSizingStore{}), body, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// system_id is optional -- the credential already identifies the reporter --
// but a mismatch is a broken reporter, never something to silently override.
func TestSizingIngestRejectsMismatchedSystemID(t *testing.T) {
	body := `{"schema_version":1,"system_id":"someone-else","days":[]}`
	if rec := postSizing(t, sizingServer(&fakeSizingStore{}), body, true); rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestSizingIngestRejectsNonPost(t *testing.T) {
	h := sizingServer(&fakeSizingStore{})
	req := httptest.NewRequest(http.MethodGet, "/v1/sizing-reports", nil)
	req.SetBasicAuth(testSystemID, testSecret)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

// The zero SizingConfig leaves the route unregistered, so a deployment that
// has not wired the pipeline serves a plain 404 rather than a half-working
// endpoint.
func TestSizingRouteAbsentWhenUnconfigured(t *testing.T) {
	h := NewServer(&fakePublisher{}, nil,
		StaticAuth{SystemID: testSystemID, Secret: testSecret},
		ThreatConfig{}, SizingConfig{}, nil, nil)
	rec := postSizing(t, h, validReport("2026-09-01"), true)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestSizingIngestAcceptsGzip(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(validReport("2026-09-01"))); err != nil {
		t.Fatalf("gzip: %v", err)
	}
	gz.Close()

	st := &fakeSizingStore{}
	req := httptest.NewRequest(http.MethodPost, "/v1/sizing-reports", &buf)
	req.SetBasicAuth(testSystemID, testSecret)
	req.Header.Set("Content-Encoding", "gzip")
	rec := httptest.NewRecorder()
	sizingServer(st).ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body.String())
	}
	if st.upserts != 1 {
		t.Error("the gzipped report did not reach the store")
	}
}

func TestSizingIngestRejectsDeclaredOversizeBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/sizing-reports", strings.NewReader("{}"))
	req.SetBasicAuth(testSystemID, testSecret)
	req.ContentLength = maxSizingReportSize + 1
	rec := httptest.NewRecorder()
	sizingServer(&fakeSizingStore{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

// A store failure is a 503, which is retryable -- and redelivery is free by
// construction, so a delayed report is always better than a lost one.
func TestSizingIngestStoreFailureIs503(t *testing.T) {
	st := &fakeSizingStore{upsertErr: context.DeadlineExceeded}
	if rec := postSizing(t, sizingServer(st), validReport("2026-09-01"), true); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// A report whose every day was rejected still gets its 202 and its counters:
// the counters are the way a reporter sees why nothing was stored.
func TestSizingIngestAcceptsAReportItStoredNothingFrom(t *testing.T) {
	st := &fakeSizingStore{}
	rec := postSizing(t, sizingServer(st), validReport("2020-01-01"), true)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
	var resp sizingIngestResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.StoredDays != 0 || resp.StoredNodes != 0 {
		t.Errorf("response = %+v, want nothing stored", resp)
	}
	if resp.Dropped.DroppedDay != 1 {
		t.Errorf("dropped_day = %d, want 1", resp.Dropped.DroppedDay)
	}
	if st.ingests != 1 {
		t.Error("the counters were not recorded")
	}
	// With no usable day the counters land under the arrival day rather than
	// being thrown away -- dropping them would hide the reporter that needs
	// fixing.
	if st.counterD != 0 {
		t.Errorf("counter day = %d, want 0 so the store falls back to the arrival day", st.counterD)
	}
}

// Ingest is fail-open on content: one malformed node must not cost the report
// its siblings.
func TestSizingIngestKeepsSiblingsOfABadNode(t *testing.T) {
	body := `{"schema_version":1,"days":[{"day":"2026-09-01","nodes":[
		{"node_id":0,"metrics_present":true,"sample_coverage":0.99,
		 "hardware":{"cpu_cores":4,"mem_total_bytes":8589934592}},
		{"node_id":2,"metrics_present":true,"sample_coverage":0.99,
		 "hardware":{"cpu_cores":4,"mem_total_bytes":8589934592}}]}]}`

	st := &fakeSizingStore{}
	rec := postSizing(t, sizingServer(st), body, true)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
	var resp sizingIngestResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.StoredNodes != 1 {
		t.Errorf("stored nodes = %d, want 1", resp.StoredNodes)
	}
	if resp.Dropped.DroppedNode != 1 {
		t.Errorf("dropped_node = %d, want 1", resp.Dropped.DroppedNode)
	}
}
