// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package threat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/blocklist"
	"github.com/nethesis/nethesis-insights/internal/platform/metrics"
	threatstore "github.com/nethesis/nethesis-insights/internal/store/threat"
)

type downloadSink struct{ rows []threatstore.FeedDownloadRow }

func (d *downloadSink) AddFeedDownloads(_ context.Context, rows []threatstore.FeedDownloadRow) error {
	d.rows = append(d.rows, rows...)
	return nil
}

// Every feed answer reaches FeedServed, wired here exactly as threatd wires
// it: threatd_feed_requests_total counts each one by feed and code, and the
// daily download counts attribute each to its system.
func TestFeedRequestsAreCountedPerFeedAndCode(t *testing.T) {
	reg := metrics.NewRegistry("threatd")
	counter := metrics.NewFeedRequests(reg, []string{blocklist.FeedFull, blocklist.FeedBasic}, FeedCodes)
	downloads := blocklist.NewDownloads()

	full := generatedSnapshot(t, "203.0.113.7", threatNow)
	// No basic snapshot wired: /v1/basic-feed answers 503.
	h := NewServer(&fakeThreatStore{}, nil, full, nil, trustedProxy, Config{
		MaxDecisions: 500,
		FeedServed: func(fr FeedRequest) {
			counter.Inc(fr.Feed, fr.Code)
			downloads.Record(threatNow, fr.Feed, fr.SystemID, fr.Code, fr.Body)
		},
	}, metrics.Handler(reg), nil)

	do := func(method, path, etag string, auth bool) int {
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = "127.0.0.1:12345"
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		if auth {
			req.SetBasicAuth(testSystemID, testSecret)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for _, c := range []struct {
		method, path, etag string
		auth               bool
		want               int
	}{
		{http.MethodGet, "/v1/feed", "", true, http.StatusOK},
		{http.MethodGet, "/v1/feed", "", true, http.StatusOK},
		{http.MethodHead, "/v1/feed", "", true, http.StatusOK},
		{http.MethodGet, "/v1/feed", full.View().ETag, true, http.StatusNotModified},
		{http.MethodGet, "/v1/feed", "", false, http.StatusUnauthorized},
		{http.MethodPost, "/v1/feed", "", true, http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/basic-feed", "", true, http.StatusServiceUnavailable},
	} {
		if got := do(c.method, c.path, c.etag, c.auth); got != c.want {
			t.Fatalf("%s %s: got %d, want %d", c.method, c.path, got, c.want)
		}
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		`threatd_feed_requests_total{code="200",feed="full"} 3`,
		`threatd_feed_requests_total{code="304",feed="full"} 1`,
		`threatd_feed_requests_total{code="401",feed="full"} 1`,
		`threatd_feed_requests_total{code="405",feed="full"} 1`,
		`threatd_feed_requests_total{code="503",feed="basic"} 1`,
		// Pre-created at 0, before anything was answered with it.
		`threatd_feed_requests_total{code="200",feed="basic"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape is missing %q", want)
		}
	}

	sink := &downloadSink{}
	if _, err := downloads.Flush(context.Background(), sink); err != nil {
		t.Fatal(err)
	}
	day := threatstore.DayString(threatNow)
	// The 401 and the 405 carry no system and are not attributed; the HEAD
	// is a request but not a download.
	want := []threatstore.FeedDownloadRow{
		{Day: day, Feed: blocklist.FeedBasic, SystemID: testSystemID, Requests: 1},
		{Day: day, Feed: blocklist.FeedFull, SystemID: testSystemID, Requests: 4, Downloads: 2, NotModified: 1},
	}
	if !reflect.DeepEqual(sink.rows, want) {
		t.Fatalf("daily counts: got %+v,\nwant %+v", sink.rows, want)
	}
}
