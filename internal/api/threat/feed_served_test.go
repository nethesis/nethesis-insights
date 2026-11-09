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
// it: the daily download counts attribute each to its system and tell a
// download from a not-modified answer. The live per-feed rate has no
// counter of its own; threatd_http_requests_total separates the two feeds
// by route.
func TestFeedAnswersAreCountedPerSystem(t *testing.T) {
	reg := metrics.NewRegistry("threatd")
	downloads := blocklist.NewDownloads()

	full := generatedSnapshot(t, "203.0.113.7", threatNow)
	// No basic snapshot wired: /v1/basic-feed answers 503.
	h := NewServer(&fakeThreatStore{}, nil, full, nil, trustedProxy, Config{
		MaxDecisions: 500,
		FeedServed: func(fr FeedRequest) {
			downloads.Record(threatNow, blocklist.Poll{
				Feed: fr.Feed, Client: fr.Client, SystemID: fr.SystemID, IP: fr.IP,
				Code: fr.Code, Body: fr.Body,
			})
		},
	}, metrics.Handler(reg), metrics.NewHTTP(reg))

	do := func(method, path, etag string, auth bool) int {
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = "127.0.0.1:12345"
		// As Traefik sends them: the full feed through NethSecurity's base
		// URL, the basic one through NS8 CrowdSec's.
		req.Header.Set("X-Forwarded-For", "198.51.100.9")
		if strings.HasPrefix(path, "/v1/basic-feed") {
			req.Header.Set("X-Forwarded-Prefix", "/blocklist/crowdsec")
		} else {
			req.Header.Set("X-Forwarded-Prefix", "/blocklist")
		}
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
		`threatd_http_requests_total{method="GET",route="/v1/feed",status="200"} 2`,
		`threatd_http_requests_total{method="HEAD",route="/v1/feed",status="200"} 1`,
		`threatd_http_requests_total{method="GET",route="/v1/feed",status="304"} 1`,
		`threatd_http_requests_total{method="GET",route="/v1/basic-feed",status="503"} 1`,
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
		{Day: day, Feed: blocklist.FeedBasic, Client: blocklist.ClientCrowdSec, SystemID: testSystemID,
			Requests: 1, LastIP: "198.51.100.9", LastSeenAt: threatNow},
		{Day: day, Feed: blocklist.FeedFull, Client: blocklist.ClientNethSecurity, SystemID: testSystemID,
			Requests: 4, Downloads: 2, NotModified: 1, LastIP: "198.51.100.9", LastSeenAt: threatNow},
	}
	if !reflect.DeepEqual(sink.rows, want) {
		t.Fatalf("daily counts: got %+v,\nwant %+v", sink.rows, want)
	}
}

// The client label comes from the LAST X-Forwarded-Prefix value, and only
// from a trusted proxy: stripPrefix appends its value after any the client
// sent, and a request from anywhere else is "direct" whatever it claims.
func TestFeedClientTrustsOnlyTheProxysPrefix(t *testing.T) {
	for _, c := range []struct {
		name, remote string
		prefixes     []string
		want         string
	}{
		{"nethsecurity", "127.0.0.1:1", []string{"/blocklist"}, blocklist.ClientNethSecurity},
		{"crowdsec", "127.0.0.1:1", []string{"/blocklist/crowdsec"}, blocklist.ClientCrowdSec},
		{"no header", "127.0.0.1:1", nil, blocklist.ClientDirect},
		{"client value before traefik's", "127.0.0.1:1", []string{"/blocklist/crowdsec", "/blocklist"}, blocklist.ClientNethSecurity},
		{"untrusted remote", "203.0.113.50:1", []string{"/blocklist"}, blocklist.ClientDirect},
	} {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/feed", nil)
			req.RemoteAddr = c.remote
			for _, p := range c.prefixes {
				req.Header.Add("X-Forwarded-Prefix", p)
			}
			if got := feedClient(req, trustedProxy); got != c.want {
				t.Fatalf("feedClient = %q, want %q", got, c.want)
			}
		})
	}
}
