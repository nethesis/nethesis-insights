// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package httpx

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Logging is the request logger every binary in this repository wraps its
// mux with (insightsd, threatd, sizingd directly; authd's newHandler calls
// it too). CLAUDE.md's "Secrets and data protection" invariant says the
// request logger must never touch the Authorization header -- and it has two
// log call sites inside this one function (the "request received" Debug line
// and the "request" Info line), both of which must honor it. This test fails
// if either one starts logging the header's value instead of merely its
// presence, and it is the only place that invariant is pinned by a test.
func TestLoggingNeverLogsTheAuthorizationHeaderValue(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	// A distinctive value that would stand out clearly if it leaked, unlike
	// a short common word that could show up in log output by coincidence.
	const secretHeader = "Basic Z2lhY29tbzpodW50ZXIy" // base64("giacomo:hunter2")

	h := Logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), nil)

	r := httptest.NewRequest(http.MethodPost, "/v1/bundles?since=42", nil)
	r.Header.Set("Authorization", secretHeader)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	out := buf.String()
	if strings.Contains(out, secretHeader) {
		t.Fatalf("request logger leaked the Authorization header value:\n%s", out)
	}
	// The whole base64 payload is the likeliest leak; also check the raw
	// credential fragment in case something ever decodes it before logging.
	if strings.Contains(out, "hunter2") {
		t.Fatalf("request logger leaked the decoded credential:\n%s", out)
	}

	// The negative check above is only meaningful if the logger actually
	// looked at the header. Confirm it did, via the presence flag the code
	// is supposed to log instead of the value.
	if !strings.Contains(out, "has_authorization=true") {
		t.Fatalf("logger output = %q, want has_authorization=true -- the presence check must still run", out)
	}
}

// A request with no Authorization header must log the presence flag as
// false, not merely omit it -- the flag itself has to be trustworthy so an
// operator can tell "no credential" apart from "logger broke".
func TestLoggingReportsAbsentAuthorizationHeader(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	h := Logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), nil)
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if !strings.Contains(buf.String(), "has_authorization=false") {
		t.Fatalf("logger output = %q, want has_authorization=false", buf.String())
	}
}

// The status line is what makes the logger useful at all: method, path and
// the status code the wrapped handler actually wrote (not a hardcoded 200),
// plus a duration. A handler that never calls WriteHeader still defaults to
// 200 via statusRecorder's zero value.
func TestLoggingRecordsMethodPathAndTheHandlersStatus(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	defer slog.SetDefault(prev)

	h := Logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}), nil)
	r := httptest.NewRequest(http.MethodPost, "/v1/findings", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	out := buf.String()
	for _, want := range []string{`method=POST`, `path=/v1/findings`, `status=418`} {
		if !strings.Contains(out, want) {
			t.Errorf("logger output = %q, want it to contain %q", out, want)
		}
	}
}

// recordingMetrics is a MetricsRecorder that just remembers its last call,
// so a test can assert what Logging fed it without pulling in a real
// prometheus registry.
type recordingMetrics struct {
	method, route string
	status        int
	calls         int
}

func (r *recordingMetrics) Observe(method, route string, status int, _ time.Duration) {
	r.method, r.route, r.status = method, route, status
	r.calls++
}

// A nil MetricsRecorder must not panic -- every UI mux in this codebase
// passes nil, since only the four binaries' API muxes carry a /metrics
// endpoint.
func TestLoggingToleratesNilMetricsRecorder(t *testing.T) {
	h := Logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), nil)
	r := httptest.NewRequest(http.MethodGet, "/v1/findings", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r) // must not panic
}

// CLAUDE.md's cardinality rule: the route label fed to metrics must be the
// registered ServeMux pattern, never the raw request path. This is the
// regression test for that -- two distinct paths matching the SAME pattern
// (a wildcard) must report the SAME route label, and an unmatched path must
// report a fixed label rather than itself.
func TestLoggingMetricsRouteLabelIsThePatternNotThePath(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/findings", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/systems/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := &recordingMetrics{}
	h := Logging(mux, rec)

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/findings", nil))
	if rec.route != "/v1/findings" || rec.method != "GET" || rec.status != http.StatusOK {
		t.Fatalf("got method=%q route=%q status=%d, want GET /v1/findings 200", rec.method, rec.route, rec.status)
	}

	// Two distinct system ids must collapse onto the SAME route label --
	// the wildcard pattern, never the id itself. This is the check that
	// would catch a regression back to r.URL.Path.
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/systems/alpha", nil))
	firstRoute := rec.route
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/systems/bravo", nil))
	if rec.route != firstRoute {
		t.Fatalf("route label changed between requests to the same pattern: %q vs %q -- looks like the raw path leaked into the label", firstRoute, rec.route)
	}
	if rec.route != "/systems/{id}" {
		t.Fatalf("route = %q, want the registered pattern /systems/{id}", rec.route)
	}
	if strings.Contains(rec.route, "alpha") || strings.Contains(rec.route, "bravo") {
		t.Fatalf("route label %q leaked a path segment", rec.route)
	}

	// An unmatched path must not become an unbounded label either.
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/no/such/route", nil))
	if rec.route != "unmatched" {
		t.Fatalf("route = %q for a 404, want the fixed \"unmatched\" label", rec.route)
	}
	if rec.calls != 4 {
		t.Fatalf("Observe called %d times, want 4", rec.calls)
	}
}
