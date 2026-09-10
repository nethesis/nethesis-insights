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
	}))

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
	}))
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
	}))
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
