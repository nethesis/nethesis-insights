// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/auth"
	"github.com/nethesis/nethesis-insights/internal/model"
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

const (
	testSystemID = "sys1"
	testSecret   = "s3cret"
)

func testServer(p Publisher) http.Handler {
	return NewServer(p, nil, StaticAuth{SystemID: testSystemID, Secret: testSecret}, ThreatConfig{}, SizingConfig{}, nil, nil)
}

func validBundle() string {
	b, _ := json.Marshal(model.Bundle{
		SchemaVersion: model.SchemaVersion,
		SystemID:      testSystemID,
		Window:        model.Window{Start: 1000, End: 2000},
	})
	return string(b)
}

func postBundle(t *testing.T, h http.Handler, body string, withAuth bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/bundles", strings.NewReader(body))
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

// The 401 body stays opaque, but the error carries a reason for the debug log
// -- and never the presented secret.
func TestStaticAuthExplainsWhyItRejected(t *testing.T) {
	sa := StaticAuth{SystemID: testSystemID, Secret: testSecret}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("wrong-system", "hunter2")

	_, err := sa.Validate(context.Background(), req.Header.Get("Authorization"))
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("error: got %v, want ErrInvalidCredentials", err)
	}
	if !strings.Contains(err.Error(), "wrong-system") {
		t.Fatalf("error %q does not name the presented system_id", err)
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error %q leaks the presented secret", err)
	}
}

// Exclusion happens at ingest, before the queue, so that the gate, the prompt,
// system_templates and module_baselines all read the same filtered bundle and
// cannot disagree about which modules are in scope.
func TestIngestExcludesConfiguredModules(t *testing.T) {
	pub := &fakePublisher{}
	h := NewServer(pub, nil, StaticAuth{SystemID: testSystemID, Secret: testSecret},
		ThreatConfig{}, SizingConfig{}, map[string]bool{"crowdsec1": true}, nil)

	body, err := json.Marshal(model.Bundle{
		SchemaVersion: model.SchemaVersion,
		SystemID:      testSystemID,
		Window:        model.Window{Start: 1000, End: 2000},
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
		Window:        model.Window{Start: 1000, End: 2000},
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
	h := NewServer(pub, nil, StaticAuth{SystemID: testSystemID, Secret: testSecret},
		ThreatConfig{}, SizingConfig{}, nil, map[string]bool{"insights": true})

	body, err := json.Marshal(model.Bundle{
		SchemaVersion: model.SchemaVersion,
		SystemID:      testSystemID,
		Window:        model.Window{Start: 1000, End: 2000},
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
