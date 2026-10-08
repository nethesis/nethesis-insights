// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const okBody = `{"model":"m","choices":[{"message":{"role":"assistant","content":"{}"}}],"usage":{"prompt_tokens":10,"completion_tokens":2}}`

// tierServer answers each request with the next status in statuses and
// records the service_tier every request carried.
func tierServer(t *testing.T, statuses ...int) (*httptest.Server, *[]string) {
	t.Helper()
	var tiers []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ServiceTier *string `json:"service_tier"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		tier := "<absent>"
		if body.ServiceTier != nil {
			tier = *body.ServiceTier
		}
		tiers = append(tiers, tier)
		status := statuses[len(tiers)-1]
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte(okBody))
			return
		}
		_, _ = w.Write([]byte(`{"error":{"message":"resource unavailable"}}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &tiers
}

func TestServiceTierIsSentWhenConfigured(t *testing.T) {
	srv, tiers := tierServer(t, http.StatusOK)
	if _, err := NewOpenAI(srv.URL, "k", "flex", time.Second).Complete(context.Background(), Request{Model: "m"}); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if len(*tiers) != 1 || (*tiers)[0] != "flex" {
		t.Fatalf("tiers = %v, want [flex]", *tiers)
	}
}

// Some providers reject fields they do not know, so an unconfigured tier is
// not sent at all.
func TestServiceTierIsOmittedWhenEmpty(t *testing.T) {
	srv, tiers := tierServer(t, http.StatusOK)
	if _, err := NewOpenAI(srv.URL, "k", "", time.Second).Complete(context.Background(), Request{Model: "m"}); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if len(*tiers) != 1 || (*tiers)[0] != "<absent>" {
		t.Fatalf("tiers = %v, want the field absent", *tiers)
	}
}

// A window whose call failed is analysed again only if the edge resends it,
// so a flex 429 is retried once at the default tier rather than lost.
func TestFlex429FallsBackToTheDefaultTier(t *testing.T) {
	srv, tiers := tierServer(t, http.StatusTooManyRequests, http.StatusOK)
	resp, err := NewOpenAI(srv.URL, "k", "flex", time.Second).Complete(context.Background(), Request{Model: "m"})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if resp.InputTokens != 10 {
		t.Fatalf("response = %+v, want the retried call's", resp)
	}
	if len(*tiers) != 2 || (*tiers)[0] != "flex" || (*tiers)[1] != "<absent>" {
		t.Fatalf("tiers = %v, want [flex <absent>]", *tiers)
	}
}

func TestA429WithoutATierIsNotRetried(t *testing.T) {
	srv, tiers := tierServer(t, http.StatusTooManyRequests)
	_, err := NewOpenAI(srv.URL, "k", "", time.Second).Complete(context.Background(), Request{Model: "m"})
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("err = %v, want the 429", err)
	}
	if len(*tiers) != 1 {
		t.Fatalf("made %d requests, want 1", len(*tiers))
	}
}
