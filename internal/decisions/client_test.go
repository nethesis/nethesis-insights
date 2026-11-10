// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package decisions

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDecidePostsBody(t *testing.T) {
	const key = "sk-test-secret-key"
	const body = `{"model":"gpt-6-luna","input":"x"}`
	var gotPath, gotAuth, gotCT, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := New(srv.URL+"/v1", key, 5*time.Second)
	out, err := c.Decide(context.Background(), []byte(body))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if gotPath != "/v1/decisions" {
		t.Errorf("path = %q, want /v1/decisions", gotPath)
	}
	if gotAuth != "Bearer "+key {
		t.Errorf("Authorization = %q, want bearer key", gotAuth)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	if gotBody != body {
		t.Errorf("body = %q, want %q", gotBody, body)
	}
	if string(out) != `{"ok":true}` {
		t.Errorf("response = %q, want the 2xx body", out)
	}
}

func TestStatusErrorClasses(t *testing.T) {
	cases := []struct {
		code      int
		fatal     bool
		retryable bool
	}{
		{http.StatusUnauthorized, true, false},
		{http.StatusForbidden, true, false},
		{http.StatusNotFound, true, false},
		{http.StatusTooManyRequests, false, true},
		{http.StatusInternalServerError, false, true},
		{http.StatusServiceUnavailable, false, true},
		{http.StatusBadRequest, false, false},
		{http.StatusUnprocessableEntity, false, false},
	}
	for _, tc := range cases {
		e := &StatusError{StatusCode: tc.code}
		if e.Fatal() != tc.fatal {
			t.Errorf("%d: Fatal() = %v, want %v", tc.code, e.Fatal(), tc.fatal)
		}
		if e.Retryable() != tc.retryable {
			t.Errorf("%d: Retryable() = %v, want %v", tc.code, e.Retryable(), tc.retryable)
		}
	}
}

func TestStatusErrorReturnedAndBodyCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(strings.Repeat("x", 2000)))
	}))
	defer srv.Close()

	c := New(srv.URL+"/v1", "k", 5*time.Second)
	_, err := c.Decide(context.Background(), []byte(`{}`))
	var se *StatusError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want *StatusError", err)
	}
	if se.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d, want 400", se.StatusCode)
	}
	if len(se.Body) != 500 {
		t.Errorf("Body length = %d, want 500 (capped)", len(se.Body))
	}
}

func TestErrorNeverCarriesKey(t *testing.T) {
	const key = "sk-test-secret-key"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`invalid api key`))
	}))
	defer srv.Close()

	c := New(srv.URL+"/v1", key, 5*time.Second)
	_, err := c.Decide(context.Background(), []byte(`{}`))
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), key) {
		t.Errorf("error %q carries the API key", err.Error())
	}

	// Transport failure: the URL in the error must not carry the key either.
	dead := New("http://127.0.0.1:1/v1", key, time.Second)
	_, err = dead.Decide(context.Background(), []byte(`{}`))
	if err == nil {
		t.Fatal("want transport error")
	}
	if strings.Contains(err.Error(), key) {
		t.Errorf("transport error %q carries the API key", err.Error())
	}
}
