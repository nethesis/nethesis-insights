// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package embed

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func okBody(model string, vec string) string {
	return `{"model":"` + model + `","data":[{"embedding":` + vec + `}]}`
}

func TestEmbedHappyPath(t *testing.T) {
	var gotPath, gotCT, gotMethod string
	var gotInput string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotCT, gotMethod = r.URL.Path, r.Header.Get("Content-Type"), r.Method
		var in struct {
			Input string `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		gotInput = in.Input
		_, _ = w.Write([]byte(okBody("m1", "[3,4]")))
	}))
	defer srv.Close()

	vec, model, err := New(srv.URL, time.Second).Embed(context.Background(), "hello")
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/embeddings" || !strings.HasPrefix(gotCT, "application/json") || gotInput != "hello" {
		t.Fatalf("request: %s %s %q %q", gotMethod, gotPath, gotCT, gotInput)
	}
	if model != "m1" {
		t.Fatalf("model %q", model)
	}
	if len(vec) != 2 || math.Abs(float64(vec[0])-0.6) > 1e-6 || math.Abs(float64(vec[1])-0.8) > 1e-6 {
		t.Fatalf("vec %v", vec)
	}
}

func TestEmbedRetriesShorter(t *testing.T) {
	var lens []int
	succeedAt := 1000
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Input string `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		lens = append(lens, len(in.Input))
		if len(in.Input) > succeedAt {
			http.Error(w, "input is too large", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(okBody("m", "[1]")))
	}))
	defer srv.Close()

	text := strings.Repeat("a", 5000)
	if _, _, err := New(srv.URL, time.Second).Embed(context.Background(), text); err != nil {
		t.Fatal(err)
	}
	if len(lens) != 2 || lens[0] != 5000 || lens[1] != 1000 {
		t.Fatalf("lens %v", lens)
	}

	lens, succeedAt = nil, 600
	if _, _, err := New(srv.URL, time.Second).Embed(context.Background(), text); err != nil {
		t.Fatal(err)
	}
	if len(lens) != 3 || lens[0] != 5000 || lens[1] != 1000 || lens[2] != 600 {
		t.Fatalf("lens %v", lens)
	}
}

func TestEmbedCutIsRuneSafe(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Input string `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		seen = append(seen, in.Input)
		http.Error(w, "too large", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, _, err := New(srv.URL, time.Second).Embed(context.Background(), strings.Repeat("é", 2000))
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err %v", err)
	}
	if len(seen) != 4 {
		t.Fatalf("attempts %d", len(seen))
	}
	for _, s := range seen {
		if !utf8.ValidString(s) {
			t.Fatal("invalid UTF-8 sent")
		}
	}
	if len(seen[1]) != 1000 || len(seen[2]) != 600 || len(seen[3]) != 300 {
		t.Fatalf("lens %d %d %d", len(seen[1]), len(seen[2]), len(seen[3]))
	}
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("not ErrRejected: %v", err)
	}
	if !strings.Contains(err.Error(), "HTTP 500") || !strings.Contains(err.Error(), "4000, 1000, 600, 300 bytes") {
		t.Fatalf("message %q", err)
	}
}

func TestEmbedSucceedsAtShortestCut(t *testing.T) {
	var lens []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Input string `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		lens = append(lens, len(in.Input))
		if len(in.Input) > 300 {
			http.Error(w, "too large", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(okBody("m", "[1]")))
	}))
	defer srv.Close()
	if _, _, err := New(srv.URL, time.Second).Embed(context.Background(), strings.Repeat("a", 1500)); err != nil {
		t.Fatal(err)
	}
	if len(lens) != 4 || lens[3] != 300 {
		t.Fatalf("lens %v", lens)
	}
}

func TestEmbedShortTextFailsOnce(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	_, _, err := New(srv.URL, time.Second).Embed(context.Background(), "tiny")
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("want ErrRejected, got %v", err)
	}
	// Cutting would not change the text, so retrying is pointless.
	if n != 1 {
		t.Fatalf("attempts %d", n)
	}
}

func TestEmbedBadResponses(t *testing.T) {
	for name, body := range map[string]string{
		"empty data":      `{"model":"m","data":[]}`,
		"empty embedding": `{"model":"m","data":[{"embedding":[]}]}`,
		"empty model":     `{"model":"","data":[{"embedding":[1]}]}`,
		"bad json":        `{`,
		"zero vector":     `{"model":"m","data":[{"embedding":[0,0]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			n := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n++
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()
			if _, _, err := New(srv.URL, time.Second).Embed(context.Background(), strings.Repeat("a", 3000)); err == nil {
				t.Fatal("want error")
			}
			if n != 1 {
				t.Fatalf("retried: %d", n)
			}
		})
	}
}

func TestEmbedConnectionRefusedNoRetry(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	if _, _, err := New(url, time.Second).Embed(context.Background(), "x"); err == nil {
		t.Fatal("want error")
	}
}
