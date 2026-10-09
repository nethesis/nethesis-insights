// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package embed is the client for the local embedding sidecar (llama-server,
// OpenAI-compatible /v1/embeddings). It is I/O, used by the logs pipeline's
// grouping pass only.
package embed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// retryCuts are the byte lengths tried, in order, after a non-2xx answer:
// llama-server answers an input longer than its batch with HTTP 500.
var retryCuts = []int{1000, 600, 300}

const maxResponseBytes = 1 << 20

// Client talks to one embedding sidecar.
type Client struct {
	baseURL string
	client  *http.Client
}

// New returns a client for the sidecar at baseURL.
func New(baseURL string, timeout time.Duration) *Client {
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), client: &http.Client{Timeout: timeout}}
}

type statusError struct{ status int }

func (e *statusError) Error() string { return fmt.Sprintf("embed: server answered HTTP %d", e.status) }

// ErrRejected is returned (test with errors.Is) when the server answered every
// size attempt with a non-2xx status. The input, not the sidecar, is the
// problem; callers skip it rather than treat the sidecar as down.
var ErrRejected = errors.New("embed: input rejected")

type rejectedError struct {
	status int
	sizes  []int
}

func (e *rejectedError) Error() string {
	parts := make([]string, len(e.sizes))
	for i, n := range e.sizes {
		parts[i] = strconv.Itoa(n)
	}
	return fmt.Sprintf("embed: server answered HTTP %d at %s bytes", e.status, strings.Join(parts, ", "))
}

func (e *rejectedError) Is(target error) bool { return target == ErrRejected }

// Embed posts text to <baseURL>/v1/embeddings and returns the L2-normalised
// vector and the model name the server reported. A non-2xx answer is retried
// at most three times with the text cut to 1000, 600 then 300 bytes (on a rune
// boundary; a cut that would not shorten the text is skipped). If every size is
// refused the error satisfies errors.Is(err, ErrRejected);
// any other failure returns immediately. The text is never logged.
func (c *Client) Embed(ctx context.Context, text string) ([]float32, string, error) {
	vec, model, err := c.embed(ctx, text)
	var se *statusError
	if err == nil || !errors.As(err, &se) {
		return vec, model, err
	}
	sizes := []int{len(text)}
	for _, n := range retryCuts {
		cut := cutBytes(text, n)
		if len(cut) >= len(text) {
			continue
		}
		text = cut
		sizes = append(sizes, len(text))
		vec, model, err = c.embed(ctx, text)
		if err == nil || !errors.As(err, &se) {
			return vec, model, err
		}
	}
	return nil, "", &rejectedError{status: se.status, sizes: sizes}
}

// cutBytes cuts s to at most n bytes, backing up to a rune boundary.
func cutBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

type response struct {
	Model string `json:"model"`
	Data  []struct {
		Embedding []float32 `json:"embedding"`
	} `json:"data"`
}

func (c *Client) embed(ctx context.Context, text string) ([]float32, string, error) {
	payload, err := json.Marshal(map[string]string{"input": text})
	if err != nil {
		return nil, "", fmt.Errorf("embed: encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/embeddings", bytes.NewReader(payload))
	if err != nil {
		return nil, "", fmt.Errorf("embed: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("embed: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, "", &statusError{status: resp.StatusCode}
	}

	var parsed response
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&parsed); err != nil {
		return nil, "", fmt.Errorf("embed: decode response: %w", err)
	}
	if parsed.Model == "" {
		return nil, "", errors.New("embed: response carries no model name")
	}
	if len(parsed.Data) == 0 || len(parsed.Data[0].Embedding) == 0 {
		return nil, "", errors.New("embed: response carries no embedding")
	}
	vec := parsed.Data[0].Embedding
	var sum float64
	for _, x := range vec {
		sum += float64(x) * float64(x)
	}
	if sum == 0 || math.IsNaN(sum) || math.IsInf(sum, 0) {
		return nil, "", errors.New("embed: embedding has no usable magnitude")
	}
	norm := float32(math.Sqrt(sum))
	for i := range vec {
		vec[i] /= norm
	}
	return vec, parsed.Model, nil
}
