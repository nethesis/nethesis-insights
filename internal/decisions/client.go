// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package decisions is the HTTP client for the OpenAI Decisions API. It
// takes and returns raw bytes: the request and response shapes belong to
// internal/decide. It never retries; the caller's pass retries on its next
// tick.
package decisions

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// maxErrorBody caps how much of an error response is kept for diagnostics.
const maxErrorBody = 500

// Client posts decision requests to {baseURL}/decisions.
type Client struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// New returns a client for the Decisions API rooted at baseURL (for example
// https://api.openai.com/v1). The API key is sent as a bearer token and is
// never included in any error.
func New(baseURL, apiKey string, timeout time.Duration) *Client {
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		client:  &http.Client{Timeout: timeout},
	}
}

// Decide POSTs body and returns the response body of a 2xx answer. A non-2xx
// answer is a *StatusError; a transport failure is wrapped and carries only
// the method and URL, never headers.
func (c *Client) Decide(ctx context.Context, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/decisions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("decisions: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("decisions: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		return nil, &StatusError{StatusCode: resp.StatusCode, Body: string(limited)}
	}

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("decisions: read response: %w", err)
	}
	return out, nil
}

// StatusError is a non-2xx answer from the Decisions API. Body is the first
// 500 bytes of the answer.
type StatusError struct {
	StatusCode int
	Body       string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("decisions: http %d: %s", e.StatusCode, e.Body)
}

// Fatal reports whether retrying cannot help until someone fixes the
// credential, the endpoint or the model: 401, 403, 404.
func (e *StatusError) Fatal() bool {
	return e.StatusCode == http.StatusUnauthorized ||
		e.StatusCode == http.StatusForbidden ||
		e.StatusCode == http.StatusNotFound
}

// Retryable reports whether the same request may succeed later: 429 and any
// 5xx. Everything else (400, 422, ...) is a request the API will keep
// refusing.
func (e *StatusError) Retryable() bool {
	return e.StatusCode == http.StatusTooManyRequests || e.StatusCode >= 500
}
