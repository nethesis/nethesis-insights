// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package llm

import (
	"context"
	"fmt"
)

type Request struct {
	Model      string
	UserPrompt string
}

type Response struct {
	Content      string
	Model        string
	InputTokens  int
	OutputTokens int

	// CachedTokens is the part of InputTokens the provider served from its
	// prompt cache, at half price. Providers that do not report it leave it
	// zero, which prices the call as if nothing was cached -- the safe
	// direction for a cost figure.
	CachedTokens int
}

type Client interface {
	Complete(ctx context.Context, req Request) (Response, error)
}

// HTTPError represents a non-2xx response from the LLM backend. Body is
// captured for diagnostics but the request (which may carry the API key) is
// never included.
type HTTPError struct {
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("llm: http %d: %s", e.StatusCode, e.Body)
}

// Permanent reports whether retrying this request is pointless: true for any
// 4xx status except 429 (rate limited, which is worth retrying).
func (e *HTTPError) Permanent() bool {
	return e.StatusCode >= 400 && e.StatusCode < 500 && e.StatusCode != 429
}
