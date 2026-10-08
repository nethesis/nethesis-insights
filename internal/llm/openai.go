// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/nethesis/nethesis-insights/internal/prompt"
)

type OpenAI struct {
	baseURL     string
	apiKey      string
	serviceTier string
	client      *http.Client
}

// NewOpenAI returns a client for an OpenAI-compatible chat completions
// endpoint. serviceTier is sent as `service_tier` when non-empty; "flex"
// halves OpenAI's price in exchange for slower answers and occasional 429s
// when capacity is short. Analysis is asynchronous, so the latency costs
// nothing, and a flex 429 is retried once at the default tier (see Complete).
func NewOpenAI(baseURL, apiKey, serviceTier string, timeout time.Duration) *OpenAI {
	return &OpenAI{
		baseURL:     baseURL,
		apiKey:      apiKey,
		serviceTier: serviceTier,
		client:      &http.Client{Timeout: timeout},
	}
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type jsonSchemaFormat struct {
	Name   string         `json:"name"`
	Strict bool           `json:"strict"`
	Schema map[string]any `json:"schema"`
}

type responseFormat struct {
	Type       string           `json:"type"`
	JSONSchema jsonSchemaFormat `json:"json_schema"`
}

// chatRequest deliberately has NO temperature field: some backends reject
// any non-default value with a 400.
type chatRequest struct {
	Model          string         `json:"model"`
	Messages       []chatMessage  `json:"messages"`
	ResponseFormat responseFormat `json:"response_format"`
	ServiceTier    string         `json:"service_tier,omitempty"`
}

type chatChoice struct {
	Message chatMessage `json:"message"`
}

type promptTokensDetails struct {
	CachedTokens int `json:"cached_tokens"`
}

type chatUsage struct {
	PromptTokens        int                 `json:"prompt_tokens"`
	CompletionTokens    int                 `json:"completion_tokens"`
	PromptTokensDetails promptTokensDetails `json:"prompt_tokens_details"`
}

type chatResponse struct {
	Model   string       `json:"model"`
	Choices []chatChoice `json:"choices"`
	Usage   chatUsage    `json:"usage"`
}

// Complete sends one chat completion. When a service tier is configured and
// the provider answers 429 -- for flex, "resource unavailable" as often as a
// rate limit -- the request is repeated once without the tier rather than
// handed back as a transient error: a window whose call failed is analysed
// again only if the edge happens to resend it, so a lost flex slot would
// otherwise usually be a lost window.
func (o *OpenAI) Complete(ctx context.Context, req Request) (Response, error) {
	resp, err := o.complete(ctx, req, o.serviceTier)
	var httpErr *HTTPError
	if o.serviceTier != "" && errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusTooManyRequests {
		slog.Debug("llm service tier unavailable, retrying at default tier",
			"service_tier", o.serviceTier, "model", req.Model)
		return o.complete(ctx, req, "")
	}
	return resp, err
}

func (o *OpenAI) complete(ctx context.Context, req Request, serviceTier string) (Response, error) {
	body := chatRequest{
		Model: req.Model,
		Messages: []chatMessage{
			{Role: "system", Content: prompt.System},
			{Role: "user", Content: req.UserPrompt},
		},
		ResponseFormat: responseFormat{
			Type: "json_schema",
			JSONSchema: jsonSchemaFormat{
				Name:   "anomaly_report",
				Strict: true,
				Schema: prompt.Schema,
			},
		},
		ServiceTier: serviceTier,
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return Response{}, fmt.Errorf("llm: encode request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return Response{}, fmt.Errorf("llm: build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+o.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	// The URL and payload size are safe to log; the Authorization header is
	// never touched here or anywhere else in this package.
	slog.Debug("llm request",
		"url", o.baseURL+"/chat/completions",
		"model", req.Model,
		"payload_bytes", len(payload),
	)

	start := time.Now()
	resp, err := o.client.Do(httpReq)
	if err != nil {
		slog.Debug("llm transport error",
			"model", req.Model,
			"duration_ms", time.Since(start).Milliseconds(),
			"ctx_err", ctx.Err(),
			"error", err.Error(),
		)
		// http.Client wraps transport errors in *url.Error, whose Error()
		// includes only the method and URL, never headers -- so the API
		// key (sent as a header) cannot leak here. We still never format
		// httpReq or o.apiKey directly into any error string.
		return Response{}, fmt.Errorf("llm: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	slog.Debug("llm response headers",
		"status", resp.StatusCode,
		"duration_ms", time.Since(start).Milliseconds(),
		"content_type", resp.Header.Get("Content-Type"),
	)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		slog.Debug("llm error body", "status", resp.StatusCode, "body", string(limited))
		return Response{}, &HTTPError{StatusCode: resp.StatusCode, Body: string(limited)}
	}

	var parsed chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		slog.Debug("llm response decode failed",
			"duration_ms", time.Since(start).Milliseconds(),
			"ctx_err", ctx.Err(),
			"error", err.Error(),
		)
		return Response{}, fmt.Errorf("llm: decode response: %w", err)
	}

	if len(parsed.Choices) == 0 {
		return Response{}, errors.New("llm: no choices in response")
	}

	return Response{
		Content:      parsed.Choices[0].Message.Content,
		Model:        parsed.Model,
		InputTokens:  parsed.Usage.PromptTokens,
		OutputTokens: parsed.Usage.CompletionTokens,
		CachedTokens: parsed.Usage.PromptTokensDetails.CachedTokens,
	}, nil
}
