// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Command stubserver is a tiny fake OpenAI-compatible chat completions
// endpoint for manual/local testing of insightsd. It needs no API key and
// always returns one canned finding.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

type chatResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

func main() {
	addr := ":8081"
	if v := os.Getenv("STUB_LISTEN_ADDR"); v != "" {
		addr = v
	}

	http.HandleFunc("/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		log.Printf("stub received request for model=%v", req["model"])

		content := `{"window_assessment":"degraded","findings":[` +
			`{"severity":"high","title":"Disk usage climbing fast",` +
			`"summary":"Observed volume of disk-warning log lines is far above baseline for this window.",` +
			`"suggested_action":"Check disk usage on affected volumes and clean up if needed.",` +
			`"modules":["disk"],"evidence":["disk usage on VOLUME at PCT percent"]}` +
			`]}`

		resp := chatResponse{Model: "stub-model"}
		resp.Choices = []struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
		}{{}}
		resp.Choices[0].Message.Role = "assistant"
		resp.Choices[0].Message.Content = content
		resp.Usage.PromptTokens = 123
		resp.Usage.CompletionTokens = 45

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	log.Printf("stub llm server listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
