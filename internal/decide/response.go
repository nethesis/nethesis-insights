// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package decide

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Answer is the API's verdict on the one question asked.
type Answer struct {
	Choice     string
	Confidence float64
	Refused    bool
}

// Usage is the token accounting of one call.
type Usage struct {
	InputTokens, CachedTokens, OutputTokens int
}

type response struct {
	Answers []struct {
		Type       string  `json:"type"`
		Choice     string  `json:"choice"`
		Confidence float64 `json:"confidence"`
	} `json:"answers"`
	Usage struct {
		InputTokens        int `json:"input_tokens"`
		InputTokensDetails struct {
			CachedTokens int `json:"cached_tokens"`
		} `json:"input_tokens_details"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// ParseResponse reads the first answer and the usage. A refusal is an Answer
// with Refused set, not an error; an unknown choice or no answer is an error.
func ParseResponse(body []byte) (Answer, Usage, error) {
	var r response
	if err := json.Unmarshal(body, &r); err != nil {
		return Answer{}, Usage{}, fmt.Errorf("decide: parse response: %w", err)
	}
	u := Usage{
		InputTokens:  r.Usage.InputTokens,
		CachedTokens: r.Usage.InputTokensDetails.CachedTokens,
		OutputTokens: r.Usage.OutputTokens,
	}
	if len(r.Answers) == 0 {
		return Answer{}, u, errors.New("decide: response has no answers")
	}
	a := r.Answers[0]
	if a.Type == "refusal" {
		return Answer{Refused: true}, u, nil
	}
	switch a.Choice {
	case "customer", "operator", "dismissed":
	default:
		return Answer{}, u, fmt.Errorf("decide: unknown choice %q", a.Choice)
	}
	return Answer{Choice: a.Choice, Confidence: a.Confidence}, u, nil
}
