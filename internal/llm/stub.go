// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package llm

import "context"

// Stub is a test double for Client.
type Stub struct {
	Content      string
	Model        string
	InputTokens  int
	OutputTokens int
	Err          error

	Calls       int
	LastRequest Request
}

func (s *Stub) Complete(ctx context.Context, req Request) (Response, error) {
	s.Calls++
	s.LastRequest = req
	if s.Err != nil {
		return Response{}, s.Err
	}
	return Response{
		Content:      s.Content,
		Model:        s.Model,
		InputTokens:  s.InputTokens,
		OutputTokens: s.OutputTokens,
	}, nil
}
