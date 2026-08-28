// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/threat"
)

// maxAllowlistRequestSize bounds the body: a CIDR and a short reason
// string, nowhere near a bundle's size.
const maxAllowlistRequestSize = 8 << 10 // 8 KiB

// handleAllowlistRequest is the client-facing half of allowlist management:
// a customer asking that a CIDR be exempted from blocklist promotion.
//
// This is a review queue, not a decision procedure. The distinct-system
// counter returned here ranks the admin's review queue and does nothing
// else -- there is no path anywhere in this codebase from a client request,
// however many systems make it, to a live threat_allowlist entry. Only an
// explicit admin approval (internal/admin) creates one. See the "no
// automatic promotion" decision in docs/plans/2026-08-28-allowlist-management.md.
func (s *server) handleAllowlistRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	authenticatedSystemID, ok := s.authenticate(w, r)
	if !ok {
		return
	}

	var body model.AllowlistRequestBody
	if err := json.NewDecoder(io.LimitReader(r.Body, maxAllowlistRequestSize)).Decode(&body); err != nil {
		reject(w, r, http.StatusBadRequest, "invalid json body", "error", err.Error())
		return
	}

	// force=true: the over-broad-prefix guardrail protects promotion, not a
	// request for review -- a human decides at approval time, and rejecting
	// a customer's request over breadth here would just be a confusing
	// error for something that does no damage by itself.
	cidr, _, err := threat.ParseAllowlistEntry(body.CIDR, true)
	if err != nil {
		reject(w, r, http.StatusBadRequest, "invalid cidr", "error", err.Error())
		return
	}
	// Free text from a customer: capped and control-character-stripped here
	// (never rejected -- fail-open on content, like every other text field
	// in this pipeline), rendered escaped by the operator UI, never trusted.
	reason := threat.CleanText(body.Reason, model.MaxAllowlistReasonLen)

	now := s.threat.Now()
	requests, err := s.store.UpsertAllowlistRequest(r.Context(), cidr, authenticatedSystemID, reason, now)
	if err != nil {
		slog.Error("upsert allowlist request failed", "system_id", authenticatedSystemID, "cidr", cidr, "error", err)
		writeJSONError(w, http.StatusServiceUnavailable, "temporarily unavailable")
		return
	}

	slog.Debug("allowlist request accepted", "system_id", authenticatedSystemID, "cidr", cidr, "requests", requests)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(model.AllowlistRequestResult{Accepted: true, Requests: requests})
}
