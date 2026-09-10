// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package threat

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/platform/httpx"
	threatstore "github.com/nethesis/nethesis-insights/internal/store/threat"
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
// explicit admin approval (internal/ui/threat's write routes) creates one.
// See "The two consensus rules are not symmetric" in docs/architecture.md for
// why the blocklist can afford an automatic rule and this cannot.
func (s *server) handleAllowlistRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	authenticatedSystemID, err := httpx.SystemID(r, s.trusted)
	if err != nil {
		slog.Debug("unauthorized", "error", err, "remote_addr", r.RemoteAddr)
		writeError(w, http.StatusUnauthorized, "unauthorized")
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

	now := s.cfg.Now()
	requests, err := s.store.UpsertAllowlistRequest(r.Context(), cidr, authenticatedSystemID, reason,
		now, s.cfg.MaxAllowlistRequestsPerSys)
	switch {
	// The per-system cap. A request is a permanent row that only a human
	// ever removes, so this bound is enforced at ingest like every other one
	// in this pipeline -- and it answers 429 rather than 400 because the ask
	// is well formed: the system has simply used up its share of the review
	// queue and needs its earlier asks decided first. A refresh of a CIDR
	// the system already asked about is never refused; only a new CIDR can
	// hit this.
	case errors.Is(err, threatstore.ErrTooManyAllowlistRequests):
		reject(w, r, http.StatusTooManyRequests, "too many pending allowlist requests for this system",
			"system_id", authenticatedSystemID, "cidr", cidr)
		return
	case err != nil:
		slog.Error("upsert allowlist request failed", "system_id", authenticatedSystemID, "cidr", cidr, "error", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily unavailable")
		return
	}

	slog.Debug("allowlist request accepted", "system_id", authenticatedSystemID, "cidr", cidr, "requests", requests)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(model.AllowlistRequestResult{Accepted: true, Requests: requests})
}
