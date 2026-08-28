// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/store"
	"github.com/nethesis/nethesis-insights/internal/threat"
)

// AllowlistStore is the slice of store.Store this package needs. Declared
// here, narrow, so the handlers are testable with a small fake instead of
// the whole store -- the same reasoning as api.ThreatStore.
// *store.SQLiteStore satisfies it.
type AllowlistStore interface {
	ListThreatAllowlist(ctx context.Context) ([]store.AllowlistRow, error)
	UpsertThreatAllowlistEntry(ctx context.Context, e store.AllowlistRow) error
	DeleteThreatAllowlistEntry(ctx context.Context, cidr string) (bool, error)
	PendingAllowlistRequests(ctx context.Context, limit int) ([]store.AllowlistRequestRow, error)
	UpsertAllowlistReview(ctx context.Context, cidr, state, decidedBy, note string, now int64) error
	AppendAllowlistAudit(ctx context.Context, cidr, action, actor, detail string, now int64) error
	ListAllowlistAudit(ctx context.Context, limit int) ([]store.AllowlistAuditRow, error)
}

// maxAdminBodySize bounds a request body. Every body on this API is a CIDR
// plus a short reason/note -- nowhere near a bundle -- so the cap exists to
// bound a malicious or broken caller, not the honest one.
const maxAdminBodySize = 64 << 10 // 64 KiB

const (
	requestsLimit = 200
	auditLimit    = 500
)

// --- wire DTOs ---
//
// Deliberately not store.AllowlistRow etc. rendered directly: those types
// carry no JSON tags (they were only ever consumed by Go and by
// html/template, where tags are irrelevant), and this is the one place in
// the codebase where allowlist data crosses the wire as JSON. Keeping the
// mapping explicit here, rather than adding tags to the store's row types,
// keeps the store package's types free to serve UI rendering without
// worrying about wire compatibility.

type allowlistEntryJSON struct {
	CIDR      string `json:"cidr"`
	Reason    string `json:"reason"`
	CreatedBy string `json:"created_by"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt *int64 `json:"expires_at,omitempty"`
}

func toEntryJSON(r store.AllowlistRow) allowlistEntryJSON {
	return allowlistEntryJSON{
		CIDR: r.CIDR, Reason: r.Reason, CreatedBy: r.CreatedBy,
		CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt,
	}
}

type pendingRequestJSON struct {
	CIDR             string   `json:"cidr"`
	DistinctSystems  int      `json:"distinct_systems"`
	FirstRequestedAt int64    `json:"first_requested_at"`
	LastRequestedAt  int64    `json:"last_requested_at"`
	Reasons          []string `json:"reasons,omitempty"`
}

func toPendingJSON(r store.AllowlistRequestRow) pendingRequestJSON {
	return pendingRequestJSON{
		CIDR: r.CIDR, DistinctSystems: r.DistinctSystems,
		FirstRequestedAt: r.FirstRequestedAt, LastRequestedAt: r.LastRequestedAt,
		Reasons: r.Reasons,
	}
}

type auditRowJSON struct {
	ID     string `json:"id"`
	CIDR   string `json:"cidr"`
	Action string `json:"action"`
	Actor  string `json:"actor"`
	At     int64  `json:"at"`
	Detail string `json:"detail,omitempty"`
}

func toAuditJSON(r store.AllowlistAuditRow) auditRowJSON {
	return auditRowJSON{ID: r.ID, CIDR: r.CIDR, Action: r.Action, Actor: r.Actor, At: r.At, Detail: r.Detail}
}

func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, maxAdminBodySize)).Decode(v)
}

// handleAllowlist dispatches GET/POST/DELETE on /admin/v1/allowlist. All
// three share one path because the CIDR must never travel in a path
// segment (see the plan): a "/" in a path forces every caller to get %2F
// right, and some proxies normalise it away regardless.
func (s *server) handleAllowlist(w http.ResponseWriter, r *http.Request) {
	if !s.authenticate(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.listAllowlist(w, r)
	case http.MethodPost:
		s.addAllowlist(w, r)
	case http.MethodDelete:
		s.deleteAllowlist(w, r)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *server) listAllowlist(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListThreatAllowlist(r.Context())
	if err != nil {
		slog.Error("admin: list allowlist failed", "error", err)
		writeJSONError(w, http.StatusServiceUnavailable, "temporarily unavailable")
		return
	}
	out := make([]allowlistEntryJSON, len(rows))
	for i, row := range rows {
		out[i] = toEntryJSON(row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": out})
}

// addAllowlist adds or updates one entry. It is idempotent: POSTing an
// already-present CIDR is 200, never an error -- the plan is explicit that
// this must never behave like a naive REST "already exists" conflict.
func (s *server) addAllowlist(w http.ResponseWriter, r *http.Request) {
	act, ok := requireActor(w, r)
	if !ok {
		return
	}

	var body model.AllowlistEntryRequest
	if err := decodeJSON(r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json body")
		return
	}

	cidr, warning, err := threat.ParseAllowlistEntry(body.CIDR, body.Force)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	reason := threat.CleanText(body.Reason, model.MaxAllowlistReasonLen)
	now := s.now()

	if err := s.store.UpsertThreatAllowlistEntry(r.Context(), store.AllowlistRow{
		CIDR: cidr, Reason: reason, CreatedBy: act, CreatedAt: now,
	}); err != nil {
		slog.Error("admin: upsert allowlist entry failed", "cidr", cidr, "error", err)
		writeJSONError(w, http.StatusServiceUnavailable, "temporarily unavailable")
		return
	}

	// Every admin write appends exactly one audit row. The warning (a
	// non-public address, harmless but pointless) is folded into the detail
	// rather than dropped, so a reviewer reading the trail later sees it too.
	detail := auditDetail(reason, warning)
	if err := s.store.AppendAllowlistAudit(r.Context(), cidr, "allowlist.upsert", act, detail, now); err != nil {
		slog.Error("admin: append allowlist audit failed", "cidr", cidr, "error", err)
	}

	resp := map[string]any{"cidr": cidr}
	if warning != "" {
		resp["warning"] = warning
	}
	writeJSON(w, http.StatusOK, resp)
}

// deleteAllowlist removes one entry. 200 when it existed, 404 when it did
// not -- unlike the idempotent POST above, a DELETE of nothing is not the
// same event as a DELETE of something, and the caller should be able to
// tell the difference.
func (s *server) deleteAllowlist(w http.ResponseWriter, r *http.Request) {
	act, ok := requireActor(w, r)
	if !ok {
		return
	}

	raw := strings.TrimSpace(r.URL.Query().Get("cidr"))
	if raw == "" {
		writeJSONError(w, http.StatusBadRequest, "cidr query parameter is required")
		return
	}
	// force=true: breadth does not matter for a deletion, only for adding a
	// new exemption, and the caller must be able to remove whatever is
	// actually stored regardless of how broad it is.
	cidr, _, err := threat.ParseAllowlistEntry(raw, true)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	existed, err := s.store.DeleteThreatAllowlistEntry(r.Context(), cidr)
	if err != nil {
		slog.Error("admin: delete allowlist entry failed", "cidr", cidr, "error", err)
		writeJSONError(w, http.StatusServiceUnavailable, "temporarily unavailable")
		return
	}
	if !existed {
		writeJSONError(w, http.StatusNotFound, "no such allowlist entry")
		return
	}

	now := s.now()
	if err := s.store.AppendAllowlistAudit(r.Context(), cidr, "allowlist.delete", act, "", now); err != nil {
		slog.Error("admin: append allowlist audit failed", "cidr", cidr, "error", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"cidr": cidr, "deleted": true})
}

// handleRequests serves the pending review queue, ranked by distinct
// systems -- see store.PendingAllowlistRequests.
func (s *server) handleRequests(w http.ResponseWriter, r *http.Request) {
	if !s.authenticate(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	rows, err := s.store.PendingAllowlistRequests(r.Context(), requestsLimit)
	if err != nil {
		slog.Error("admin: list pending allowlist requests failed", "error", err)
		writeJSONError(w, http.StatusServiceUnavailable, "temporarily unavailable")
		return
	}
	out := make([]pendingRequestJSON, len(rows))
	for i, row := range rows {
		out[i] = toPendingJSON(row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": out})
}

// handleApprove is the ONLY path in this codebase that turns a client
// request into a threat_allowlist entry, and it only ever runs because an
// admin called it -- see the "no automatic promotion" rule in CLAUDE.md.
func (s *server) handleApprove(w http.ResponseWriter, r *http.Request) {
	if !s.authenticate(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	act, ok := requireActor(w, r)
	if !ok {
		return
	}

	var body model.AllowlistDecisionRequest
	if err := decodeJSON(r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	cidr, warning, err := threat.ParseAllowlistEntry(body.CIDR, body.Force)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	note := threat.CleanText(body.Note, model.MaxAllowlistReasonLen)
	reason := note
	if reason == "" {
		reason = "approved via admin API"
	}
	now := s.now()

	if err := s.store.UpsertThreatAllowlistEntry(r.Context(), store.AllowlistRow{
		CIDR: cidr, Reason: reason, CreatedBy: act, CreatedAt: now,
	}); err != nil {
		slog.Error("admin: approve allowlist request failed", "cidr", cidr, "error", err)
		writeJSONError(w, http.StatusServiceUnavailable, "temporarily unavailable")
		return
	}
	// Retire the CIDR from the pending queue. Logged, not fatal: the entry
	// already exists, which is the operationally important half of this
	// call, and a review-row failure should not be reported as the whole
	// approval having failed.
	if err := s.store.UpsertAllowlistReview(r.Context(), cidr, store.AllowlistReviewApproved, act, note, now); err != nil {
		slog.Error("admin: record allowlist review failed", "cidr", cidr, "error", err)
	}
	detail := auditDetail(note, warning)
	if err := s.store.AppendAllowlistAudit(r.Context(), cidr, "request.approve", act, detail, now); err != nil {
		slog.Error("admin: append allowlist audit failed", "cidr", cidr, "error", err)
	}

	resp := map[string]any{"cidr": cidr, "state": store.AllowlistReviewApproved}
	if warning != "" {
		resp["warning"] = warning
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleReject records a rejection. It creates no allowlist entry -- there
// is nothing here that could auto-promote anything.
func (s *server) handleReject(w http.ResponseWriter, r *http.Request) {
	if !s.authenticate(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	act, ok := requireActor(w, r)
	if !ok {
		return
	}

	var body model.AllowlistDecisionRequest
	if err := decodeJSON(r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if strings.TrimSpace(body.CIDR) == "" {
		writeJSONError(w, http.StatusBadRequest, "cidr is required")
		return
	}
	// force=true: a rejection does not create anything, so the
	// over-broad-prefix guardrail (which exists to protect promotion) does
	// not apply -- only normalization to the same canonical key the request
	// queue uses.
	cidr, _, err := threat.ParseAllowlistEntry(body.CIDR, true)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	note := threat.CleanText(body.Note, model.MaxAllowlistReasonLen)
	now := s.now()

	if err := s.store.UpsertAllowlistReview(r.Context(), cidr, store.AllowlistReviewRejected, act, note, now); err != nil {
		slog.Error("admin: record allowlist review failed", "cidr", cidr, "error", err)
		writeJSONError(w, http.StatusServiceUnavailable, "temporarily unavailable")
		return
	}
	if err := s.store.AppendAllowlistAudit(r.Context(), cidr, "request.reject", act, note, now); err != nil {
		slog.Error("admin: append allowlist audit failed", "cidr", cidr, "error", err)
	}

	writeJSON(w, http.StatusOK, map[string]any{"cidr": cidr, "state": store.AllowlistReviewRejected})
}

// handleAudit serves the append-only trail, newest first.
func (s *server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if !s.authenticate(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	rows, err := s.store.ListAllowlistAudit(r.Context(), auditLimit)
	if err != nil {
		slog.Error("admin: list allowlist audit failed", "error", err)
		writeJSONError(w, http.StatusServiceUnavailable, "temporarily unavailable")
		return
	}
	out := make([]auditRowJSON, len(rows))
	for i, row := range rows {
		out[i] = toAuditJSON(row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": out})
}

func auditDetail(reason, warning string) string {
	if warning == "" {
		return reason
	}
	if reason == "" {
		return "(" + warning + ")"
	}
	return reason + " (" + warning + ")"
}
