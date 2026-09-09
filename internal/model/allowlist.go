// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package model

// Allowlist management wire types: a client-facing request path (a review
// queue, never a decision procedure -- see the "no automatic promotion"
// invariant in CLAUDE.md) and the operator UI write routes
// (internal/ui/threat) that turn an approved request, or an out-of-band
// decision, into an actual threat_allowlist row. There is no separate admin
// API any more -- the UI's write routes are the only writer.

// MaxAllowlistReasonLen bounds the free-text reason carried on a client
// request, an admin's direct entry, and an approve/reject note. It is
// customer- or operator-supplied text that ends up in a rendered page and a
// log line, so it is capped the same way threat.MaxScenarioLen caps a
// scenario name.
const MaxAllowlistReasonLen = 512

// MaxAdminActorLen bounds the HTTP Basic username the operator UI's write
// routes record as the actor. There is no X-Admin-Actor header any more --
// the separate admin plane it belonged to is gone -- and the username is
// self-declared exactly as that header was: anyone holding the admin key can
// claim any name, so this is a rendering/logging bound, never an identity
// control.
const MaxAdminActorLen = 128

// AllowlistRequestBody is the POST /blocklist/v1/allowlist-requests body: a customer
// asking that a CIDR be exempted from blocklist promotion. It is never, by
// itself, enough to create an allowlist entry -- only an explicit admin
// approval does that.
type AllowlistRequestBody struct {
	CIDR   string `json:"cidr"`
	Reason string `json:"reason"`
}

// AllowlistRequestResult answers a client's request. Requests is the
// current count of distinct systems that have asked for this CIDR --
// returned so the caller can see its request landed, never a promise that
// it will be approved.
type AllowlistRequestResult struct {
	Accepted bool `json:"accepted"`
	Requests int  `json:"requests"`
}

// AllowlistEntryRequest adds or updates one allowlist entry directly, out of
// the review queue. Force overrides the over-broad-prefix guardrail
// (threat.ParseAllowlistEntry) -- required to allowlist anything shorter
// than a /24 (IPv4) or /48 (IPv6).
type AllowlistEntryRequest struct {
	CIDR   string `json:"cidr"`
	Reason string `json:"reason"`
	Force  bool   `json:"force,omitempty"`
}

// AllowlistDecisionRequest is the body of an approve-or-reject decision on a
// pending allowlist request: the CIDR being decided, an optional note for
// the audit trail, and (approve only) the same over-broad-prefix override as
// AllowlistEntryRequest.
type AllowlistDecisionRequest struct {
	CIDR  string `json:"cidr"`
	Note  string `json:"note,omitempty"`
	Force bool   `json:"force,omitempty"`
}
