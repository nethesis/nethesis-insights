// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package model

// Threat Shield wire and internal types. This is a separate pipeline from the
// bundle/gate/LLM path: CrowdSec ban decisions in, fleet-consensus blocklist
// out, no LLM call and no fingerprint anywhere in it.

// ThreatSchemaVersion is the envelope version edges must send. It is
// independent of SchemaVersion (the bundle envelope): the two pipelines
// version separately because they evolve separately.
const ThreatSchemaVersion = 1

// Decision mirrors CrowdSec's models.Decision as emitted by
// `cscli decisions list --output json` and by the notification-http plugin.
// Every field is carried verbatim; the server owns the interpretation, so a
// new scenario is a server release rather than a fleet-wide reconfiguration.
type Decision struct {
	ID        int64  `json:"id,omitempty"`
	Value     string `json:"value"`
	Scope     string `json:"scope"`
	Type      string `json:"type"`
	Scenario  string `json:"scenario"`
	Origin    string `json:"origin"`
	Duration  string `json:"duration"`
	CreatedAt string `json:"created_at"`
}

// ThreatReport is the POST /v1/threat-events body. SystemID is optional --
// the authenticated credential is what identifies the reporter -- but when
// present it must equal the authenticated system, exactly like Bundle.
type ThreatReport struct {
	SchemaVersion int        `json:"schema_version"`
	SystemID      string     `json:"system_id,omitempty"`
	Decisions     []Decision `json:"decisions"`
}

// ThreatEvent is the sanitized internal form: a public attacker address, a
// category from the fixed v1 set, and metadata reduced to a typed allowlist.
// AttackerIP is always a normalized netip.Addr.String(), so text equality is
// identity -- that is what lets a portable TEXT column behave like INET.
type ThreatEvent struct {
	AttackerIP string         `json:"attacker_ip"`
	Category   string         `json:"category"`
	ObservedAt int64          `json:"observed_at"`
	HitCount   int64          `json:"hit_count"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// ThreatCounters accounts for every decision that did not become an event.
// Ingest is fail-open on content (spec §10): a malformed decision is dropped
// and counted, never a reason to reject the batch. The counters are returned
// to the reporter and persisted per day so "why is this node contributing
// nothing" is answerable from the operator UI instead of from logs.
type ThreatCounters struct {
	Accepted         int `json:"accepted"`
	DroppedType      int `json:"dropped_type"`
	DroppedScope     int `json:"dropped_scope"`
	DroppedOrigin    int `json:"dropped_origin"`
	DroppedBadIP     int `json:"dropped_bad_ip"`
	DroppedPrivateIP int `json:"dropped_private_ip"`
	DroppedScenario  int `json:"dropped_scenario"`
	DroppedTime      int `json:"dropped_time"`
	Truncated        int `json:"truncated"`
}

// ThreatCategories is the v1 category set (design D3). It is deliberately
// fixed: an unknown scenario is dropped and counted rather than folded into a
// catch-all, because a catch-all category is evidence of nothing.
var ThreatCategories = []string{"port_scan", "ssh_bruteforce", "http_exploit", "sip_probe"}

func ValidThreatCategory(c string) bool {
	for _, known := range ThreatCategories {
		if known == c {
			return true
		}
	}
	return false
}
