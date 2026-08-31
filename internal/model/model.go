// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package model

import "sort"

const SchemaVersion = 1

type Window struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}

type DigestEntry struct {
	ModuleID string   `json:"module_id"`
	Priority int      `json:"priority"`
	Observed int64    `json:"observed"`
	Expected *float64 `json:"expected,omitempty"`
}

type Template struct {
	Template  string   `json:"template"`
	Count     int64    `json:"count"`
	ModuleID  string   `json:"module_id"`
	Priority  int      `json:"priority"`
	Category  string   `json:"category,omitempty"`
	FirstSeen int64    `json:"first_seen"`
	LastSeen  int64    `json:"last_seen"`
	Samples   []string `json:"samples,omitempty"`
}

type TruncatedModule struct {
	ModuleID  string `json:"module_id"`
	Dropped   int64  `json:"dropped"`
	Truncated bool   `json:"truncated"`
}

type Budget struct {
	MaxLines         int               `json:"max_lines"`
	LinesSeen        int64             `json:"lines_seen"`
	LinesKept        int64             `json:"lines_kept"`
	TruncatedModules []TruncatedModule `json:"truncated_modules,omitempty"`
}

type Bundle struct {
	SchemaVersion    int           `json:"schema_version"`
	SystemID         string        `json:"system_id"`
	CollectorVersion string        `json:"collector_version"`
	MaskingVersion   int           `json:"masking_version"`
	Window           Window        `json:"window"`
	Digest           []DigestEntry `json:"digest"`
	Templates        []Template    `json:"templates"`
	Budget           Budget        `json:"budget"`
}

type Finding struct {
	ID              string   `json:"id"`
	SystemID        string   `json:"system_id"`
	Fingerprint     string   `json:"fingerprint"`
	Severity        string   `json:"severity"`
	Title           string   `json:"title"`
	Summary         string   `json:"summary"`
	SuggestedAction string   `json:"suggested_action"`
	Modules         []string `json:"modules"`
	Evidence        []string `json:"evidence"`
	Status          string   `json:"status"`
	OccurrenceCount int      `json:"occurrence_count"`
	FirstSeen       int64    `json:"first_seen"`
	LastSeen        int64    `json:"last_seen"`
	ReopenedAt      *int64   `json:"reopened_at,omitempty"`
	LLMModel        string   `json:"llm_model"`
	PromptVersion   string   `json:"prompt_version"`
}

var Severities = []string{"critical", "high", "medium", "low"}

var Assessments = []string{"nominal", "degraded", "incident"}

const StatusOpen = "open"
const StatusStale = "stale"

// SeverityRank returns the index of s in Severities, or len(Severities) if unknown.
func SeverityRank(s string) int {
	for i, sev := range Severities {
		if sev == s {
			return i
		}
	}
	return len(Severities)
}

func ValidSeverity(s string) bool {
	for _, sev := range Severities {
		if sev == s {
			return true
		}
	}
	return false
}

func ValidAssessment(s string) bool {
	for _, a := range Assessments {
		if a == s {
			return true
		}
	}
	return false
}

// SortFindings sorts by severity rank ascending (critical first), then LastSeen descending.
func SortFindings(f []Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		ri, rj := SeverityRank(f[i].Severity), SeverityRank(f[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return f[i].LastSeen > f[j].LastSeen
	})
}

// LessTemplate orders templates by (ModuleID, Priority, Template).
//
// This is the single definition of template order. prompt.SortedTemplates uses
// it to number the identifiers the model cites, and fingerprint uses it to pick
// the canonical primary template out of a cited set. Those two must agree: if
// they ever disagree, a finding's identity stops matching the evidence the
// operator is shown for it.
func LessTemplate(a, b Template) bool {
	if a.ModuleID != b.ModuleID {
		return a.ModuleID < b.ModuleID
	}
	if a.Priority != b.Priority {
		return a.Priority < b.Priority
	}
	return a.Template < b.Template
}

// CategoryOf returns the Category of the matching template, else "".
func (b Bundle) CategoryOf(template string) string {
	for _, t := range b.Templates {
		if t.Template == template {
			return t.Category
		}
	}
	return ""
}

// ExcludeModules returns a copy of b with every template, digest entry and
// truncation record whose ModuleID is in excluded removed.
//
// A module that owns a dedicated pipeline must not also be analysed by the LLM
// one. CrowdSec is the case this exists for: its decisions already travel
// through /v1/threat-events into the blocklist, so shipping its log lines to the
// model pays twice for the same signal and floods the gate with novelty churn.
//
// All three collections are filtered together. Dropping only Templates would
// leave the digest firing deviation reasons for a module the prompt never
// mentions, which is a gate decision nobody can explain from the stored data.
//
// An empty or nil excluded set returns b unchanged. The empty module id is the
// host bucket (sshd, systemd, runagent) and is an ordinary module here: it is
// excluded only if the caller explicitly lists it.
func (b Bundle) ExcludeModules(excluded map[string]bool) Bundle {
	if len(excluded) == 0 {
		return b
	}

	out := b

	out.Templates = make([]Template, 0, len(b.Templates))
	for _, t := range b.Templates {
		if !excluded[t.ModuleID] {
			out.Templates = append(out.Templates, t)
		}
	}

	out.Digest = make([]DigestEntry, 0, len(b.Digest))
	for _, e := range b.Digest {
		if !excluded[e.ModuleID] {
			out.Digest = append(out.Digest, e)
		}
	}

	out.Budget = b.Budget
	out.Budget.TruncatedModules = make([]TruncatedModule, 0, len(b.Budget.TruncatedModules))
	for _, tm := range b.Budget.TruncatedModules {
		if !excluded[tm.ModuleID] {
			out.Budget.TruncatedModules = append(out.Budget.TruncatedModules, tm)
		}
	}

	return out
}
