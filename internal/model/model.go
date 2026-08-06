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

// CategoryOf returns the Category of the matching template, else "".
func (b Bundle) CategoryOf(template string) string {
	for _, t := range b.Templates {
		if t.Template == template {
			return t.Category
		}
	}
	return ""
}
