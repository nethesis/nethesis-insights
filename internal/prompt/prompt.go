// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package prompt

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/nethesis/nethesis-insights/internal/model"
)

const Version = "v1"

const System = `You analyze NethServer logs. You receive a digest of log volumes and masked ` +
	`log-line templates with counts for one time window. Report ONLY real problems: ` +
	`things that indicate misconfiguration, failure, resource exhaustion, security ` +
	`concerns, or other conditions an administrator would want to act on. Report only ` +
	`NEW or CHANGED conditions -- never repeat anything listed in the ALREADY KNOWN ` +
	`section, even if it is still occurring. ` +
	`In "evidence", list ONLY the bracketed template identifiers such as T1 or T7, ` +
	`exactly as shown at the start of each TEMPLATES line. Do not copy template text, ` +
	`counts, module names or any other part of the line into evidence, and never ` +
	`invent an identifier. Leave "modules" empty; it is derived from the identifiers ` +
	`you cite. The title, summary and suggested_action are read by a system ` +
	`administrator: write them in plain language, and never mention template ` +
	`identifiers or numeric priority levels in them -- name the module, or say ` +
	`nothing. If nothing in this window warrants reporting, return an empty findings ` +
	`array with window_assessment "nominal".`

// Schema is the strict JSON schema the LLM response must conform to.
var Schema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"window_assessment": map[string]any{
			"type": "string",
			"enum": model.Assessments,
		},
		"findings": map[string]any{
			"type": "array",
			"items": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"severity": map[string]any{
						"type": "string",
						"enum": model.Severities,
					},
					"title":            map[string]any{"type": "string"},
					"summary":          map[string]any{"type": "string"},
					"suggested_action": map[string]any{"type": "string"},
					"modules": map[string]any{
						"type":  "array",
						"items": map[string]any{"type": "string"},
					},
					"evidence": map[string]any{
						"type":  "array",
						"items": map[string]any{"type": "string"},
					},
				},
				"required": []string{
					"severity", "title", "summary", "suggested_action", "modules", "evidence",
				},
				"additionalProperties": false,
			},
		},
	},
	"required":             []string{"window_assessment", "findings"},
	"additionalProperties": false,
}

type ParsedFinding struct {
	Severity        string   `json:"severity"`
	Title           string   `json:"title"`
	Summary         string   `json:"summary"`
	SuggestedAction string   `json:"suggested_action"`
	Modules         []string `json:"modules"`
	Evidence        []string `json:"evidence"`
}

type responseBody struct {
	WindowAssessment string          `json:"window_assessment"`
	Findings         []ParsedFinding `json:"findings"`
}

// HostBucketLabel is how an empty module_id is shown to the model. Host
// records carry no module_id label at all, and printing nothing there would
// read as a missing field rather than a real bucket.
const HostBucketLabel = "<host>"

// TemplateID is the identifier shown for the i-th template of SortedTemplates.
func TemplateID(i int) string { return fmt.Sprintf("T%d", i+1) }

// SortedTemplates returns the bundle's templates in the exact order Render
// numbers them, so the analyzer resolves the identifiers the model was shown.
func SortedTemplates(b model.Bundle) []model.Template {
	templates := make([]model.Template, len(b.Templates))
	copy(templates, b.Templates)
	sort.Slice(templates, func(i, j int) bool {
		if templates[i].ModuleID != templates[j].ModuleID {
			return templates[i].ModuleID < templates[j].ModuleID
		}
		if templates[i].Priority != templates[j].Priority {
			return templates[i].Priority < templates[j].Priority
		}
		return templates[i].Template < templates[j].Template
	})
	return templates
}

// ResolveEvidence maps cited identifiers back to templates.
//
// Identity is computed from what this returns, never from model-authored
// text. Letting the model supply evidence strings directly made a fingerprint
// depend on the occurrence count printed beside the template, so the same
// condition changed identity every window and was re-raised forever -- the
// exact failure deduplication exists to prevent.
func ResolveEvidence(b model.Bundle, ids []string) ([]model.Template, error) {
	sorted := SortedTemplates(b)
	index := make(map[string]model.Template, len(sorted))
	for i, t := range sorted {
		index[TemplateID(i)] = t
	}
	out := make([]model.Template, 0, len(ids))
	seen := map[string]bool{}
	for _, raw := range ids {
		id := strings.ToUpper(strings.TrimSpace(raw))
		t, ok := index[id]
		if !ok {
			return nil, fmt.Errorf("prompt: evidence cites unknown template %q", raw)
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("prompt: evidence resolved to no templates")
	}
	return out, nil
}

// Render produces a deterministic prompt for the given bundle and currently
// open findings. Everything is sorted so the same inputs always produce the
// same bytes, regardless of input slice order. Samples are never included.
func Render(b model.Bundle, open []model.Finding) string {
	var sb strings.Builder

	sb.WriteString("WINDOW\n")
	sb.WriteString(fmt.Sprintf("start_ms=%d end_ms=%d collector=%s masking=%d\n\n",
		b.Window.Start, b.Window.End, b.CollectorVersion, b.MaskingVersion))

	sb.WriteString("DIGEST (module priority observed expected ratio)\n")
	digest := make([]model.DigestEntry, len(b.Digest))
	copy(digest, b.Digest)
	sort.Slice(digest, func(i, j int) bool {
		if digest[i].ModuleID != digest[j].ModuleID {
			return digest[i].ModuleID < digest[j].ModuleID
		}
		return digest[i].Priority < digest[j].Priority
	})
	for _, e := range digest {
		expectedStr := "-"
		ratioStr := "-"
		if e.Expected != nil {
			expectedStr = fmt.Sprintf("%.2f", *e.Expected)
			if *e.Expected > 0 {
				ratioStr = fmt.Sprintf("%.2f", float64(e.Observed)/(*e.Expected))
			}
		}
		sb.WriteString(fmt.Sprintf("%s %d %d %s %s\n", e.ModuleID, e.Priority, e.Observed, expectedStr, ratioStr))
	}
	sb.WriteString("\n")

	sb.WriteString("TEMPLATES (cite these identifiers in evidence)\n")
	templates := SortedTemplates(b)
	for i, t := range templates {
		cat := t.Category
		if cat == "" {
			cat = "-"
		}
		mod := t.ModuleID
		if mod == "" {
			mod = HostBucketLabel
		}
		sb.WriteString(fmt.Sprintf("[%s] count=%d module=%s priority=%d category=%s\n    %s\n",
			TemplateID(i), t.Count, mod, t.Priority, cat, t.Template))
	}
	sb.WriteString("\n")

	sb.WriteString("SAMPLING\n")
	sb.WriteString(fmt.Sprintf("lines_seen=%d lines_kept=%d max_lines=%d\n",
		b.Budget.LinesSeen, b.Budget.LinesKept, b.Budget.MaxLines))
	sb.WriteString("under_sampled (module dropped)\n")
	truncated := make([]model.TruncatedModule, len(b.Budget.TruncatedModules))
	copy(truncated, b.Budget.TruncatedModules)
	sort.Slice(truncated, func(i, j int) bool {
		return truncated[i].ModuleID < truncated[j].ModuleID
	})
	for _, tm := range truncated {
		sb.WriteString(fmt.Sprintf("%s %d\n", tm.ModuleID, tm.Dropped))
	}
	sb.WriteString("\n")

	sb.WriteString("ALREADY KNOWN (do not report these again)\n")
	if len(open) == 0 {
		sb.WriteString("none\n")
	} else {
		known := make([]model.Finding, len(open))
		copy(known, open)
		sort.Slice(known, func(i, j int) bool {
			if known[i].Severity != known[j].Severity {
				return known[i].Severity < known[j].Severity
			}
			return known[i].Title < known[j].Title
		})
		for _, f := range known {
			sb.WriteString(fmt.Sprintf("[%s] %s\n", f.Severity, f.Title))
		}
	}

	return sb.String()
}

// Parse extracts findings from an LLM response body, stripping an optional
// markdown ```json fence, then validating strictly.
func Parse(body string) ([]ParsedFinding, string, error) {
	cleaned := stripFence(body)

	var rb responseBody
	if err := json.Unmarshal([]byte(cleaned), &rb); err != nil {
		return nil, "", fmt.Errorf("prompt: invalid json: %w", err)
	}

	if !model.ValidAssessment(rb.WindowAssessment) {
		return nil, "", fmt.Errorf("prompt: invalid window assessment %q", rb.WindowAssessment)
	}

	for i, f := range rb.Findings {
		if !model.ValidSeverity(f.Severity) {
			return nil, "", fmt.Errorf("prompt: finding %d has invalid severity %q", i, f.Severity)
		}
		if strings.TrimSpace(f.Title) == "" {
			return nil, "", fmt.Errorf("prompt: finding %d has blank title", i)
		}
		if strings.TrimSpace(f.Summary) == "" {
			return nil, "", fmt.Errorf("prompt: finding %d has blank summary", i)
		}
		if len(f.Evidence) == 0 {
			return nil, "", fmt.Errorf("prompt: finding %d has empty evidence", i)
		}
	}

	return rb.Findings, rb.WindowAssessment, nil
}

func stripFence(body string) string {
	s := strings.TrimSpace(body)
	if strings.HasPrefix(s, "```") {
		// Strip the opening fence line (```json or ```).
		if idx := strings.IndexByte(s, '\n'); idx != -1 {
			s = s[idx+1:]
		}
		s = strings.TrimSuffix(strings.TrimSpace(s), "```")
	}
	return strings.TrimSpace(s)
}
