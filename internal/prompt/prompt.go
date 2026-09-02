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

const Version = "v3"

const System = `You analyze NethServer logs. You receive a digest of log volumes and masked ` +
	`log-line templates with counts for one time window. Report ONLY real problems: ` +
	`things that indicate misconfiguration, failure, resource exhaustion, security ` +
	`concerns, or other conditions an administrator would want to act on. Report only ` +
	`NEW or CHANGED conditions -- never repeat anything listed in the ALREADY KNOWN ` +
	`section, even if it is still occurring. Each ALREADY KNOWN entry shows the ` +
	`template identifiers it was raised from; if a condition you are about to report ` +
	`matches one of those entries, do not report it, and if you report it anyway you ` +
	`must cite exactly the same identifiers. ` +
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

// TemplateID is the identifier shown for the i-th line of Select.
func TemplateID(i int) string { return fmt.Sprintf("T%d", i+1) }

// Selection is what the gate found, and therefore what the prompt shows.
//
// A bundle from a real node carries 160-190 templates and renders a 32 KB
// prompt, of which roughly 70% is template text. Almost none of it is why the
// call happened: on the three multi-module systems measured on 2026-09-01, the
// templates implicated by the gate's own reasons were 19 of 69, 9 of 72 and 46
// of 159. Sending the rest costs money on every call and buries the evidence
// the model is supposed to weigh.
type Selection struct {
	// Novel is the set of canonical keys new to this system, and
	// DeviatingModules the module instances over tolerance. Both come from
	// gate.Decision, so the prompt shows exactly what paid for the call.
	// Novel keys are already family-scoped (model.CanonicalKey); the
	// deviating modules are not, and Select collapses them itself.
	Novel            map[string]bool
	DeviatingModules map[string]bool

	// MaxAmbient caps how many of the remaining templates are shown, most
	// frequent first. They are context, not evidence: without any, a model
	// asked "is this window unusual" cannot see what usual looks like.
	MaxAmbient int
}

// Line is one template as the prompt shows it: a representative template
// carrying the summed count of every variant that canonicalizes to the same
// key, and how many variants that was.
//
// A "variant" is both a spelling and an instance. Lines are grouped on the
// module *family*, so the same cron line emitted by 82 nethvoice instances is
// one Line with Variants=82, and the representative's ModuleID is the family.
type Line struct {
	Template model.Template
	Variants int
}

// Select returns the lines the prompt shows, in model.LessTemplate order.
//
// Two steps. First collapse: templates sharing a canonical key within one
// (module family, priority) become one line, because the collector's masking
// leaves fields literal that cannot distinguish two conditions -- 65 spellings
// of one Prometheus message are one condition, and showing all 65 invites the
// model to report 65 findings. The representative is the highest-count
// variant, so the text an operator eventually reads is the one that actually
// dominated the window.
//
// Grouping on the family rather than the instance is the same collapse one
// axis over: 82 nethvoice instances running one image emit one condition
// between them, and 82 prompt lines invite 82 findings just as 65 spellings
// do.
//
// Then select: everything novel, everything the edge classified as security,
// everything in a deviating module, and the top MaxAmbient of the remainder by
// count.
//
// Callers must pass the same Selection to Render and ResolveEvidence:
// TemplateID numbers this list, so the identifiers the model cites only
// resolve against the list it was shown.
func Select(b model.Bundle, sel Selection) []Line {
	type key struct {
		moduleID string
		priority int
		canon    string
	}

	// The gate reports deviation per module instance, because module_baselines
	// is keyed that way -- one instance flooding is signal about that
	// instance. Lines here are grouped per family, so the question a group
	// asks is whether *any* of its instances deviates. Collapsing the set once
	// is what keeps a deviating line out of the ambient pool, where
	// MaxAmbient can drop the very line that paid for the call.
	deviatingFamilies := make(map[string]bool, len(sel.DeviatingModules))
	for m := range sel.DeviatingModules {
		deviatingFamilies[model.ModuleFamily(m)] = true
	}

	grouped := map[key]*Line{}
	var order []key
	for _, t := range b.Templates {
		k := key{model.ModuleFamily(t.ModuleID), t.Priority, model.CanonicalTemplate(t.Template)}
		line, ok := grouped[k]
		if !ok {
			cp := t
			cp.ModuleID = k.moduleID
			cp.Samples = nil
			grouped[k] = &Line{Template: cp, Variants: 1}
			order = append(order, k)
			continue
		}
		line.Variants++
		line.Template.Count += t.Count
		// The representative is the busiest variant; ties break on template
		// order so the choice does not depend on map or slice iteration.
		if t.Count > line.Template.Count-t.Count ||
			(t.Count == line.Template.Count-t.Count && t.Template < line.Template.Template) {
			count := line.Template.Count
			line.Template = t
			line.Template.ModuleID = k.moduleID
			line.Template.Samples = nil
			line.Template.Count = count
		}
		if t.Category == "security" {
			line.Template.Category = "security"
		}
	}

	var kept, ambient []Line
	for _, k := range order {
		line := *grouped[k]
		switch {
		case sel.Novel[model.CanonicalKey(k.moduleID, line.Template.Template)],
			line.Template.Category == "security",
			deviatingFamilies[k.moduleID]:
			kept = append(kept, line)
		default:
			ambient = append(ambient, line)
		}
	}

	// Ambient lines are ranked by volume, then by template order so equal
	// counts do not depend on input order.
	sort.Slice(ambient, func(i, j int) bool {
		if ambient[i].Template.Count != ambient[j].Template.Count {
			return ambient[i].Template.Count > ambient[j].Template.Count
		}
		return model.LessTemplate(ambient[i].Template, ambient[j].Template)
	})
	if sel.MaxAmbient >= 0 && len(ambient) > sel.MaxAmbient {
		ambient = ambient[:sel.MaxAmbient]
	}

	out := append(kept, ambient...)
	sort.Slice(out, func(i, j int) bool {
		return model.LessTemplate(out[i].Template, out[j].Template)
	})
	return out
}

// ResolveEvidence maps cited identifiers back to templates.
//
// Identity is computed from what this returns, never from model-authored
// text. Letting the model supply evidence strings directly made a fingerprint
// depend on the occurrence count printed beside the template, so the same
// condition changed identity every window and was re-raised forever -- the
// exact failure deduplication exists to prevent.
func ResolveEvidence(b model.Bundle, sel Selection, ids []string) ([]model.Template, error) {
	lines := Select(b, sel)
	index := make(map[string]model.Template, len(lines))
	for i, l := range lines {
		index[TemplateID(i)] = l.Template
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

// header is the invariant opening of every user prompt. It is first, and the
// per-window WINDOW block is last, so that everything a provider can cache
// sits in a common prefix: OpenAI caches the longest shared prefix of a
// request, and a prompt that opened with "start_ms=1788269400000" shared
// nothing beyond the system message.
//
// It is also the only place the section layout is explained, which the model
// previously had to infer.
const header = `SECTIONS
DIGEST     one line per (module, priority) bucket: observed, expected, ratio.
           Buckets the gate flagged as deviating are marked with *.
TEMPLATES  the log lines worth your attention this window, each with an
           identifier to cite. count is how many lines matched; variants is
           how many spellings of the same line were folded into it. Templates
           that are neither new, security-classified nor in a deviating module
           are shown only as ambient context, most frequent first.
SAMPLING   how much of the window survived the collector's line budget.
ALREADY KNOWN  conditions already raised for this system. Do not report them
           again.
WINDOW     the time range and collector version this bundle covers.

`

// Render produces a deterministic prompt for the given bundle and currently
// open findings. Everything is sorted so the same inputs always produce the
// same bytes, regardless of input slice order. Samples are never included.
func Render(b model.Bundle, open []model.Finding, sel Selection) string {
	var sb strings.Builder

	sb.WriteString(header)

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
		mark := ""
		if sel.DeviatingModules[e.ModuleID] {
			mark = " *"
		}
		sb.WriteString(fmt.Sprintf("%s %d %d %s %s%s\n", e.ModuleID, e.Priority, e.Observed, expectedStr, ratioStr, mark))
	}
	sb.WriteString("\n")

	sb.WriteString("TEMPLATES (cite these identifiers in evidence)\n")
	lines := Select(b, sel)
	for i, l := range lines {
		t := l.Template
		cat := t.Category
		if cat == "" {
			cat = "-"
		}
		mod := t.ModuleID
		if mod == "" {
			mod = HostBucketLabel
		}
		variants := ""
		if l.Variants > 1 {
			variants = fmt.Sprintf(" variants=%d", l.Variants)
		}
		sb.WriteString(fmt.Sprintf("[%s] count=%d module=%s priority=%d category=%s%s\n    %s\n",
			TemplateID(i), t.Count, mod, t.Priority, cat, variants, t.Template))
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
		// Map each known finding's stored evidence text back to the
		// identifiers used in THIS window, so the model has something to
		// match on. Printing only the title left it guessing, and a
		// differently-worded restatement then arrived as a new finding.
		//
		// The lookup is by canonical text, not by exact text: the finding was
		// raised from whichever variant the collector shipped that day, and
		// this window may carry a different spelling of the same line.
		idByText := make(map[string]string, len(lines))
		for i, l := range lines {
			canon := model.CanonicalTemplate(l.Template.Template)
			if _, seen := idByText[canon]; !seen {
				idByText[canon] = TemplateID(i)
			}
		}

		for _, f := range known {
			sb.WriteString(fmt.Sprintf("[%s] %s\n", f.Severity, f.Title))
			// A template the finding was raised from may be absent this
			// window. Omit it rather than invent an identifier the model
			// could cite back into ResolveEvidence as unknown.
			ids := make([]string, 0, len(f.Evidence))
			seen := map[string]bool{}
			for _, ev := range f.Evidence {
				if id, ok := idByText[model.CanonicalTemplate(ev)]; ok && !seen[id] {
					seen[id] = true
					ids = append(ids, id)
				}
			}
			if len(ids) > 0 {
				sort.Strings(ids)
				sb.WriteString(fmt.Sprintf("    evidence: %s\n", strings.Join(ids, ", ")))
			}
		}
	}

	sb.WriteString("\nWINDOW\n")
	sb.WriteString(fmt.Sprintf("start_ms=%d end_ms=%d collector=%s masking=%d\n",
		b.Window.Start, b.Window.End, b.CollectorVersion, b.MaskingVersion))

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
