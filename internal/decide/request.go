// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package decide

import (
	"bytes"
	"encoding/json"
	"math"
	"sort"

	"github.com/nethesis/nethesis-insights/internal/grouping"
)

// Evidence is cut to MaxLines lines of MaxRunes runes each.
const (
	MaxLines = 6
	MaxRunes = 400
	// K is how many precedents accompany a request.
	K = 15
)

// Class is the description of one finding class sent to the API. Field order
// is the JSON key order and matches what was measured.
type Class struct {
	Modules  []string `json:"modules"`
	Title    string   `json:"title"`
	Summary  string   `json:"summary"`
	Evidence []string `json:"evidence"`
}

// Describe builds a Class, cutting evidence to the measured shape. Nil slices
// become empty ones so the JSON never carries null.
func Describe(modules, evidence []string, title, summary string) Class {
	c := Class{Modules: []string{}, Title: title, Summary: summary, Evidence: []string{}}
	c.Modules = append(c.Modules, modules...)
	for i, l := range evidence {
		if i == MaxLines {
			break
		}
		if r := []rune(l); len(r) > MaxRunes {
			l = string(r[:MaxRunes])
		}
		c.Evidence = append(c.Evidence, l)
	}
	return c
}

// Precedent is a class a person already decided; Class flattens into the
// same JSON object.
type Precedent struct {
	Class
	Decision   string  `json:"decision"`
	Similarity float64 `json:"similarity"`
}

// Candidate is a decided class with its embedding, the pool Nearest draws on.
type Candidate struct {
	Class    Class
	Decision string
	Vector   []float32
}

// Nearest returns the k candidates most similar to target by cosine,
// descending, ties in pool order, similarity rounded to 3 decimals.
func Nearest(target []float32, pool []Candidate, k int) []Precedent {
	type scored struct {
		i int
		s float64
	}
	sc := make([]scored, len(pool))
	for i, c := range pool {
		sc[i] = scored{i, grouping.Cosine(target, c.Vector)}
	}
	sort.SliceStable(sc, func(a, b int) bool { return sc[a].s > sc[b].s })
	if k > len(sc) {
		k = len(sc)
	}
	out := make([]Precedent, 0, k)
	for _, s := range sc[:k] {
		c := pool[s.i]
		out = append(out, Precedent{Class: c.Class, Decision: c.Decision,
			Similarity: math.Round(s.s*1000) / 1000})
	}
	return out
}

type part struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
	Data any    `json:"data,omitempty"`
}

type message struct {
	Role    string `json:"role"`
	Content []part `json:"content"`
}

type choice struct {
	Value       string `json:"value"`
	Description string `json:"description"`
}

type question struct {
	Type         string   `json:"type"`
	Name         string   `json:"name"`
	Instructions string   `json:"instructions"`
	Choices      []choice `json:"choices"`
}

type request struct {
	Model     string     `json:"model"`
	Input     []message  `json:"input"`
	Questions []question `json:"questions"`
}

const baseInstructions = "This is one class of findings that an LLM raised from a NethServer 8 cluster's logs. " +
	"Decide how the review team should handle it. Past decisions on similar classes, when " +
	"given, are precedent: follow them where they apply."

const rulesIntro = "\n\nApply these review rules. In them \"internal\" is the choice operator and " +
	"\"dismiss\" is the choice dismissed. Rules are checked in order; the first that " +
	"matches wins; when none matches, choose dismissed. Precedents show how the rules " +
	"were applied; where a precedent contradicts a rule, the rule wins.\n\n"

var choices = []choice{
	{"customer", "Send to the customer: a real problem on this system that the " +
		"customer's own administrator can see and act on -- a failed service, update or backup, " +
		"a crash, memory exhaustion, data corruption, a configuration the administrator can fix, " +
		"or attacks against the system that the administrator should know about."},
	{"operator", "Keep internal for Nethesis: a real problem whose fix is in " +
		"Nethesis software or infrastructure -- a bug in a NethServer/NethVoice component, an internal " +
		"service or integration, Nethesis backup/monitoring/cloud services. The customer cannot act on it."},
	{"dismissed", "Dismiss: expected or harmless noise, a transient one-off, a " +
		"problem of a third party (a remote mail sender's DNS/SPF/DKIM, a client's device), an end-user " +
		"action failing normally, or a warning with no consequence."},
}

// BuildRequest renders the Decisions API request body. A nil precedents slice
// means zero-shot: the target alone, no precedent parts.
func BuildRequest(model string, target Class, precedents []Precedent) ([]byte, error) {
	parts := []part{
		{Type: "input_text", Text: "Finding class to decide:"},
		{Type: "input_json", Data: target},
	}
	if precedents != nil {
		parts = append(parts,
			part{Type: "input_text", Text: "The 15 most similar classes the review team already decided, most similar first, with their decision:"},
			part{Type: "input_json", Data: map[string][]Precedent{"precedents": precedents}})
	}
	req := request{
		Model: model,
		Input: []message{{Role: "user", Content: parts}},
		Questions: []question{{
			Type: "choice", Name: "decision",
			Instructions: baseInstructions + rulesIntro + Rules,
			Choices:      choices,
		}},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(req); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
