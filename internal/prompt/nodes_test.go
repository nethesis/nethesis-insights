// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package prompt

import (
	"reflect"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/model"
)

func nodeBundle(nodes ...[]int) model.Bundle {
	b := model.Bundle{
		SchemaVersion:    model.SchemaVersion,
		SystemID:         "sys-1",
		CollectorVersion: "1.0.0",
		Window:           model.Window{Start: 1700000000000, End: 1700000900000},
		Digest: []model.DigestEntry{
			{ModuleID: "openldap1", Priority: 3, Observed: 10},
		},
	}
	for i, ns := range nodes {
		b.Templates = append(b.Templates, model.Template{
			Template:  "openldap: connection from <IP> rejected",
			Count:     int64(i + 1),
			ModuleID:  "openldap1",
			Priority:  3,
			FirstSeen: 1700000000000,
			LastSeen:  1700000900000,
			Nodes:     ns,
		})
	}
	return b
}

// The load-bearing privacy rule: a node id -- and therefore the FQDN it
// resolves to -- is never shown to the model. If this ever fails, someone has
// started rendering attribution into the prompt, and a model-authored node
// becomes possible.
func TestNodesNeverReachThePrompt(t *testing.T) {
	sel := Selection{MaxAmbient: 50}

	without := nodeBundle(nil)
	with := nodeBundle([]int{1, 2, 3})

	a := Render(without, nil, sel)
	b := Render(with, nil, sel)

	if a != b {
		t.Errorf("node attribution changed the rendered prompt.\nwithout:\n%s\nwith:\n%s", a, b)
	}
}

// Select folds masked variants of one condition into a single line. The node
// sets must union across that fold: the same condition can appear as
// different variants on different nodes, and keeping only the busiest
// variant's set would attribute the line to the wrong machine.
func TestSelectUnionsNodesAcrossFoldedVariants(t *testing.T) {
	b := model.Bundle{
		SystemID: "sys-1",
		Templates: []model.Template{
			// Same canonical template, different masked variants and
			// different counts, so the representative is the second.
			{Template: "openldap: rejected 1 connections", Count: 1, ModuleID: "openldap1", Priority: 3, Nodes: []int{1}},
			{Template: "openldap: rejected 9 connections", Count: 99, ModuleID: "openldap1", Priority: 3, Nodes: []int{3}},
		},
	}

	lines := Select(b, Selection{MaxAmbient: 50})
	if len(lines) != 1 {
		t.Fatalf("expected the variants to fold into one line, got %d", len(lines))
	}
	if got, want := lines[0].Template.Nodes, []int{1, 3}; !reflect.DeepEqual(got, want) {
		t.Errorf("Nodes = %v, want %v -- the fold dropped a node", got, want)
	}
}

func TestSelectSanitizesNodesOfAnUnfoldedLine(t *testing.T) {
	b := model.Bundle{
		SystemID: "sys-1",
		Templates: []model.Template{
			{Template: "a line", Count: 1, ModuleID: "openldap1", Priority: 3, Nodes: []int{2, 0, 2, 1}},
		},
	}
	lines := Select(b, Selection{MaxAmbient: 50})
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1", len(lines))
	}
	if got, want := lines[0].Template.Nodes, []int{1, 2}; !reflect.DeepEqual(got, want) {
		t.Errorf("Nodes = %v, want %v", got, want)
	}
}

// ResolveEvidence is where the analyzer picks attribution up, so the node set
// has to survive the round trip from bundle to cited template.
func TestResolveEvidenceCarriesNodes(t *testing.T) {
	b := nodeBundle([]int{2, 1})
	sel := Selection{MaxAmbient: 50}

	cited, err := ResolveEvidence(b, sel, []string{TemplateID(0)})
	if err != nil {
		t.Fatalf("ResolveEvidence: %v", err)
	}
	if len(cited) != 1 {
		t.Fatalf("got %d cited templates, want 1", len(cited))
	}
	if got, want := cited[0].Nodes, []int{1, 2}; !reflect.DeepEqual(got, want) {
		t.Errorf("Nodes = %v, want %v", got, want)
	}
}
