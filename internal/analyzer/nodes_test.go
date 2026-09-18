// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package analyzer

import (
	"context"
	"reflect"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/llm"
	"github.com/nethesis/nethesis-insights/internal/model"
)

// findingResponse is a stub reply citing T1, which is the only template the
// bundles below carry.
const findingResponse = `{"window_assessment":"incident","findings":[{"severity":"high","title":"t","summary":"s","suggested_action":"a","evidence":["T1"]}]}`

func nodeBundle(systemID string, windowStart int64, templateNodes []int, roster []model.NodeInfo) model.Bundle {
	return model.Bundle{
		SchemaVersion:    model.SchemaVersion,
		SystemID:         systemID,
		CollectorVersion: "1.0",
		Window:           model.Window{Start: windowStart, End: windowStart + 100},
		Templates: []model.Template{
			{Template: "tpl1", Count: 5, ModuleID: "mod1", Priority: 1, Nodes: templateNodes},
		},
		Digest: []model.DigestEntry{
			{ModuleID: "mod1", Priority: 1, Observed: 5},
		},
		Nodes: roster,
	}
}

func TestFindingCarriesTheCitedTemplatesNodes(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	stub := &llm.Stub{Content: findingResponse}
	a := New(s, stub, testBudget(s), testConfig(), func() int64 { return 1000 })

	b := nodeBundle("sys1", 100, []int{3, 1}, []model.NodeInfo{
		{NodeID: 1, FQDN: "a.example.org"},
		{NodeID: 3, FQDN: "c.example.org"},
	})
	if err := a.Process(ctx, b); err != nil {
		t.Fatalf("process: %v", err)
	}

	found, err := s.ListFindings(ctx, "sys1", 0, "")
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("got %d findings, want 1", len(found))
	}
	if got, want := found[0].Nodes, []int{1, 3}; !reflect.DeepEqual(got, want) {
		t.Errorf("Nodes = %v, want %v", got, want)
	}

	if err := s.ResolveNodes(ctx, "sys1", found); err != nil {
		t.Fatalf("resolve nodes: %v", err)
	}
	want := []model.NodeInfo{
		{NodeID: 1, FQDN: "a.example.org"},
		{NodeID: 3, FQDN: "c.example.org"},
	}
	if !reflect.DeepEqual(found[0].NodeRefs, want) {
		t.Errorf("NodeRefs = %+v, want %+v", found[0].NodeRefs, want)
	}
}

// Last-window semantics: a condition that moved from node 1 to node 3 reads
// as node 3, not as both. A union would grow until a long-lived finding
// listed the whole cluster and discriminated nothing.
func TestRecurrenceReplacesTheNodeSetRatherThanAccumulating(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	stub := &llm.Stub{Content: findingResponse}
	a := New(s, stub, testBudget(s), testConfig(), func() int64 { return 1000 })

	roster := []model.NodeInfo{
		{NodeID: 1, FQDN: "a.example.org"},
		{NodeID: 3, FQDN: "c.example.org"},
	}
	if err := a.Process(ctx, nodeBundle("sys1", 100, []int{1}, roster)); err != nil {
		t.Fatalf("first process: %v", err)
	}
	// The second window must reach the LLM for the finding to recur, so make
	// it deviate: a steady window is gated out and would never re-upsert.
	second := nodeBundle("sys1", 300, []int{3}, roster)
	second.Digest[0].Observed = 500
	if err := a.Process(ctx, second); err != nil {
		t.Fatalf("second process: %v", err)
	}

	found, err := s.ListFindings(ctx, "sys1", 0, "")
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("got %d findings, want 1 -- the node set must not change identity", len(found))
	}
	if found[0].OccurrenceCount != 2 {
		t.Fatalf("occurrence_count = %d, want 2", found[0].OccurrenceCount)
	}
	if got, want := found[0].Nodes, []int{3}; !reflect.DeepEqual(got, want) {
		t.Errorf("Nodes = %v, want %v -- the set accumulated instead of being replaced", got, want)
	}
}

// The roster is a fact about the cluster, not a product of the analysis, so a
// window that never reaches the LLM still names the machines.
func TestGatedOutBundleStillRecordsTheRoster(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	stub := &llm.Stub{Content: `{"window_assessment":"nominal","findings":[]}`}
	a := New(s, stub, testBudget(s), testConfig(), func() int64 { return 1000 })

	// Seed: the first bundle for a new system always has novel templates.
	seed := nodeBundle("sys1", 0, []int{1}, nil)
	if err := a.Process(ctx, seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	callsAfterSeed := stub.Calls

	// A steady bundle is gated out, but it carries the roster.
	b := nodeBundle("sys1", 100, []int{1}, []model.NodeInfo{{NodeID: 1, FQDN: "a.example.org"}})
	if err := a.Process(ctx, b); err != nil {
		t.Fatalf("process: %v", err)
	}
	if stub.Calls != callsAfterSeed {
		t.Fatalf("expected the second bundle to be gated out, calls %d -> %d", callsAfterSeed, stub.Calls)
	}

	roster, err := s.NodeRoster(ctx, "sys1")
	if err != nil {
		t.Fatalf("node roster: %v", err)
	}
	if roster[1] != "a.example.org" {
		t.Errorf("roster[1] = %q, want %q", roster[1], "a.example.org")
	}
}

// A window whose roster lookup failed for one node must not blank the name
// an earlier window already established -- otherwise the UI flickers between
// a name and a bare id.
func TestAnEmptyNameDoesNotEraseAKnownOne(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if err := s.UpsertNodes(ctx, "sys1", []model.NodeInfo{{NodeID: 1, FQDN: "a.example.org"}}, 1000); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if err := s.UpsertNodes(ctx, "sys1", []model.NodeInfo{{NodeID: 1}}, 2000); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	roster, err := s.NodeRoster(ctx, "sys1")
	if err != nil {
		t.Fatalf("node roster: %v", err)
	}
	if roster[1] != "a.example.org" {
		t.Errorf("roster[1] = %q, want the previously known name to survive", roster[1])
	}
}

// A rename must propagate, since the roster is resent every window.
func TestARenamePropagates(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if err := s.UpsertNodes(ctx, "sys1", []model.NodeInfo{{NodeID: 1, FQDN: "old.example.org"}}, 1000); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if err := s.UpsertNodes(ctx, "sys1", []model.NodeInfo{{NodeID: 1, FQDN: "new.example.org"}}, 2000); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	roster, err := s.NodeRoster(ctx, "sys1")
	if err != nil {
		t.Fatalf("node roster: %v", err)
	}
	if roster[1] != "new.example.org" {
		t.Errorf("roster[1] = %q, want %q", roster[1], "new.example.org")
	}
}

// A bundle from a collector that predates node attribution must analyse
// exactly as before, with no attribution rather than an error.
func TestABundleWithoutNodeDataStillProducesAFinding(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	stub := &llm.Stub{Content: findingResponse}
	a := New(s, stub, testBudget(s), testConfig(), func() int64 { return 1000 })

	if err := a.Process(ctx, nodeBundle("sys1", 100, nil, nil)); err != nil {
		t.Fatalf("process: %v", err)
	}

	found, err := s.ListFindings(ctx, "sys1", 0, "")
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("got %d findings, want 1", len(found))
	}
	if found[0].Nodes != nil {
		t.Errorf("Nodes = %v, want nil", found[0].Nodes)
	}
}
