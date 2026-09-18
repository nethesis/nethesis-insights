// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package model

import (
	"reflect"
	"strings"
	"testing"
)

func TestSanitizeFQDN(t *testing.T) {
	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." +
		strings.Repeat("c", 60) + "." + strings.Repeat("d", 60) + ".example.org"

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "rl1.leader.default.gs.nethserver.net", "rl1.leader.default.gs.nethserver.net"},
		{"single label", "localhost", "localhost"},
		{"surrounding space", "  node1.example.org\t", "node1.example.org"},
		{"uppercase is lowered", "RL1.Example.ORG", "rl1.example.org"},
		{"root dot trimmed", "node1.example.org.", "node1.example.org"},
		{"hyphens kept", "web-01.example.org", "web-01.example.org"},
		{"digits kept", "node1.example.org", "node1.example.org"},

		// Rejections. Every one of these returns "", which drops the name
		// and keeps the node id -- failing toward less stored data.
		{"empty", "", ""},
		{"only space", "   ", ""},
		{"no letter at all", "10.5.4.1", ""},
		{"leading dot", ".example.org", ""},
		{"trailing hyphen", "node1.example.org-", ""},
		{"leading hyphen", "-node1.example.org", ""},
		{"empty label", "node1..example.org", ""},
		{"space inside", "node 1.example.org", ""},
		{"underscore", "node_1.example.org", ""},
		{"control character", "node1\x00.example.org", ""},
		{"newline", "node1.example.org\nsecond", ""},
		{"a log line", "<3> [sshd] Failed password for root", ""},
		{"a url", "https://node1.example.org/path", ""},
		{"a credential", "user:hunter2@node1.example.org", ""},
		{"too long", long, ""},
		{"label over 63", strings.Repeat("a", 64) + ".example.org", ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := SanitizeFQDN(c.in); got != c.want {
				t.Errorf("SanitizeFQDN(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestSanitizeNodeIDs(t *testing.T) {
	cases := []struct {
		name string
		in   []int
		want []int
	}{
		{"nil", nil, nil},
		{"sorted and deduped", []int{3, 1, 3, 2}, []int{1, 2, 3}},
		{"zero dropped", []int{0, 1}, []int{1}},
		{"negative dropped", []int{-2, 1}, []int{1}},
		{"all invalid yields nil", []int{0, -1}, nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := SanitizeNodeIDs(c.in); !reflect.DeepEqual(got, c.want) {
				t.Errorf("SanitizeNodeIDs(%v) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// Caps truncate rather than reject: the same rule threat.Sanitize and
// sizing.Sanitize follow, so an oversized input costs the overflow, not the
// whole bundle.
func TestSanitizeNodeIDsTruncatesRatherThanRejects(t *testing.T) {
	in := make([]int, 0, MaxNodesPerTemplate+10)
	for i := 1; i <= MaxNodesPerTemplate+10; i++ {
		in = append(in, i)
	}
	got := SanitizeNodeIDs(in)
	if len(got) != MaxNodesPerTemplate {
		t.Fatalf("len = %d, want %d", len(got), MaxNodesPerTemplate)
	}
	if got[0] != 1 {
		t.Errorf("kept the wrong end: got[0] = %d, want 1", got[0])
	}
}

func TestSanitizeRoster(t *testing.T) {
	in := []NodeInfo{
		{NodeID: 2, FQDN: "b.example.org"},
		{NodeID: 1, FQDN: "a.example.org"},
		{NodeID: 0, FQDN: "dropped.example.org"},       // id below 1
		{NodeID: 3, FQDN: "<3> [sshd] not a hostname"}, // name dropped, id kept
		{NodeID: 1, FQDN: "duplicate.example.org"},     // first wins
	}
	want := []NodeInfo{
		{NodeID: 1, FQDN: "a.example.org"},
		{NodeID: 2, FQDN: "b.example.org"},
		{NodeID: 3, FQDN: ""},
	}
	if got := SanitizeRoster(in); !reflect.DeepEqual(got, want) {
		t.Errorf("SanitizeRoster() = %+v, want %+v", got, want)
	}
}

func TestSanitizeRosterTruncatesRatherThanRejects(t *testing.T) {
	in := make([]NodeInfo, 0, MaxRosterNodes+5)
	for i := 1; i <= MaxRosterNodes+5; i++ {
		in = append(in, NodeInfo{NodeID: i})
	}
	if got := SanitizeRoster(in); len(got) != MaxRosterNodes {
		t.Errorf("len = %d, want %d", len(got), MaxRosterNodes)
	}
}

// A bundle carrying no node data at all must survive untouched: a collector
// older than this feature is not an error, it is a bundle without
// attribution.
func TestSanitizeNodesLeavesABundleWithoutNodeDataIntact(t *testing.T) {
	b := Bundle{
		SystemID:  "sys-1",
		Templates: []Template{{Template: "a", ModuleID: "m"}},
	}
	got := b.SanitizeNodes()
	if len(got.Nodes) != 0 {
		t.Errorf("Nodes = %v, want empty", got.Nodes)
	}
	if len(got.Templates) != 1 || got.Templates[0].Nodes != nil {
		t.Errorf("Templates = %+v, want one template with no nodes", got.Templates)
	}
}

func TestSanitizeNodesCleansRosterAndTemplates(t *testing.T) {
	b := Bundle{
		SystemID: "sys-1",
		Nodes: []NodeInfo{
			{NodeID: 2, FQDN: "  B.Example.ORG "},
			{NodeID: 0, FQDN: "ghost.example.org"},
		},
		Templates: []Template{
			{Template: "a", Nodes: []int{3, 1, 1, 0}},
		},
	}
	got := b.SanitizeNodes()

	wantRoster := []NodeInfo{{NodeID: 2, FQDN: "b.example.org"}}
	if !reflect.DeepEqual(got.Nodes, wantRoster) {
		t.Errorf("Nodes = %+v, want %+v", got.Nodes, wantRoster)
	}
	wantNodes := []int{1, 3}
	if !reflect.DeepEqual(got.Templates[0].Nodes, wantNodes) {
		t.Errorf("Templates[0].Nodes = %v, want %v", got.Templates[0].Nodes, wantNodes)
	}
}

// The sanitizer must not write through to the caller's bundle: handleBundles
// sanitizes before publishing to the queue, and an in-place edit would be a
// mutation of a decoded request body shared with the response path.
func TestSanitizeNodesDoesNotMutateItsInput(t *testing.T) {
	b := Bundle{
		Nodes:     []NodeInfo{{NodeID: 1, FQDN: "A.EXAMPLE.ORG"}},
		Templates: []Template{{Template: "a", Nodes: []int{2, 1}}},
	}
	_ = b.SanitizeNodes()

	if b.Nodes[0].FQDN != "A.EXAMPLE.ORG" {
		t.Errorf("roster mutated: %q", b.Nodes[0].FQDN)
	}
	if !reflect.DeepEqual(b.Templates[0].Nodes, []int{2, 1}) {
		t.Errorf("template nodes mutated: %v", b.Templates[0].Nodes)
	}
}
