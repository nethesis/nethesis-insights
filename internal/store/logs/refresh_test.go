// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package logs

import (
	"context"
	"reflect"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/model"
)

// refreshFinding stores one finding raised from a single sshd line at 1000.
func refreshFinding(t *testing.T, s *Store, systemID string, nodes []int) {
	t.Helper()
	if _, err := s.UpsertFinding(context.Background(), model.Finding{
		SystemID: systemID, Fingerprint: "fp1", Severity: "high",
		Title: "t", Summary: "s", SuggestedAction: "a",
		Modules: []string{"sshd"}, Evidence: []string{"failed password for <USER> from <IP> (DE/<NUM>)"},
		Nodes: nodes, ClassKey: "v4:c1",
	}, 1000); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
}

func onlyFinding(t *testing.T, s *Store, systemID string) model.Finding {
	t.Helper()
	all, err := s.ListAllFindings(context.Background(), FindingFilter{System: systemID})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("got %d findings, want 1", len(all))
	}
	return all[0]
}

// A finding whose lines keep arriving stays open without the model
// re-reporting it -- the model is told never to.
func TestRefreshKeepsAContinuingFindingOpen(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	refreshFinding(t, s, "sys1", nil)

	// Another spelling of the same line: the country code is a masking leak
	// that model.CanonicalKey folds.
	n, err := s.RefreshFindings(ctx, "sys1", []model.Template{
		{ModuleID: "sshd1", Template: "failed password for <USER> from <IP> (US/<NUM>)"},
	}, 9000)
	mustDo(t, err)
	if n != 1 {
		t.Fatalf("refreshed %d findings, want 1", n)
	}
	mustDo(t, func() error { _, err := s.MarkStale(ctx, "sys1", 5000); return err }())

	f := onlyFinding(t, s, "sys1")
	if f.Status != model.StatusOpen || f.LastSeen != 9000 || f.OccurrenceCount != 2 {
		t.Fatalf("got status=%s last_seen=%d count=%d, want open/9000/2", f.Status, f.LastSeen, f.OccurrenceCount)
	}
	if f.ReopenedAt != nil {
		t.Fatalf("an open finding was stamped reopened: %v", *f.ReopenedAt)
	}
	c, ok, err := s.GetClass(ctx, "v4:c1")
	mustDo(t, err)
	if !ok || c.LastSeen != 9000 {
		t.Fatalf("class last_seen = %d, want 9000", c.LastSeen)
	}
}

func TestRefreshReopensAStaleFinding(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	refreshFinding(t, s, "sys1", nil)
	mustDo(t, func() error { _, err := s.MarkStale(ctx, "sys1", 5000); return err }())

	_, err := s.RefreshFindings(ctx, "sys1", []model.Template{
		{ModuleID: "sshd1", Template: "failed password for <USER> from <IP> (DE/<NUM>)"},
	}, 9000)
	mustDo(t, err)

	f := onlyFinding(t, s, "sys1")
	if f.Status != model.StatusOpen || f.ReopenedAt == nil || *f.ReopenedAt != 9000 {
		t.Fatalf("got status=%s reopened_at=%v, want open at 9000", f.Status, f.ReopenedAt)
	}
}

// Unrelated lines, and the same line on another system, touch nothing.
func TestRefreshIgnoresOtherLinesAndSystems(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	refreshFinding(t, s, "sys1", nil)

	for _, tc := range []struct {
		system string
		ts     []model.Template
	}{
		{"sys1", []model.Template{{ModuleID: "sshd1", Template: "accepted publickey for <USER>"}}},
		{"sys1", []model.Template{{ModuleID: "postfix1", Template: "failed password for <USER> from <IP> (DE/<NUM>)"}}},
		{"sys2", []model.Template{{ModuleID: "sshd1", Template: "failed password for <USER> from <IP> (DE/<NUM>)"}}},
		{"sys1", nil},
	} {
		n, err := s.RefreshFindings(ctx, tc.system, tc.ts, 9000)
		mustDo(t, err)
		if n != 0 {
			t.Errorf("%s %v: refreshed %d findings, want 0", tc.system, tc.ts, n)
		}
	}
	if f := onlyFinding(t, s, "sys1"); f.LastSeen != 1000 || f.OccurrenceCount != 1 {
		t.Fatalf("got last_seen=%d count=%d, want untouched 1000/1", f.LastSeen, f.OccurrenceCount)
	}
}

// A window counts once in occurrence_count: refreshing it twice, or the
// model re-reporting the finding in the window that refreshed it, adds
// nothing more.
func TestRefreshCountsAWindowOnce(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	refreshFinding(t, s, "sys1", nil)
	line := []model.Template{{ModuleID: "sshd1", Template: "failed password for <USER> from <IP> (DE/<NUM>)"}}

	_, err := s.RefreshFindings(ctx, "sys1", line, 9000)
	mustDo(t, err)
	_, err = s.RefreshFindings(ctx, "sys1", line, 9000)
	mustDo(t, err)
	if _, err := s.UpsertFinding(ctx, model.Finding{
		SystemID: "sys1", Fingerprint: "fp1", Severity: "high",
		Title: "t", Summary: "s", SuggestedAction: "a",
		Modules: []string{"sshd"}, Evidence: []string{"failed password for <USER> from <IP> (DE/<NUM>)"},
		ClassKey: "v4:c1",
	}, 9000); err != nil {
		t.Fatalf("re-report: %v", err)
	}

	if f := onlyFinding(t, s, "sys1"); f.OccurrenceCount != 2 || f.LastSeen != 9000 {
		t.Fatalf("got count=%d last_seen=%d, want 2/9000", f.OccurrenceCount, f.LastSeen)
	}
}

// Nodes become the nodes this window's matching lines came from, and are
// kept when the window says nothing about nodes.
func TestRefreshReplacesNodesFromTheWindow(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	refreshFinding(t, s, "sys1", []int{1, 2})

	_, err := s.RefreshFindings(ctx, "sys1", []model.Template{
		{ModuleID: "sshd1", Template: "failed password for <USER> from <IP> (DE/<NUM>)"},
	}, 9000)
	mustDo(t, err)
	if got := onlyFinding(t, s, "sys1").Nodes; !reflect.DeepEqual(got, []int{1, 2}) {
		t.Fatalf("nodes = %v, want [1 2] kept when the window carries none", got)
	}

	_, err = s.RefreshFindings(ctx, "sys1", []model.Template{
		{ModuleID: "sshd1", Template: "failed password for <USER> from <IP> (DE/<NUM>)", Nodes: []int{3}},
	}, 10000)
	mustDo(t, err)
	if got := onlyFinding(t, s, "sys1").Nodes; !reflect.DeepEqual(got, []int{3}) {
		t.Fatalf("nodes = %v, want [3]", got)
	}
}
