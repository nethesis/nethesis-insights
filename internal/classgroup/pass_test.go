// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package classgroup

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/grouping"
	"github.com/nethesis/nethesis-insights/internal/model"
	logsstore "github.com/nethesis/nethesis-insights/internal/store/logs"
)

type fakeReader struct {
	ungrouped   []logsstore.ClassEvidence
	anchors     []grouping.Anchor
	set         []logsstore.ClassGroup
	anchorReads int
	models      []string
}

func (f *fakeReader) UngroupedClasses(_ context.Context, model string, _ int) ([]logsstore.ClassEvidence, error) {
	f.models = append(f.models, model)
	return f.ungrouped, nil
}
func (f *fakeReader) GroupAnchors(context.Context, string) ([]grouping.Anchor, error) {
	f.anchorReads++
	return f.anchors, nil
}
func (f *fakeReader) SetClassGroup(_ context.Context, g logsstore.ClassGroup) error {
	f.set = append(f.set, g)
	return nil
}

type reply struct {
	vec   []float32
	model string
	err   error
}

// fakeEmbedder answers the probe first, then one reply per class.
type fakeEmbedder struct {
	replies []reply
	calls   int
}

func (f *fakeEmbedder) Embed(context.Context, string) ([]float32, string, error) {
	r := f.replies[f.calls]
	f.calls++
	return r.vec, r.model, r.err
}

func ev(key string) logsstore.ClassEvidence {
	return logsstore.ClassEvidence{Key: key, Evidence: []string{key}}
}

func run(t *testing.T, r Reader, e Embedder) {
	t.Helper()
	if err := New(r, e, Config{Threshold: 0.9, Batch: 10}).Run(context.Background(), 777); err != nil {
		t.Fatal(err)
	}
}

func TestSidecarDownAtProbeWritesNothing(t *testing.T) {
	r := &fakeReader{ungrouped: []logsstore.ClassEvidence{ev("a")}}
	run(t, r, &fakeEmbedder{replies: []reply{{err: errors.New("down")}}})
	if len(r.set) != 0 || len(r.models) != 0 {
		t.Fatalf("touched the store: %+v %v", r.set, r.models)
	}
}

func TestEmptyUngroupedSkipsAnchors(t *testing.T) {
	r := &fakeReader{}
	run(t, r, &fakeEmbedder{replies: []reply{{vec: []float32{1, 0}, model: "m"}}})
	if r.anchorReads != 0 {
		t.Fatal("anchors read for nothing")
	}
}

func TestJoinVersusNewAndRecordedFields(t *testing.T) {
	r := &fakeReader{
		ungrouped: []logsstore.ClassEvidence{ev("near"), ev("far")},
		anchors:   []grouping.Anchor{{Key: "anc", Vector: []float32{1, 0}}},
	}
	e := &fakeEmbedder{replies: []reply{
		{vec: []float32{1, 0}, model: "m"},
		{vec: []float32{1, 0}, model: "m"},
		{vec: []float32{0, 1}, model: "m"},
	}}
	run(t, r, e)
	if len(r.set) != 2 {
		t.Fatalf("rows: %+v", r.set)
	}
	near, far := r.set[0], r.set[1]
	if near.Key != "near" || near.Anchor != "anc" || near.Similarity < 0.99 {
		t.Fatalf("near: %+v", near)
	}
	if far.Key != "far" || far.Anchor != "far" || far.Similarity != 1 {
		t.Fatalf("far: %+v", far)
	}
	if near.Threshold != 0.9 || near.Model != "m" || near.At != 777 || len(near.Vector) != 2 {
		t.Fatalf("recorded: %+v", near)
	}
}

func TestNewAnchorAttractsLaterClassInSamePass(t *testing.T) {
	r := &fakeReader{ungrouped: []logsstore.ClassEvidence{ev("a"), ev("b")}}
	e := &fakeEmbedder{replies: []reply{
		{vec: []float32{1, 0}, model: "m"},
		{vec: []float32{0, 1}, model: "m"},
		{vec: []float32{0, 1}, model: "m"},
	}}
	run(t, r, e)
	if got := []string{r.set[0].Anchor, r.set[1].Anchor}; !reflect.DeepEqual(got, []string{"a", "a"}) {
		// a is the first anchor (vector 0,1); b must join it.
		t.Fatalf("anchors %v", got)
	}
}

func TestEmbedErrorMidPassStopsAfterWrittenRows(t *testing.T) {
	r := &fakeReader{ungrouped: []logsstore.ClassEvidence{ev("a"), ev("b"), ev("c")}}
	e := &fakeEmbedder{replies: []reply{
		{vec: []float32{1, 0}, model: "m"},
		{vec: []float32{1, 0}, model: "m"},
		{err: errors.New("boom")},
	}}
	run(t, r, e)
	if len(r.set) != 1 || e.calls != 3 {
		t.Fatalf("rows %d calls %d", len(r.set), e.calls)
	}
}

func TestModelChangeMidPassStops(t *testing.T) {
	r := &fakeReader{ungrouped: []logsstore.ClassEvidence{ev("a"), ev("b")}}
	e := &fakeEmbedder{replies: []reply{
		{vec: []float32{1, 0}, model: "m"},
		{vec: []float32{1, 0}, model: "m"},
		{vec: []float32{1, 0}, model: "other"},
	}}
	run(t, r, e)
	if len(r.set) != 1 {
		t.Fatalf("rows %+v", r.set)
	}
}

// TestGroupingNeverDecides runs the pass on a real store: a pending class
// whose group already holds a decided class stays pending and no decision row
// appears.
func TestGroupingNeverDecides(t *testing.T) {
	ctx := context.Background()
	s, err := logsstore.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Init(ctx); err != nil {
		t.Fatal(err)
	}
	for i, class := range []string{"v3:decided", "v3:pending"} {
		f := model.Finding{SystemID: "s", Fingerprint: class, Severity: "low", Title: class,
			Modules: []string{}, Evidence: []string{class}, ClassKey: class, PromptVersion: "p1"}
		if _, err := s.UpsertFinding(ctx, f, int64(1000+i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetClassGroup(ctx, logsstore.ClassGroup{Key: "v3:decided", Anchor: "v3:decided",
		Similarity: 1, Threshold: 0.9, Model: "m", Vector: []float32{1, 0}, At: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetClassVisibility(ctx, "v3:decided", logsstore.VisibilityCustomer, "op", 2000); err != nil {
		t.Fatal(err)
	}
	before, _ := s.ClassDecisions(ctx, "v3:pending")
	allBefore, _ := s.ListClassDecisions(ctx, 100)

	e := &fakeEmbedder{replies: []reply{
		{vec: []float32{1, 0}, model: "m"},
		{vec: []float32{1, 0}, model: "m"},
	}}
	run(t, s, e)

	anchors, _ := s.GroupAnchors(ctx, "m")
	if len(anchors) != 1 {
		t.Fatalf("pending class did not join: %+v", anchors)
	}
	c, _, _ := s.GetClass(ctx, "v3:pending")
	if c.Visibility != logsstore.VisibilityPending {
		t.Fatalf("visibility %s", c.Visibility)
	}
	after, _ := s.ClassDecisions(ctx, "v3:pending")
	allAfter, _ := s.ListClassDecisions(ctx, 100)
	if len(after) != len(before) || len(allAfter) != len(allBefore) {
		t.Fatal("decision rows changed")
	}
}
