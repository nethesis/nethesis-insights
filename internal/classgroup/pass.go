// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package classgroup runs insightsd's review-grouping pass: it embeds finding
// classes that have no group yet and stores the anchor each one joins (or
// becomes), so /review can show similar classes together and suggest one
// decision for them.
//
// The pass only writes class_groups. It never touches finding_classes or
// class_decisions: a suggestion is applied only by an operator POST. It
// degrades rather than fails -- with the embedding sidecar down it logs and
// returns nil, and everything else keeps working.
package classgroup

import (
	"context"
	"errors"
	"log/slog"

	"github.com/nethesis/nethesis-insights/internal/embed"
	"github.com/nethesis/nethesis-insights/internal/grouping"
	logsstore "github.com/nethesis/nethesis-insights/internal/store/logs"
)

// PassName is the pass's name in svc.RunPassLoop's log line and the `pass`
// metric label; one definition shared with cmd/insightsd.
const PassName = "class grouping"

// Reader is the slice of logsstore.Store this pass needs.
type Reader interface {
	UngroupedClasses(ctx context.Context, model string, limit int) ([]logsstore.ClassEvidence, error)
	GroupAnchors(ctx context.Context, model string) ([]grouping.Anchor, error)
	SetClassGroup(ctx context.Context, g logsstore.ClassGroup) error
}

// Embedder is *embed.Client. The string is the model name the server reported.
type Embedder interface {
	Embed(ctx context.Context, text string) ([]float32, string, error)
}

// Config is the pass's settings.
type Config struct {
	Threshold float64
	Batch     int // classes per pass
}

// Runner performs one grouping pass.
type Runner struct {
	store Reader
	emb   Embedder
	cfg   Config
}

func New(r Reader, e Embedder, cfg Config) *Runner {
	return &Runner{store: r, emb: e, cfg: cfg}
}

// Run groups up to Config.Batch ungrouped classes. A sidecar failure, or a
// model change under it, ends the pass quietly; the rest waits for the next.
// A class the sidecar rejects at every size is skipped and retried next pass.
// Store errors are returned.
func (r *Runner) Run(ctx context.Context, now int64) error {
	_, model, err := r.emb.Embed(ctx, grouping.Text(nil, []string{"probe"}))
	if err != nil {
		slog.Warn("embedding sidecar unavailable", "error", err)
		return nil
	}
	classes, err := r.store.UngroupedClasses(ctx, model, r.cfg.Batch)
	if err != nil {
		return err
	}
	if len(classes) == 0 {
		return nil
	}
	anchors, err := r.store.GroupAnchors(ctx, model)
	if err != nil {
		return err
	}

	var joined, created, errs, rejected int
	for _, c := range classes {
		text := grouping.Text(c.Modules, c.Evidence)
		vec, m, err := r.emb.Embed(ctx, text)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, embed.ErrRejected) {
				// The sidecar refuses this class even at the shortest cut.
				// Skip it so it cannot block every class behind it; it is
				// still ungrouped and is retried next pass.
				rejected++
				slog.Warn("embedding rejected, skipping class", "class_key", c.Key, "error", err)
				continue
			}
			errs++
			slog.Warn("embedding failed, ending pass", "class_key", c.Key, "error", err)
			break
		}
		if m != model {
			errs++
			slog.Warn("embedding model changed, ending pass", "was", model, "now", m)
			break
		}
		best, sim, ok := grouping.Assign(vec, anchors, r.cfg.Threshold)
		g := logsstore.ClassGroup{Key: c.Key, Threshold: r.cfg.Threshold, Model: model, Vector: vec, At: now}
		route := "new_group"
		if ok {
			route = "joined_group"
			g.Anchor, g.Similarity = best, sim
		} else {
			g.Anchor, g.Similarity = c.Key, 1
		}
		if err := r.store.SetClassGroup(ctx, g); err != nil {
			return err
		}
		if ok {
			joined++
		} else {
			created++
			anchors = append(anchors, grouping.Anchor{Key: c.Key, Vector: vec})
		}
		slog.Info("class grouping decision",
			"class_key", c.Key, "route", route, "anchor", g.Anchor,
			"best_anchor", best, "similarity", sim, "threshold", r.cfg.Threshold,
			"model", model, "chars", len(text))
	}
	slog.Info("class grouping pass", "grouped", joined+created, "joined", joined, "new", created, "errors", errs, "rejected", rejected)
	return nil
}
