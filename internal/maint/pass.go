// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package maint runs insightsd's housekeeping pass: pruning the tables that
// would otherwise grow monotonically forever now that the fleet feeds the
// pipeline every 15 minutes -- system_templates, findings and analyses.
// module_baselines is deliberately not pruned here; see
// internal/store/logs/prune.go's PruneTemplates doc for why.
//
// It mirrors internal/blocklist and internal/baseline -- a narrow Reader, a
// Config, a Runner.Run(ctx, now) error -- because it is the same shape of
// job: a periodic pass driven by a ticker in the owning binary (cmd/insightsd).
// Unlike those two, none of the three deletes here depends on another --
// there is no rollup that must run first, because the logs pipeline keeps no
// rollup table (see PruneAnalyses' doc for what that costs) -- so Run has no
// internal step order to document and no ordering to get wrong: each prune
// is independent, and a failure in one must not stop the others.
package maint

import (
	"context"
	"log/slog"
	"time"

	"github.com/nethesis/nethesis-insights/internal/platform/svc"
)

// Reader is the slice of logsstore.Store this pass needs. Declared here,
// like blocklist.Reader and baseline.Reader, so this package is testable
// with a fake and the layering stays a DAG. *logsstore.Store satisfies it.
type Reader interface {
	PruneTemplates(ctx context.Context, olderThan int64) (int, error)
	PruneFindings(ctx context.Context, olderThan int64) (int, error)
	PruneAnalyses(ctx context.Context, olderThan int64) (int, error)
}

// Config is the pass's three retention windows. Each is independently
// justified, in detail, next to its environment variable in
// cmd/insightsd/main.go; the short version:
//
//   - TemplateRetention must comfortably outlive the longest natural gap
//     between occurrences of a real recurring line, or a resurrected
//     template manufactures a new_templates gate firing -- and therefore an
//     LLM call -- for a line that was never actually new. Default 400 days:
//     past a full year, since an annual job (a New Year's cron, a yearly
//     license check) is exactly the kind of "longest gap" this needs to
//     survive, with margin over the quarterly-certificate-renewal case that
//     is the usual worst case named when this kind of retention is reviewed.
//   - FindingRetention only affects continuity (occurrence_count, whether a
//     recurrence reads as reopened or brand new) -- see PruneFindings' doc
//     for why that is a display cost, not a financial one, and so is allowed
//     a shorter default: 180 days.
//   - AnalysisRetention permanently truncates the operator UI's /cost and
//     /gate history, because there is no rollup table for this pipeline (see
//     PruneAnalyses' doc). Default 90 days: enough for a quarter of spend
//     trend; the days before that are gone for good once pruned.
type Config struct {
	TemplateRetention time.Duration
	FindingRetention  time.Duration
	AnalysisRetention time.Duration
}

// Runner performs one prune pass.
type Runner struct {
	store Reader
	cfg   Config
}

func New(r Reader, cfg Config) *Runner {
	return &Runner{store: r, cfg: cfg}
}

// Run prunes system_templates, findings and analyses independently against
// `now`. A failure pruning one table is logged and does not stop the
// others -- the same "housekeeping is logged, not fatal" treatment
// internal/blocklist and internal/baseline give their own rollup/prune
// steps, applied here to all three because pruning is this pass's entire
// job, not a secondary step protecting a published artifact that must not
// be blocked by it. Run therefore always returns nil; the error return
// exists only to satisfy the same `Run(ctx, now) error` shape blocklist.Runner
// and baseline.Runner have, for RunLoop below.
func (r *Runner) Run(ctx context.Context, now int64) error {
	templatesPruned := r.prune(ctx, "templates", r.store.PruneTemplates, now-r.cfg.TemplateRetention.Milliseconds())
	findingsPruned := r.prune(ctx, "findings", r.store.PruneFindings, now-r.cfg.FindingRetention.Milliseconds())
	analysesPruned := r.prune(ctx, "analyses", r.store.PruneAnalyses, now-r.cfg.AnalysisRetention.Milliseconds())

	slog.Info("log maintenance pass",
		"templates_pruned", templatesPruned,
		"findings_pruned", findingsPruned,
		"analyses_pruned", analysesPruned)
	return nil
}

// prune runs one table's bounded prune call, logging rather than returning
// any failure -- see Run's doc for why.
func (r *Runner) prune(ctx context.Context, table string, fn func(context.Context, int64) (int, error), olderThan int64) int {
	n, err := fn(ctx, olderThan)
	if err != nil {
		slog.Error("maint: prune failed", "table", table, "error", err)
		return 0
	}
	return n
}

// RunLoop runs the pass immediately and then every interval until ctx is
// cancelled -- immediately so a restart does not leave months of backlog
// unpruned until the first tick, the same reason blocklist's and baseline's
// loops run their first pass before waiting.
//
// This used to be a third byte-for-byte copy of the ticker loop threatd and
// sizingd each kept privately, unexported, in their own main.go: no package
// under internal/platform existed yet that every binary could import, so
// each pass loop's owner carried its own. internal/platform/svc now holds
// that loop (svc.RunPassLoop), so RunLoop is a thin wrapper over it: *Runner
// already satisfies svc.Pass, and there is nothing left for this method to
// do but supply the log line's name. cmd/insightsd/main.go is unaffected --
// it still just calls maintRunner.RunLoop(ctx, interval).
func (r *Runner) RunLoop(ctx context.Context, interval time.Duration) <-chan struct{} {
	return svc.RunPassLoop(ctx, "log maintenance", r, interval)
}
