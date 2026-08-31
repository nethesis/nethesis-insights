// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package analyzer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"time"

	"github.com/nethesis/nethesis-insights/internal/fingerprint"
	"github.com/nethesis/nethesis-insights/internal/gate"
	"github.com/nethesis/nethesis-insights/internal/llm"
	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/prompt"
	"github.com/nethesis/nethesis-insights/internal/store"
)

// ErrPermanent marks failures that a retry cannot fix (e.g. a schema
// rejection from the LLM, or a non-retryable 4xx).
var ErrPermanent = errors.New("permanent failure")

type Config struct {
	Tolerance     float64
	StaleAfter    time.Duration
	EWMAAlpha     float64
	Model         string
	InputPerMTok  float64
	OutputPerMTok float64
}

type Analyzer struct {
	store store.Store
	llm   llm.Client
	cfg   Config
	now   func() int64
}

func New(s store.Store, c llm.Client, cfg Config, now func() int64) *Analyzer {
	return &Analyzer{store: s, llm: c, cfg: cfg, now: now}
}

// analysisEntry carries the fields record() needs to finalize an analysis
// row, independent of whether the bundle was gated out or fully processed.
type analysisEntry struct {
	windowStart  int64
	windowEnd    int64
	gated        bool
	gateReasons  []string
	llmCalled    bool
	inputTokens  int
	outputTokens int
	costMicros   int64
	model        string
	durationMs   int
	errMsg       string
}

// record persists the durable side effects of processing a bundle -- template
// and baseline bookkeeping plus the analysis row -- in a fixed order. It is
// the ONLY place templates are recorded, and it must only be called for a
// gated-out bundle or after a fully successful LLM analysis. If it ran
// earlier (e.g. before an LLM call), a failed call would make the retry see
// stale "known" templates and lose the anomaly permanently.
func (a *Analyzer) record(ctx context.Context, b model.Bundle, entry analysisEntry) error {
	now := a.now()

	if err := a.store.UpsertTemplates(ctx, b.SystemID, b.Templates, now); err != nil {
		return fmt.Errorf("analyzer: upsert templates: %w", err)
	}
	if err := a.store.UpsertBaselines(ctx, b.SystemID, b.Digest, a.cfg.EWMAAlpha); err != nil {
		return fmt.Errorf("analyzer: upsert baselines: %w", err)
	}
	if _, err := a.store.MarkStale(ctx, b.SystemID, now-a.cfg.StaleAfter.Milliseconds()); err != nil {
		return fmt.Errorf("analyzer: mark stale: %w", err)
	}

	if err := a.store.FinalizeAnalysis(ctx, store.Analysis{
		SystemID:     b.SystemID,
		WindowStart:  entry.windowStart,
		WindowEnd:    entry.windowEnd,
		Gated:        entry.gated,
		GateReasons:  entry.gateReasons,
		LLMCalled:    entry.llmCalled,
		InputTokens:  entry.inputTokens,
		OutputTokens: entry.outputTokens,
		CostMicros:   entry.costMicros,
		Model:        entry.model,
		DurationMs:   entry.durationMs,
		Error:        entry.errMsg,
	}); err != nil {
		return fmt.Errorf("analyzer: finalize analysis: %w", err)
	}

	return nil
}

func (a *Analyzer) Process(ctx context.Context, b model.Bundle) error {
	start := time.Now()
	now := a.now()

	// 1. Claim the window; a duplicate is a successful no-op (the edge
	// retried a bundle we already processed).
	fresh, err := a.store.BeginAnalysis(ctx, b.SystemID, b.Window.Start, b.Window.End, now)
	if err != nil {
		return fmt.Errorf("analyzer: begin analysis: %w", err)
	}
	if !fresh {
		slog.Info("duplicate window skipped", "system_id", b.SystemID, "window_start", b.Window.Start)
		return nil
	}

	// 2. Register the system.
	if err := a.store.UpsertSystem(ctx, store.System{
		SystemID:         b.SystemID,
		CollectorVersion: b.CollectorVersion,
		FirstSeen:        now,
		LastSeen:         now,
	}); err != nil {
		return fmt.Errorf("analyzer: upsert system: %w", err)
	}

	// 3. Read prior state BEFORE writing anything -- if templates were
	// recorded first, everything in this bundle would look known and the
	// gate would never fire.
	knownTemplates, err := a.store.KnownTemplates(ctx, b.SystemID)
	if err != nil {
		return fmt.Errorf("analyzer: known templates: %w", err)
	}
	baselines, err := a.store.Baselines(ctx, b.SystemID)
	if err != nil {
		return fmt.Errorf("analyzer: baselines: %w", err)
	}

	slog.Debug("prior state loaded",
		"system_id", b.SystemID,
		"known_templates", len(knownTemplates),
		"baselines", len(baselines),
		"bundle_templates", len(b.Templates),
		"bundle_digest_entries", len(b.Digest),
	)

	// 4. Decide whether this bundle is worth an LLM call.
	decision := gate.Evaluate(b, gate.SystemState{
		KnownTemplates: knownTemplates,
		Baselines:      baselines,
	}, a.cfg.Tolerance)

	slog.Debug("gate decision",
		"system_id", b.SystemID,
		"window_start", b.Window.Start,
		"call", decision.Call,
		"reasons", decision.Reasons,
		"tolerance", a.cfg.Tolerance,
	)

	// 5. Gated out: record bookkeeping, no LLM call.
	if !decision.Call {
		slog.Info("bundle gated out", "system_id", b.SystemID, "window_start", b.Window.Start)
		return a.record(ctx, b, analysisEntry{
			windowStart: b.Window.Start,
			windowEnd:   b.Window.End,
			gated:       true,
			gateReasons: decision.Reasons,
			durationMs:  int(time.Since(start).Milliseconds()),
		})
	}

	// 6. Call the LLM.
	open, err := a.store.OpenFindings(ctx, b.SystemID)
	if err != nil {
		return fmt.Errorf("analyzer: open findings: %w", err)
	}
	rendered := prompt.Render(b, open)

	slog.Debug("calling llm",
		"system_id", b.SystemID,
		"model", a.cfg.Model,
		"prompt_bytes", len(rendered),
		"open_findings", len(open),
	)

	llmStart := time.Now()
	resp, err := a.llm.Complete(ctx, llm.Request{Model: a.cfg.Model, UserPrompt: rendered})
	if err != nil {
		var httpErr *llm.HTTPError
		permanent := errors.As(err, &httpErr) && httpErr.Permanent()
		durationMs := int(time.Since(start).Milliseconds())

		// ctx.Err() separates "the provider failed" from "our own deadline or
		// shutdown cut the call short" -- the two look identical downstream.
		slog.Debug("llm call failed",
			"system_id", b.SystemID,
			"model", a.cfg.Model,
			"permanent", permanent,
			"llm_duration_ms", time.Since(llmStart).Milliseconds(),
			"ctx_err", ctx.Err(),
			"error", err.Error(),
		)

		if permanent {
			// The request itself is wrong and will fail identically forever.
			// Close the window so it is not retried into the same wall.
			if finalizeErr := a.store.FinalizeAnalysis(ctx, store.Analysis{
				SystemID:    b.SystemID,
				WindowStart: b.Window.Start,
				WindowEnd:   b.Window.End,
				GateReasons: decision.Reasons,
				LLMCalled:   true,
				Model:       a.cfg.Model,
				DurationMs:  durationMs,
				Error:       err.Error(),
			}); finalizeErr != nil {
				slog.Error("finalize analysis after permanent llm error failed", "error", finalizeErr)
			}
			return fmt.Errorf("analyzer: llm call: %w: %w", ErrPermanent, err)
		}

		// Transient: record the attempt but leave the window claimable, or
		// the edge's retry is rejected as a duplicate and the window is lost.
		if recErr := a.store.RecordAttemptError(ctx, b.SystemID, b.Window.Start,
			decision.Reasons, durationMs, err.Error()); recErr != nil {
			slog.Error("recording failed llm attempt failed", "error", recErr)
		}
		return fmt.Errorf("analyzer: llm call: %w", err)
	}

	slog.Debug("llm responded",
		"system_id", b.SystemID,
		"model", resp.Model,
		"llm_duration_ms", time.Since(llmStart).Milliseconds(),
		"input_tokens", resp.InputTokens,
		"output_tokens", resp.OutputTokens,
		"content_bytes", len(resp.Content),
	)

	// 7. Parse the response.
	parsed, _, err := prompt.Parse(resp.Content)
	if err != nil {
		finalizeErr := a.store.FinalizeAnalysis(ctx, store.Analysis{
			SystemID:     b.SystemID,
			WindowStart:  b.Window.Start,
			WindowEnd:    b.Window.End,
			Gated:        false,
			GateReasons:  decision.Reasons,
			LLMCalled:    true,
			InputTokens:  resp.InputTokens,
			OutputTokens: resp.OutputTokens,
			Model:        a.cfg.Model,
			DurationMs:   int(time.Since(start).Milliseconds()),
			Error:        err.Error(),
		})
		if finalizeErr != nil {
			slog.Error("finalize analysis after parse error failed", "error", finalizeErr)
		}
		slog.Debug("llm response rejected",
			"system_id", b.SystemID, "content_bytes", len(resp.Content), "error", err.Error())
		return fmt.Errorf("analyzer: parse response: %w: %w", ErrPermanent, err)
	}

	slog.Debug("response parsed", "system_id", b.SystemID, "findings", len(parsed))

	// 8. Persist each finding, deduplicated by fingerprint.
	for _, pf := range parsed {
		// The model cites template identifiers; the server resolves them.
		// Evidence text, module set and category are all derived here, so no
		// model-authored string can reach the fingerprint.
		cited, resolveErr := prompt.ResolveEvidence(b, pf.Evidence)
		if resolveErr != nil {
			slog.Warn("analyzer: discarding finding with unresolvable evidence",
				"system_id", b.SystemID, "title", pf.Title, "error", resolveErr)
			continue
		}

		category := ""
		evidence := make([]string, 0, len(cited))
		moduleSet := map[string]bool{}
		for _, t := range cited {
			evidence = append(evidence, t.Template)
			moduleSet[t.ModuleID] = true
			if t.Category == "security" {
				category = "security"
			}
		}
		modules := make([]string, 0, len(moduleSet))
		for m := range moduleSet {
			modules = append(modules, m)
		}
		sort.Strings(modules)

		// Identity hashes a single derived key, not the cited set: the model
		// picks which templates to cite, and letting that choice reach the
		// hash made the same condition a new finding every window. The full
		// cited list is still stored on the row -- it is what the operator
		// reads -- it just does not decide identity.
		fp := fingerprint.Compute(b.SystemID, modules, fingerprint.EvidenceKey(cited), category)

		outcome, err := a.store.UpsertFinding(ctx, model.Finding{
			SystemID:        b.SystemID,
			Fingerprint:     fp,
			Severity:        pf.Severity,
			Title:           pf.Title,
			Summary:         pf.Summary,
			SuggestedAction: pf.SuggestedAction,
			Modules:         modules,
			Evidence:        evidence,
			LLMModel:        resp.Model,
			PromptVersion:   prompt.Version,
		}, now)
		if err != nil {
			return fmt.Errorf("analyzer: upsert finding: %w", err)
		}
		if outcome != store.OutcomeBumped {
			slog.Info("finding outcome", "system_id", b.SystemID, "fingerprint", fp, "outcome", outcome)
		}
	}

	// 9. Record bookkeeping now that the analysis fully succeeded.
	costMicros := int64(math.Round(((float64(resp.InputTokens)/1e6)*a.cfg.InputPerMTok + (float64(resp.OutputTokens)/1e6)*a.cfg.OutputPerMTok) * 1e6))

	return a.record(ctx, b, analysisEntry{
		windowStart:  b.Window.Start,
		windowEnd:    b.Window.End,
		gated:        false,
		gateReasons:  decision.Reasons,
		llmCalled:    true,
		inputTokens:  resp.InputTokens,
		outputTokens: resp.OutputTokens,
		costMicros:   costMicros,
		model:        resp.Model,
		durationMs:   int(time.Since(start).Milliseconds()),
	})
}
