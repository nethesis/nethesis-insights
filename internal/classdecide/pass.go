// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package classdecide runs insightsd's automatic review pass. Security-tagged
// pending classes go to the customer in code, with no call; every other
// pending class is put to the Decisions API together with the written review
// rules and the most similar classes a person already decided, and the answer
// is applied only when its confidence reaches the configured minimum.
//
// The pass writes only through logsstore (RecordDecisionAsk,
// DeliverSecurityClass), which keeps the decision trail append-only. It never
// fails a pass because the API is unhappy: an outage ends the pass quietly and
// the class is asked again next time.
package classdecide

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/nethesis/nethesis-insights/internal/decide"
	"github.com/nethesis/nethesis-insights/internal/decisions"
	logsstore "github.com/nethesis/nethesis-insights/internal/store/logs"
)

// PassName is the pass's name in svc.RunPassLoop's log line and the `pass`
// metric label; one definition shared with cmd/insightsd.
const PassName = "class decision"

// Results lists every value Metrics.Result can receive, so a metric can be
// pre-initialised.
var Results = []string{"applied", "unsure", "failed", "late", "error", "security"}

// Store is the slice of logsstore.Store this pass needs.
type Store interface {
	PendingSecurityClasses(ctx context.Context) ([]string, error)
	DecisionCandidates(ctx context.Context, rulesVersion, model, embedModel string, limit int) ([]logsstore.DecisionCandidate, error)
	DecisionPrecedents(ctx context.Context, embedModel string) ([]decide.Candidate, error)
	RecordDecisionAsk(ctx context.Context, a logsstore.DecisionAsk) (string, error)
	DeliverSecurityClass(ctx context.Context, key string, now int64) (bool, error)
	CurrentEmbedModel(ctx context.Context) (string, error)
}

// Client is *decisions.Client.
type Client interface {
	Decide(ctx context.Context, body []byte) ([]byte, error)
}

// Metrics receives the pass's outcomes. A nil *Metrics, or a nil func, is a
// no-op.
type Metrics struct {
	Result func(result string)
	Cost   func(micros int64)
}

func (m *Metrics) result(r string) {
	if m != nil && m.Result != nil {
		m.Result(r)
	}
}

func (m *Metrics) cost(micros int64) {
	if m != nil && m.Cost != nil && micros != 0 {
		m.Cost(micros)
	}
}

// Config is the pass's settings.
type Config struct {
	Model         string
	MinConfidence float64
	Batch         int // classes asked per pass
	Prices        decide.Prices
	// Grouping is true when the embedding sidecar is configured: classes are
	// then asked only once embedded, with their nearest precedents. When
	// false the pass is zero-shot.
	Grouping bool
	Metrics  *Metrics
}

// Runner performs one decision pass.
type Runner struct {
	store  Store
	client Client
	cfg    Config
}

func New(s Store, c Client, cfg Config) *Runner {
	return &Runner{store: s, client: c, cfg: cfg}
}

// Run delivers pending security classes, then asks about up to Config.Batch
// others. An API outage or rejected credential ends the pass with nil and
// records nothing; store errors are returned.
func (r *Runner) Run(ctx context.Context, now int64) error {
	delivered, err := r.deliverSecurity(ctx, now)
	if err != nil {
		return err
	}

	embedModel := ""
	if r.cfg.Grouping {
		if embedModel, err = r.store.CurrentEmbedModel(ctx); err != nil {
			return err
		}
	}
	cands, err := r.store.DecisionCandidates(ctx, decide.RulesVersion, r.cfg.Model, embedModel, r.cfg.Batch)
	if err != nil {
		return err
	}
	var pool []decide.Candidate
	if len(cands) > 0 && r.cfg.Grouping {
		if pool, err = r.store.DecisionPrecedents(ctx, embedModel); err != nil {
			return err
		}
	}

	var applied, unsure, failed, late, waiting int
	for _, c := range cands {
		if ctx.Err() != nil {
			return nil
		}
		if r.cfg.Grouping && c.Vector == nil {
			waiting++ // not embedded yet; asked once it is
			continue
		}
		var precedents []decide.Precedent
		if r.cfg.Grouping {
			precedents = decide.Nearest(c.Vector, pool, decide.K)
			if len(precedents) == 0 {
				precedents = nil // zero-shot, not an empty precedents part
			}
		}
		body, err := decide.BuildRequest(r.cfg.Model, c.Class, precedents)
		if err != nil {
			return err
		}
		raw, err := r.client.Decide(ctx, body)
		ask := logsstore.DecisionAsk{Key: c.Key, RulesVersion: decide.RulesVersion, Model: r.cfg.Model, At: now}
		var reason error
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var se *decisions.StatusError
			if errors.As(err, &se) && !se.Fatal() && !se.Retryable() {
				ask.Result = logsstore.AskFailed
				reason = err
			} else {
				slog.Warn("decisions API unavailable, ending pass", "class_key", c.Key, "error", err)
				r.cfg.Metrics.result("error")
				break
			}
		} else {
			a, u, perr := decide.ParseResponse(raw)
			ask.Usage = u
			ask.CostMicros = r.cfg.Prices.CostMicros(u)
			switch {
			case perr != nil:
				ask.Result = logsstore.AskFailed
				reason = perr
			case a.Refused:
				ask.Result = logsstore.AskFailed
				reason = errors.New("refused")
			default:
				ask.Choice, ask.Confidence = a.Choice, a.Confidence
				ask.Result = logsstore.AskUnsure
				if a.Confidence >= r.cfg.MinConfidence {
					ask.Result = logsstore.AskApplied
				}
				ask.Detail = fmt.Sprintf("rules %s, %s, confidence %.2f", decide.RulesVersion, r.cfg.Model, a.Confidence)
			}
		}
		res, err := r.store.RecordDecisionAsk(ctx, ask)
		if err != nil {
			return err
		}
		r.cfg.Metrics.result(res)
		r.cfg.Metrics.cost(ask.CostMicros)
		switch res {
		case logsstore.AskApplied:
			applied++
		case logsstore.AskUnsure:
			unsure++
		case logsstore.AskLate:
			late++
		default:
			failed++
		}
		attrs := []any{"class_key", c.Key, "result", res, "choice", ask.Choice,
			"confidence", ask.Confidence, "cost_micros", ask.CostMicros}
		if reason != nil {
			attrs = append(attrs, "error", reason)
		}
		slog.Info("class decision", attrs...)
	}
	if delivered+applied+unsure+failed+late+waiting > 0 {
		slog.Info("class decision pass", "security", delivered, "applied", applied,
			"unsure", unsure, "failed", failed, "late", late, "waiting", waiting)
	}
	return nil
}

func (r *Runner) deliverSecurity(ctx context.Context, now int64) (int, error) {
	keys, err := r.store.PendingSecurityClasses(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, k := range keys {
		ok, err := r.store.DeliverSecurityClass(ctx, k, now)
		if err != nil {
			return n, err
		}
		if ok {
			n++
			r.cfg.Metrics.result("security")
			slog.Info("class decision", "class_key", k, "result", "security", "choice", "customer")
		}
	}
	return n, nil
}
