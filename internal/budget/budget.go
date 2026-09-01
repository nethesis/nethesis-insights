// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package budget is the ceiling under LLM spend.
//
// The gate (internal/gate) decides whether one window is worth a call. That is
// a per-window judgement, and it cannot answer the fleet-level question: what
// is the most this can cost if the judgement is wrong, or if every node's
// templates go novel in the same window because a collector upgrade changed
// the masking rules. Measured on the dev fleet before this existed, three real
// nodes fired the gate on 9 windows out of 9, which extrapolates to ~$13,200 a
// month at 2700 systems -- the same number as not gating at all.
//
// Three limits, each answering a different failure:
//
//   - MaxConcurrency bounds how many calls are in flight, so a correlated
//     novelty event queues instead of arriving at the provider at once.
//   - MaxCallsPerSystemPerDay bounds one system, so a node whose logs are
//     pathological cannot spend the fleet's budget by itself. This is the
//     limit that turns cost into arithmetic.
//   - DailySpendCapUSD bounds the fleet. On breach the gate degrades to
//     security-only rather than stopping: a spend cap that blinds the system
//     to a break-in is worse than the invoice.
package budget

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// Reader is the slice of the cost ledger this package needs. The ledger is the
// analyses table: every call already records what it cost, so no new
// bookkeeping is introduced here.
type Reader interface {
	DailySpendMicros(ctx context.Context, since int64) (int64, error)
	SystemCallsSince(ctx context.Context, systemID string, since int64) (int, error)
}

type Config struct {
	// MaxConcurrency is the number of LLM calls allowed in flight. Zero means
	// unlimited.
	MaxConcurrency int

	// MaxCallsPerSystemPerDay caps one system's calls per UTC day. Zero means
	// unlimited.
	MaxCallsPerSystemPerDay int

	// DailySpendCapUSD degrades the gate to security-only once the fleet's
	// spend for the UTC day crosses it. Zero means unlimited.
	DailySpendCapUSD float64
}

// Verdict is what the analyzer does with a window.
type Verdict struct {
	// Suppressed names the limit that stopped this window, or "" if none did.
	// It is stored on the analyses row so an operator can tell a window nobody
	// wanted from a window nobody could afford.
	Suppressed string

	// SecurityOnly narrows the gate to novel or surging security templates.
	SecurityOnly bool
}

const (
	SuppressedSystemCap = "system_call_cap"
	ReasonSpendCap      = "daily_spend_cap"
)

type Controller struct {
	reader Reader
	cfg    Config
	now    func() int64
	sem    chan struct{}
}

func New(r Reader, cfg Config, now func() int64) *Controller {
	c := &Controller{reader: r, cfg: cfg, now: now}
	if cfg.MaxConcurrency > 0 {
		c.sem = make(chan struct{}, cfg.MaxConcurrency)
	}
	return c
}

// Check reports what the budget allows for this system right now.
//
// Both limits are counted off the ledger for the current UTC day rather than
// from an in-process counter, so a restart does not reset them -- a crash loop
// would otherwise be a way to spend without limit.
func (c *Controller) Check(ctx context.Context, systemID string) (Verdict, error) {
	var v Verdict
	dayStart := startOfUTCDay(c.now())

	if c.cfg.MaxCallsPerSystemPerDay > 0 {
		calls, err := c.reader.SystemCallsSince(ctx, systemID, dayStart)
		if err != nil {
			return v, fmt.Errorf("budget: system calls: %w", err)
		}
		if calls >= c.cfg.MaxCallsPerSystemPerDay {
			slog.Warn("system daily call cap reached",
				"system_id", systemID, "calls", calls, "cap", c.cfg.MaxCallsPerSystemPerDay)
			v.Suppressed = SuppressedSystemCap
			return v, nil
		}
	}

	if c.cfg.DailySpendCapUSD > 0 {
		spent, err := c.reader.DailySpendMicros(ctx, dayStart)
		if err != nil {
			return v, fmt.Errorf("budget: daily spend: %w", err)
		}
		if float64(spent)/1e6 >= c.cfg.DailySpendCapUSD {
			slog.Warn("daily spend cap reached, gate degraded to security only",
				"spent_usd", float64(spent)/1e6, "cap_usd", c.cfg.DailySpendCapUSD)
			v.SecurityOnly = true
		}
	}

	return v, nil
}

// Acquire blocks until a call slot is free. The returned function releases it
// and must always be called.
func (c *Controller) Acquire(ctx context.Context) (func(), error) {
	if c.sem == nil {
		return func() {}, nil
	}
	select {
	case c.sem <- struct{}{}:
		return func() { <-c.sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// startOfUTCDay returns midnight UTC of the day containing ms.
func startOfUTCDay(ms int64) int64 {
	t := time.UnixMilli(ms).UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC).UnixMilli()
}
