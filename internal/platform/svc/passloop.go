// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package svc

import (
	"context"
	"log/slog"
	"time"
)

// Pass is a periodic background job: threatd's blocklist consensus,
// sizingd's cohort pass and insightsd's log-maintenance pass (via
// internal/maint.Runner) all satisfy it.
type Pass interface {
	Run(ctx context.Context, now int64) error
}

// PassRecorder observes one completed run of a Pass: its name (the same
// short string RunPassLoop already logs against -- a closed set of one per
// binary that runs a pass), whether it failed, how long it took and the
// clock value it ran with. Declared here, narrow, so this package needs no
// dependency on prometheus; *metrics.Pass satisfies it. A nil PassRecorder
// is valid and simply skips metrics.
type PassRecorder interface {
	Observe(pass string, err error, duration time.Duration, now int64)
}

// RunPassLoop runs r immediately and then every interval until ctx is
// cancelled. A failed pass is logged and the loop continues: whatever it did
// not replace keeps being served, which is the designed degradation. name
// tags the log line, since a binary may run more than one pass. rec, when
// non-nil, is fed the same outcome after every run.
func RunPassLoop(ctx context.Context, name string, r Pass, interval time.Duration, rec PassRecorder) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			runStart := time.Now()
			now := time.Now().UnixMilli()
			err := r.Run(ctx, now)
			if rec != nil {
				rec.Observe(name, err, time.Since(runStart), now)
			}
			if err != nil && ctx.Err() == nil {
				slog.Error("background pass failed", "pass", name, "error", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return done
}
