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

// RunPassLoop runs r immediately and then every interval until ctx is
// cancelled. A failed pass is logged and the loop continues: whatever it did
// not replace keeps being served, which is the designed degradation. name
// tags the log line, since a binary may run more than one pass.
func RunPassLoop(ctx context.Context, name string, r Pass, interval time.Duration) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if err := r.Run(ctx, time.Now().UnixMilli()); err != nil && ctx.Err() == nil {
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
