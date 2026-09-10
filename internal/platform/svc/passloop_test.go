// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package svc

import (
	"context"
	"errors"
	"testing"
	"time"
)

type recordingPass struct {
	calls chan int64
	err   error
}

func (p *recordingPass) Run(_ context.Context, now int64) error {
	p.calls <- now
	return p.err
}

// RunPassLoop must run the pass immediately, not wait for the first tick --
// otherwise a restart leaves whatever the pass maintains stale until a full
// interval has elapsed. This is the property every caller (threatd's
// consensus pass, sizingd's cohort pass, insightsd's maintenance pass)
// depends on.
func TestRunPassLoopRunsImmediately(t *testing.T) {
	p := &recordingPass{calls: make(chan int64, 10)}
	ctx, cancel := context.WithCancel(context.Background())
	done := RunPassLoop(ctx, "test", p, time.Hour)

	select {
	case <-p.calls:
	case <-time.After(2 * time.Second):
		t.Fatal("Run was not called immediately")
	}

	cancel()
	<-done
}

// After the immediate run, RunPassLoop must keep firing on the ticker.
func TestRunPassLoopRunsOnTicker(t *testing.T) {
	p := &recordingPass{calls: make(chan int64, 10)}
	ctx, cancel := context.WithCancel(context.Background())
	done := RunPassLoop(ctx, "test", p, 10*time.Millisecond)

	<-p.calls // the immediate run
	select {
	case <-p.calls:
	case <-time.After(2 * time.Second):
		t.Fatal("Run was not called again on the ticker")
	}

	cancel()
	<-done
}

// Cancelling ctx must stop the loop: the done channel closes and the
// goroutine exits instead of running forever.
func TestRunPassLoopStopsOnCancel(t *testing.T) {
	p := &recordingPass{calls: make(chan int64, 10)}
	ctx, cancel := context.WithCancel(context.Background())
	done := RunPassLoop(ctx, "test", p, 5*time.Millisecond)
	<-p.calls // the immediate run

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunPassLoop did not stop after ctx was cancelled")
	}
}

// A failing pass must not stop the loop -- whatever it did not replace keeps
// being served, and the next tick tries again.
func TestRunPassLoopContinuesAfterError(t *testing.T) {
	p := &recordingPass{calls: make(chan int64, 10), err: errors.New("boom")}
	ctx, cancel := context.WithCancel(context.Background())
	done := RunPassLoop(ctx, "test", p, 5*time.Millisecond)

	<-p.calls // the immediate run, which fails
	select {
	case <-p.calls:
	case <-time.After(2 * time.Second):
		t.Fatal("the loop stopped retrying after a failed pass")
	}

	cancel()
	<-done
}
