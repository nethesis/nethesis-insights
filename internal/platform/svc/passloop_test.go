// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package svc

import (
	"context"
	"errors"
	"sync"
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
	done := RunPassLoop(ctx, "test", p, time.Hour, nil)

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
	done := RunPassLoop(ctx, "test", p, 10*time.Millisecond, nil)

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
	done := RunPassLoop(ctx, "test", p, 5*time.Millisecond, nil)
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
	done := RunPassLoop(ctx, "test", p, 5*time.Millisecond, nil)

	<-p.calls // the immediate run, which fails
	select {
	case <-p.calls:
	case <-time.After(2 * time.Second):
		t.Fatal("the loop stopped retrying after a failed pass")
	}

	cancel()
	<-done
}

// recordingRecorder is a PassRecorder that remembers its last observation,
// so a test can assert what RunPassLoop fed it without a real prometheus
// registry.
type recordingRecorder struct {
	mu    sync.Mutex
	calls int
	name  string
	err   error
}

func (r *recordingRecorder) Observe(pass string, err error, _ time.Duration, _ int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.name = pass
	r.err = err
}

func (r *recordingRecorder) snapshot() (calls int, name string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls, r.name, r.err
}

// A non-nil PassRecorder must be fed the outcome of every run, tagged with
// the pass's name and whether it failed.
func TestRunPassLoopFeedsTheRecorderOnSuccessAndFailure(t *testing.T) {
	okPass := &recordingPass{calls: make(chan int64, 10)}
	rec := &recordingRecorder{}
	ctx, cancel := context.WithCancel(context.Background())
	done := RunPassLoop(ctx, "ok pass", okPass, time.Hour, rec)
	<-okPass.calls
	cancel()
	<-done

	calls, name, err := rec.snapshot()
	if calls != 1 || name != "ok pass" || err != nil {
		t.Fatalf("got calls=%d name=%q err=%v, want 1 \"ok pass\" <nil>", calls, name, err)
	}

	failPass := &recordingPass{calls: make(chan int64, 10), err: errors.New("boom")}
	rec2 := &recordingRecorder{}
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := RunPassLoop(ctx2, "failing pass", failPass, time.Hour, rec2)
	<-failPass.calls
	cancel2()
	<-done2

	calls2, name2, err2 := rec2.snapshot()
	if calls2 != 1 || name2 != "failing pass" || err2 == nil {
		t.Fatalf("got calls=%d name=%q err=%v, want 1 \"failing pass\" a non-nil error", calls2, name2, err2)
	}
}
