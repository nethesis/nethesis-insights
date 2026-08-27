// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package queue

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nethesis/nethesis-insights/internal/model"
)

func bundle(systemID string, windowStart int64) model.Bundle {
	return model.Bundle{
		SystemID: systemID,
		Window:   model.Window{Start: windowStart, End: windowStart + 1},
	}
}

func TestPublishDoesNotWaitForTheHandler(t *testing.T) {
	release := make(chan struct{})
	done := make(chan struct{})

	q := New(4, time.Minute, func(ctx context.Context, b model.Bundle) error {
		<-release
		close(done)
		return nil
	})
	q.Start(1)

	// Publish must return while the handler is still blocked, otherwise the
	// HTTP handler would again be waiting on the LLM.
	publishReturned := make(chan struct{})
	go func() {
		if err := q.Publish(bundle("s1", 1)); err != nil {
			t.Errorf("publish: %v", err)
		}
		close(publishReturned)
	}()

	select {
	case <-publishReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on the handler")
	}

	close(release)
	<-done
	q.Stop()
}

func TestPublishReportsFullInsteadOfBlocking(t *testing.T) {
	// No workers started: nothing drains the buffer.
	q := New(2, time.Minute, func(ctx context.Context, b model.Bundle) error { return nil })

	if err := q.Publish(bundle("s1", 1)); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	if err := q.Publish(bundle("s1", 2)); err != nil {
		t.Fatalf("second publish: %v", err)
	}
	if err := q.Publish(bundle("s1", 3)); !errors.Is(err, ErrFull) {
		t.Fatalf("third publish: got %v, want ErrFull", err)
	}
	if got := q.Depth(); got != 2 {
		t.Fatalf("depth: got %d, want 2", got)
	}
}

func TestStopDrainsAcknowledgedBundles(t *testing.T) {
	var mu sync.Mutex
	var seen []int64

	q := New(8, time.Minute, func(ctx context.Context, b model.Bundle) error {
		mu.Lock()
		seen = append(seen, b.Window.Start)
		mu.Unlock()
		return nil
	})

	for i := int64(1); i <= 5; i++ {
		if err := q.Publish(bundle("s1", i)); err != nil {
			t.Fatalf("publish %d: %v", i, err)
		}
	}
	q.Start(2)
	q.Stop()

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 5 {
		t.Fatalf("processed %d bundles, want 5 -- an accepted bundle was dropped", len(seen))
	}
}

// An edge that resends a window while its analysis is still running must not
// buy a second LLM call for the same data.
func TestDuplicateWindowInFlightIsNotAnalyzedTwice(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	release := make(chan struct{})
	started := make(chan struct{})

	q := New(8, time.Minute, func(ctx context.Context, b model.Bundle) error {
		mu.Lock()
		calls++
		if calls == 1 {
			close(started)
		}
		mu.Unlock()
		<-release
		return nil
	})
	q.Start(2)

	if err := q.Publish(bundle("s1", 100)); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	<-started

	// Same window, analysis still running: accepted, but not queued again.
	if err := q.Publish(bundle("s1", 100)); err != nil {
		t.Fatalf("resend must be a successful no-op, got %v", err)
	}
	// A different window of the same system is unrelated work.
	if err := q.Publish(bundle("s1", 200)); err != nil {
		t.Fatalf("other window: %v", err)
	}
	// So is the same window on another system.
	if err := q.Publish(bundle("s2", 100)); err != nil {
		t.Fatalf("other system: %v", err)
	}

	close(release)
	q.Stop()

	mu.Lock()
	defer mu.Unlock()
	if calls != 3 {
		t.Fatalf("handler ran %d times, want 3 (the resent window must not run twice)", calls)
	}
}

// Once the analysis is done the window is claimable again: a later resend is
// the store's duplicate-window case, not the queue's.
//
// The claim is released in a defer that runs *after* the handler returns, so
// the handler signalling its own entry is not a barrier past the release.
// With exactly one worker, a sentinel window on a different key cannot begin
// until process() for the first window has fully returned -- which is
// precisely when the claim was dropped. Waiting for the sentinel is therefore
// a deterministic barrier, with no sleep and no retry loop.
func TestWindowIsClaimableAgainAfterTheAnalysisFinishes(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	done := make(chan struct{}, 3)

	q := New(4, time.Minute, func(ctx context.Context, b model.Bundle) error {
		mu.Lock()
		seen = append(seen, fmt.Sprintf("%s/%d", b.SystemID, b.Window.Start))
		mu.Unlock()
		done <- struct{}{}
		return nil
	})
	q.Start(1)

	publishAndWait := func(what string, b model.Bundle) {
		t.Helper()
		if err := q.Publish(b); err != nil {
			t.Fatalf("publish %s: %v", what, err)
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s never ran -- the window stayed claimed after completion", what)
		}
	}

	publishAndWait("the first analysis", bundle("s1", 100))
	publishAndWait("the barrier window", bundle("s2", 999))
	publishAndWait("the resend after completion", bundle("s1", 100))

	q.Stop()

	mu.Lock()
	defer mu.Unlock()
	want := []string{"s1/100", "s2/999", "s1/100"}
	if !slices.Equal(seen, want) {
		t.Fatalf("handler saw %v, want %v", seen, want)
	}
}

// A full queue must not leave the window claimed: nothing was accepted, so a
// retry has to be able to get in.
func TestRejectedBundleDoesNotStayClaimed(t *testing.T) {
	q := New(1, time.Minute, func(ctx context.Context, b model.Bundle) error { return nil })

	if err := q.Publish(bundle("s1", 100)); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	if err := q.Publish(bundle("s1", 200)); !errors.Is(err, ErrFull) {
		t.Fatalf("second publish: got %v, want ErrFull", err)
	}

	// Drain one slot, then the rejected window must be publishable.
	<-q.ch
	if err := q.Publish(bundle("s1", 200)); err != nil {
		t.Fatalf("retry after ErrFull: got %v, want it accepted", err)
	}
}

func TestHandlerRunsOnABackgroundContextWithTimeout(t *testing.T) {
	deadlines := make(chan time.Time, 1)

	q := New(1, 50*time.Millisecond, func(ctx context.Context, b model.Bundle) error {
		dl, ok := ctx.Deadline()
		if !ok {
			t.Error("handler context has no deadline")
		}
		deadlines <- dl
		<-ctx.Done()
		return ctx.Err()
	})
	q.Start(1)

	if err := q.Publish(bundle("s1", 1)); err != nil {
		t.Fatalf("publish: %v", err)
	}

	select {
	case <-deadlines:
	case <-time.After(2 * time.Second):
		t.Fatal("handler never ran")
	}
	q.Stop()
}
