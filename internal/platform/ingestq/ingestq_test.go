// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package ingestq

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// The bound is the point: past capacity Publish must fail immediately rather
// than block, so a burst sheds load at the edge instead of growing the
// server until it dies.
//
// Publishing item 0 and then waiting on started -- signaled from inside the
// handler, so it only fires once the worker has actually pulled item 0 off
// the channel -- is what makes the rest of this test deterministic. Start
// returning is not that signal: it only proves the worker goroutines exist,
// not that one of them has reached its first channel receive, so publishing
// all three items immediately after Start raced item 0 against items 1 and 2
// for a buffer slot and failed the vast majority of the time under
// GOMAXPROCS>1 (see the fix for this test in the task-11 follow-up report).
func TestPublishRefusesWhenFull(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	q := New(2, time.Second, func(ctx context.Context, n int) error {
		if n == 0 {
			started <- struct{}{}
		}
		<-release
		return nil
	})
	q.Start(1)
	defer func() { close(release); q.Stop() }()

	if err := q.Publish(0); err != nil {
		t.Fatalf("Publish(0) = %v, want nil", err)
	}
	<-started // item 0 is now claimed by the worker and blocking on release.

	// Two more fill the buffer.
	for i := 1; i < 3; i++ {
		if err := q.Publish(i); err != nil {
			t.Fatalf("Publish(%d) = %v, want nil", i, err)
		}
	}
	waitFor(t, func() bool { return q.Depth() == 2 })

	if err := q.Publish(99); !errors.Is(err, ErrFull) {
		t.Fatalf("Publish past capacity = %v, want ErrFull", err)
	}
}

// Every accepted item must reach the handler exactly once, from any worker.
func TestEveryPublishedItemIsHandledOnce(t *testing.T) {
	const items = 200

	var mu sync.Mutex
	seen := map[int]int{}
	done := make(chan struct{})

	q := New(items, time.Second, func(ctx context.Context, n int) error {
		mu.Lock()
		seen[n]++
		if len(seen) == items {
			close(done)
		}
		mu.Unlock()
		return nil
	})
	q.Start(4)
	defer q.Stop()

	for i := 0; i < items; i++ {
		if err := q.Publish(i); err != nil {
			t.Fatalf("Publish(%d): %v", i, err)
		}
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not see every item")
	}

	mu.Lock()
	defer mu.Unlock()
	for i := 0; i < items; i++ {
		if seen[i] != 1 {
			t.Errorf("item %d handled %d times, want 1", i, seen[i])
		}
	}
}

// Stop must drain what was accepted. An item the server answered 202 for and
// then dropped at shutdown is worse than one it refused with a 503.
func TestStopDrainsAcceptedItems(t *testing.T) {
	var mu sync.Mutex
	var handled int

	q := New(16, time.Second, func(ctx context.Context, n int) error {
		time.Sleep(5 * time.Millisecond)
		mu.Lock()
		handled++
		mu.Unlock()
		return nil
	})
	q.Start(2)

	for i := 0; i < 16; i++ {
		if err := q.Publish(i); err != nil {
			t.Fatalf("Publish(%d): %v", i, err)
		}
	}
	q.Stop()

	mu.Lock()
	defer mu.Unlock()
	if handled != 16 {
		t.Errorf("handled %d items after Stop, want 16", handled)
	}
}

// A handler that fails or panics must not take the worker down with it:
// one bad report cannot stop every later report from being stored.
func TestAFailingHandlerDoesNotKillTheWorker(t *testing.T) {
	var mu sync.Mutex
	var handled int
	done := make(chan struct{})

	q := New(8, time.Second, func(ctx context.Context, n int) error {
		mu.Lock()
		handled++
		if handled == 3 {
			close(done)
		}
		mu.Unlock()
		switch n {
		case 0:
			return errors.New("boom")
		case 1:
			panic("worse")
		}
		return nil
	})
	q.Start(1)
	defer q.Stop()

	for i := 0; i < 3; i++ {
		if err := q.Publish(i); err != nil {
			t.Fatalf("Publish(%d): %v", i, err)
		}
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the worker died on a failing handler")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met within the deadline")
}
