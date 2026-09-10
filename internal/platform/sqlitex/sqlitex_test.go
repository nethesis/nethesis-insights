// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package sqlitex

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// The three pragmas are the whole reason this package exists: WAL so a
// reader never blocks the writer, busy_timeout so a contended write waits
// instead of failing, and MaxOpenConns(1) so "single writer" is structural
// rather than a convention each store has to remember.
func TestOpenAppliesTheRequiredPragmas(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()

	var mode string
	if err := db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatalf("journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want wal", mode)
	}

	var timeout int
	if err := db.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&timeout); err != nil {
		t.Fatalf("busy_timeout: %v", err)
	}
	if timeout != 5000 {
		t.Errorf("busy_timeout = %d, want 5000", timeout)
	}

	if got := db.DB.DB.Stats().MaxOpenConnections; got != 1 {
		t.Errorf("MaxOpenConnections = %d, want 1", got)
	}
}

// TestLockSerializesConcurrentWrites is the reason DB embeds a mutex at all:
// every store package in this repository holds it around a write so that,
// even though SetMaxOpenConns(1) already prevents SQLite from running two
// writes at once, a contended write blocks here in Go rather than surfacing
// as SQLITE_BUSY. Deleting the Lock/Unlock calls (or making them no-ops)
// would leave every existing test green, because none of them exercise
// concurrent writers.
//
// Full determinism is not achievable here: proving "Lock blocks a second
// caller" without a broken build inherently means proving a negative over
// some wall-clock window, which is what the two-phase test below does. This
// test instead uses two independent, timing-*insensitive* signals that a
// removed or no-op Lock/Unlock breaks reliably:
//
//  1. `go test -race` (this project's standard test invocation, per
//     CLAUDE.md's Commands section) turns concurrent, unsynchronized
//     increments of an ordinary int into a reported data race essentially
//     every run once enough goroutines/iterations are in flight -- the race
//     detector's instrumentation, not a timer, is what catches it.
//  2. Even without -race, an unsynchronized read-modify-write loses updates
//     under real concurrency (GOMAXPROCS > 1) with overwhelming probability
//     at this iteration count, so the final counter is wrong. It is not a
//     mathematical certainty without the race detector, which is why (1) is
//     the primary signal and this is corroborating.
func TestLockSerializesConcurrentWrites(t *testing.T) {
	db := &DB{}

	const goroutines = 50
	const perGoroutine = 400

	var counter int // deliberately not atomic -- that is what Lock/Unlock must protect.
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				db.Lock()
				counter++
				db.Unlock()
			}
		}()
	}
	wg.Wait()

	if want := goroutines * perGoroutine; counter != want {
		t.Fatalf("counter = %d, want %d -- Lock/Unlock did not serialize the increments", counter, want)
	}
}

// TestLockBlocksASecondCallerUntilUnlock is the direct, causal check that
// Lock actually excludes a concurrent caller: it proves a second Lock cannot
// return before Unlock is called, and does return once it is. The first
// assertion is timing-independent in the direction that matters (a broken,
// no-op Lock fails it virtually immediately, well inside the wait window);
// only the second half's positive wait is a bounded timeout, needed because
// "it eventually unblocks" cannot be observed instantaneously.
func TestLockBlocksASecondCallerUntilUnlock(t *testing.T) {
	db := &DB{}
	db.Lock()

	acquired := make(chan struct{})
	go func() {
		db.Lock()
		close(acquired)
	}()

	select {
	case <-acquired:
		t.Fatal("a second Lock returned while the first caller still held it -- Lock is not serializing")
	case <-time.After(200 * time.Millisecond):
		// Still blocked, as required.
	}

	db.Unlock()

	select {
	case <-acquired:
		// Unblocked after Unlock, as required.
	case <-time.After(5 * time.Second):
		t.Fatal("the second Lock never acquired after Unlock")
	}
}
