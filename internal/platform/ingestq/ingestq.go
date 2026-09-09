// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package ingestq is a generic bounded work queue for HTTP ingest handlers
// that write to a single-writer database.
//
// It does not introduce single-writer semantics: SQLite's SetMaxOpenConns(1)
// plus the store's write mutex already serialize every write, and a report's
// insert already runs as one transaction. What this package adds is a
// bound. Without it, a burst of reporters produces one blocked goroutine per
// in-flight request, each holding a decoded payload, all queued on the
// mutex with no limit and no way to shed load -- the server degrades by
// growing until something dies. A bounded channel with a fixed consumer
// count turns that into a queue depth an operator can see and a fast 503 the
// caller retries, the same trade internal/queue makes for bundles.
//
// internal/queue is deliberately not refactored onto this package: it
// carries a (system_id, window_start) in-flight claim that makes bundle
// redelivery idempotent, which this package neither has nor needs, and
// rewriting that working, load-bearing code for symmetry would buy nothing.
package ingestq

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ErrFull is returned when the buffer is saturated. The caller must answer
// 503 so the client retries later, rather than dropping the item silently.
var ErrFull = errors.New("ingestq: full")

// Handler processes one item. It runs on a background context, never on the
// request context: a disconnected client must not abort work that has
// already been accepted and, in the threat-events case, already sanitized.
type Handler[T any] func(ctx context.Context, item T) error

// Queue is a bounded channel of T with a fixed pool of worker goroutines.
// The zero value is not usable; construct one with New.
type Queue[T any] struct {
	ch      chan T
	handler Handler[T]
	timeout time.Duration
	wg      sync.WaitGroup

	// workers records what Start was called with, for an operator UI's queue
	// status row -- it never changes after Start, so reading it concurrently
	// with Depth/Cap needs no lock, the same as those two.
	workers int
}

// New returns a queue holding at most size items. Each item gets at most
// timeout to be handled. Call Start to run the workers.
func New[T any](size int, timeout time.Duration, h Handler[T]) *Queue[T] {
	if size < 1 {
		size = 1
	}
	return &Queue[T]{
		ch:      make(chan T, size),
		handler: h,
		timeout: timeout,
	}
}

// Publish accepts an item for later handling, or reports ErrFull immediately.
// It never blocks: blocking here would reintroduce the coupling the queue
// exists to remove.
func (q *Queue[T]) Publish(item T) error {
	select {
	case q.ch <- item:
		return nil
	default:
		return ErrFull
	}
}

// Start launches the workers. Call Stop to drain and wait.
func (q *Queue[T]) Start(workers int) {
	if workers < 1 {
		workers = 1
	}
	q.workers = workers
	for i := 0; i < workers; i++ {
		q.wg.Add(1)
		go func(worker int) {
			defer q.wg.Done()
			for item := range q.ch {
				q.process(worker, item)
			}
		}(i)
	}
}

// process handles one item with its own timeout and recovers a panicking
// handler: one malformed item must not take a worker -- and with it every
// later item queued behind it -- down.
func (q *Queue[T]) process(worker int, item T) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("ingestq: handler panicked, item dropped",
				"worker", worker, "panic", fmt.Sprint(r))
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), q.timeout)
	defer cancel()

	if err := q.handler(ctx, item); err != nil {
		slog.Error("ingestq: handler failed, item dropped", "worker", worker, "error", err)
	}
}

// Stop closes the queue and waits for accepted items to finish. Items still
// buffered are processed first: they were already acknowledged to the
// caller, which will not send them again.
func (q *Queue[T]) Stop() {
	close(q.ch)
	q.wg.Wait()
}

// Depth reports how many items are waiting. Exposed for logging and tests.
func (q *Queue[T]) Depth() int { return len(q.ch) }

// Cap reports the configured buffer size -- how many items can be waiting,
// not how many can be in flight at once. A busy queue can hold up to
// Cap()+Workers() items simultaneously accepted: one per worker already
// received off the channel and being handled, plus up to Cap() still
// buffered. Exposed for logging and tests.
func (q *Queue[T]) Cap() int { return cap(q.ch) }

// Workers reports how many worker goroutines Start launched. Exposed for an
// operator UI's queue status row.
func (q *Queue[T]) Workers() int { return q.workers }
