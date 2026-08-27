// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package queue decouples ingest from analysis. The HTTP handler answers as
// soon as a bundle is accepted onto an in-memory bounded channel, so an edge
// node never waits on an LLM call and never loses a window because its own
// client timeout fired first.
//
// This is the permanent design, not a stand-in for a durable broker: at this
// fleet's throughput a broker's durability was evaluated and rejected as not
// worth its operational cost (see the design spec, §3.1-§3.2). The accepted
// trade is that nothing here survives a process restart.
package queue

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/nethesis/nethesis-insights/internal/model"
)

// ErrFull is returned when the buffer is saturated. The caller must answer
// 503 so the edge retries the window later, rather than dropping it.
var ErrFull = errors.New("queue: full")

// Handler processes one bundle. It runs on a background context, never on the
// request context: a disconnected client must not abort an LLM call that has
// already been paid for.
type Handler func(ctx context.Context, b model.Bundle) error

// window identifies the unit of idempotency: (system_id, window_start), the
// same key the analyses table is unique on.
type window struct {
	systemID string
	start    int64
}

type Queue struct {
	ch      chan model.Bundle
	handler Handler
	timeout time.Duration
	wg      sync.WaitGroup

	// inflight holds the windows queued or being analyzed right now. The
	// store keeps a window claimable until it completes -- deliberately, so a
	// retry after a transient failure is not rejected as a duplicate -- which
	// means an edge that resends while an analysis is still running would
	// start a second LLM call for the same data. This set closes that gap for
	// the lifetime of the process.
	mu       sync.Mutex
	inflight map[window]bool
}

// New returns a queue holding at most size bundles. Each bundle gets at most
// timeout to be analyzed. Call Start to run the workers.
func New(size int, timeout time.Duration, h Handler) *Queue {
	if size < 1 {
		size = 1
	}
	return &Queue{
		ch:       make(chan model.Bundle, size),
		handler:  h,
		timeout:  timeout,
		inflight: map[window]bool{},
	}
}

// Publish accepts a bundle for later analysis, or reports ErrFull immediately.
// It never blocks: blocking here would reintroduce the coupling the queue
// exists to remove.
//
// Re-sending a window that is still queued or in flight is a successful
// no-op, not an error -- the edge did nothing wrong, and the analysis it is
// asking for is already happening.
func (q *Queue) Publish(b model.Bundle) error {
	w := window{systemID: b.SystemID, start: b.Window.Start}

	q.mu.Lock()
	if q.inflight[w] {
		q.mu.Unlock()
		slog.Info("duplicate window already in flight, not queued again",
			"system_id", b.SystemID, "window_start", b.Window.Start)
		return nil
	}
	q.inflight[w] = true
	q.mu.Unlock()

	select {
	case q.ch <- b:
		slog.Debug("bundle queued",
			"system_id", b.SystemID,
			"window_start", b.Window.Start,
			"templates", len(b.Templates),
			"queue_depth", len(q.ch),
			"queue_capacity", cap(q.ch),
		)
		return nil
	default:
		// Nothing was queued, so the claim must not outlive the attempt.
		q.release(w)
		slog.Warn("bundle rejected, queue full",
			"system_id", b.SystemID,
			"window_start", b.Window.Start,
			"queue_capacity", cap(q.ch),
		)
		return ErrFull
	}
}

func (q *Queue) release(w window) {
	q.mu.Lock()
	delete(q.inflight, w)
	q.mu.Unlock()
}

// Start launches the workers. Call Stop to drain and wait.
func (q *Queue) Start(workers int) {
	if workers < 1 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		q.wg.Add(1)
		go func(worker int) {
			defer q.wg.Done()
			for b := range q.ch {
				q.process(worker, b)
			}
		}(i)
	}
}

func (q *Queue) process(worker int, b model.Bundle) {
	start := time.Now()
	// Released only once the analysis is over: while it runs, a resend of the
	// same window must not start a second one. Afterwards the store's own
	// idempotency takes over.
	defer q.release(window{systemID: b.SystemID, start: b.Window.Start})

	ctx, cancel := context.WithTimeout(context.Background(), q.timeout)
	defer cancel()

	slog.Debug("analysis started",
		"worker", worker,
		"system_id", b.SystemID,
		"window_start", b.Window.Start,
		"queue_depth", len(q.ch),
	)

	if err := q.handler(ctx, b); err != nil {
		slog.Error("bundle processing failed",
			"system_id", b.SystemID,
			"window_start", b.Window.Start,
			"duration_ms", time.Since(start).Milliseconds(),
			"error", err,
		)
		return
	}

	slog.Info("bundle processed",
		"system_id", b.SystemID,
		"window_start", b.Window.Start,
		"duration_ms", time.Since(start).Milliseconds(),
	)
}

// Stop closes the queue and waits for in-flight bundles to finish. Bundles
// still buffered are processed first: they were already acknowledged to the
// edge, which will not send them again.
func (q *Queue) Stop() {
	close(q.ch)
	q.wg.Wait()
}

// Depth reports how many bundles are waiting. Exposed for logging and tests.
func (q *Queue) Depth() int { return len(q.ch) }
