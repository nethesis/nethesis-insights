// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package queue decouples ingest from analysis. The HTTP handler answers as
// soon as a bundle is durable enough to be accepted -- here, buffered in
// memory -- so an edge node never waits on an LLM call and never loses a
// window because its own client timeout fired first.
//
// This is the prototype stand-in for the Redpanda `bundles` topic of the
// design (Task 11+). The interface is deliberately the subset that survives
// that swap: Publish returns "accepted" or "rejected", never a result.
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

type Queue struct {
	ch      chan model.Bundle
	handler Handler
	timeout time.Duration
	wg      sync.WaitGroup
}

// New returns a queue holding at most size bundles. Each bundle gets at most
// timeout to be analyzed. Call Start to run the workers.
func New(size int, timeout time.Duration, h Handler) *Queue {
	if size < 1 {
		size = 1
	}
	return &Queue{
		ch:      make(chan model.Bundle, size),
		handler: h,
		timeout: timeout,
	}
}

// Publish accepts a bundle for later analysis, or reports ErrFull immediately.
// It never blocks: blocking here would reintroduce the coupling the queue
// exists to remove.
func (q *Queue) Publish(b model.Bundle) error {
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
		slog.Warn("bundle rejected, queue full",
			"system_id", b.SystemID,
			"window_start", b.Window.Start,
			"queue_capacity", cap(q.ch),
		)
		return ErrFull
	}
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
