// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package metrics

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

// FeedRequests is threatd's feed_requests_total{feed,code}: every answer a
// blocklist feed handler gave, by feed and HTTP status. The feed names and
// the status codes the handler can answer are passed in, never restated
// here, and every combination is pre-created at 0.
type FeedRequests struct {
	counter *prometheus.CounterVec
}

// NewFeedRequests builds and registers the counter into reg.
func NewFeedRequests(reg *Registry, feeds []string, codes []int) *FeedRequests {
	f := &FeedRequests{counter: prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "feed_requests_total",
		Help: "Blocklist feed requests, by feed (full: /v1/feed, basic: /v1/basic-feed) and HTTP status code.",
	}, []string{"feed", "code"})}
	reg.prefixed.MustRegister(f.counter)
	for _, feed := range feeds {
		for _, code := range codes {
			f.counter.WithLabelValues(feed, strconv.Itoa(code))
		}
	}
	return f
}

// Inc records one answer.
func (f *FeedRequests) Inc(feed string, code int) {
	f.counter.WithLabelValues(feed, strconv.Itoa(code)).Inc()
}
