// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package threat

import (
	"context"
	"sync"
	"time"

	threatstore "github.com/nethesis/nethesis-insights/internal/store/threat"
)

// statsCacheTTL bounds how often /stats re-scans threat_events.
// ThreatDailyStats is GROUP BY day, scenario with COUNT(DISTINCT
// attacker_ip) over every retained event, and SQLite's single connection
// (SetMaxOpenConns(1) plus the store's write mutex) means that scan holds
// the store's only connection for its duration -- repeated page loads (an
// operator hitting refresh, or several browsers open on the same dashboard)
// can otherwise stall ingest writes behind a read nobody strictly needed
// fresher than a few minutes ago.
const statsCacheTTL = 5 * time.Minute

// dailyStatsCache holds the last computed ThreatDailyStats result behind one
// mutex, held for the whole refresh rather than only for the swap. That is
// what makes a concurrent request arriving mid-refresh block and then read
// the just-finished result instead of starting a second scan of its own:
// there is no separate in-flight bookkeeping, because the lock already
// serializes it.
//
// A failed fetch is never cached: get returns the error as-is and leaves
// the last good rows and their timestamp in place, so a transient store
// hiccup does not pin the page in an error state for the rest of the TTL.
type dailyStatsCache struct {
	mu   sync.Mutex
	now  func() int64
	have bool
	at   int64
	rows []threatstore.ThreatDailyRow
}

// newDailyStatsCache builds an empty cache using now as its clock. now is
// injected (rather than calling time.Now directly) so a test can pin both
// "how old is the cache" and "what day is today" to the same instant.
func newDailyStatsCache(now func() int64) *dailyStatsCache {
	return &dailyStatsCache{now: now}
}

// get returns the cached rows, calling fetch first when the cache is empty
// or older than statsCacheTTL. It also returns when the returned rows were
// computed, for the page to say so.
func (c *dailyStatsCache) get(ctx context.Context, fetch func(context.Context) ([]threatstore.ThreatDailyRow, error)) ([]threatstore.ThreatDailyRow, int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.have && c.now()-c.at < statsCacheTTL.Milliseconds() {
		return c.rows, c.at, nil
	}

	rows, err := fetch(ctx)
	if err != nil {
		return nil, 0, err
	}
	c.rows, c.at, c.have = rows, c.now(), true
	return c.rows, c.at, nil
}
