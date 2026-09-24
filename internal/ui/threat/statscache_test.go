// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package threat

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	threatstore "github.com/nethesis/nethesis-insights/internal/store/threat"
	"github.com/nethesis/nethesis-insights/internal/ui/chrome"
)

// TestStatsCacheDoesNotCacheAFailedFetch pins the unit-level half of the
// cache's error behavior: a store hiccup must not pin the page in an error
// state for the rest of the TTL, so a failed fetch leaves nothing cached and
// the very next call tries again.
func TestStatsCacheDoesNotCacheAFailedFetch(t *testing.T) {
	c := newDailyStatsCache(func() int64 { return 1000 })
	boom := errors.New("store unavailable")
	var calls int
	failing := func(context.Context) ([]threatstore.ThreatDailyRow, error) {
		calls++
		return nil, boom
	}

	if _, _, err := c.get(context.Background(), failing); !errors.Is(err, boom) {
		t.Fatalf("get: got %v, want %v", err, boom)
	}
	if _, _, err := c.get(context.Background(), failing); !errors.Is(err, boom) {
		t.Fatalf("second get: got %v, want %v", err, boom)
	}
	if calls != 2 {
		t.Fatalf("failing fetch called %d times, want 2 (a failure must not be cached)", calls)
	}
}

// Two /stats loads inside the TTL must hit the reader once; a load after the
// TTL must hit it again. That is the whole point of the cache: GROUP BY day,
// scenario over every retained event holds the store's only connection
// (SetMaxOpenConns(1)) for its duration, and repeated page loads must not
// each pay for a fresh scan.
func TestStatsPageCachesDailyTotalsForTheTTL(t *testing.T) {
	now := testNow
	clock := func() int64 { return now }
	r := threatReader()
	h, err := NewServer(r, nil, nil, nil, chrome.Config{Info: testInfo()}, testRetention, clock)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	get(t, h, "/stats")
	get(t, h, "/stats")
	if calls := atomic.LoadInt32(&r.threatDailyCalls); calls != 1 {
		t.Fatalf("ThreatDailyStats called %d times inside the TTL, want 1", calls)
	}

	now += statsCacheTTL.Milliseconds() + 1
	get(t, h, "/stats")
	if calls := atomic.LoadInt32(&r.threatDailyCalls); calls != 2 {
		t.Fatalf("ThreatDailyStats called %d times after the TTL, want 2", calls)
	}
}

// A refresh already in flight must not let a concurrent request start a
// second scan of its own: the cache holds its lock for the whole fetch, so a
// request arriving mid-refresh blocks and then reads the result the first
// request just computed, rather than racing it to the database.
func TestStatsPageSingleFlightsAConcurrentRefresh(t *testing.T) {
	r := threatReader()
	r.threatDailyGate = make(chan struct{})
	r.threatDailyStarted = make(chan struct{}, 1)
	h, err := NewServer(r, nil, nil, nil, chrome.Config{Info: testInfo()}, testRetention, testClock)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); get(t, h, "/stats") }()
	<-r.threatDailyStarted // the first request now holds the cache's lock, inside fetch

	done := make(chan struct{})
	go func() {
		defer wg.Done()
		defer close(done)
		get(t, h, "/stats")
	}()
	select {
	case <-done:
		t.Fatal("the second request returned before the first one's fetch was released")
	case <-time.After(20 * time.Millisecond):
		// Expected: the second request is blocked on the cache's mutex.
	}

	close(r.threatDailyGate)
	wg.Wait()

	if calls := atomic.LoadInt32(&r.threatDailyCalls); calls != 1 {
		t.Fatalf("ThreatDailyStats called %d times, want 1 (a single in-flight refresh)", calls)
	}
}

func TestStatsPageShowsWhenTotalsWereComputed(t *testing.T) {
	h := newTestServerWithFeed(t, threatReader(), nil)
	body := get(t, h, "/stats").Body.String()
	if !strings.Contains(body, "Computed at") {
		t.Fatalf("/stats does not say when the totals were computed:\n%s", body)
	}
}
