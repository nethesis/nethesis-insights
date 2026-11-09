// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package blocklist

import (
	"context"
	"net/http"
	"sort"
	"sync"

	threatstore "github.com/nethesis/nethesis-insights/internal/store/threat"
)

// The two feed names, as stored in threat_feed_downloads_daily.feed and
// exported as the feed label of threatd_feed_requests_total and
// threatd_blocklist_entries.
const (
	FeedFull  = "full"
	FeedBasic = "basic"
)

// MaxDownloadKeys bounds how many (day, feed, system) counters Downloads
// holds between two flushes. The fleet is ~2700 systems on two feeds, and
// a flush runs every consensus pass, so a real deployment stays far below
// it; it exists so that nothing a client sends can grow this map without
// limit. A request whose key would exceed it is dropped from the daily
// counts (the Prometheus counter still sees it) and reported by Flush.
const MaxDownloadKeys = 50000

// DownloadWriter is the store method a flush writes through.
// *threatstore.Store satisfies it.
type DownloadWriter interface {
	AddFeedDownloads(ctx context.Context, rows []threatstore.FeedDownloadRow) error
}

type downloadKey struct{ day, feed, systemID string }

type downloadCounts struct{ requests, downloads, notModified int64 }

// Downloads counts feed polls per UTC day, feed and system in memory, and
// Flush adds them to threat_feed_downloads_daily. The feed handlers record
// into it on every request; a database write per poll would put ~2700
// nodes' polling on threatd's single SQLite writer, so the write happens
// once per consensus pass instead (and once more on graceful shutdown). A
// crash loses at most the counts recorded since the last flush.
//
// It is safe for concurrent use.
type Downloads struct {
	mu       sync.Mutex
	counts   map[downloadKey]downloadCounts
	overflow int64
}

func NewDownloads() *Downloads {
	return &Downloads{counts: map[downloadKey]downloadCounts{}}
}

// Record counts one feed request answered with code at now (unix millis).
// body says whether the response carried the list itself -- a GET answered
// 200; HEAD never does. A request with no system_id (a 401) is not counted:
// there is no system to attribute it to.
func (d *Downloads) Record(now int64, feed, systemID string, code int, body bool) {
	if d == nil || systemID == "" {
		return
	}
	k := downloadKey{day: threatstore.DayString(now), feed: feed, systemID: systemID}

	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.counts[k]
	if !ok && len(d.counts) >= MaxDownloadKeys {
		d.overflow++
		return
	}
	c.requests++
	switch {
	case code == http.StatusOK && body:
		c.downloads++
	case code == http.StatusNotModified:
		c.notModified++
	}
	d.counts[k] = c
}

// Flush adds everything counted since the previous flush to the store and
// returns how many requests were dropped for exceeding MaxDownloadKeys in
// that time. On a write error the counts are merged back, so the next
// flush retries them instead of losing them.
func (d *Downloads) Flush(ctx context.Context, w DownloadWriter) (int64, error) {
	if d == nil {
		return 0, nil
	}
	d.mu.Lock()
	taken, overflow := d.counts, d.overflow
	d.counts, d.overflow = map[downloadKey]downloadCounts{}, 0
	d.mu.Unlock()

	if len(taken) == 0 {
		return overflow, nil
	}
	rows := make([]threatstore.FeedDownloadRow, 0, len(taken))
	for k, c := range taken {
		rows = append(rows, threatstore.FeedDownloadRow{
			Day: k.day, Feed: k.feed, SystemID: k.systemID,
			Requests: c.requests, Downloads: c.downloads, NotModified: c.notModified,
		})
	}
	// A fixed order, so one flush always writes its rows the same way.
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Day != b.Day {
			return a.Day < b.Day
		}
		if a.Feed != b.Feed {
			return a.Feed < b.Feed
		}
		return a.SystemID < b.SystemID
	})

	if err := w.AddFeedDownloads(ctx, rows); err != nil {
		d.restore(taken, overflow)
		return 0, err
	}
	return overflow, nil
}

// restore merges a batch whose write failed back into the live counts,
// still within MaxDownloadKeys.
func (d *Downloads) restore(taken map[downloadKey]downloadCounts, overflow int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.overflow += overflow
	for k, c := range taken {
		cur, ok := d.counts[k]
		if !ok && len(d.counts) >= MaxDownloadKeys {
			d.overflow += c.requests
			continue
		}
		cur.requests += c.requests
		cur.downloads += c.downloads
		cur.notModified += c.notModified
		d.counts[k] = cur
	}
}
