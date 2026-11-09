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
// exported as the feed label of threatd_blocklist_entries.
const (
	FeedFull  = "full"
	FeedBasic = "basic"
)

// The client names, as stored in threat_feed_downloads_daily.client: which
// public base URL a feed request came in on. NethSecurity firewalls call
// /blocklist/v1/, NS8 CrowdSec nodes /blocklist/crowdsec/v1/; ClientDirect
// is a request that did not come through either Traefik route.
const (
	ClientNethSecurity = "nethsecurity"
	ClientCrowdSec     = "crowdsec"
	ClientDirect       = "direct"
)

// ClientForPrefix names the client from the prefix Traefik's stripPrefix
// middleware removed, as it reports it in X-Forwarded-Prefix:
// "/blocklist" (strip-blocklist) is NethSecurity, "/blocklist/crowdsec"
// (strip-blocklist-crowdsec) is NS8 CrowdSec, and anything else -- no
// header, a request that bypassed the proxy -- is ClientDirect.
//
// This is statistics only, never an access decision. The entitlement was
// already checked by the forwardAuth middleware on the route, and threatd
// still never learns which entitlement ran: the prefix says which URL was
// called, nothing about which check let it through, and serving or refusing
// a feed must never depend on it.
func ClientForPrefix(prefix string) string {
	switch prefix {
	case "/blocklist":
		return ClientNethSecurity
	case "/blocklist/crowdsec":
		return ClientCrowdSec
	default:
		return ClientDirect
	}
}

// MaxDownloadKeys bounds how many (day, feed, client, system) counters Downloads
// holds between two flushes. The fleet is ~2700 systems on two feeds, and
// a flush runs every consensus pass, so a real deployment stays far below
// it; it exists so that nothing a client sends can grow this map without
// limit. A request whose key would exceed it is dropped from the daily
// counts (threatd_http_requests_total still counts it) and reported by Flush.
const MaxDownloadKeys = 50000

// DownloadWriter is the store method a flush writes through.
// *threatstore.Store satisfies it.
type DownloadWriter interface {
	AddFeedDownloads(ctx context.Context, rows []threatstore.FeedDownloadRow) error
}

type downloadKey struct{ day, feed, client, systemID string }

// downloadCounts adds up; lastIP and lastSeen are the latest request's,
// whichever order requests and failed flushes merge in.
type downloadCounts struct {
	requests, downloads, notModified int64
	lastIP                           string
	lastSeen                         int64
}

// merge folds o into c: counters add, and the later request's address and
// time win.
func (c *downloadCounts) merge(o downloadCounts) {
	c.requests += o.requests
	c.downloads += o.downloads
	c.notModified += o.notModified
	if o.lastSeen >= c.lastSeen {
		c.lastSeen, c.lastIP = o.lastSeen, o.lastIP
	}
}

// Poll is one answered feed request, as Downloads records it. Feed is
// FeedFull or FeedBasic, Client one of the Client* names (see
// ClientForPrefix), IP the machine's address as httpx.ClientIP resolved
// it. Body says whether the response carried the list itself -- a GET
// answered 200; HEAD never does.
type Poll struct {
	Feed, Client, SystemID, IP string
	Code                       int
	Body                       bool
}

// Downloads counts feed polls per UTC day, feed, client and system in
// memory, with each machine's last address and last request time, and
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

// Record counts one feed request answered at now (unix millis). A request
// with no system_id (a 401) is not counted: there is no system to
// attribute it to.
func (d *Downloads) Record(now int64, p Poll) {
	if d == nil || p.SystemID == "" {
		return
	}
	k := downloadKey{day: threatstore.DayString(now), feed: p.Feed, client: p.Client, systemID: p.SystemID}
	one := downloadCounts{requests: 1, lastIP: p.IP, lastSeen: now}
	switch {
	case p.Code == http.StatusOK && p.Body:
		one.downloads = 1
	case p.Code == http.StatusNotModified:
		one.notModified = 1
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.counts[k]
	if !ok && len(d.counts) >= MaxDownloadKeys {
		d.overflow++
		return
	}
	c.merge(one)
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
			Day: k.day, Feed: k.feed, Client: k.client, SystemID: k.systemID,
			Requests: c.requests, Downloads: c.downloads, NotModified: c.notModified,
			LastIP: c.lastIP, LastSeenAt: c.lastSeen,
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
		if a.Client != b.Client {
			return a.Client < b.Client
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
		cur.merge(c)
		d.counts[k] = cur
	}
}
