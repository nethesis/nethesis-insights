// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package threat

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// threat_feed_downloads_daily accumulates: each flush carries only what was
// counted since the previous one, so a second flush for the same
// (day, feed, system) must add to the row, never replace it.
func TestAddFeedDownloadsAddsAcrossFlushes(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	first := []FeedDownloadRow{{Day: "2026-11-09", Feed: "basic", SystemID: "sys-a", Requests: 3, Downloads: 1, NotModified: 2}}
	second := []FeedDownloadRow{{Day: "2026-11-09", Feed: "basic", SystemID: "sys-a", Requests: 2, Downloads: 1, NotModified: 1}}
	if err := s.AddFeedDownloads(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := s.AddFeedDownloads(ctx, second); err != nil {
		t.Fatal(err)
	}

	got, err := s.FeedDownloadStats(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []FeedDownloadDayRow{{Day: "2026-11-09", Feed: "basic", Systems: 1, Requests: 5, Downloads: 2, NotModified: 3}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// Distinct systems is the adoption number: one system polling all day, on
// any number of flushes, counts once per day and feed, and a system counts
// separately on each feed it polls.
func TestFeedDownloadStatsCountsEachSystemOncePerDayAndFeed(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for range 3 {
		if err := s.AddFeedDownloads(ctx, []FeedDownloadRow{
			{Day: "2026-11-09", Feed: "full", SystemID: "sys-a", Requests: 1, Downloads: 1},
			{Day: "2026-11-09", Feed: "full", SystemID: "sys-b", Requests: 1, NotModified: 1},
			{Day: "2026-11-09", Feed: "basic", SystemID: "sys-a", Requests: 1, NotModified: 1},
			{Day: "2026-11-08", Feed: "full", SystemID: "sys-a", Requests: 1, Downloads: 1},
		}); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.FeedDownloadStats(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []FeedDownloadDayRow{
		{Day: "2026-11-09", Feed: "basic", Systems: 1, Requests: 3, NotModified: 3},
		{Day: "2026-11-09", Feed: "full", Systems: 2, Requests: 6, Downloads: 3, NotModified: 3},
		{Day: "2026-11-08", Feed: "full", Systems: 1, Requests: 3, Downloads: 3},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v,\nwant %+v", got, want)
	}
}

func TestPruneFeedDownloadsDailyDropsOnlyStaleDays(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.AddFeedDownloads(ctx, []FeedDownloadRow{
		{Day: "2026-05-01", Feed: "full", SystemID: "sys-a", Requests: 1, Downloads: 1},
		{Day: "2026-05-01", Feed: "basic", SystemID: "sys-b", Requests: 1, Downloads: 1},
		{Day: "2026-08-28", Feed: "full", SystemID: "sys-a", Requests: 1, Downloads: 1},
	}); err != nil {
		t.Fatal(err)
	}

	n, err := s.PruneFeedDownloadsDaily(ctx, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("pruned rows: got %d, want 2", n)
	}
	got, err := s.FeedDownloadStats(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Day != "2026-08-28" {
		t.Fatalf("after prune: got %+v, want only 2026-08-28", got)
	}
}

// /stats shows only its last few days, so FeedDownloadStats must not fold
// the rest of the retained table: a day before since's is not returned,
// since's own day is.
func TestFeedDownloadStatsSkipsDaysBeforeSince(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.AddFeedDownloads(ctx, []FeedDownloadRow{
		{Day: "2026-10-10", Feed: "full", SystemID: "sys-a", Requests: 1, Downloads: 1},
		{Day: "2026-10-11", Feed: "full", SystemID: "sys-a", Requests: 2, Downloads: 2},
		{Day: "2026-11-09", Feed: "basic", SystemID: "sys-b", Requests: 3, NotModified: 3},
	}); err != nil {
		t.Fatal(err)
	}

	since := time.Date(2026, 10, 11, 15, 0, 0, 0, time.UTC).UnixMilli()
	got, err := s.FeedDownloadStats(ctx, since, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []FeedDownloadDayRow{
		{Day: "2026-11-09", Feed: "basic", Systems: 1, Requests: 3, NotModified: 3},
		{Day: "2026-10-11", Feed: "full", Systems: 1, Requests: 2, Downloads: 2},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v,\nwant %+v", got, want)
	}
}

// Machines is the adoption number: a system counts only on a day it got the
// list or a not-modified answer. One that only ever got a 503 (threatd just
// restarted, no pass yet) or only sent a HEAD did not take the feed, so it
// is not a machine -- but its requests still count.
func TestFeedDownloadStatsCountsOnlySystemsThatReceivedTheFeed(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.AddFeedDownloads(ctx, []FeedDownloadRow{
		{Day: "2026-11-09", Feed: "full", SystemID: "sys-ok", Requests: 2, Downloads: 1, NotModified: 1},
		{Day: "2026-11-09", Feed: "full", SystemID: "sys-304", Requests: 1, NotModified: 1},
		{Day: "2026-11-09", Feed: "full", SystemID: "sys-503", Requests: 4},
		{Day: "2026-11-09", Feed: "basic", SystemID: "sys-503", Requests: 3},
	}); err != nil {
		t.Fatal(err)
	}

	got, err := s.FeedDownloadStats(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []FeedDownloadDayRow{
		{Day: "2026-11-09", Feed: "basic", Systems: 0, Requests: 3},
		{Day: "2026-11-09", Feed: "full", Systems: 2, Requests: 7, Downloads: 1, NotModified: 2},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v,\nwant %+v", got, want)
	}
}
