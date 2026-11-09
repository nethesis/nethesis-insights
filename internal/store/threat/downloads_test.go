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

// A row's counters add across flushes while last_ip follows last_seen_at:
// a flush carrying an older request (a batch merged back after a failed
// write, say) must not overwrite a newer address.
func TestAddFeedDownloadsKeepsTheLatestAddress(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const day = "2026-11-09"
	t0 := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC).UnixMilli()

	for _, r := range []FeedDownloadRow{
		{Requests: 1, Downloads: 1, LastIP: "198.51.100.1", LastSeenAt: t0},
		{Requests: 2, NotModified: 2, LastIP: "198.51.100.2", LastSeenAt: t0 + 2000},
		{Requests: 1, NotModified: 1, LastIP: "198.51.100.3", LastSeenAt: t0 + 1000}, // older
	} {
		r.Day, r.Feed, r.Client, r.SystemID = day, "full", "nethsecurity", "sys-a"
		if err := s.AddFeedDownloads(ctx, []FeedDownloadRow{r}); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.FeedDownloadMachines(ctx, 0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []FeedMachineRow{{
		SystemID: "sys-a", Feed: "full", Client: "nethsecurity", FirstDay: day,
		LastSeenAt: t0 + 2000, LastIP: "198.51.100.2", Requests: 4, Downloads: 1, NotModified: 3,
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v,\nwant %+v", got, want)
	}
}

// One row per (system, feed, client), folded across days, its address
// taken from its latest day; latest request first; the prefix filter is
// case-sensitive and exact ids are their own prefix; rows before since's
// day are not read at all; the limit cuts the tail.
func TestFeedDownloadMachines(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	at := func(day string, hour int) int64 {
		d, err := time.Parse("2006-01-02", day)
		if err != nil {
			t.Fatal(err)
		}
		return d.Add(time.Duration(hour) * time.Hour).UnixMilli()
	}
	row := func(day, feed, client, sys, ip string, hour int) FeedDownloadRow {
		return FeedDownloadRow{Day: day, Feed: feed, Client: client, SystemID: sys,
			Requests: 1, Downloads: 1, LastIP: ip, LastSeenAt: at(day, hour)}
	}
	if err := s.AddFeedDownloads(ctx, []FeedDownloadRow{
		row("2026-09-01", "full", "nethsecurity", "sys-a", "192.0.2.99", 9), // before since
		row("2026-11-07", "full", "nethsecurity", "sys-a", "192.0.2.1", 9),
		row("2026-11-09", "full", "nethsecurity", "sys-a", "192.0.2.2", 8),
		row("2026-11-08", "basic", "crowdsec", "sys-a", "192.0.2.3", 23),
		row("2026-11-09", "basic", "crowdsec", "sys-b", "192.0.2.4", 11),
		row("2026-11-09", "basic", "direct", "SYS-C", "192.0.2.5", 1),
	}); err != nil {
		t.Fatal(err)
	}
	since := at("2026-10-11", 12)

	got, err := s.FeedDownloadMachines(ctx, since, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []FeedMachineRow{
		{SystemID: "sys-b", Feed: "basic", Client: "crowdsec", FirstDay: "2026-11-09", LastSeenAt: at("2026-11-09", 11), LastIP: "192.0.2.4", Requests: 1, Downloads: 1},
		{SystemID: "sys-a", Feed: "full", Client: "nethsecurity", FirstDay: "2026-11-07", LastSeenAt: at("2026-11-09", 8), LastIP: "192.0.2.2", Requests: 2, Downloads: 2},
		{SystemID: "SYS-C", Feed: "basic", Client: "direct", FirstDay: "2026-11-09", LastSeenAt: at("2026-11-09", 1), LastIP: "192.0.2.5", Requests: 1, Downloads: 1},
		{SystemID: "sys-a", Feed: "basic", Client: "crowdsec", FirstDay: "2026-11-08", LastSeenAt: at("2026-11-08", 23), LastIP: "192.0.2.3", Requests: 1, Downloads: 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v,\nwant %+v", got, want)
	}

	for prefix, wantN := range map[string]int{"sys-": 3, "sys-a": 2, "sys-b": 1, "SYS": 1, "sys-a-longer": 0, "ys": 0} {
		got, err := s.FeedDownloadMachines(ctx, since, prefix, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != wantN {
			t.Errorf("prefix %q: got %d rows, want %d: %+v", prefix, len(got), wantN, got)
		}
	}

	got, err = s.FeedDownloadMachines(ctx, since, "", 2)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want[:2]) {
		t.Fatalf("limit 2: got %+v, want %+v", got, want[:2])
	}
}

// /stats' Machines number keeps its meaning with the client in the key: a
// system that fetched one feed through both base URLs on one day is one
// machine, and its requests still all count.
func TestFeedDownloadStatsCountsASystemOnceAcrossClients(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.AddFeedDownloads(ctx, []FeedDownloadRow{
		{Day: "2026-11-09", Feed: "basic", Client: "nethsecurity", SystemID: "sys-a", Requests: 2, Downloads: 1, NotModified: 1},
		{Day: "2026-11-09", Feed: "basic", Client: "crowdsec", SystemID: "sys-a", Requests: 1, Downloads: 1},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.FeedDownloadStats(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []FeedDownloadDayRow{{Day: "2026-11-09", Feed: "basic", Systems: 1, Requests: 3, Downloads: 2, NotModified: 1}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
