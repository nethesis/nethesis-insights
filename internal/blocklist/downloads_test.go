// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package blocklist

import (
	"context"
	"net/http"
	"reflect"
	"strconv"
	"testing"
	"time"

	threatstore "github.com/nethesis/nethesis-insights/internal/store/threat"
)

type recordingWriter struct {
	rows []threatstore.FeedDownloadRow
	err  error
}

func (w *recordingWriter) AddFeedDownloads(_ context.Context, rows []threatstore.FeedDownloadRow) error {
	if w.err != nil {
		return w.err
	}
	w.rows = append(w.rows, rows...)
	return nil
}

// Every request with a system counts; only a GET answered 200 is a
// download, only a 304 is not-modified, and a request with no system (a
// 401) is not attributed to anyone.
func TestDownloadsRecordClassifiesEachAnswer(t *testing.T) {
	d := NewDownloads()
	d.Record(now, FeedFull, "sys-a", http.StatusOK, true)
	d.Record(now, FeedFull, "sys-a", http.StatusOK, false) // HEAD
	d.Record(now, FeedFull, "sys-a", http.StatusNotModified, false)
	d.Record(now, FeedFull, "sys-a", http.StatusServiceUnavailable, false)
	d.Record(now, FeedFull, "", http.StatusUnauthorized, false)
	d.Record(now, FeedBasic, "sys-a", http.StatusNotModified, false)

	w := &recordingWriter{}
	if _, err := d.Flush(context.Background(), w); err != nil {
		t.Fatal(err)
	}
	day := threatstore.DayString(now)
	want := []threatstore.FeedDownloadRow{
		{Day: day, Feed: FeedBasic, SystemID: "sys-a", Requests: 1, NotModified: 1},
		{Day: day, Feed: FeedFull, SystemID: "sys-a", Requests: 4, Downloads: 1, NotModified: 1},
	}
	if !reflect.DeepEqual(w.rows, want) {
		t.Fatalf("got %+v,\nwant %+v", w.rows, want)
	}

	// A flush drains: the next one has nothing to write.
	w.rows = nil
	if _, err := d.Flush(context.Background(), w); err != nil || len(w.rows) != 0 {
		t.Fatalf("second flush wrote %+v (err %v), want nothing", w.rows, err)
	}
}

// A failed write keeps the counts for the next flush rather than losing
// them, and merges them with what arrived in between.
func TestDownloadsFailedFlushIsRetried(t *testing.T) {
	d := NewDownloads()
	d.Record(now, FeedBasic, "sys-a", http.StatusOK, true)

	if _, err := d.Flush(context.Background(), &recordingWriter{err: errBoom}); err == nil {
		t.Fatal("Flush: got nil error from a failing writer")
	}
	d.Record(now, FeedBasic, "sys-a", http.StatusNotModified, false)

	w := &recordingWriter{}
	if _, err := d.Flush(context.Background(), w); err != nil {
		t.Fatal(err)
	}
	want := []threatstore.FeedDownloadRow{{Day: threatstore.DayString(now), Feed: FeedBasic, SystemID: "sys-a", Requests: 2, Downloads: 1, NotModified: 1}}
	if !reflect.DeepEqual(w.rows, want) {
		t.Fatalf("got %+v, want %+v", w.rows, want)
	}
}

// The map is bounded: past MaxDownloadKeys a new key is dropped and
// reported, while an existing key keeps counting.
func TestDownloadsAreBounded(t *testing.T) {
	d := NewDownloads()
	for i := range MaxDownloadKeys {
		d.Record(now, FeedFull, "sys-"+strconv.Itoa(i), http.StatusOK, true)
	}
	d.Record(now, FeedFull, "one-too-many", http.StatusOK, true)
	d.Record(now, FeedFull, "sys-0", http.StatusOK, true) // an existing key

	w := &recordingWriter{}
	dropped, err := d.Flush(context.Background(), w)
	if err != nil {
		t.Fatal(err)
	}
	if dropped != 1 || len(w.rows) != MaxDownloadKeys {
		t.Fatalf("dropped %d, wrote %d rows; want 1 and %d", dropped, len(w.rows), MaxDownloadKeys)
	}
}

// The consensus pass flushes the counts into the real table, adding to
// what earlier passes wrote, and prunes days past THREAT_INGEST_RETENTION.
func TestRunFlushesAndPrunesFeedDownloads(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.AddFeedDownloads(ctx, []threatstore.FeedDownloadRow{
		{Day: "2026-05-01", Feed: FeedFull, SystemID: "sys-old", Requests: 1, Downloads: 1},
	}); err != nil {
		t.Fatal(err)
	}

	d := NewDownloads()
	cfg := testConfig()
	cfg.IngestRetention = 30 * 24 * time.Hour
	r := New(s, NewSnapshot(), NewSnapshot(), cfg).WithDownloads(d)

	for range 2 {
		d.Record(now, FeedBasic, "sys-a", http.StatusOK, true)
		if err := r.Run(ctx, now); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.FeedDownloadStats(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []threatstore.FeedDownloadDayRow{{Day: threatstore.DayString(now), Feed: FeedBasic, Systems: 1, Requests: 2, Downloads: 2}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
