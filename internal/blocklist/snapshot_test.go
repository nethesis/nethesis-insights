// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package blocklist

import (
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"
	"time"

	threatstore "github.com/nethesis/nethesis-insights/internal/store/threat"
)

func rows(ips ...string) []threatstore.BlocklistRow {
	out := make([]threatstore.BlocklistRow, 0, len(ips))
	for _, ip := range ips {
		out = append(out, threatstore.BlocklistRow{AttackerIP: ip})
	}
	return out
}

func testRule() Rule {
	return Rule{MinSystems: 3, Window: time.Hour, TTL: 24 * time.Hour}
}

// An empty snapshot must be distinguishable from an empty list: the feed
// answers 503 before the first pass, because "no threats" silently disables
// protection on every client that imports it.
func TestNewSnapshotIsNotReady(t *testing.T) {
	s := NewSnapshot()
	v := s.View()
	if v.Ready {
		t.Fatal("a fresh snapshot must not be ready")
	}
	if v.Body != nil || v.ETag != "" || v.Entries != 0 {
		t.Fatalf("fresh snapshot is not empty: %q %q %d", v.Body, v.ETag, v.Entries)
	}
}

func TestGenerateRendersHeaderAndEntries(t *testing.T) {
	s := NewSnapshot()
	now := time.Date(2026, 8, 28, 10, 5, 0, 0, time.UTC).UnixMilli()

	if err := s.Generate(rows("203.0.113.12", "198.51.100.44"), testRule(), false, now); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	lines := strings.Split(strings.TrimRight(string(s.View().Body), "\n"), "\n")
	if lines[0] != "# nethesis threat shield v1" {
		t.Fatalf("first line: %q", lines[0])
	}
	want := "# generated: 2026-08-28T10:05:00Z  entries: 2  rule: 3 systems / 1h0m0s window / 24h0m0s ttl"
	if lines[1] != want {
		t.Fatalf("header:\ngot  %q\nwant %q", lines[1], want)
	}
	// Sorted numerically within the family, so 198.x precedes 203.x.
	if lines[2] != "198.51.100.44" || lines[3] != "203.0.113.12" {
		t.Fatalf("entries out of order: %v", lines[2:])
	}
	if v := s.View(); !v.Ready || v.Entries != 2 || v.GeneratedAt != now {
		t.Fatalf("state: ready=%v entries=%d generated=%d", v.Ready, v.Entries, v.GeneratedAt)
	}
}

// Deterministic order is what makes the ETag meaningful: the same set of
// entries must always produce the same body, whatever order the store
// returned them in.
func TestGenerateIsDeterministic(t *testing.T) {
	now := time.Now().UnixMilli()
	a, b := NewSnapshot(), NewSnapshot()

	if err := a.Generate(rows("203.0.113.9", "198.51.100.1", "2001:db8::5"), testRule(), false, now); err != nil {
		t.Fatalf("Generate a: %v", err)
	}
	if err := b.Generate(rows("2001:db8::5", "203.0.113.9", "198.51.100.1"), testRule(), false, now); err != nil {
		t.Fatalf("Generate b: %v", err)
	}

	aView, bView := a.View(), b.View()
	if string(aView.Body) != string(bView.Body) {
		t.Fatalf("bodies differ:\n%q\n%q", aView.Body, bView.Body)
	}
	if aView.ETag != bView.ETag {
		t.Fatalf("etags differ: %q vs %q", aView.ETag, bView.ETag)
	}
	// IPv4 sorts before IPv6.
	got := strings.Split(strings.TrimRight(string(aView.Body), "\n"), "\n")[2:]
	want := []string{"198.51.100.1", "203.0.113.9", "2001:db8::5"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order: got %v, want %v", got, want)
		}
	}
}

// The ETag must survive a regeneration that changed nothing. Hashing the
// rendered body would rotate it every consensus pass, because the body
// carries a fresh `generated:` timestamp -- and every subscriber would then
// re-download the whole list on every poll, defeating the entire mechanism.
func TestETagIsStableAcrossRegenerationsOfTheSameEntries(t *testing.T) {
	s := NewSnapshot()
	entries := rows("203.0.113.1", "203.0.113.2")

	if err := s.Generate(entries, testRule(), false, 1000); err != nil {
		t.Fatalf("first: %v", err)
	}
	firstView := s.View()
	first, firstBody := firstView.ETag, string(firstView.Body)

	if err := s.Generate(entries, testRule(), false, 1000+5*60*1000); err != nil {
		t.Fatalf("second: %v", err)
	}

	if got := s.View(); got.ETag != first {
		t.Fatalf("etag rotated on an unchanged list: %q -> %q", first, got.ETag)
	} else if string(got.Body) == firstBody {
		// The body must still be refreshed, so a client can judge staleness.
		t.Fatal("the body's generated timestamp did not advance")
	}
}

// The rule is part of the identity: the same addresses published under a
// different promotion rule are a different list.
func TestETagChangesWithTheRule(t *testing.T) {
	s := NewSnapshot()
	_ = s.Generate(rows("203.0.113.1"), testRule(), false, 1000)
	first := s.View().ETag

	stricter := testRule()
	stricter.MinSystems = 5
	_ = s.Generate(rows("203.0.113.1"), stricter, false, 1000)

	if s.View().ETag == first {
		t.Fatal("etag did not change when the promotion rule did")
	}
}

func TestETagChangesWithContent(t *testing.T) {
	now := time.Now().UnixMilli()
	s := NewSnapshot()

	_ = s.Generate(rows("203.0.113.1"), testRule(), false, now)
	first := s.View().ETag
	if !strings.HasPrefix(first, `"sha256-`) {
		t.Fatalf("etag format: %q", first)
	}

	_ = s.Generate(rows("203.0.113.1", "203.0.113.2"), testRule(), false, now)
	if s.View().ETag == first {
		t.Fatal("etag did not change when the body did")
	}
}

func TestGzipRoundTripsToTheBody(t *testing.T) {
	s := NewSnapshot()
	if err := s.Generate(rows("203.0.113.1", "203.0.113.2"), testRule(), false, time.Now().UnixMilli()); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	view := s.View()
	zr, err := gzip.NewReader(bytes.NewReader(view.Gzip))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer func() { _ = zr.Close() }()
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("read gzip: %v", err)
	}
	if string(got) != string(view.Body) {
		t.Fatalf("gzip body mismatch:\n%q\n%q", got, view.Body)
	}
}

// Generate publishes every row it is given -- the cap is applied when the
// rows are chosen -- and records whether the pass capped them, for /status.
func TestGenerateRecordsWhetherTheFeedWasCapped(t *testing.T) {
	s := NewSnapshot()
	if err := s.Generate(rows("203.0.113.1", "203.0.113.2"), testRule(), true, time.Now().UnixMilli()); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if v := s.View(); v.Entries != 2 || !v.Capped {
		t.Fatalf("entries=%d capped=%v, want 2 and capped", v.Entries, v.Capped)
	}
	if err := s.Generate(rows("203.0.113.1"), testRule(), false, time.Now().UnixMilli()); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if s.View().Capped {
		t.Fatal("a later uncapped generation still reports capped")
	}
}

// A corrupted row must not stop the rest of the fleet's protection being
// published.
func TestGenerateSkipsUnparseableRows(t *testing.T) {
	s := NewSnapshot()
	if err := s.Generate(rows("203.0.113.1", "garbage", ""), testRule(), false, time.Now().UnixMilli()); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if s.View().Entries != 1 {
		t.Fatalf("entries: got %d, want 1", s.View().Entries)
	}
}

// A legitimately empty consensus still produces a valid, ready snapshot: the
// header alone tells a client the feed is live and currently lists nothing.
func TestGenerateWithNoEntriesIsStillReady(t *testing.T) {
	s := NewSnapshot()
	if err := s.Generate(nil, testRule(), false, time.Now().UnixMilli()); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	v := s.View()
	if !v.Ready {
		t.Fatal("an empty but successful generation must be ready")
	}
	if v.Entries != 0 {
		t.Fatalf("entries: got %d, want 0", v.Entries)
	}
	if !strings.HasPrefix(string(v.Body), "# nethesis threat shield v1\n") {
		t.Fatalf("body: %q", v.Body)
	}
}
