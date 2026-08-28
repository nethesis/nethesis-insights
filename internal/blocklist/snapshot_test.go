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

	"github.com/nethesis/nethesis-insights/internal/store"
)

func rows(ips ...string) []store.BlocklistRow {
	out := make([]store.BlocklistRow, 0, len(ips))
	for _, ip := range ips {
		out = append(out, store.BlocklistRow{AttackerIP: ip})
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
	if s.Ready() {
		t.Fatal("a fresh snapshot must not be ready")
	}
	if s.Body() != nil || s.ETag() != "" || s.Entries() != 0 {
		t.Fatalf("fresh snapshot is not empty: %q %q %d", s.Body(), s.ETag(), s.Entries())
	}
}

func TestGenerateRendersHeaderAndEntries(t *testing.T) {
	s := NewSnapshot()
	now := time.Date(2026, 8, 28, 10, 5, 0, 0, time.UTC).UnixMilli()

	if err := s.Generate(rows("203.0.113.12", "198.51.100.44"), testRule(), 100, now); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	lines := strings.Split(strings.TrimRight(string(s.Body()), "\n"), "\n")
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
	if !s.Ready() || s.Entries() != 2 || s.GeneratedAt() != now {
		t.Fatalf("state: ready=%v entries=%d generated=%d", s.Ready(), s.Entries(), s.GeneratedAt())
	}
}

// Deterministic order is what makes the ETag meaningful: the same set of
// entries must always produce the same body, whatever order the store
// returned them in.
func TestGenerateIsDeterministic(t *testing.T) {
	now := time.Now().UnixMilli()
	a, b := NewSnapshot(), NewSnapshot()

	if err := a.Generate(rows("203.0.113.9", "198.51.100.1", "2001:db8::5"), testRule(), 100, now); err != nil {
		t.Fatalf("Generate a: %v", err)
	}
	if err := b.Generate(rows("2001:db8::5", "203.0.113.9", "198.51.100.1"), testRule(), 100, now); err != nil {
		t.Fatalf("Generate b: %v", err)
	}

	if string(a.Body()) != string(b.Body()) {
		t.Fatalf("bodies differ:\n%q\n%q", a.Body(), b.Body())
	}
	if a.ETag() != b.ETag() {
		t.Fatalf("etags differ: %q vs %q", a.ETag(), b.ETag())
	}
	// IPv4 sorts before IPv6.
	got := strings.Split(strings.TrimRight(string(a.Body()), "\n"), "\n")[2:]
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

	if err := s.Generate(entries, testRule(), 100, 1000); err != nil {
		t.Fatalf("first: %v", err)
	}
	first, firstBody := s.ETag(), string(s.Body())

	if err := s.Generate(entries, testRule(), 100, 1000+5*60*1000); err != nil {
		t.Fatalf("second: %v", err)
	}

	if s.ETag() != first {
		t.Fatalf("etag rotated on an unchanged list: %q -> %q", first, s.ETag())
	}
	// The body must still be refreshed, so a client can judge staleness.
	if string(s.Body()) == firstBody {
		t.Fatal("the body's generated timestamp did not advance")
	}
}

// The rule is part of the identity: the same addresses published under a
// different promotion rule are a different list.
func TestETagChangesWithTheRule(t *testing.T) {
	s := NewSnapshot()
	_ = s.Generate(rows("203.0.113.1"), testRule(), 100, 1000)
	first := s.ETag()

	stricter := testRule()
	stricter.MinSystems = 5
	_ = s.Generate(rows("203.0.113.1"), stricter, 100, 1000)

	if s.ETag() == first {
		t.Fatal("etag did not change when the promotion rule did")
	}
}

func TestETagChangesWithContent(t *testing.T) {
	now := time.Now().UnixMilli()
	s := NewSnapshot()

	_ = s.Generate(rows("203.0.113.1"), testRule(), 100, now)
	first := s.ETag()
	if !strings.HasPrefix(first, `"sha256-`) {
		t.Fatalf("etag format: %q", first)
	}

	_ = s.Generate(rows("203.0.113.1", "203.0.113.2"), testRule(), 100, now)
	if s.ETag() == first {
		t.Fatal("etag did not change when the body did")
	}
}

func TestGzipRoundTripsToTheBody(t *testing.T) {
	s := NewSnapshot()
	if err := s.Generate(rows("203.0.113.1", "203.0.113.2"), testRule(), 100, time.Now().UnixMilli()); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	zr, err := gzip.NewReader(bytes.NewReader(s.Gzip()))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer zr.Close()
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("read gzip: %v", err)
	}
	if string(got) != string(s.Body()) {
		t.Fatalf("gzip body mismatch:\n%q\n%q", got, s.Body())
	}
}

func TestGenerateCapsEntries(t *testing.T) {
	var ips []string
	for i := 1; i <= 20; i++ {
		ips = append(ips, "203.0.113."+string(rune('0'+i/10))+string(rune('0'+i%10)))
	}
	s := NewSnapshot()
	if err := s.Generate(rows(ips...), testRule(), 5, time.Now().UnixMilli()); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if s.Entries() != 5 {
		t.Fatalf("entries: got %d, want 5", s.Entries())
	}
	if n := strings.Count(string(s.Body()), "\n"); n != 7 { // 2 header lines + 5
		t.Fatalf("body lines: got %d, want 7", n)
	}
}

// A corrupted row must not stop the rest of the fleet's protection being
// published.
func TestGenerateSkipsUnparseableRows(t *testing.T) {
	s := NewSnapshot()
	if err := s.Generate(rows("203.0.113.1", "garbage", ""), testRule(), 100, time.Now().UnixMilli()); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if s.Entries() != 1 {
		t.Fatalf("entries: got %d, want 1", s.Entries())
	}
}

// A legitimately empty consensus still produces a valid, ready snapshot: the
// header alone tells a client the feed is live and currently lists nothing.
func TestGenerateWithNoEntriesIsStillReady(t *testing.T) {
	s := NewSnapshot()
	if err := s.Generate(nil, testRule(), 100, time.Now().UnixMilli()); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !s.Ready() {
		t.Fatal("an empty but successful generation must be ready")
	}
	if s.Entries() != 0 {
		t.Fatalf("entries: got %d, want 0", s.Entries())
	}
	if !strings.HasPrefix(string(s.Body()), "# nethesis threat shield v1\n") {
		t.Fatalf("body: %q", s.Body())
	}
}
