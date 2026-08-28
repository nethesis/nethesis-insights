// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package blocklist computes fleet consensus over reported CrowdSec bans and
// renders the served feed.
//
// It replaces the design's Redis materialization with an in-process snapshot:
// serving never touches the database, so feed cost is flat regardless of how
// many subscribers poll, and a database hiccup cannot blank the list.
package blocklist

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/nethesis/nethesis-insights/internal/store"
)

// Rule is the promotion rule in force, rendered into the feed header so a
// consumer can see what the list means without reading our documentation.
type Rule struct {
	MinSystems int
	Window     time.Duration
	TTL        time.Duration
}

func (r Rule) String() string {
	return fmt.Sprintf("%d systems / %s window / %s ttl", r.MinSystems, r.Window, r.TTL)
}

// Snapshot holds the rendered feed. Every field is replaced together, under
// one lock, by a successful generation -- and only by a successful
// generation. A failed consensus pass leaves the previous body in place with
// its original generated_at, so subscribers get a stale list, never a blank
// one (spec §10). The header timestamp is what lets a client decide to
// distrust an old feed.
type Snapshot struct {
	mu          sync.RWMutex
	body        []byte
	gz          []byte
	etag        string
	generatedAt int64
	entries     int
	ready       bool
}

func NewSnapshot() *Snapshot { return &Snapshot{} }

// Generate renders rows into a new snapshot and swaps it in. rows beyond
// maxEntries are dropped: a feed that outgrows its consumers' memory is worse
// than a truncated one, and the cap is deterministic because the order is.
func (s *Snapshot) Generate(rows []store.BlocklistRow, rule Rule, maxEntries int, now int64) error {
	addrs := make([]netip.Addr, 0, len(rows))
	for _, r := range rows {
		a, err := netip.ParseAddr(r.AttackerIP)
		if err != nil {
			// Rows are written from already-parsed addresses, so this is a
			// corrupted row rather than untrusted input: skip it instead of
			// refusing to publish everything else.
			continue
		}
		addrs = append(addrs, a.Unmap())
	}
	// Deterministic, and sane to read: v4 before v6, numeric within a family.
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Compare(addrs[j]) < 0 })
	if maxEntries > 0 && len(addrs) > maxEntries {
		addrs = addrs[:maxEntries]
	}

	var buf bytes.Buffer
	buf.WriteString("# nethesis threat shield v1\n")
	fmt.Fprintf(&buf, "# generated: %s  entries: %d  rule: %s\n",
		time.UnixMilli(now).UTC().Format(time.RFC3339), len(addrs), rule)

	// The ETag covers the entries and the rule, NOT the rendered body.
	//
	// The body carries a fresh `generated:` timestamp on every pass, so
	// hashing it would rotate the ETag every BLOCKLIST_CONSENSUS_INTERVAL even
	// when nothing changed -- and every subscriber would re-download the whole
	// list on every poll, which is precisely what the ETag exists to avoid.
	// A client caches on the entry set; that is what the tag must identify.
	h := sha256.New()
	fmt.Fprintf(h, "v1\n%s\n", rule)
	for _, a := range addrs {
		s := a.String()
		buf.WriteString(s)
		buf.WriteByte('\n')
		h.Write([]byte(s))
		h.Write([]byte{'\n'})
	}
	body := buf.Bytes()
	etag := `"sha256-` + hex.EncodeToString(h.Sum(nil)) + `"`

	// Compressed once here rather than per request: the whole point of a
	// snapshot is that serving is free.
	var gzBuf bytes.Buffer
	zw := gzip.NewWriter(&gzBuf)
	if _, err := zw.Write(body); err != nil {
		return fmt.Errorf("blocklist: gzip snapshot: %w", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("blocklist: close gzip snapshot: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.body = body
	s.gz = gzBuf.Bytes()
	s.etag = etag
	s.generatedAt = now
	s.entries = len(addrs)
	s.ready = true
	return nil
}

// Ready reports whether a snapshot has ever been generated. Before the first
// successful pass the feed must answer 503 rather than an empty body: an
// empty list means "no threats", which silently disables protection on every
// client that imports it.
func (s *Snapshot) Ready() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ready
}

func (s *Snapshot) Body() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.body
}

func (s *Snapshot) Gzip() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.gz
}

func (s *Snapshot) ETag() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.etag
}

func (s *Snapshot) GeneratedAt() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.generatedAt
}

func (s *Snapshot) Entries() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.entries
}
