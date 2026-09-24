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

	threatstore "github.com/nethesis/nethesis-insights/internal/store/threat"
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
	capped      bool
	ready       bool
}

func NewSnapshot() *Snapshot { return &Snapshot{} }

// Generate renders rows into a new snapshot and swaps it in. Every row is
// published: BLOCKLIST_MAX_ENTRIES is applied when the rows are chosen (see
// Runner.Run), and capped records whether that choice left any out.
func (s *Snapshot) Generate(rows []threatstore.BlocklistRow, rule Rule, capped bool, now int64) error {
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
	// hash.Hash.Write never returns an error (it's documented not to), but
	// fmt.Fprintf's own signature always returns one regardless of the
	// Writer passed in, so errcheck can't see through to that guarantee --
	// discard it explicitly rather than leaving it unchecked.
	_, _ = fmt.Fprintf(h, "v1\n%s\n", rule)
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
	s.capped = capped
	s.ready = true
	return nil
}

// View is one generation's servable state, read together under a single
// lock. It is the ONLY way anything outside this package observes a
// Snapshot: Body(), Gzip(), ETag(), Entries(), GeneratedAt(), Ready() and
// Capped() used to exist as separate accessors, each taking its own RLock,
// and a Generate landing between two of those calls could pair one
// generation's ETag with another's entry count or capped flag -- the same
// torn read the feed handler used to have, just moved into the operator UI's
// status page instead of fixed. View is what both callers (the feed handler
// in internal/api/threat and the status/index pages in internal/ui/threat)
// use now; there is no other way to read this state.
type View struct {
	Ready       bool
	ETag        string
	Body, Gzip  []byte
	Entries     int
	GeneratedAt int64
	Capped      bool
}

// View returns one generation's full state under a single read lock. The
// slices are never mutated after Generate, so sharing them is safe.
func (s *Snapshot) View() View {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return View{
		Ready:       s.ready,
		ETag:        s.etag,
		Body:        s.body,
		Gzip:        s.gz,
		Entries:     s.entries,
		GeneratedAt: s.generatedAt,
		Capped:      s.capped,
	}
}
