// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package trigger derives a window's trigger key: a fleet-wide name for the
// condition that made the gate fire, looked up before paying for an LLM call.
//
// It is pure for the same reason gate and fingerprint are: whether a window
// is paid for turns on it, and a table-driven test with no fixtures is the
// only honest way to pin that down.
//
// A trigger key is not a finding's identity. fingerprint.Compute names what
// the model concluded, per system; a trigger key names what the gate saw,
// across systems, before any model ran. It carries no system_id on purpose:
// the same condition on two clusters is one trigger, reviewed once.
package trigger

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"sort"
	"strconv"

	"github.com/nethesis/nethesis-insights/internal/gate"
	"github.com/nethesis/nethesis-insights/internal/model"
)

// Version prefixes every key. Changing what Key hashes renames every trigger
// fleet-wide, and every operator decision recorded against the old names
// stops applying -- so, like fingerprint.Version, it is bumped deliberately
// and the break is visible.
const Version = "t1"

// Key returns the trigger key for a gate decision:
//
//   - the canonical keys of the novel templates, but only when novelty
//     actually fired (quorum met, or a novel security template). Sub-quorum
//     novelty rides along a deviation window without paying for it, and on
//     the dev fleet it made 404 of 818 deviation-only windows unique;
//   - the deviating buckets, folded to (model.ModuleFamily, priority). The
//     family because 82 nethvoice instances deviating together are one
//     condition; the priority because an error surge and an info surge in
//     one module are not;
//   - one security bit, set when security_new or security_surge fired.
//
// Every list is sorted and deduplicated and every field length-prefixed, as
// in fingerprint -- never a strings.Join, whose separator is forgeable.
func Key(d gate.Decision) string {
	h := sha256.New()

	var novel []string
	if d.NoveltyFired {
		novel = make([]string, 0, len(d.Novel))
		for k := range d.Novel {
			novel = append(novel, k)
		}
	}
	writeList(h, novel)

	type bucket struct {
		family   string
		priority int
	}
	seen := map[bucket]bool{}
	buckets := make([]bucket, 0, len(d.DeviatingBuckets))
	for _, b := range d.DeviatingBuckets {
		k := bucket{family: model.ModuleFamily(b.ModuleID), priority: b.Priority}
		if !seen[k] {
			seen[k] = true
			buckets = append(buckets, k)
		}
	}
	sort.Slice(buckets, func(i, j int) bool {
		if buckets[i].family != buckets[j].family {
			return buckets[i].family < buckets[j].family
		}
		return buckets[i].priority < buckets[j].priority
	})
	writeCount(h, uint64(len(buckets)))
	for _, b := range buckets {
		writeField(h, b.family)
		writeField(h, strconv.Itoa(b.priority))
	}

	if IsSecurity(d) {
		writeField(h, "security")
	} else {
		writeField(h, "")
	}

	return Version + ":" + hex.EncodeToString(h.Sum(nil))
}

// IsSecurity reports whether the key for d carries the security bit. A
// security trigger is delivered to the customer without review and can never
// be ignored, so the analyzer and the store both ask this, and they must ask
// the same question the key encodes.
func IsSecurity(d gate.Decision) bool {
	return d.SecurityNew || d.SecuritySurge
}

func writeField(h hash.Hash, s string) {
	writeCount(h, uint64(len(s)))
	h.Write([]byte(s))
}

// writeCount writes an 8-byte big-endian count. It takes a uint64 so every
// caller converts a len(), which cannot be negative, at the call site.
func writeCount(h hash.Hash, n uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], n)
	h.Write(buf[:])
}

// writeList sorts, dedups, then writes a count followed by each
// length-prefixed element. Copied from fingerprint rather than imported:
// fingerprint's hashing is its identity formula, and sharing it would make a
// change there silently rename every trigger too.
func writeList(h hash.Hash, items []string) {
	sorted := make([]string, len(items))
	copy(sorted, items)
	sort.Strings(sorted)

	deduped := sorted[:0:0]
	for i, s := range sorted {
		if i == 0 || s != sorted[i-1] {
			deduped = append(deduped, s)
		}
	}

	writeCount(h, uint64(len(deduped)))
	for _, s := range deduped {
		writeField(h, s)
	}
}
