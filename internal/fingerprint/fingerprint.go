// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package fingerprint

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"sort"
)

const Version = "v1"

// writeField writes an 8-byte big-endian length prefix followed by s.
func writeField(h hash.Hash, s string) {
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(s)))
	h.Write(lenBuf[:])
	h.Write([]byte(s))
}

// writeList sorts, dedups, then writes an 8-byte big-endian count followed by
// each length-prefixed element. This (rather than strings.Join) prevents an
// attacker from forging a collision by shifting characters across a
// separator byte.
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

	var countBuf [8]byte
	binary.BigEndian.PutUint64(countBuf[:], uint64(len(deduped)))
	h.Write(countBuf[:])
	for _, s := range deduped {
		writeField(h, s)
	}
}

// Compute returns a stable sha256 hex fingerprint over the given fields.
// Every field is length-prefixed with an 8-byte big-endian length so that
// concatenation cannot forge collisions between different inputs, e.g.
// "ab"+"c" cannot collide with "a"+"bc".
func Compute(systemID string, modules, evidence []string, category string) string {
	h := sha256.New()

	writeField(h, Version)
	writeField(h, systemID)
	writeField(h, category)
	writeList(h, modules)
	writeList(h, evidence)

	return hex.EncodeToString(h.Sum(nil))
}
