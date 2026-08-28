// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package threat

import (
	"fmt"
	"net/netip"
)

// Allowlist is a set of CIDRs that must never be promoted to the blocklist,
// however many systems report them -- a shared resolver, a customer's own WAN
// range, a partner's scanner.
//
// It replaces the design's Postgres-only `<<=` containment operator with
// portable Go, and it is applied at promotion rather than at read, so adding
// an entry retroactively unlists the address on the next consensus pass
// instead of only hiding it from the feed.
type Allowlist struct {
	prefixes []netip.Prefix
}

// ParseAllowlist builds an Allowlist from CIDR strings. It reports the first
// unparseable entry rather than skipping it: an allowlist that silently lost
// a row would fail open, listing an address someone had explicitly excluded.
func ParseAllowlist(cidrs []string) (Allowlist, error) {
	out := Allowlist{prefixes: make([]netip.Prefix, 0, len(cidrs))}
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return Allowlist{}, fmt.Errorf("threat: allowlist entry %q: %w", c, err)
		}
		out.prefixes = append(out.prefixes, p.Masked())
	}
	return out, nil
}

// Contains reports whether addr falls inside any allowlisted prefix.
func (a Allowlist) Contains(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range a.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Len is the number of prefixes, for logging a loaded allowlist without
// dumping its contents on every pass.
func (a Allowlist) Len() int { return len(a.prefixes) }
