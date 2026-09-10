// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package threat

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
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
		out.prefixes = append(out.prefixes, normalizeAllowlistPrefix(p))
	}
	return out, nil
}

// Contains reports whether addr falls inside any allowlisted prefix.
//
// The address is unmapped and stripped of its zone first, and the zone is
// the load-bearing half: netip.Prefix.Contains is false for any address
// carrying one, because a prefix has no zone to compare. Left as it arrives,
// a reporter could evade the only promotion exclusion this pipeline has by
// appending "%1" to the address it wanted published -- an exemption that
// reads as active in the operator UI while matching nothing.
func (a Allowlist) Contains(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	for _, p := range a.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// normalizeAllowlistPrefix puts a parsed prefix into the one form this
// server stores and compares by text equality: masked, and with a v4-mapped
// prefix reduced to the IPv4 prefix it actually describes.
//
// The unmapping is not cosmetic. attacker_ip is stored unmapped, so a
// ::ffff:203.0.113.0/120 entry would match nothing at all -- an exemption
// that silently does not work, which is the same fail-open direction as an
// entry that was quietly dropped. It also measures such a prefix against the
// right floor: ::ffff:0.0.0.0/96 *is* 0.0.0.0/0, and weighing it against the
// v6 floor of /48 let the widest possible exemption through the guardrail.
//
// A zone needs no handling here: netip.ParsePrefix refuses one outright.
func normalizeAllowlistPrefix(p netip.Prefix) netip.Prefix {
	p = p.Masked()
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		// The mapped prefix ::ffff:0:0/96 is the v4 space, so the v4 bit
		// count is whatever is left after those 96 bits.
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p
}

// Len is the number of prefixes, for logging a loaded allowlist without
// dumping its contents on every pass.
func (a Allowlist) Len() int { return len(a.prefixes) }

// MinAllowlistPrefixV4 and MinAllowlistPrefixV6 are the widest prefix an
// admin may allowlist. Below these floors a single entry hides a meaningful
// slice of the address space from consensus --
// 0.0.0.0/0 is the extreme case, and it would do so silently: nothing else
// in the system would report that the feed had quietly stopped growing.
// The floor is per address family because "how much address space" a given
// bit count covers is wildly different between the two.
const (
	MinAllowlistPrefixV4 = 24
	MinAllowlistPrefixV6 = 48
)

// ErrAllowlistPrefixTooBroad is returned by ParseAllowlistEntry when a
// prefix is wider than the guardrail floor for its address family. There is
// no override: an exemption that broad is never what was meant, and the one
// time it is, it is cheap to say as a handful of narrower entries.
var ErrAllowlistPrefixTooBroad = errors.New("threat: allowlist prefix is broader than the guardrail floor")

// ParseAllowlistEntry validates and normalizes one admin- or
// customer-supplied allowlist candidate -- a bare address or a CIDR -- into
// the canonical string this server stores and compares by text equality,
// exactly like attacker_ip.
//
// A bare address normalizes to a full-length prefix (/32 or /128), which
// trivially clears the guardrail below since it can only ever cover the one
// address; anything wider than MinAllowlistPrefixV4/V6 is rejected. There is
// deliberately no override. A wrong blocklist entry blocks a legitimate
// address loudly and expires; a wrong allowlist entry exempts an attacker
// silently and permanently, and one wide enough to matter -- 0.0.0.0/0 being
// the extreme -- disables the whole feed with nothing anywhere reporting
// that it had quietly stopped growing. An override flag on a form is also
// one more thing a forged request can carry, and it bought nothing a few
// narrower entries do not.
//
// Use NormalizeAllowlistCIDR instead for a path that names an existing entry
// rather than creating one.
//
// The returned warning is non-empty (and err nil) when the address is not
// public unicast: publicUnicast is exactly what promotion checks, so a
// private or reserved entry can never be promoted in the first place --
// allowlisting one is pointless but harmless, and rejecting it outright
// would be a confusing error for a request that does no damage.
func ParseAllowlistEntry(input string) (cidr string, warning string, err error) {
	p, warning, err := parseAllowlistCandidate(input)
	if err != nil {
		return "", "", err
	}

	floor := MinAllowlistPrefixV4
	if p.Addr().Is6() {
		floor = MinAllowlistPrefixV6
	}
	if p.Bits() < floor {
		return "", "", fmt.Errorf("%w: %s is a /%d, the floor is /%d for this address family",
			ErrAllowlistPrefixTooBroad, p, p.Bits(), floor)
	}

	return p.String(), warning, nil
}

// NormalizeAllowlistCIDR canonicalizes an allowlist CIDR the same way
// ParseAllowlistEntry does but without the breadth floor, for the paths that
// *name* an entry rather than create one: removing a stored entry, and
// recording a decision on a client's request. Those must be able to name
// whatever is actually stored, and none of them can exempt an address from
// promotion -- the floor guards adding an exemption, not removing one.
//
// It is still validation, not a bypass: malformed input is refused here too.
func NormalizeAllowlistCIDR(input string) (cidr string, warning string, err error) {
	p, warning, err := parseAllowlistCandidate(input)
	if err != nil {
		return "", "", err
	}
	return p.String(), warning, nil
}

// parseAllowlistCandidate accepts either spelling -- a bare address or a
// CIDR -- and returns the canonical prefix plus the not-public-unicast
// warning. The zone is dropped rather than the entry: an admin who types one
// means the address, and an entry stored with a zone could never match the
// unmapped, unzoned attacker_ip the store holds. (Ingest takes the opposite
// route and drops a zoned address outright -- see publicUnicast. Both fail
// closed: nothing zoned is ever stored as evidence, and nothing zoned is
// ever stored as an exemption that would not work.)
func parseAllowlistCandidate(input string) (netip.Prefix, string, error) {
	input = strings.TrimSpace(input)

	if addr, err := netip.ParseAddr(input); err == nil {
		addr = addr.Unmap().WithZone("")
		return netip.PrefixFrom(addr, addr.BitLen()), allowlistWarning(addr), nil
	}

	p, err := netip.ParsePrefix(input)
	if err != nil {
		return netip.Prefix{}, "", fmt.Errorf("threat: allowlist entry %q: %w", input, err)
	}
	p = normalizeAllowlistPrefix(p)
	return p, allowlistWarning(p.Addr()), nil
}

// allowlistWarning reports the pointless-but-harmless case: an address that
// publicUnicast would reject at promotion time anyway.
func allowlistWarning(addr netip.Addr) string {
	if publicUnicast(addr) {
		return ""
	}
	return "not a public unicast address; it can never be promoted, so allowlisting it has no effect"
}
