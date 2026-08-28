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

// MinAllowlistPrefixV4 and MinAllowlistPrefixV6 are the narrowest prefix an
// admin may allowlist without passing force. Below these floors a single
// entry hides a meaningful slice of the address space from consensus --
// 0.0.0.0/0 is the extreme case, and it would do so silently: nothing else
// in the system would report that the feed had quietly stopped growing.
// The floor is per address family because "how much address space" a given
// bit count covers is wildly different between the two.
const (
	MinAllowlistPrefixV4 = 24
	MinAllowlistPrefixV6 = 48
)

// ErrAllowlistPrefixTooBroad is returned by ParseAllowlistEntry when a
// prefix is wider than the guardrail floor for its address family and the
// caller did not pass force.
var ErrAllowlistPrefixTooBroad = errors.New("threat: allowlist prefix is broader than the guardrail floor")

// ParseAllowlistEntry validates and normalizes one admin- or
// customer-supplied allowlist candidate -- a bare address or a CIDR -- into
// the canonical string this server stores and compares by text equality,
// exactly like attacker_ip.
//
// A bare address normalizes to a full-length prefix (/32 or /128), which
// trivially clears the guardrail below since it can only ever cover the one
// address; anything wider than MinAllowlistPrefixV4/V6 is rejected unless
// force is true.
//
// The returned warning is non-empty (and err nil) when the address is not
// public unicast: publicUnicast is exactly what promotion checks, so a
// private or reserved entry can never be promoted in the first place --
// allowlisting one is pointless but harmless, and rejecting it outright
// would be a confusing error for a request that does no damage.
func ParseAllowlistEntry(input string, force bool) (cidr string, warning string, err error) {
	input = strings.TrimSpace(input)

	if addr, aerr := netip.ParseAddr(input); aerr == nil {
		addr = addr.Unmap()
		p := netip.PrefixFrom(addr, addr.BitLen())
		return p.String(), allowlistWarning(addr), nil
	}

	p, perr := netip.ParsePrefix(input)
	if perr != nil {
		return "", "", fmt.Errorf("threat: allowlist entry %q: %w", input, perr)
	}
	p = p.Masked()

	if !force {
		floor := MinAllowlistPrefixV4
		if p.Addr().Is6() {
			floor = MinAllowlistPrefixV6
		}
		if p.Bits() < floor {
			return "", "", fmt.Errorf("%w: %s is a /%d, the floor is /%d for this address family (pass force to override)",
				ErrAllowlistPrefixTooBroad, p, p.Bits(), floor)
		}
	}

	return p.String(), allowlistWarning(p.Addr().Unmap()), nil
}

// allowlistWarning reports the pointless-but-harmless case: an address that
// publicUnicast would reject at promotion time anyway.
func allowlistWarning(addr netip.Addr) string {
	if publicUnicast(addr) {
		return ""
	}
	return "not a public unicast address; it can never be promoted, so allowlisting it has no effect"
}
