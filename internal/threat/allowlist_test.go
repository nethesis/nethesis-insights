// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package threat

import (
	"net/netip"
	"testing"
)

func TestAllowlistContains(t *testing.T) {
	a, err := ParseAllowlist([]string{"203.0.113.0/24", "198.51.100.7/32", "2001:db8::/32"})
	if err != nil {
		t.Fatalf("ParseAllowlist: %v", err)
	}

	in := []string{"203.0.113.1", "203.0.113.255", "198.51.100.7", "2001:db8::dead"}
	out := []string{"203.0.114.1", "198.51.100.8", "2001:db9::1", "192.0.2.1"}

	for _, ip := range in {
		if !a.Contains(netip.MustParseAddr(ip)) {
			t.Fatalf("%s: not allowlisted, want allowlisted", ip)
		}
	}
	for _, ip := range out {
		if a.Contains(netip.MustParseAddr(ip)) {
			t.Fatalf("%s: allowlisted, want not allowlisted", ip)
		}
	}
}

// A host-bit-carrying prefix like 203.0.113.5/24 is what a human types; it
// must behave as the /24 rather than matching nothing.
func TestAllowlistMasksHostBits(t *testing.T) {
	a, err := ParseAllowlist([]string{"203.0.113.5/24"})
	if err != nil {
		t.Fatalf("ParseAllowlist: %v", err)
	}
	if !a.Contains(netip.MustParseAddr("203.0.113.200")) {
		t.Fatal("203.0.113.200 should be covered by 203.0.113.5/24")
	}
}

func TestAllowlistMatchesIPv4MappedAddresses(t *testing.T) {
	a, _ := ParseAllowlist([]string{"203.0.113.0/24"})
	if !a.Contains(netip.MustParseAddr("::ffff:203.0.113.7")) {
		t.Fatal("an IPv4-mapped address must match its IPv4 prefix")
	}
}

// An allowlist that silently lost a row would fail open, listing an address
// someone had explicitly excluded.
func TestParseAllowlistRejectsAnInvalidEntry(t *testing.T) {
	if _, err := ParseAllowlist([]string{"203.0.113.0/24", "not-a-cidr"}); err == nil {
		t.Fatal("ParseAllowlist: got nil error for an invalid entry")
	}
	// A bare address is not a prefix; requiring the mask keeps the intent
	// explicit rather than guessing /32.
	if _, err := ParseAllowlist([]string{"203.0.113.7"}); err == nil {
		t.Fatal("ParseAllowlist: got nil error for a bare address")
	}
}

func TestEmptyAllowlistContainsNothing(t *testing.T) {
	a, err := ParseAllowlist(nil)
	if err != nil {
		t.Fatalf("ParseAllowlist(nil): %v", err)
	}
	if a.Len() != 0 {
		t.Fatalf("Len: got %d, want 0", a.Len())
	}
	if a.Contains(netip.MustParseAddr("203.0.113.1")) {
		t.Fatal("an empty allowlist must contain nothing")
	}
}
