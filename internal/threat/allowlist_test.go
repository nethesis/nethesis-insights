// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package threat

import (
	"errors"
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

// ParseAllowlistEntry is the admin/request-path validator: unlike
// ParseAllowlist above, it accepts a bare address (normalizing it to a
// full-length prefix) and enforces the over-broad-prefix guardrail.
func TestParseAllowlistEntry(t *testing.T) {
	cases := []struct {
		name        string
		input       string
		force       bool
		wantCIDR    string
		wantWarning bool
		wantErr     bool
	}{
		{name: "bare v4 address normalizes to /32", input: "203.0.113.7", wantCIDR: "203.0.113.7/32"},
		{name: "bare v6 address normalizes to /128", input: "2001:db8::1", wantCIDR: "2001:db8::1/128"},
		{name: "v4 prefix at the floor is accepted", input: "203.0.113.0/24", wantCIDR: "203.0.113.0/24"},
		{name: "v4 prefix narrower than the floor is accepted", input: "203.0.113.0/28", wantCIDR: "203.0.113.0/28"},
		{name: "v6 prefix at the floor is accepted", input: "2001:db8::/48", wantCIDR: "2001:db8::/48"},
		{name: "unmasked prefix is masked", input: "203.0.113.5/24", wantCIDR: "203.0.113.0/24"},
		{
			name:    "v4 prefix wider than the floor is rejected without force",
			input:   "203.0.113.0/16",
			wantErr: true,
		},
		{
			name:     "v4 prefix wider than the floor is accepted with force",
			input:    "203.0.113.0/16",
			force:    true,
			wantCIDR: "203.0.0.0/16", // masked: only the network bits survive
		},
		{
			name:    "v6 prefix wider than the floor is rejected without force",
			input:   "2001:db8::/32",
			wantErr: true,
		},
		{
			name:     "v6 prefix wider than the floor is accepted with force",
			input:    "2001:db8::/32",
			force:    true,
			wantCIDR: "2001:db8::/32",
		},
		{
			name:    "0.0.0.0/0 is rejected without force",
			input:   "0.0.0.0/0",
			wantErr: true,
		},
		{
			// Not rejected by ParseAllowlistEntry with force, but the network
			// address of 0.0.0.0/0 is the unspecified address, which
			// publicUnicast rejects -- so this carries a warning too, on top
			// of being the exact case the guardrail exists for.
			name:        "0.0.0.0/0 is accepted with force",
			input:       "0.0.0.0/0",
			force:       true,
			wantCIDR:    "0.0.0.0/0",
			wantWarning: true,
		},
		{
			name:        "a private prefix is accepted with a warning",
			input:       "10.0.0.0/8",
			force:       true,
			wantCIDR:    "10.0.0.0/8",
			wantWarning: true,
		},
		{
			name:        "a bare loopback address is accepted with a warning",
			input:       "127.0.0.1",
			wantCIDR:    "127.0.0.1/32",
			wantWarning: true,
		},
		{name: "garbage is rejected", input: "not-a-cidr", wantErr: true},
		{name: "empty is rejected", input: "", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cidr, warning, err := ParseAllowlistEntry(tc.input, tc.force)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseAllowlistEntry(%q, %v): got nil error, want one", tc.input, tc.force)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseAllowlistEntry(%q, %v): %v", tc.input, tc.force, err)
			}
			if cidr != tc.wantCIDR {
				t.Fatalf("cidr: got %q, want %q", cidr, tc.wantCIDR)
			}
			if (warning != "") != tc.wantWarning {
				t.Fatalf("warning: got %q, want non-empty=%v", warning, tc.wantWarning)
			}
		})
	}
}

// The floor without force must name the specific error so an admin API
// caller can tell "malformed" apart from "too broad, needs force".
func TestParseAllowlistEntryTooBroadWrapsTheSentinelError(t *testing.T) {
	_, _, err := ParseAllowlistEntry("203.0.113.0/16", false)
	if !errors.Is(err, ErrAllowlistPrefixTooBroad) {
		t.Fatalf("error %v does not wrap ErrAllowlistPrefixTooBroad", err)
	}
}
