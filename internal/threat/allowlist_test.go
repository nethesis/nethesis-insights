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

// netip.Prefix.Contains is false for any address carrying a zone, because a
// prefix has none. Left unnormalized that turns the allowlist -- the only
// promotion exclusion there is -- into something a reporter can evade by
// appending "%1" to the address it wants promoted.
func TestAllowlistMatchesZonedAddresses(t *testing.T) {
	a, err := ParseAllowlist([]string{"2001:db8::/48", "203.0.113.0/24"})
	if err != nil {
		t.Fatalf("ParseAllowlist: %v", err)
	}
	for _, ip := range []string{"2001:db8::9%eth0", "2001:db8::9%1", "::ffff:203.0.113.7%eth0"} {
		if !a.Contains(netip.MustParseAddr(ip)) {
			t.Fatalf("%s: not allowlisted, want allowlisted -- a zone must not defeat the match", ip)
		}
	}
	if a.Contains(netip.MustParseAddr("2001:db9::9%eth0")) {
		t.Fatal("stripping the zone must not widen the match")
	}
}

// A v4-mapped prefix can never match what the store holds: attacker_ip is
// written unmapped, so ::ffff:203.0.113.0/120 stored verbatim would be an
// entry that silently matches nothing -- the same fail-open direction as a
// dropped row. It is normalized to its IPv4 form instead.
func TestParseAllowlistNormalizesIPv4MappedPrefixes(t *testing.T) {
	a, err := ParseAllowlist([]string{"::ffff:203.0.113.0/120"})
	if err != nil {
		t.Fatalf("ParseAllowlist: %v", err)
	}
	if !a.Contains(netip.MustParseAddr("203.0.113.7")) {
		t.Fatal("::ffff:203.0.113.0/120 must cover 203.0.113.7")
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
// full-length prefix) and enforces the over-broad-prefix guardrail. There is
// no override: a prefix wider than the floor is refused however it arrives.
func TestParseAllowlistEntry(t *testing.T) {
	cases := []struct {
		name        string
		input       string
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
		// The zone is dropped rather than the entry: the admin means the
		// address, and an entry stored with a zone could never match the
		// unmapped, unzoned attacker_ip the store holds.
		{name: "a zoned bare address loses its zone", input: "2001:db8::1%eth0", wantCIDR: "2001:db8::1/128"},
		{name: "a v4-mapped bare address normalizes to v4", input: "::ffff:203.0.113.7", wantCIDR: "203.0.113.7/32"},
		// A v4-mapped prefix becomes its v4 form, so the v4 floor -- not the
		// v6 one -- decides it. ::ffff:0.0.0.0/96 is 0.0.0.0/0 wearing a v6
		// hat, and used to clear the guardrail by being measured against /48.
		{name: "a v4-mapped prefix normalizes to v4", input: "::ffff:203.0.113.0/120", wantCIDR: "203.0.113.0/24"},
		{name: "a v4-mapped default route is rejected like 0.0.0.0/0", input: "::ffff:0.0.0.0/96", wantErr: true},
		{name: "v4 prefix wider than the floor is rejected", input: "203.0.113.0/16", wantErr: true},
		{name: "v6 prefix wider than the floor is rejected", input: "2001:db8::/32", wantErr: true},
		{name: "0.0.0.0/0 is rejected", input: "0.0.0.0/0", wantErr: true},
		{name: "::/0 is rejected", input: "::/0", wantErr: true},
		{
			// Pointless but harmless: publicUnicast is what promotion
			// checks, so a private entry can never exclude anything. A /8 is
			// also wider than the floor, hence the narrower prefix here.
			name:        "a private prefix is accepted with a warning",
			input:       "10.0.0.0/24",
			wantCIDR:    "10.0.0.0/24",
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
			cidr, warning, err := ParseAllowlistEntry(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseAllowlistEntry(%q): got nil error, want one", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseAllowlistEntry(%q): %v", tc.input, err)
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

// The floor must name the specific error so a caller can tell "malformed"
// apart from "too broad to be an exemption".
func TestParseAllowlistEntryTooBroadWrapsTheSentinelError(t *testing.T) {
	_, _, err := ParseAllowlistEntry("203.0.113.0/16")
	if !errors.Is(err, ErrAllowlistPrefixTooBroad) {
		t.Fatalf("error %v does not wrap ErrAllowlistPrefixTooBroad", err)
	}
}

// NormalizeAllowlistCIDR is for the paths that *name* an entry rather than
// create one -- removing a stored entry, recording a rejected request. Those
// must be able to name whatever is actually stored, so the breadth floor
// does not apply; nothing they do can exempt an address from promotion.
func TestNormalizeAllowlistCIDRSkipsTheBreadthFloor(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"0.0.0.0/0", "0.0.0.0/0"},
		{"::/0", "::/0"},
		{"203.0.113.0/16", "203.0.0.0/16"},
		{"203.0.113.7", "203.0.113.7/32"},
		{"2001:db8::1%eth0", "2001:db8::1/128"},
		{"::ffff:203.0.113.0/120", "203.0.113.0/24"},
	} {
		got, _, err := NormalizeAllowlistCIDR(tc.input)
		if err != nil {
			t.Fatalf("NormalizeAllowlistCIDR(%q): %v", tc.input, err)
		}
		if got != tc.want {
			t.Fatalf("NormalizeAllowlistCIDR(%q): got %q, want %q", tc.input, got, tc.want)
		}
	}

	// Malformed input is still refused -- skipping the floor is not
	// skipping validation.
	if _, _, err := NormalizeAllowlistCIDR("not-a-cidr"); err == nil {
		t.Fatal("NormalizeAllowlistCIDR: got nil error for garbage")
	}
}
