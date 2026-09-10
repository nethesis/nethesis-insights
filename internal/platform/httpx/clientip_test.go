// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// ClientIP is the input to threat.Sanitize's reporter-own-address check, so
// a wrong answer here is a wrong drop decision on a third party's address.
// The rule: X-Forwarded-For is consulted only when RemoteAddr is a proxy we
// configured, and then only its rightmost entry -- Traefik overwrites the
// header, but rightmost stays correct if it is ever configured to append.
func TestClientIP(t *testing.T) {
	trusted, err := ParseTrustedProxies("127.0.0.0/8,::1/128")
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}

	cases := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{"untrusted remote, no header", "203.0.113.7:4444", "", "203.0.113.7"},
		{"untrusted remote ignores a forged header", "203.0.113.7:4444", "10.0.0.1", "203.0.113.7"},
		{"trusted remote, single value", "127.0.0.1:5555", "198.51.100.9", "198.51.100.9"},
		{"trusted remote takes the rightmost value", "127.0.0.1:5555", "10.0.0.1, 198.51.100.9", "198.51.100.9"},
		{"trusted remote, no header", "127.0.0.1:5555", "", "127.0.0.1"},
		{"trusted remote, unparseable header", "127.0.0.1:5555", "not-an-address", "127.0.0.1"},
		{"trusted remote, empty header", "127.0.0.1:5555", "   ", "127.0.0.1"},
		{"trusted IPv6 loopback", "[::1]:5555", "198.51.100.9", "198.51.100.9"},
		{"remote addr without a port", "127.0.0.1", "198.51.100.9", "198.51.100.9"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/v1/events", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := ClientIP(r, trusted); got != tc.want {
				t.Errorf("ClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// An empty configuration must trust nobody rather than everybody: a missing
// TRUSTED_PROXY_CIDRS must not silently turn the header on.
func TestEmptyTrustedProxiesTrustsNoHeader(t *testing.T) {
	var none TrustedProxies
	r := httptest.NewRequest(http.MethodPost, "/v1/events", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("X-Forwarded-For", "198.51.100.9")
	if got := ClientIP(r, none); got != "127.0.0.1" {
		t.Errorf("ClientIP = %q, want the remote address", got)
	}
}

// A bare address (no "/bits") in TRUSTED_PROXY_CIDRS must be promoted to a
// single-host prefix, not silently dropped and not widened to its subnet --
// an operator who configured "the proxy's one address" must not end up
// trusting its whole /24 or /64 by accident.
func TestParseTrustedProxiesPromotesABareAddressToASingleHost(t *testing.T) {
	trusted, err := ParseTrustedProxies("203.0.113.5")
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	if !trusted.Contains("203.0.113.5:1234") {
		t.Error("the bare address itself must be trusted")
	}
	if trusted.Contains("203.0.113.6:1234") {
		t.Error("a neighboring address must not be trusted -- a bare address must be a /32, not a widened subnet")
	}

	trustedV6, err := ParseTrustedProxies("2001:db8::1")
	if err != nil {
		t.Fatalf("ParseTrustedProxies (v6): %v", err)
	}
	if !trustedV6.Contains("[2001:db8::1]:1234") {
		t.Error("the bare IPv6 address itself must be trusted")
	}
	if trustedV6.Contains("[2001:db8::2]:1234") {
		t.Error("a neighboring IPv6 address must not be trusted -- a bare address must be a /128, not a widened subnet")
	}
}

// A value that is neither a CIDR prefix nor a bare address must fail the
// parse rather than being silently dropped: a dropped entry in a
// comma-separated list could mask a config typo that was meant to name a
// real, different proxy, and TRUSTED_PROXY_CIDRS is the whole trust
// boundary for reading system_id and X-Forwarded-For.
func TestParseTrustedProxiesRejectsAnUnparseableEntry(t *testing.T) {
	if _, err := ParseTrustedProxies("not-an-address"); err == nil {
		t.Fatal("ParseTrustedProxies(garbage) returned a nil error")
	}
	if _, err := ParseTrustedProxies("127.0.0.1/8,not-an-address"); err == nil {
		t.Fatal("ParseTrustedProxies with one bad entry among good ones returned a nil error")
	}
}
