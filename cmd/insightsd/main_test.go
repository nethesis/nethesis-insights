// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"testing"

	"github.com/nethesis/nethesis-insights/internal/ui"
)

// The operator UI is unauthenticated and fleet-wide, so "off unless
// UI_LISTEN_ADDR is set" is a security property, not a convenience. Assert it
// directly rather than by inspection of main().
func TestNewUIServerIsNilWhenTheAddressIsEmpty(t *testing.T) {
	if got := newUIServer("", nil, nil, nil, ui.Info{}, nil, ""); got != nil {
		t.Fatalf("newUIServer(\"\") returned %v, want nil -- the UI must be off by default", got)
	}
}

func TestNewUIServerBindsTheConfiguredAddress(t *testing.T) {
	srv := newUIServer("127.0.0.1:9596", nil, nil, nil, ui.Info{}, nil, "")
	if srv == nil {
		t.Fatal("newUIServer returned nil for a configured address")
	}
	if srv.Addr != "127.0.0.1:9596" {
		t.Fatalf("addr: got %q, want %q", srv.Addr, "127.0.0.1:9596")
	}
	if srv.Handler == nil {
		t.Fatal("ui server has no handler")
	}
	// Its own timeout: an unauthenticated listener must not be holdable open
	// by a client that never finishes sending its headers.
	if srv.ReadHeaderTimeout <= 0 {
		t.Fatalf("ReadHeaderTimeout: got %v, want a positive timeout", srv.ReadHeaderTimeout)
	}
}

func TestIsLoopbackBind(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:9596", true},
		{"127.1.2.3:9596", true},
		{"[::1]:9596", true},
		// Every interface: the case the startup warning exists for.
		{":9596", false},
		{"0.0.0.0:9596", false},
		{"[::]:9596", false},
		{"10.0.0.5:9596", false},
		// Not a literal IP, so not provably loopback.
		{"localhost:9596", false},
		// Unparseable: warn rather than assume the safe answer.
		{"9596", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isLoopbackBind(c.addr); got != c.want {
			t.Errorf("isLoopbackBind(%q): got %v, want %v", c.addr, got, c.want)
		}
	}
}

// secretState is the only thing standing between AUTH_PEPPER / LLM_API_KEY and
// an unauthenticated status page.
func TestSecretStateNeverCarriesAValue(t *testing.T) {
	if got := secretState(true); got != "set" {
		t.Fatalf("secretState(true): got %q, want %q", got, "set")
	}
	if got := secretState(false); got != "unset" {
		t.Fatalf("secretState(false): got %q, want %q", got, "unset")
	}
}
