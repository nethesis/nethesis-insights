// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"testing"

	"github.com/nethesis/nethesis-insights/internal/ui/chrome"
)

// The operator UI is unauthenticated and fleet-wide, so "off unless
// UI_LISTEN_ADDR is set" is a security property, not a convenience. Assert it
// directly rather than by inspection of main().
func TestNewUIServerIsNilWhenTheAddressIsEmpty(t *testing.T) {
	if got := newUIServer("", "", nil, nil, nil, "", chrome.Info{}); got != nil {
		t.Fatalf("newUIServer(\"\") returned %v, want nil -- the UI must be off by default", got)
	}
}

func TestNewUIServerBindsTheConfiguredAddress(t *testing.T) {
	srv := newUIServer("127.0.0.1:9596", "", nil, nil, nil, "", chrome.Info{})
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
