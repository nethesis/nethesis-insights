// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"testing"

	"github.com/nethesis/nethesis-insights/internal/ui/chrome"
)

// The operator UI's GET is unauthenticated and fleet-wide -- every cluster's
// node pressure and published cohorts -- so "off unless UI_LISTEN_ADDR is
// set" is a security property, not a convenience, exactly as
// cmd/insightsd/main_test.go pins for insightsd. Assert it directly here too
// rather than trusting that sizingd's copy of newUIServer kept the same
// early return.
func TestNewUIServerIsNilWhenTheAddressIsEmpty(t *testing.T) {
	if got := newUIServer("", "", nil, chrome.Info{}); got != nil {
		t.Fatalf("newUIServer(\"\") returned %v, want nil -- the UI must be off by default", got)
	}
}
