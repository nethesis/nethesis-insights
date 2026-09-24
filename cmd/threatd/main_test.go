// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/nethesis/nethesis-insights/internal/blocklist"
	"github.com/nethesis/nethesis-insights/internal/ui/chrome"
)

// The operator UI's GET is unauthenticated and fleet-wide -- every promoted
// blocklist entry, every reported event -- so "off unless UI_LISTEN_ADDR is
// set" is a security property, not a convenience, exactly as
// cmd/insightsd/main_test.go pins for insightsd. Assert it directly here too
// rather than trusting that threatd's copy of newUIServer kept the same
// early return.
func TestNewUIServerIsNilWhenTheAddressIsEmpty(t *testing.T) {
	if got := newUIServer("", "", nil, nil, nil, nil, "", chrome.Info{}); got != nil {
		t.Fatalf("newUIServer(\"\") returned %v, want nil -- the UI must be off by default", got)
	}
}

func validConsensus() blocklist.Config {
	return blocklist.Config{
		Window:                    time.Hour,
		MinSystems:                3,
		TTL:                       24 * time.Hour,
		MaxEntries:                50000,
		Retention:                 168 * time.Hour,
		AllowlistRequestRetention: 2160 * time.Hour,
	}
}

// The defaults must start. Every case below breaks exactly one rule on top
// of them, so a failure names the rule that broke rather than any other.
func TestValidateConsensusAcceptsTheDefaults(t *testing.T) {
	if err := validateConsensus(validConsensus(), 5*time.Minute); err != nil {
		t.Fatalf("defaults refused: %v", err)
	}
}

func TestValidateConsensusRefusesEachBadValue(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*blocklist.Config)
		interval time.Duration
		wantVar  string
	}{
		// BLOCKLIST_MIN_SYSTEMS=1 lets any single subscriber publish any
		// address fleet-wide; 2 is still below the documented rule.
		{"one system", func(c *blocklist.Config) { c.MinSystems = 1 }, time.Minute, "BLOCKLIST_MIN_SYSTEMS"},
		{"two systems", func(c *blocklist.Config) { c.MinSystems = 2 }, time.Minute, "BLOCKLIST_MIN_SYSTEMS"},
		// time.NewTicker panics on a non-positive interval.
		{"zero interval", func(*blocklist.Config) {}, 0, "BLOCKLIST_CONSENSUS_INTERVAL"},
		{"negative interval", func(*blocklist.Config) {}, -time.Minute, "BLOCKLIST_CONSENSUS_INTERVAL"},
		{"zero window", func(c *blocklist.Config) { c.Window = 0 }, time.Minute, "BLOCKLIST_WINDOW"},
		// promote would write an expires_at already in the past, and the
		// same pass's ExpireBlocklist would delete it.
		{"ttl below window", func(c *blocklist.Config) { c.TTL = 30 * time.Minute }, time.Minute, "BLOCKLIST_TTL"},
		{"zero max entries", func(c *blocklist.Config) { c.MaxEntries = 0 }, time.Minute, "BLOCKLIST_MAX_ENTRIES"},
		// Events pruned before the window closes are never counted.
		{"retention below window", func(c *blocklist.Config) { c.Retention = 30 * time.Minute }, time.Minute, "THREAT_EVENT_RETENTION"},
		{"zero request retention", func(c *blocklist.Config) { c.AllowlistRequestRetention = 0 }, time.Minute, "THREAT_ALLOWLIST_REQUEST_RETENTION"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConsensus()
			tc.mutate(&cfg)
			err := validateConsensus(cfg, tc.interval)
			if err == nil {
				t.Fatalf("accepted; want an error naming %s", tc.wantVar)
			}
			if !strings.Contains(err.Error(), tc.wantVar) {
				t.Fatalf("error %q does not name %s", err, tc.wantVar)
			}
		})
	}
}
