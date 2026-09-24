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

// validLimits mirrors validConsensus: the defaults every ingestLimits field
// must start from so a case below breaks exactly the one rule it names.
func validLimits() ingestLimits {
	return ingestLimits{
		QueueSize:             256,
		QueueWorkers:          2,
		QueueTimeout:          30 * time.Second,
		MaxDecisions:          500,
		MaxAllowlistPerSystem: 25,
	}
}

// The defaults must start. Every case below breaks exactly one rule on top
// of them, so a failure names the rule that broke rather than any other.
func TestValidateConfigAcceptsTheDefaults(t *testing.T) {
	if err := validateConfig(validConsensus(), 5*time.Minute, validLimits()); err != nil {
		t.Fatalf("defaults refused: %v", err)
	}
}

func TestValidateConfigRefusesEachBadValue(t *testing.T) {
	cases := []struct {
		name      string
		mutateCfg func(*blocklist.Config)
		mutateLim func(*ingestLimits)
		interval  time.Duration
		wantVar   string
	}{
		// BLOCKLIST_MIN_SYSTEMS=1 lets any single subscriber publish any
		// address fleet-wide; 2 is still below the documented rule.
		{name: "one system", mutateCfg: func(c *blocklist.Config) { c.MinSystems = 1 }, interval: time.Minute, wantVar: "BLOCKLIST_MIN_SYSTEMS"},
		{name: "two systems", mutateCfg: func(c *blocklist.Config) { c.MinSystems = 2 }, interval: time.Minute, wantVar: "BLOCKLIST_MIN_SYSTEMS"},
		// time.NewTicker panics on a non-positive interval.
		{name: "zero interval", interval: 0, wantVar: "BLOCKLIST_CONSENSUS_INTERVAL"},
		{name: "negative interval", interval: -time.Minute, wantVar: "BLOCKLIST_CONSENSUS_INTERVAL"},
		{name: "zero window", mutateCfg: func(c *blocklist.Config) { c.Window = 0 }, interval: time.Minute, wantVar: "BLOCKLIST_WINDOW"},
		// promote would write an expires_at already in the past, and the
		// same pass's ExpireBlocklist would delete it.
		{name: "ttl below window", mutateCfg: func(c *blocklist.Config) { c.TTL = 30 * time.Minute }, interval: time.Minute, wantVar: "BLOCKLIST_TTL"},
		{name: "zero max entries", mutateCfg: func(c *blocklist.Config) { c.MaxEntries = 0 }, interval: time.Minute, wantVar: "BLOCKLIST_MAX_ENTRIES"},
		// Events pruned before the window closes are never counted.
		{name: "retention below window", mutateCfg: func(c *blocklist.Config) { c.Retention = 30 * time.Minute }, interval: time.Minute, wantVar: "THREAT_EVENT_RETENTION"},
		{name: "zero request retention", mutateCfg: func(c *blocklist.Config) { c.AllowlistRequestRetention = 0 }, interval: time.Minute, wantVar: "THREAT_ALLOWLIST_REQUEST_RETENTION"},
		// An unbounded queue timeout, size or workers count, or an
		// unbounded per-request cap, each silently loses data one way or
		// another -- see the doc comment on ingestLimits.
		{name: "zero queue size", mutateLim: func(l *ingestLimits) { l.QueueSize = 0 }, interval: time.Minute, wantVar: "THREAT_QUEUE_SIZE"},
		{name: "zero queue workers", mutateLim: func(l *ingestLimits) { l.QueueWorkers = 0 }, interval: time.Minute, wantVar: "THREAT_QUEUE_WORKERS"},
		{name: "zero queue timeout", mutateLim: func(l *ingestLimits) { l.QueueTimeout = 0 }, interval: time.Minute, wantVar: "THREAT_QUEUE_TIMEOUT"},
		{name: "negative queue timeout", mutateLim: func(l *ingestLimits) { l.QueueTimeout = -time.Second }, interval: time.Minute, wantVar: "THREAT_QUEUE_TIMEOUT"},
		{name: "zero max decisions", mutateLim: func(l *ingestLimits) { l.MaxDecisions = 0 }, interval: time.Minute, wantVar: "THREAT_MAX_DECISIONS_PER_REQUEST"},
		{name: "zero max allowlist requests per system", mutateLim: func(l *ingestLimits) { l.MaxAllowlistPerSystem = 0 }, interval: time.Minute, wantVar: "THREAT_MAX_ALLOWLIST_REQUESTS_PER_SYSTEM"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConsensus()
			if tc.mutateCfg != nil {
				tc.mutateCfg(&cfg)
			}
			lim := validLimits()
			if tc.mutateLim != nil {
				tc.mutateLim(&lim)
			}
			err := validateConfig(cfg, tc.interval, lim)
			if err == nil {
				t.Fatalf("accepted; want an error naming %s", tc.wantVar)
			}
			if !strings.Contains(err.Error(), tc.wantVar) {
				t.Fatalf("error %q does not name %s", err, tc.wantVar)
			}
		})
	}
}
