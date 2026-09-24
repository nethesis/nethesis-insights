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
		IngestRetention:           2160 * time.Hour,
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

// A consensus interval equal to the window is fine -- every sighting is
// still inside the window for at least one pass. Only exceeding it leaves a
// gap no pass ever counts.
func TestValidateConfigAcceptsAnIntervalEqualToTheWindow(t *testing.T) {
	cfg := validConsensus()
	if err := validateConfig(cfg, cfg.Window, validLimits()); err != nil {
		t.Fatalf("interval == window refused: %v", err)
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
		// A pass every 2h cannot count a sighting that lands inside a 1h
		// window and ages back out of it before the next pass runs.
		{name: "interval longer than window", interval: 2 * time.Hour, wantVar: "must not exceed BLOCKLIST_WINDOW"},
		// promote would write an expires_at already in the past, and the
		// same pass's ExpireBlocklist would delete it.
		{name: "ttl below window", mutateCfg: func(c *blocklist.Config) { c.TTL = 30 * time.Minute }, interval: time.Minute, wantVar: "BLOCKLIST_TTL"},
		{name: "zero max entries", mutateCfg: func(c *blocklist.Config) { c.MaxEntries = 0 }, interval: time.Minute, wantVar: "BLOCKLIST_MAX_ENTRIES"},
		// Events pruned before the window closes are never counted.
		{name: "retention below window", mutateCfg: func(c *blocklist.Config) { c.Retention = 30 * time.Minute }, interval: time.Minute, wantVar: "THREAT_EVENT_RETENTION"},
		{name: "zero request retention", mutateCfg: func(c *blocklist.Config) { c.AllowlistRequestRetention = 0 }, interval: time.Minute, wantVar: "THREAT_ALLOWLIST_REQUEST_RETENTION"},
		// threat_ingest_daily grows one row per reporting system per
		// day forever without a floor on its own retention.
		{name: "zero ingest retention", mutateCfg: func(c *blocklist.Config) { c.IngestRetention = 0 }, interval: time.Minute, wantVar: "THREAT_INGEST_RETENTION"},
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

// setValidThreatdEnv sets every environment variable loadStartupConfig reads
// to a value it accepts, so a test can override just the one or two it cares
// about without a stray unset variable also happening to be invalid and
// masking the assertion.
func setValidThreatdEnv(t *testing.T) {
	t.Helper()
	for k, v := range map[string]string{
		"BLOCKLIST_CONSENSUS_INTERVAL":             "5m",
		"BLOCKLIST_WINDOW":                         "1h",
		"BLOCKLIST_MIN_SYSTEMS":                    "3",
		"BLOCKLIST_TTL":                            "24h",
		"BLOCKLIST_MAX_ENTRIES":                    "50000",
		"THREAT_EVENT_RETENTION":                   "168h",
		"THREAT_INGEST_RETENTION":                  "2160h",
		"THREAT_MAX_DECISIONS_PER_REQUEST":         "500",
		"THREAT_MAX_ALLOWLIST_REQUESTS_PER_SYSTEM": "25",
		"THREAT_ALLOWLIST_REQUEST_RETENTION":       "2160h",
		"THREAT_QUEUE_SIZE":                        "256",
		"THREAT_QUEUE_WORKERS":                     "2",
		"THREAT_QUEUE_TIMEOUT":                     "30s",
	} {
		t.Setenv(k, v)
	}
}

func TestLoadStartupConfigAcceptsAFullyValidEnvironment(t *testing.T) {
	setValidThreatdEnv(t)

	cfg, interval, limits, err := loadStartupConfig()
	if err != nil {
		t.Fatalf("loadStartupConfig: %v", err)
	}
	if interval != 5*time.Minute || cfg.Window != time.Hour || cfg.IngestRetention != 2160*time.Hour || limits.QueueSize != 256 {
		t.Fatalf("loadStartupConfig did not parse the environment: interval=%v cfg=%+v limits=%+v",
			interval, cfg, limits)
	}
}

// A set-but-unparseable value (a plain GetenvDuration/GetenvInt would fall
// back to the default and start anyway) and an out-of-range one must
// both be named in the one error loadStartupConfig returns -- not just the
// first problem it happens to find.
func TestLoadStartupConfigReportsParseAndRangeErrorsTogether(t *testing.T) {
	setValidThreatdEnv(t)
	// Go's ParseDuration has no "d" unit: the documented failure mode for
	// THREAT_EVENT_RETENTION=30d silently becoming the 168h default.
	t.Setenv("THREAT_EVENT_RETENTION", "30d")
	t.Setenv("BLOCKLIST_MAX_ENTRIES", "0")

	_, _, _, err := loadStartupConfig()
	if err == nil {
		t.Fatal("loadStartupConfig: got nil error, want one naming both problems")
	}
	for _, want := range []string{"THREAT_EVENT_RETENTION", "BLOCKLIST_MAX_ENTRIES"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not name %s", err, want)
		}
	}
}
