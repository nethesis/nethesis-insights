// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package blocklist

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	threatstore "github.com/nethesis/nethesis-insights/internal/store/threat"
)

// runBoth runs one pass with a fresh Runner and fresh snapshots, as a
// restarted threatd would, and returns the full and the basic feed.
func runBoth(t *testing.T, s *threatstore.Store, at int64) (full, basic *Snapshot) {
	t.Helper()
	full, basic = NewSnapshot(), NewSnapshot()
	if err := New(s, full, basic, testConfig()).Run(context.Background(), at); err != nil {
		t.Fatalf("Run: %v", err)
	}
	return full, basic
}

func promoteThree(t *testing.T, s *threatstore.Store, ip string) {
	t.Helper()
	for _, sys := range []string{"sys-a", "sys-b", "sys-c"} {
		report(t, s, sys, ip, "ssh_bruteforce", 5*minute)
	}
}

func serves(snap *Snapshot, ip string) bool {
	return strings.Contains(string(snap.View().Body), "\n"+ip+"\n")
}

func TestBasicCutoffAlignsToTheEpoch(t *testing.T) {
	midnight := time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC).UnixMilli()
	cases := []struct {
		name     string
		at       int64
		interval time.Duration
		want     int64
	}{
		{"midday rounds down to midnight UTC", now, 24 * time.Hour, midnight},
		{"exactly on the boundary", midnight, 24 * time.Hour, midnight},
		{"one millisecond before the boundary", midnight - 1, 24 * time.Hour, midnight - 24*hour},
		{"hourly interval", now + 30*minute, time.Hour, now},
		{"non-positive interval publishes nothing", now, 0, math.MinInt64},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := BasicCutoff(c.at, c.interval); got != c.want {
				t.Fatalf("BasicCutoff: got %d, want %d", got, c.want)
			}
		})
	}
}

// What the entitlement buys: a new address reaches the full feed on the
// pass that promotes it, and the basic feed only after the next boundary.
func TestBasicFeedWithholdsANewEntryUntilTheNextBoundary(t *testing.T) {
	s := newTestStore(t)
	promoteThree(t, s, "203.0.113.7")

	full, basic := runBoth(t, s, now)
	if !serves(full, "203.0.113.7") {
		t.Fatalf("full feed does not serve the promoted address:\n%s", full.View().Body)
	}
	if serves(basic, "203.0.113.7") {
		t.Fatalf("basic feed serves an address listed after its last boundary:\n%s", basic.View().Body)
	}
	if !basic.View().Ready {
		t.Fatal("an empty basic feed must still be ready: 503 would read as an outage")
	}

	// Still before the boundary: a later pass changes nothing.
	if _, basic = runBoth(t, s, now+11*hour); serves(basic, "203.0.113.7") {
		t.Fatal("basic feed took the address before the boundary")
	}

	// Past midnight UTC, with fresh snapshots: it is published, and the
	// rule is computed from first_listed_at, so a restart does not reset it.
	if _, basic = runBoth(t, s, now+12*hour+5*minute); !serves(basic, "203.0.113.7") {
		t.Fatalf("basic feed still withholds the address after the boundary:\n%s", basic.View().Body)
	}
}

// Only additions are delayed. An allowlisted address leaves both feeds on
// the same pass: the free tier must not keep blocking it for another day.
func TestBasicFeedDropsAnAllowlistedAddressOnTheSamePass(t *testing.T) {
	s := newTestStore(t)
	promoteThree(t, s, "203.0.113.7")
	runBoth(t, s, now)

	later := now + 12*hour + 5*minute
	if _, basic := runBoth(t, s, later); !serves(basic, "203.0.113.7") {
		t.Fatal("setup: the address never reached the basic feed")
	}

	if err := s.AddAllowlistEntry(context.Background(), threatstore.AllowlistRow{
		CIDR: "203.0.113.0/24", Reason: "partner scanner", CreatedBy: "ops", CreatedAt: later,
	}); err != nil {
		t.Fatalf("seed allowlist: %v", err)
	}

	full, basic := runBoth(t, s, later+5*minute)
	if serves(full, "203.0.113.7") || serves(basic, "203.0.113.7") {
		t.Fatalf("allowlisted address still served: full=%v basic=%v",
			serves(full, "203.0.113.7"), serves(basic, "203.0.113.7"))
	}
}

// An expired entry leaves the basic feed with the full one.
func TestBasicFeedDropsAnExpiredEntry(t *testing.T) {
	s := newTestStore(t)
	promoteThree(t, s, "203.0.113.7")
	runBoth(t, s, now)

	full, basic := runBoth(t, s, now+2*24*hour)
	if serves(full, "203.0.113.7") || serves(basic, "203.0.113.7") {
		t.Fatal("expired address still served")
	}
}

// The header says what the basic list is, and the delay is part of the
// rule and therefore of the ETag: the two feeds never share a tag, so a
// cache keyed on it cannot answer one feed's poll with the other's body.
func TestBasicFeedNamesItsDelayAndHasItsOwnETag(t *testing.T) {
	s := newTestStore(t)
	promoteThree(t, s, "203.0.113.7")
	runBoth(t, s, now)

	full, basic := runBoth(t, s, now+12*hour+5*minute)
	if !strings.Contains(string(basic.View().Body), "new entries every 24h0m0s") {
		t.Fatalf("basic header does not name its delay:\n%s", basic.View().Body)
	}
	if strings.Contains(string(full.View().Body), "new entries every") {
		t.Fatalf("full header names a delay:\n%s", full.View().Body)
	}
	if full.View().ETag == basic.View().ETag {
		t.Fatal("same entries, but the two feeds must not share an ETag")
	}
}
