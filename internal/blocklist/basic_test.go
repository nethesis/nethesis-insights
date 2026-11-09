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

const day = 24 * hour

// runBoth runs one pass with a fresh Runner and fresh snapshots, as a
// restarted threatd would, and returns the full and the basic feed.
func runBoth(t *testing.T, s *threatstore.Store, at int64) (full, basic *Snapshot) {
	t.Helper()
	return runBothCfg(t, s, testConfig(), at)
}

func runBothCfg(t *testing.T, s *threatstore.Store, cfg Config, at int64) (full, basic *Snapshot) {
	t.Helper()
	full, basic = NewSnapshot(), NewSnapshot()
	if err := New(s, full, basic, cfg).Run(context.Background(), at); err != nil {
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

// seedListed writes a live blocklist row directly, so a test controls its
// first_listed_at and expires_at to the millisecond. No events back it, so
// no pass refreshes it: it stays exactly as seeded until it expires.
func seedListed(t *testing.T, s *threatstore.Store, ip string, firstListed, expires int64) {
	t.Helper()
	seedListedSeen(t, s, ip, firstListed, firstListed, expires)
}

// seedListedSeen is seedListed with last_seen_at set too: the order both
// caps cut on.
func seedListedSeen(t *testing.T, s *threatstore.Store, ip string, firstListed, lastSeen, expires int64) {
	t.Helper()
	if err := s.UpsertBlocklistEntries(context.Background(), []threatstore.BlocklistRow{{
		AttackerIP:      ip,
		FirstListedAt:   firstListed,
		LastSeenAt:      lastSeen,
		ExpiresAt:       expires,
		DistinctSystems: 3,
		Scenarios:       []string{"ssh_bruteforce"},
	}}); err != nil {
		t.Fatalf("seed blocklist: %v", err)
	}
}

func serves(snap *Snapshot, ip string) bool {
	return strings.Contains(string(snap.View().Body), "\n"+ip+"\n")
}

func TestBasicCutoffIsTheDelayBeforeNow(t *testing.T) {
	cases := []struct {
		name  string
		delay time.Duration
		want  int64
	}{
		{"one day", 24 * time.Hour, now - day},
		{"one hour", time.Hour, now - hour},
		{"one millisecond", time.Millisecond, now - 1},
		{"sub-millisecond delay publishes nothing", 500 * time.Microsecond, math.MinInt64},
		{"zero delay publishes nothing", 0, math.MinInt64},
		{"negative delay publishes nothing", -time.Hour, math.MinInt64},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := BasicCutoff(now, c.delay); got != c.want {
				t.Fatalf("BasicCutoff: got %d, want %d", got, c.want)
			}
		})
	}
}

// An entry is on the basic feed iff it has been listed for at least the
// delay, measured from its own first_listed_at.
func TestBasicFeedPublishesAnEntryOnceListedForTheDelay(t *testing.T) {
	cases := []struct {
		name string
		age  int64
		want bool
	}{
		{"one millisecond short of the delay", day - 1, false},
		{"exactly the delay", day, true},
		{"one millisecond past the delay", day + 1, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newTestStore(t)
			seedListed(t, s, "203.0.113.7", now-c.age, now+2*day)

			full, basic := runBoth(t, s, now)
			if !serves(full, "203.0.113.7") {
				t.Fatalf("full feed does not serve a live entry:\n%s", full.View().Body)
			}
			if got := serves(basic, "203.0.113.7"); got != c.want {
				t.Fatalf("basic feed serves the entry: got %v, want %v\n%s", got, c.want, basic.View().Body)
			}
			if !basic.View().Ready {
				t.Fatal("an empty basic feed must still be ready: 503 would read as an outage")
			}
		})
	}
}

// Two addresses promoted at different times reach the basic feed at
// different times: there is no shared fleet-wide boundary at which every
// pending addition lands together.
func TestBasicFeedDelaysEachAddressFromItsOwnListing(t *testing.T) {
	s := newTestStore(t)
	// 13:00 and 16:00 UTC the day before now (12:00 UTC): both before the
	// same midnight, so an epoch-aligned boundary would publish them together.
	seedListed(t, s, "203.0.113.7", now-23*hour, now+2*day)
	seedListed(t, s, "198.51.100.9", now-20*hour, now+2*day)

	cases := []struct {
		name        string
		at          int64
		first, last bool
	}{
		{"neither has waited a day", now, false, false},
		{"the first has", now + hour, true, false},
		{"both have", now + 4*hour, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, basic := runBoth(t, s, c.at)
			if got := serves(basic, "203.0.113.7"); got != c.first {
				t.Fatalf("203.0.113.7 served: got %v, want %v", got, c.first)
			}
			if got := serves(basic, "198.51.100.9"); got != c.last {
				t.Fatalf("198.51.100.9 served: got %v, want %v", got, c.last)
			}
		})
	}
}

// End to end through promotion, with the defaults (delay and TTL both 24h):
// an address the fleet reports once expires before it has waited the delay,
// so it never reaches the basic feed; one the fleet keeps reporting does,
// and fresh snapshots (a restart) do not reset its wait.
func TestBasicFeedCarriesAddressesTheFleetKeepsReporting(t *testing.T) {
	s := newTestStore(t)
	promoteThree(t, s, "203.0.113.7")
	promoteThree(t, s, "198.51.100.9")

	full, basic := runBoth(t, s, now)
	if !serves(full, "203.0.113.7") || serves(basic, "203.0.113.7") {
		t.Fatal("a freshly promoted address must be on the full feed only")
	}

	// Only 203.0.113.7 is reported again, twenty hours later.
	for _, sys := range []string{"sys-a", "sys-b", "sys-c"} {
		report(t, s, sys, "203.0.113.7", "ssh_bruteforce", -20*hour)
	}
	runBoth(t, s, now+20*hour+minute)

	full, basic = runBoth(t, s, now+day)
	if !serves(basic, "203.0.113.7") {
		t.Fatalf("a re-reported address is not on the basic feed a day after its listing:\n%s", basic.View().Body)
	}
	if serves(full, "198.51.100.9") || serves(basic, "198.51.100.9") {
		t.Fatal("an address reported once must have expired before it waited out the delay")
	}
}

// Only additions are delayed. An address that expires or is allowlisted
// leaves both feeds on the same pass: the free tier must not keep blocking
// it for the whole delay.
func TestBasicFeedRemovalsReachBothFeedsOnTheSamePass(t *testing.T) {
	cases := []struct {
		name    string
		expires int64
		remove  func(t *testing.T, s *threatstore.Store)
	}{
		{
			name:    "expiry",
			expires: now + 10*minute,
			remove:  func(*testing.T, *threatstore.Store) {},
		},
		{
			name:    "allowlist",
			expires: now + 2*day,
			remove: func(t *testing.T, s *threatstore.Store) {
				if err := s.AddAllowlistEntry(context.Background(), threatstore.AllowlistRow{
					CIDR: "203.0.113.0/24", Reason: "partner scanner", CreatedBy: "ops", CreatedAt: now,
				}); err != nil {
					t.Fatalf("seed allowlist: %v", err)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newTestStore(t)
			seedListed(t, s, "203.0.113.7", now-30*hour, c.expires)
			if full, basic := runBoth(t, s, now); !serves(full, "203.0.113.7") || !serves(basic, "203.0.113.7") {
				t.Fatal("setup: the address is not on both feeds")
			}

			c.remove(t, s)
			full, basic := runBoth(t, s, now+15*minute)
			if serves(full, "203.0.113.7") || serves(basic, "203.0.113.7") {
				t.Fatalf("removed address still served: full=%v basic=%v",
					serves(full, "203.0.113.7"), serves(basic, "203.0.113.7"))
			}
		})
	}
}

// A delay that cannot hold anything back fails closed: an empty, ready
// basic feed, never the live list handed out without the entitlement.
// 500us truncates to zero milliseconds, the unit first_listed_at is in.
func TestBasicFeedFailsClosedOnANonPositiveDelay(t *testing.T) {
	for _, delay := range []time.Duration{500 * time.Microsecond, 0, -time.Hour} {
		t.Run(delay.String(), func(t *testing.T) {
			s := newTestStore(t)
			seedListed(t, s, "203.0.113.7", now-30*day, now+2*day)
			cfg := testConfig()
			cfg.BasicDelay = delay

			full, basic := runBothCfg(t, s, cfg, now)
			if !serves(full, "203.0.113.7") {
				t.Fatal("setup: the full feed does not serve the entry")
			}
			if v := basic.View(); !v.Ready || v.Entries != 0 {
				t.Fatalf("basic feed: ready=%v entries=%d, want ready and empty", v.Ready, v.Entries)
			}
		})
	}
}

// The header says what the basic list is, and the delay is part of the
// rule and therefore of the ETag: the two feeds never share a tag, so a
// cache keyed on it cannot answer one feed's poll with the other's body.
func TestBasicFeedNamesItsDelayAndHasItsOwnETag(t *testing.T) {
	s := newTestStore(t)
	seedListed(t, s, "203.0.113.7", now-30*hour, now+2*day)

	full, basic := runBoth(t, s, now)
	if !strings.Contains(string(basic.View().Body), "/ new entries after 24h0m0s\n") {
		t.Fatalf("basic header does not name its delay:\n%s", basic.View().Body)
	}
	if strings.Contains(string(full.View().Body), "new entries after") {
		t.Fatalf("full header names a delay:\n%s", full.View().Body)
	}
	if full.View().ETag == basic.View().ETag {
		t.Fatal("same entries, but the two feeds must not share an ETag")
	}
}

// The basic feed has its own cap and its own capped flag: it can bind
// while the full feed, under a larger cap, publishes everything. What is
// cut is what the fleet saw longest ago, as for the full feed.
func TestBasicCapBindsOnItsOwn(t *testing.T) {
	s := newTestStore(t)
	seedListedSeen(t, s, "203.0.113.1", now-30*hour, now-3*hour, now+2*day)
	seedListedSeen(t, s, "203.0.113.2", now-30*hour, now-2*hour, now+2*day)
	seedListedSeen(t, s, "203.0.113.3", now-30*hour, now-1*hour, now+2*day)
	cfg := testConfig()
	cfg.MaxEntries = 10
	cfg.BasicMaxEntries = 2

	full, basic := runBothCfg(t, s, cfg, now)
	if v := full.View(); v.Capped || v.Entries != 3 {
		t.Fatalf("full feed: capped=%v entries=%d, want uncapped with 3", v.Capped, v.Entries)
	}
	if v := basic.View(); !v.Capped || v.Entries != 2 {
		t.Fatalf("basic feed: capped=%v entries=%d, want capped with 2", v.Capped, v.Entries)
	}
	if serves(basic, "203.0.113.1") || !serves(basic, "203.0.113.2") || !serves(basic, "203.0.113.3") {
		t.Fatalf("basic cap kept the wrong rows:\n%s", basic.View().Body)
	}
}

// When the full cap binds, the rows it keeps are the most recently seen,
// which are mostly too new for the basic feed. The basic feed is filtered
// before it is capped, so those rows cannot take the eligible ones' slots.
func TestFullCapDoesNotStarveTheBasicFeed(t *testing.T) {
	s := newTestStore(t)
	// Listed an hour ago and seen a minute ago: first under the full cap,
	// not yet eligible for the basic feed.
	seedListedSeen(t, s, "198.51.100.1", now-hour, now-minute, now+2*day)
	seedListedSeen(t, s, "198.51.100.2", now-hour, now-minute, now+2*day)
	// Eligible, but seen two hours ago: cut by the full cap.
	seedListedSeen(t, s, "203.0.113.1", now-30*hour, now-2*hour, now+2*day)
	seedListedSeen(t, s, "203.0.113.2", now-30*hour, now-2*hour, now+2*day)
	cfg := testConfig()
	cfg.MaxEntries = 2
	cfg.BasicMaxEntries = 2

	full, basic := runBothCfg(t, s, cfg, now)
	if v := full.View(); !v.Capped || v.Entries != 2 || !serves(full, "198.51.100.1") || !serves(full, "198.51.100.2") {
		t.Fatalf("full feed: capped=%v entries=%d, want capped with the two fresh rows\n%s", v.Capped, v.Entries, v.Body)
	}
	if v := basic.View(); v.Capped || v.Entries != 2 || !serves(basic, "203.0.113.1") || !serves(basic, "203.0.113.2") {
		t.Fatalf("basic feed: capped=%v entries=%d, want uncapped with the two eligible rows\n%s", v.Capped, v.Entries, v.Body)
	}
}
