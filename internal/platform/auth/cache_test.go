// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// farFuture is an expiry no test's clock reaches, for cases about eviction
// rather than about the TTL.
func farFuture() time.Time { return time.Unix(1<<40, 0) }

func positive(systemID string) entry {
	return entry{ok: true, systemID: systemID, expiresAt: farFuture()}
}

func negative() entry {
	return entry{ok: false, expiresAt: farFuture()}
}

func TestPositiveEntriesEvictLeastRecentlyUsedAtCap(t *testing.T) {
	c := newCache(time.Now, 2, 2)

	c.set("a", positive("sys-a"))
	c.set("b", positive("sys-b"))
	c.set("c", positive("sys-c"))

	if _, _, found := c.get("a"); found {
		t.Error("a should have been evicted as least recently used")
	}
	for _, key := range []string{"b", "c"} {
		if _, _, found := c.get(key); !found {
			t.Errorf("%s should still be cached", key)
		}
	}
}

func TestReadingAnEntryMakesItMostRecentlyUsed(t *testing.T) {
	c := newCache(time.Now, 2, 2)

	c.set("a", positive("sys-a"))
	c.set("b", positive("sys-b"))
	if _, _, found := c.get("a"); !found {
		t.Fatal("a should be cached before the third insert")
	}
	c.set("c", positive("sys-c"))

	if _, _, found := c.get("b"); found {
		t.Error("b should have been evicted: reading a made b the least recently used")
	}
	if _, _, found := c.get("a"); !found {
		t.Error("a should have survived: it was read after being written")
	}
}

// A flood of distinct wrong credentials must never cost a real system its
// cached outcome. Positives are the outage fallback (see the cache's doc
// comment), so one shared cap would let an attacker empty that fallback on
// demand and then wait for the validator to go down.
func TestNegativeFloodNeverEvictsPositives(t *testing.T) {
	c := newCache(time.Now, 4, 2)

	for i := 0; i < 4; i++ {
		c.set(fmt.Sprintf("sys-%d", i), positive(fmt.Sprintf("sys-%d", i)))
	}
	for i := 0; i < 500; i++ {
		c.set(fmt.Sprintf("wrong-%d", i), negative())
	}

	for i := 0; i < 4; i++ {
		key := fmt.Sprintf("sys-%d", i)
		e, _, found := c.get(key)
		if !found {
			t.Fatalf("%s was evicted by a negative flood", key)
		}
		if !e.ok || e.systemID != key {
			t.Fatalf("%s came back as %+v", key, e)
		}
	}
}

func TestNegativeEntriesAreCappedToo(t *testing.T) {
	c := newCache(time.Now, 4, 2)

	c.set("a", negative())
	c.set("b", negative())
	c.set("c", negative())

	if _, _, found := c.get("a"); found {
		t.Error("a should have been evicted as least recently used")
	}
	if _, _, found := c.get("c"); !found {
		t.Error("c should still be cached")
	}
}

// Eviction is by recency, never by expiry: Validate's unavailable branch
// serves a stale entry, so dropping one at TTL would turn a recoverable
// outage into a fleet-wide 503.
func TestStaleEntriesAreKeptForTheOutageFallback(t *testing.T) {
	now := time.Unix(1000, 0)
	c := newCache(func() time.Time { return now }, 2, 2)

	c.set("a", entry{ok: true, systemID: "sys-a", expiresAt: now.Add(time.Minute)})
	now = now.Add(time.Hour)

	e, fresh, found := c.get("a")
	if !found {
		t.Fatal("a should still be cached after its TTL lapsed")
	}
	if fresh {
		t.Error("a should be reported stale")
	}
	if e.systemID != "sys-a" {
		t.Errorf("systemID = %q, want sys-a", e.systemID)
	}
}

func TestNonPositiveCapsFallBackToTheDefaults(t *testing.T) {
	c := newCache(time.Now, 0, -1)

	if c.pos.max != defaultMaxPositiveEntries {
		t.Errorf("maxPositive = %d, want %d", c.pos.max, defaultMaxPositiveEntries)
	}
	if c.neg.max != defaultMaxNegativeEntries {
		t.Errorf("maxNegative = %d, want %d", c.neg.max, defaultMaxNegativeEntries)
	}
}

// The cap is reachable through the exported surface too, not only by
// calling the unexported cache directly.
func TestForwardAuthCapsItsNegativeCache(t *testing.T) {
	v := &validator{status: http.StatusUnauthorized}
	srv := v.server(t)
	defer srv.Close()

	a := newAuth(t, srv.URL, time.Now)
	a.MaxNegativeEntries = 2

	for i := 0; i < 100; i++ {
		_, _ = a.Validate(context.Background(), basicHeader(fmt.Sprintf("sys-%d", i), "wrong"))
	}

	if got := a.cache.len(); got > 2 {
		t.Errorf("negative cache holds %d entries, want at most 2", got)
	}
}
