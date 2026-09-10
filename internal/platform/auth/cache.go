// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"container/list"
	"sync"
	"time"
)

// Cache sizes. Positives are bounded by the fleet -- one entry per
// (system_id, secret) actually in use, ~2700 today -- so the default has
// room for growth and for a credential rotation's overlap. Negatives are
// bounded by nothing but what arrives, which is why they are capped
// smaller: an entry there is worth much less (see cache).
//
// An entry is roughly 250 bytes including the hex key, the map bucket and
// the list node, so both tiers full is about 3 MB.
const (
	defaultMaxPositiveEntries = 8192
	defaultMaxNegativeEntries = 4096
)

// entry is one cached validation outcome, keyed on HMAC(pepper,
// system_id+":"+secret) -- see ForwardAuth.cacheKey. A positive entry
// carries the system_id; a negative entry (ok == false) does not need one.
type entry struct {
	ok        bool
	systemID  string
	expiresAt time.Time
}

// cache is a TTL cache of validation outcomes, in two separately capped
// LRU tiers: one for positive outcomes, one for negative.
//
// A stale (TTL-expired) entry is kept rather than evicted:
// ForwardAuth.Validate falls back to it when the validator is unreachable,
// so "no cache hit" in the spec's fail-closed rule means no entry was ever
// cached for this key, not "the TTL lapsed a moment ago". Eviction is
// therefore by recency and never by expiry.
//
// The two tiers are separate because one shared cap would be an attack.
// Any wrong credential mints an entry, and an attacker can mint distinct
// ones as fast as the proxy's rate limit allows; under a shared cap that
// flood evicts every real system's positive entry, which is precisely the
// outage fallback above. The fleet would then 503 on the next validator
// hiccup, at a moment of the attacker's choosing. Split, negatives can
// only ever evict other negatives.
type cache struct {
	mu  sync.Mutex
	now func() time.Time

	pos lruTier
	neg lruTier
}

func newCache(now func() time.Time, maxPositive, maxNegative int) *cache {
	return &cache{
		now: now,
		pos: newLRUTier(capOr(maxPositive, defaultMaxPositiveEntries)),
		neg: newLRUTier(capOr(maxNegative, defaultMaxNegativeEntries)),
	}
}

func capOr(n, def int) int {
	if n <= 0 {
		return def
	}
	return n
}

// setLimits applies the caller's caps, which are read on every request the
// way the TTLs are, so that every tunable behaves the same way.
func (c *cache) setLimits(maxPositive, maxNegative int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pos.max = capOr(maxPositive, defaultMaxPositiveEntries)
	c.neg.max = capOr(maxNegative, defaultMaxNegativeEntries)
	c.pos.evict()
	c.neg.evict()
}

// get reports the entry for key, if any, and whether it is still within
// TTL. A found-but-stale entry is returned too, for the outage fallback.
// A read counts as a use: it is what keeps a system that is checked often
// but validated rarely (the common case, since a fresh hit never reaches
// the validator) from ageing out of a full cache.
func (c *cache) get(key string) (e entry, fresh, found bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, found = c.pos.get(key); !found {
		e, found = c.neg.get(key)
	}
	if !found {
		return entry{}, false, false
	}
	return e, c.now().Before(e.expiresAt), true
}

func (c *cache) set(key string, e entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// An outcome that flipped must not linger in the other tier, where a
	// later get would find the superseded verdict first.
	if e.ok {
		c.neg.remove(key)
		c.pos.set(key, e)
		return
	}
	c.pos.remove(key)
	c.neg.set(key, e)
}

func (c *cache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pos.ll.Len() + c.neg.ll.Len()
}

// lruTier is a fixed-capacity map of entries that discards the least
// recently used one on overflow. Not safe for concurrent use: cache owns
// the lock for both tiers.
type lruTier struct {
	max   int
	ll    *list.List // front is most recently used
	items map[string]*list.Element
}

// lruNode is what an ll element holds. It carries its own key so eviction
// can delete the map entry without searching for it.
type lruNode struct {
	key string
	e   entry
}

func newLRUTier(max int) lruTier {
	return lruTier{max: max, ll: list.New(), items: map[string]*list.Element{}}
}

func (t *lruTier) get(key string) (entry, bool) {
	el, ok := t.items[key]
	if !ok {
		return entry{}, false
	}
	t.ll.MoveToFront(el)
	return el.Value.(*lruNode).e, true
}

func (t *lruTier) set(key string, e entry) {
	if el, ok := t.items[key]; ok {
		el.Value.(*lruNode).e = e
		t.ll.MoveToFront(el)
		return
	}
	t.items[key] = t.ll.PushFront(&lruNode{key: key, e: e})
	t.evict()
}

func (t *lruTier) remove(key string) {
	if el, ok := t.items[key]; ok {
		t.ll.Remove(el)
		delete(t.items, key)
	}
}

func (t *lruTier) evict() {
	for t.ll.Len() > t.max {
		oldest := t.ll.Back()
		t.ll.Remove(oldest)
		delete(t.items, oldest.Value.(*lruNode).key)
	}
}
