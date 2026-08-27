// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"sync"
	"time"
)

// entry is one cached validation outcome, keyed on HMAC(pepper,
// system_id+":"+secret) -- see ForwardAuth.cacheKey. A positive entry
// carries the system_id; a negative entry (ok == false) does not need one.
type entry struct {
	ok        bool
	systemID  string
	expiresAt time.Time
}

// cache is a TTL cache of validation outcomes. A stale (TTL-expired) entry
// is kept rather than evicted: ForwardAuth.Validate falls back to it when
// the validator is unreachable, so "no cache hit" in the spec's fail-closed
// rule means no entry was ever cached for this key, not "the TTL lapsed a
// moment ago".
type cache struct {
	mu   sync.Mutex
	data map[string]entry
	now  func() time.Time
}

func newCache(now func() time.Time) *cache {
	return &cache{data: map[string]entry{}, now: now}
}

// get reports the entry for key, if any, and whether it is still within
// TTL. A found-but-stale entry is returned too, for the outage fallback.
func (c *cache) get(key string) (e entry, fresh, found bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, found = c.data[key]
	if !found {
		return entry{}, false, false
	}
	return e, c.now().Before(e.expiresAt), true
}

func (c *cache) set(key string, e entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = e
}
