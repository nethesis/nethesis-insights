// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package chrome

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Traefik strips the prefix before proxying, so route() never sees it and
// every emitted URL has to put it back. Every link on every page goes
// through Link, which is why it is the only place that knows the base
// exists.
func TestLink(t *testing.T) {
	cases := []struct{ base, path, want string }{
		{"", "/", "/"},
		{"", "/systems", "/systems"},
		{"/blocklist", "/", "/blocklist/"},
		{"/blocklist", "/events", "/blocklist/events"},
		{"/blocklist", "/static/style.css", "/blocklist/static/style.css"},
		{"/blocklist/", "/events", "/blocklist/events"},
		{"blocklist", "/events", "/blocklist/events"},
	}
	for _, tc := range cases {
		b := &Base{basePath: normalizeBase(tc.base)}
		if got := b.Link(tc.path); got != tc.want {
			t.Errorf("Link(%q) with base %q = %q, want %q", tc.path, tc.base, got, tc.want)
		}
	}
}

// The refresh links rebuild the current URL with one query parameter
// changed. r.URL.Path is post-strip, so the base has to be re-applied or
// every refresh link escapes the pipeline's subtree.
func TestRefreshLinksCarryTheBasePath(t *testing.T) {
	b := &Base{basePath: "/blocklist"}
	r := httptest.NewRequest(http.MethodGet, "/events?system=sys-1&refresh=10", nil)

	off, r10, r30 := b.refreshLinks(r)

	if off != "/blocklist/events?system=sys-1" {
		t.Errorf("off = %q", off)
	}
	if r10 != "/blocklist/events?refresh=10&system=sys-1" {
		t.Errorf("r10 = %q", r10)
	}
	if r30 != "/blocklist/events?refresh=30&system=sys-1" {
		t.Errorf("r30 = %q", r30)
	}
}
