// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package threat

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// wroteAnything reports whether any of the four write routes reached the
// store, so a method test can assert the absence of an effect rather than
// only the status code -- a 405 with a write already committed would be the
// same bug wearing a different answer.
func (f *fakeWriter) wroteAnything() bool {
	return len(f.upserted) > 0 || len(f.deleted) > 0 || len(f.reviews) > 0 ||
		len(f.reqDels) > 0 || len(f.audit) > 0
}

// A write route must answer POST and nothing else, and HEAD is the method
// that proves why: net/http runs a handler in full for HEAD and merely
// discards the body, ServeMux applies no method filter, and ParseForm merges
// the query string into r.Form whatever the method is -- so a HEAD with every
// parameter in the URL would otherwise perform a complete, permanent write.
// It also slips past the cross-site check, because a browser attaches Origin
// only when the method is neither GET nor HEAD and the Sec-Fetch-* headers
// only for a potentially trustworthy URL: a cross-site HEAD to a plain-HTTP
// dashboard carries neither, so chrome.sameOriginWrite sees the shape it has
// to allow for curl while the browser replays the operator's cached Basic
// credential. Admitting POST alone is what closes that.
func TestHeadWithQueryParametersCannotForgeAWrite(t *testing.T) {
	for _, p := range writePaths {
		t.Run(p, func(t *testing.T) {
			w := &fakeWriter{}
			h := newWriteTestServer(t, threatReader(), nil, w, testAdminKey)

			// Everything the handlers read, in the query string, with no
			// body at all -- and no Origin or Sec-Fetch-* header, exactly
			// what a no-cors cross-site fetch produces.
			target := p + "?" + url.Values{
				"cidr":   {"0.0.0.0/0"},
				"force":  {"1"},
				"reason": {"forged"},
				"note":   {"forged"},
			}.Encode()
			req := httptest.NewRequest(http.MethodHead, target, nil)
			req.SetBasicAuth("attacker", testAdminKey)

			rec := do(h, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("HEAD %s: got %d, want 405", p, rec.Code)
			}
			if w.wroteAnything() {
				t.Fatalf("HEAD %s reached the store: %+v", p, w)
			}
		})
	}
}

// Every other non-GET method is refused for the same reason. DELETE and PUT
// are the ones a hand-written client is most likely to try on a route named
// ".../delete"; PROPFIND stands in for the long tail nobody enumerates.
func TestOnlyPostReachesAWriteRoute(t *testing.T) {
	methods := []string{
		http.MethodDelete,
		http.MethodPut,
		http.MethodPatch,
		"PROPFIND",
	}
	for _, m := range methods {
		for _, p := range writePaths {
			t.Run(m+" "+p, func(t *testing.T) {
				w := &fakeWriter{}
				h := newWriteTestServer(t, threatReader(), nil, w, testAdminKey)

				req := httptest.NewRequest(m, p+"?cidr=0.0.0.0/0&force=1", nil)
				req.Header.Set("Sec-Fetch-Site", "same-origin")
				req.Header.Set("Origin", "http://"+req.Host)
				req.SetBasicAuth("alice", testAdminKey)

				rec := do(h, req)

				if rec.Code != http.StatusMethodNotAllowed {
					t.Fatalf("%s %s: got %d, want 405", m, p, rec.Code)
				}
				if w.wroteAnything() {
					t.Fatalf("%s %s reached the store: %+v", m, p, w)
				}
			})
		}
	}
}

// The counterpart to the two above: narrowing the gate to POST must not have
// narrowed it past POST. An authenticated same-origin form submission still
// goes through on every one of the four routes.
func TestPostStillReachesEveryWriteRoute(t *testing.T) {
	for _, tc := range []struct {
		path      string
		wantWrite func(*fakeWriter) bool
	}{
		{"/blocklist/allowlist", func(w *fakeWriter) bool { return len(w.upserted) == 1 }},
		{"/blocklist/allowlist/delete", func(w *fakeWriter) bool { return len(w.deleted) == 1 }},
		{"/allowlist-requests/approve", func(w *fakeWriter) bool { return len(w.reviews) == 1 }},
		{"/allowlist-requests/reject", func(w *fakeWriter) bool { return len(w.reviews) == 1 }},
	} {
		t.Run(tc.path, func(t *testing.T) {
			w := &fakeWriter{}
			h := newWriteTestServer(t, threatReader(), nil, w, testAdminKey)

			req := writeReq(tc.path, url.Values{"cidr": {"203.0.113.0/24"}})
			req.SetBasicAuth("alice", testAdminKey)

			rec := do(h, req)

			if rec.Code != http.StatusSeeOther {
				t.Fatalf("POST %s: got %d, want 303 (body %s)", tc.path, rec.Code, rec.Body.String())
			}
			if !tc.wantWrite(w) {
				t.Fatalf("POST %s did not reach the store: %+v", tc.path, w)
			}
		})
	}
}
