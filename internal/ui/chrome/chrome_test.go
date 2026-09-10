// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package chrome

import (
	"io/fs"
	"net/http/httptest"
	"regexp"
	"testing"
	"testing/fstest"
)

var (
	scriptRe = regexp.MustCompile(`(?i)<script`)
	jsURLRe  = regexp.MustCompile(`(?i)javascript:`)
	onAttrRe = regexp.MustCompile(`(?i)\bon[a-z]+\s*=`)
)

func assertNoJS(t *testing.T, label string, body []byte) {
	t.Helper()
	s := string(body)
	if scriptRe.Match(body) {
		t.Errorf("%s: contains a <script tag", label)
	}
	if jsURLRe.Match(body) {
		t.Errorf("%s: contains a javascript: URL", label)
	}
	if loc := onAttrRe.FindStringIndex(s); loc != nil {
		t.Errorf("%s: contains an event-handler attribute near %q", label, s[max(0, loc[0]-20):min(len(s), loc[1]+20)])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// TestNoJavaScript is the byte-level half of the zero-JS guard for the
// assets chrome itself owns: layout.html and static/. internal/ui/logs's own
// TestNoJavaScript covers its remaining page templates the same way and
// exercises these assets again through the served HTTP paths, but a
// rendered-output check cannot see an unrendered branch -- layout.html's
// `{{if gt .Refresh 0}}<meta http-equiv="refresh" ...>{{end}}` is never
// taken by a plain GET, so only a raw walk of the shipped bytes catches
// something added inside it (or any future conditional in the shared
// layout). This test is what makes that guarantee live where the bytes
// now live, in-package so it can reach the unexported assets var.
func TestNoJavaScript(t *testing.T) {
	err := fs.WalkDir(assets, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, err := fs.ReadFile(assets, path)
		if err != nil {
			return err
		}
		assertNoJS(t, "embedded asset "+path, b)
		return nil
	})
	if err != nil {
		t.Fatalf("walking embedded assets: %v", err)
	}
}

// TestRenderSecurityHeaders is fix B of the whole-branch review: since the
// split put the three dashboards behind one Traefik origin, sameOriginWrite
// alone can no longer stop a forged cross-site write if an HTML-injection
// bug ever lands on any page of any dashboard. These headers make that
// enforced rather than merely currently-true, and Cache-Control keeps the
// fleet-wide findings, attacker addresses and per-customer data these pages
// now serve over the internet out of the operator's browser cache.
func TestRenderSecurityHeaders(t *testing.T) {
	tmplFS := fstest.MapFS{
		"status.html": &fstest.MapFile{Data: []byte(`{{define "content"}}ok{{end}}`)},
	}
	b, err := New(Config{
		Name:      "testd",
		Pages:     []string{"status.html"},
		Templates: tmplFS,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	w := httptest.NewRecorder()
	b.Render(w, "status.html", PageData{})

	if got := w.Header().Get("Content-Security-Policy"); got != "default-src 'self'; script-src 'none'; form-action 'self'" {
		t.Errorf("Content-Security-Policy = %q", got)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// TestSameOriginWrite pins the three-header ladder, and in particular the
// two boundaries that are easy to get wrong. The both-absent request is
// allowed on purpose -- it is curl, which carries no ambient credential --
// and that allowance is only safe because each dashboard's route() admits
// POST and no other non-GET method, so a browser cannot produce it: Origin
// is attached to every cross-site request whose method is neither GET nor
// HEAD. Referer is a hint rather than a guarantee (a page can suppress it),
// but a mismatching one is still enough to refuse on.
func TestSameOriginWrite(t *testing.T) {
	const self = "example.test"

	cases := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{
			name:    "same-origin form post",
			headers: map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://" + self},
			want:    true,
		},
		{
			name:    "cross-site form post",
			headers: map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "http://evil.example"},
			want:    false,
		},
		{
			name:    "address bar navigation",
			headers: map[string]string{"Sec-Fetch-Site": "none"},
			want:    true,
		},
		{
			name:    "no Sec-Fetch-Site, matching Origin",
			headers: map[string]string{"Origin": "http://" + self},
			want:    true,
		},
		{
			name:    "no Sec-Fetch-Site, foreign Origin",
			headers: map[string]string{"Origin": "http://evil.example"},
			want:    false,
		},
		{
			name:    "no Sec-Fetch-Site, unparseable Origin",
			headers: map[string]string{"Origin": "http://[::1"},
			want:    false,
		},
		{
			name:    "no Sec-Fetch-Site and no Origin, matching Referer",
			headers: map[string]string{"Referer": "http://" + self + "/blocklist/"},
			want:    true,
		},
		{
			name:    "no Sec-Fetch-Site and no Origin, foreign Referer",
			headers: map[string]string{"Referer": "http://evil.example/csrf.html"},
			want:    false,
		},
		{
			// A non-browser client: nothing to abuse, and refusing it would
			// break the scripted path without closing anything.
			name: "no browser headers at all (curl)",
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "http://"+self+"/blocklist/allowlist", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			if got := sameOriginWrite(req); got != tc.want {
				t.Fatalf("sameOriginWrite = %v, want %v", got, tc.want)
			}
		})
	}
}
