// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package chrome

import (
	"io/fs"
	"regexp"
	"testing"
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
// assets chrome itself owns: layout.html and static/. internal/ui's own
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
