// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package fingerprint

import (
	"testing"

	"github.com/nethesis/nethesis-insights/internal/model"
)

func tpl(module string, priority int, text string) model.Template {
	return model.Template{ModuleID: module, Priority: priority, Template: text}
}

func fp(cited []model.Template) string {
	return Compute("sys1", []string{"crowdsec1"}, EvidenceKey(cited), "security")
}

// The bug this whole change exists for: the model cites a different subset of
// the same condition each window, and identity moves with it.
func TestEvidenceKeyStableWhenCitedSetGrows(t *testing.T) {
	small := []model.Template{tpl("crowdsec1", 3, "ssh-bf by ip <IP> (US/<NUM>)")}
	large := []model.Template{
		tpl("crowdsec1", 3, "ssh-bf by ip <IP> (US/<NUM>)"),
		tpl("crowdsec1", 3, "ssh-bf by ip <IP> (DE/<NUM>)"),
		tpl("crowdsec1", 3, "ssh-bf by ip <IP> (NL/<NUM>)"),
	}
	if fp(small) != fp(large) {
		t.Fatal("fingerprint moved when the model cited more of the same bucket")
	}
}

// The observed masking leak: one scenario, twelve country codes.
func TestEvidenceKeyStableAcrossCountryCodes(t *testing.T) {
	us := []model.Template{
		tpl("crowdsec1", 3, "ssh-bf by ip <IP> (US/<NUM>)"),
		tpl("", 6, "sshd: failed password"),
	}
	hk := []model.Template{
		tpl("crowdsec1", 3, "ssh-bf by ip <IP> (HK/<NUM>)"),
		tpl("", 6, "sshd: failed password"),
	}
	if fp(us) != fp(hk) {
		t.Fatal("fingerprint moved with the GeoIP country code")
	}
}

func TestEvidenceKeyStableAcrossBanDurations(t *testing.T) {
	short := []model.Template{
		tpl("crowdsec1", 3, "ban on ip <IP> for 4m"),
		tpl("", 6, "sshd: failed password"),
	}
	long := []model.Template{
		tpl("crowdsec1", 3, "ban on ip <IP> for 392m"),
		tpl("", 6, "sshd: failed password"),
	}
	if fp(short) != fp(long) {
		t.Fatal("fingerprint moved with the ban duration")
	}
}

// The bucket fallback merges within one bucket only. Distinctness across
// modules and priorities is what stops it over-merging genuinely different
// conditions -- the risk that fallback introduces.
func TestEvidenceKeyDistinctAcrossBuckets(t *testing.T) {
	a := EvidenceKey([]model.Template{tpl("crowdsec1", 3, "x")})
	b := EvidenceKey([]model.Template{tpl("loki1", 3, "x")})
	c := EvidenceKey([]model.Template{tpl("crowdsec1", 6, "x")})

	if a[0] == b[0] {
		t.Fatalf("different modules collapsed: %q", a[0])
	}
	if a[0] == c[0] {
		t.Fatalf("different priorities collapsed: %q", a[0])
	}
}

// Across buckets the primary template's text still matters, so two unrelated
// multi-module conditions stay distinct.
func TestEvidenceKeyDistinctAcrossPrimaryTemplates(t *testing.T) {
	a := []model.Template{tpl("", 6, "disk almost full"), tpl("loki1", 3, "z")}
	b := []model.Template{tpl("", 6, "certificate expired"), tpl("loki1", 3, "z")}
	if fp(a) == fp(b) {
		t.Fatal("unrelated conditions collapsed onto one fingerprint")
	}
}

// The key must not depend on citation order.
func TestEvidenceKeyOrderIndependent(t *testing.T) {
	forward := []model.Template{
		tpl("loki1", 3, "b"),
		tpl("", 6, "a"),
		tpl("crowdsec1", 1, "c"),
	}
	reversed := []model.Template{forward[2], forward[1], forward[0]}
	if fp(forward) != fp(reversed) {
		t.Fatal("fingerprint depends on the order templates were cited")
	}
}

func TestEvidenceKeyEmptyIsNil(t *testing.T) {
	if got := EvidenceKey(nil); got != nil {
		t.Fatalf("expected nil for no citations, got %v", got)
	}
}

// Normalize must not rewrite text it does not understand: a lowercase or
// longer token is not a country code, and a bare number is not a duration.
func TestNormalizeIsNarrow(t *testing.T) {
	for _, s := range []string{
		"connection from (us/<NUM>)",
		"module (ABC/<NUM>) failed",
		"retry count 4 exceeded",
	} {
		if got := Normalize(s); got != s {
			t.Fatalf("Normalize over-reached on %q: got %q", s, got)
		}
	}
}
