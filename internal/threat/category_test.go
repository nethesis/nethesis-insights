// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package threat

import (
	"testing"

	"github.com/nethesis/nethesis-insights/internal/model"
)

func TestCategoryForMapsKnownScenarios(t *testing.T) {
	cases := []struct {
		scenario string
		want     string
	}{
		{"crowdsecurity/ssh-bf", "ssh_bruteforce"},
		{"crowdsecurity/ssh-slow-bf_user-enum", "ssh_bruteforce"},
		{"crowdsecurity/http-probing", "http_exploit"},
		{"crowdsecurity/http-cve-probing", "http_exploit"},
		{"crowdsecurity/port-scan", "port_scan"},
		{"crowdsecurity/iptables-scan-multi_ports", "port_scan"},
		{"crowdsecurity/asterisk-bf", "sip_probe"},
	}
	for _, tc := range cases {
		got, ok := CategoryFor(tc.scenario)
		if !ok {
			t.Fatalf("CategoryFor(%q): not found, want %q", tc.scenario, tc.want)
		}
		if got != tc.want {
			t.Fatalf("CategoryFor(%q): got %q, want %q", tc.scenario, got, tc.want)
		}
	}
}

// An unknown scenario must be dropped, never folded into a catch-all: design
// D3 fixes the category set, and a bucket meaning "something happened" is not
// evidence anyone can act on.
func TestCategoryForRejectsUnknownScenario(t *testing.T) {
	for _, s := range []string{"", "crowdsecurity/brand-new-thing", "custom/local-rule", "CROWDSECURITY/SSH-BF"} {
		if got, ok := CategoryFor(s); ok {
			t.Fatalf("CategoryFor(%q): got %q, want no match", s, got)
		}
	}
}

// Every mapped scenario must resolve to one of the four v1 categories -- a
// typo in the map would otherwise create a fifth category that nothing else
// in the system knows about.
func TestEveryMappedCategoryIsValid(t *testing.T) {
	for scenario, category := range KnownScenarios() {
		if !model.ValidThreatCategory(category) {
			t.Fatalf("scenario %q maps to unknown category %q", scenario, category)
		}
	}
}

func TestKnownScenariosIsACopy(t *testing.T) {
	m := KnownScenarios()
	m["crowdsecurity/ssh-bf"] = "tampered"
	if got, _ := CategoryFor("crowdsecurity/ssh-bf"); got != "ssh_bruteforce" {
		t.Fatalf("mutating the returned map changed the package map: got %q", got)
	}
}
