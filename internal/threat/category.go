// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package threat holds the pure half of the Threat Shield pipeline: the
// scenario->category map, the ingest sanitizer and the promotion allowlist.
//
// Same purity contract as gate, fingerprint and prompt -- no I/O, no clock
// beyond an injected now -- and for a sharper reason than those: everything
// that decides whether a third party's IP address is stored and published
// lives here, so a bug in this package is a data-protection incident rather
// than a wrong answer. That is what makes it worth being table-driven
// testable with no fixtures and no database.
package threat

// categories maps a CrowdSec scenario to one of the four v1 categories
// (design D3). The match is exact on purpose: an unrecognised scenario is
// dropped and recorded by name, never folded into a catch-all, because
// "something happened" is not evidence anyone can act on.
//
// Exact matching is a maintenance cost -- CrowdSec's hub grows -- and the
// compensating control is the threat_unknown_scenarios table, which turns
// "what should we add in the next release" into a sorted list in the
// operator UI instead of guesswork.
var categories = map[string]string{
	"crowdsecurity/ssh-bf":                      "ssh_bruteforce",
	"crowdsecurity/ssh-bf_user-enum":            "ssh_bruteforce",
	"crowdsecurity/ssh-slow-bf":                 "ssh_bruteforce",
	"crowdsecurity/ssh-slow-bf_user-enum":       "ssh_bruteforce",
	"crowdsecurity/http-probing":                "http_exploit",
	"crowdsecurity/http-bad-user-agent":         "http_exploit",
	"crowdsecurity/http-path-traversal-probing": "http_exploit",
	"crowdsecurity/http-sensitive-files":        "http_exploit",
	"crowdsecurity/http-sqli-probing":           "http_exploit",
	"crowdsecurity/http-xss-probing":            "http_exploit",
	"crowdsecurity/http-backdoors-attempts":     "http_exploit",
	"crowdsecurity/http-crawl-non_statics":      "http_exploit",
	"crowdsecurity/http-cve-probing":            "http_exploit",
	"crowdsecurity/port-scan":                   "port_scan",
	"crowdsecurity/iptables-scan-multi_ports":   "port_scan",
	"crowdsecurity/asterisk-user-enum":          "sip_probe",
	"crowdsecurity/asterisk-bf":                 "sip_probe",
	"crowdsecurity/asterisk-bf_user-enum":       "sip_probe",
}

// CategoryFor resolves a CrowdSec scenario to a v1 category. The second
// return is false for an unknown scenario, which the caller must drop and
// count -- never map to a default.
func CategoryFor(scenario string) (string, bool) {
	c, ok := categories[scenario]
	return c, ok
}

// KnownScenarios returns every mapped scenario. It exists for the ingest
// contract documentation and its test, so the doc cannot drift from the map.
func KnownScenarios() map[string]string {
	out := make(map[string]string, len(categories))
	for k, v := range categories {
		out[k] = v
	}
	return out
}
