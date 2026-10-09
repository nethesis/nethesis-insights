// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package model

import (
	"regexp"
	"strings"
)

// CanonicalTemplate collapses the variable fields the edge masker leaves
// literal, so that lines describing one condition share one key.
//
// It exists because the collector's masking is field-based and therefore
// leaks whatever it has no rule for. Measured on the dev fleet (2026-09-01,
// 710 live templates across three real nodes): 512 of them sat in a group
// whose members differ only in such a leak, and a Drain-style clustering
// found just 249 distinct shapes. Every leaked variant costs three times --
// it looks novel to the gate and buys an LLM call, it occupies a line in the
// prompt, and it splits a finding's identity.
//
// The rules below are narrow on purpose: each one collapses a field that
// cannot distinguish two conditions, and nothing broader. Rules that would
// have collapsed more were rejected for merging conditions that are genuinely
// distinct:
//
//   - a generic quoted-string rule would fold msg="write block" into
//     msg="compact blocks";
//   - a short-hex rule (\b[0-9a-f]{4,}\b) matches ordinary English words --
//     "added", "face", "decade" are all hex.
//
// The result is used for three things (novelty lookup, the system_templates
// key, and finding identity), and never shown to an operator: the raw
// template text is stored and displayed unchanged.
//
// The trade this makes: a genuinely new condition that differs from a known
// line only in a canonicalized field no longer fires the novelty condition.
// If the edge classified it, security_new is checked against the same
// canonical key and is not weakened by this.
var (
	// A CrowdSec scenario keeps the GeoIP country code and the ban duration
	// literal, so one scenario mints a template per country and per duration:
	//
	//	ssh-time-based-bf by ip <IP> (US/<NUM>)   ... and (DE/<NUM>), (GB/<NUM>)
	//	ban on ip <IP> for 4m                     ... and 8m, 12m, 392m
	countryCode = regexp.MustCompile(`\(([A-Z]{2})/`)
	duration    = regexp.MustCompile(`(?:<NUM>|\b\d+)(?:ms|µs|us|ns|s|m|h|d)\b`)

	// Percentages and decimals. The edge masks integers of two digits or more
	// (its rule 11 is \d{2,}), so "wrote <NUM> buffers (1.5%); write=0.<NUM> s"
	// keeps both the percentage and the fractional part, and a Postgres
	// checkpoint line mints a fresh template every time it runs.
	percentage = regexp.MustCompile(`(?:\d+|<NUM>)(?:\.(?:\d+|<NUM>))?%`)
	decimal    = regexp.MustCompile(`(?:\d+|<NUM>)\.(?:\d+|<NUM>)`)

	// The instance digits of a bracketed syslog identifier. The collector has
	// the same rule (its masking rule 10) and it works for [nethvoice84] ->
	// [nethvoice], but its character class has no '@', so the identifier of an
	// NS8 agent -- agent@openldap55 -- survives it. Its scrub pass protects
	// those names on purpose, because a crash-looping module is named by
	// exactly those PRIORITY=3 lines. Measured on the 2026-09-02 dump: one
	// template,
	//
	//	<4> [agent@openldap55] Signal "user <USER> signal <NUM>" caught: ...
	//
	// occupied 154 of 678 rows across seven module families.
	//
	// Anchoring on the closing bracket is what keeps this narrow: [php7:error]
	// and [nextcloud] do not match, because the digits have to be the last
	// thing before the ']'.
	bracketInstance = regexp.MustCompile(`\[([A-Za-z][\w@.-]*?)\d+\]`)

	// Single digits, for the same reason: "0 WAL file(s) added, 0 removed,
	// 1 recycled" differs from "... 8 recycled" in one character. \b never
	// matches inside a word, so file references (head.go:12) are untouched,
	// and the leading priority marker is protected by splitting it off before
	// any rule runs. Module instance names (traefik1, nethvoice5) survive this
	// rule too, but no longer survive canonicalization as a whole: the
	// bracketInstance rule above takes the ones that appear as a syslog
	// identifier, and replaceOwnInstance the ones the module names itself by
	// in the message.
	singleDigit = regexp.MustCompile(`\b\d\b`)

	// Dotted hostnames. The collector has no rule at all for these and says so
	// -- it preserves hostnames deliberately -- so one line per customer domain
	// arrives as one template per customer domain.
	hostname = regexp.MustCompile(`\b(?:[A-Za-z0-9_<][A-Za-z0-9_<>-]*\.)+[A-Za-z][A-Za-z0-9]{1,23}\b`)

	// Paths of two or more segments, keeping the first segment. Keeping it is
	// what stops /v1/bundles and /user/paramurl from becoming the same key
	// while still folding /historycall/interval/user/luca together with
	// /historycall/interval/user/recep, and /home/nethvoice21/... with
	// /home/nethvoice74/...
	multiPath = regexp.MustCompile(`/([A-Za-z0-9_.<>-]+)(?:/[A-Za-z0-9_.<>~-]+){1,}`)

	// Quoted database object names, and only those: the keyword before the
	// quote is what makes the collapse safe.
	objectName = regexp.MustCompile(`\b(on|table|relation|index|database|hypertable|schema|view|constraint)\s+"[^"]*"`)
)

// sourceFileSuffix lists the trailing labels that make a dotted token a file
// name rather than a host name. Without it, source=head.go and
// source=compact.go collapse into one key and two unrelated Prometheus
// conditions become indistinguishable.
var sourceFileSuffix = map[string]bool{
	"go": true, "py": true, "c": true, "h": true, "cc": true, "cpp": true,
	"js": true, "ts": true, "jsx": true, "tsx": true, "lua": true, "rb": true,
	"php": true, "java": true, "sh": true, "pl": true, "rs": true, "erl": true,
	"conf": true, "cfg": true, "ini": true, "yaml": true, "yml": true,
	"json": true, "toml": true, "xml": true, "html": true, "css": true,
	"log": true, "txt": true, "sql": true, "db": true, "sock": true,
	"pid": true, "key": true, "crt": true, "pem": true, "so": true,
	"service": true, "socket": true, "target": true, "timer": true,
	"mount": true, "slice": true, "scope": true, "device": true, "path": true,
}

// CanonicalTemplate returns the canonical key for a masked template emitted by
// moduleID (an instance id or a family; the host bucket is "").
//
// The leading priority marker ("<3> ") is split off and restored verbatim: it
// is part of the grouping key the collector already applied, and the
// single-digit rule would otherwise rewrite it.
//
// The module is an argument, not something read off the text, because one
// rule needs it: see replaceOwnInstance.
func CanonicalTemplate(moduleID, template string) string {
	prefix, rest := splitPriority(template)

	rest = replaceOwnInstance(rest, ModuleFamily(moduleID))
	rest = countryCode.ReplaceAllString(rest, "(<CC>/")
	rest = objectName.ReplaceAllString(rest, "$1 <STR>")
	rest = replaceHostnames(rest)
	rest = multiPath.ReplaceAllString(rest, "/$1/<PATH>")
	rest = percentage.ReplaceAllString(rest, "<PCT>")
	rest = decimal.ReplaceAllString(rest, "<NUM>")
	rest = duration.ReplaceAllString(rest, "<DUR>")
	rest = bracketInstance.ReplaceAllString(rest, "[$1]")
	rest = singleDigit.ReplaceAllString(rest, "<NUM>")

	return prefix + rest
}

// splitPriority separates a leading "<N> " syslog priority marker from the
// rest of the line. A template that does not carry one is returned whole.
func splitPriority(template string) (prefix, rest string) {
	if len(template) == 0 || template[0] != '<' {
		return "", template
	}
	end := strings.IndexByte(template, '>')
	if end < 0 {
		return "", template
	}
	for _, r := range template[1:end] {
		if r < '0' || r > '9' {
			return "", template
		}
	}
	return template[:end+1], template[end+1:]
}

// replaceOwnInstance rewrites the emitting module's own instance id to its
// family wherever the message spells it out. NS8 writes the instance into the
// text of many of its lines, and the collector has no rule for a bare word:
//
//	[agent@nethvoice] <HOST>: domain <HOST> should not be used by nethvoice43. ...
//	[api-moduled] <HOST>: domain <HOST> should not be used by openldap14. ...
//
// so one warning became one template, one finding and one review class per
// instance number -- 78 classes for that single nethvoice line on the dev
// fleet on 2026-10-09, each to be decided separately.
//
// It is keyed on the line's own module, never on the word's shape. A generic
// "letters then digits" rule would fold php7 into php8, rfc4733 into rfc2833
// and sha256 into sha1 -- on the same dump such words outnumbered instance
// ids. The family the line came from is the one name known to be an instance
// id; another module's instance named in the text (the host bucket's
// "Module instance "nethvoice12" update failed") is left alone, because
// telling which words are module names would need a list of modules, and that
// list would go stale with every new NS8 application.
//
// The bracketInstance rule cannot be reused for this: it is what keeps
// [php7:error] intact, by requiring the digits to close the bracket.
func replaceOwnInstance(s, family string) string {
	if family == "" || isDigit(family[len(family)-1]) {
		// The host bucket names no instance, and a family that still ends in
		// a digit (ModuleFamily("11") == "11") is not an image name.
		return s
	}
	var b strings.Builder
	for {
		i := strings.Index(s, family)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		end := i + len(family)
		n := instanceSuffix(s[end:])
		if n == 0 || (i > 0 && isWordByte(s[i-1])) {
			// Not an instance id: part of a longer word, or the family name
			// on its own, which is already canonical.
			b.WriteString(s[:end])
			s = s[end:]
			continue
		}
		b.WriteString(s[:end])
		s = s[end+n:]
	}
}

// instanceSuffix returns the length of the instance number at the start of s
// -- digits, or the edge's <NUM> mask -- or 0 when s does not start with one
// that ends the word.
func instanceSuffix(s string) int {
	if strings.HasPrefix(s, "<NUM>") {
		return len("<NUM>")
	}
	n := 0
	for n < len(s) && isDigit(s[n]) {
		n++
	}
	if n == 0 || (n < len(s) && isWordByte(s[n])) {
		return 0
	}
	return n
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// isWordByte is regexp's \w, the class \b is defined against.
func isWordByte(c byte) bool {
	return isDigit(c) || c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// replaceHostnames rewrites dotted host names, leaving file names alone.
func replaceHostnames(s string) string {
	return hostname.ReplaceAllStringFunc(s, func(m string) string {
		last := m[strings.LastIndexByte(m, '.')+1:]
		if sourceFileSuffix[strings.ToLower(last)] {
			return m
		}
		return "<HOST>"
	})
}

// ModuleFamily reduces an NS8 module instance id to the module it is an
// instance of: nethvoice5 and nethvoice39 are both nethvoice, and
// nethvoice-proxy4 is nethvoice-proxy. An instance id is the image name
// followed by a sequence number, so this is a naming convention rather than a
// heuristic.
//
// The empty module id -- the host bucket, which carries sshd, systemd and
// runagent -- maps to itself and stays an ordinary bucket.
//
// The result never ends in a digit, so ModuleFamily is idempotent. That
// matters: store.KnownTemplates re-derives the key from a column that already
// holds a family, the way it already re-applies CanonicalTemplate to a column
// that already holds canonical text.
//
// The one shape this gets wrong is a module whose image name genuinely ends in
// a digit, which would merge with a differently-numbered sibling. No NS8
// module on the dev fleet does, and both would have to be installed on the
// same system for it to matter.
func ModuleFamily(moduleID string) string {
	family := strings.TrimRight(moduleID, "0123456789")
	if family == "" {
		return moduleID
	}
	return family
}

// CanonicalKey returns the storage and novelty key for a template: its module
// family plus its canonical text.
//
// The module is part of the key because the template text alone merges the
// same line seen in two different modules, and a line genuinely new for one of
// them then reads as known. It is the *family* rather than the instance
// because two instances of one module run the same image, the same version and
// the same code path: a line new to nethvoice20 that nethvoice47 emitted last
// week is not news about the node, it is the same condition on a second
// tenant. Measured on the 2026-09-02 dump, keying on the instance cost 301 of
// 678 rows -- pam_unix(cron:session) alone occupied 82, one per nethvoice
// instance.
//
// This is deliberately the only definition, shared by gate.Evaluate, the
// system_templates key, prompt.Select and fingerprint.Normalize. If novelty
// and identity disagreed, a window could pay for a template the store already
// knew and the finding would land on a fresh fingerprint every time.
func CanonicalKey(moduleID, template string) string {
	return ModuleFamily(moduleID) + "\x00" + CanonicalTemplate(moduleID, template)
}
