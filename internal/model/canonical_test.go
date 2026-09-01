// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package model

import "testing"

// Every pair below is two real templates taken from the dev fleet on
// 2026-09-01 that describe one condition. Before canonicalization each pair
// was two rows in system_templates, two novel templates for the gate, and two
// findings.
func TestCanonicalTemplateCollapsesLeaks(t *testing.T) {
	cases := []struct {
		name string
		a, b string
	}{
		{
			name: "postgres checkpoint percentage and single-digit counters",
			a:    `<3> [postgres-app] <TS> UTC [<PID>] LOG: checkpoint complete: wrote <NUM> buffers (0.3%); 0 WAL file(s) added, 0 removed, 0 recycled`,
			b:    `<3> [postgres-app] <TS> UTC [<PID>] LOG: checkpoint complete: wrote <NUM> buffers (1.8%); 0 WAL file(s) added, 0 removed, 2 recycled`,
		},
		{
			name: "prometheus sub-second durations",
			a:    `<3> [prometheus] time=<TS> level=INFO source=head.go:<NUM> msg="Head GC completed" component=tsdb duration=4.695035ms`,
			b:    `<3> [prometheus] time=<TS> level=INFO source=head.go:<NUM> msg="Head GC completed" component=tsdb duration=7.068587ms`,
		},
		{
			name: "nethvoice request path tail",
			a:    `<3> [nethvoice] logs.go:<NUM>: [INFO][AUTH] authorization success for user <USER> GET /user/endpoints/all`,
			b:    `<3> [nethvoice] logs.go:<NUM>: [INFO][AUTH] authorization success for user <USER> GET /user/all_avatars`,
		},
		{
			name: "container storage path per instance",
			a:    `<4> [kernel] xfs filesystem being remounted at /home/nethvoice21/.local/share/containers/storage/overlay/merged`,
			b:    `<4> [kernel] xfs filesystem being remounted at /home/nethvoice3/.local/share/containers/storage/overlay/merged`,
		},
		{
			name: "timescale continuous aggregate object name",
			a:    `<3> [timescale] <TS> UTC [<PID>] LOG: continuous aggregate refresh on "ca_dpi_stats_hourly_bytes" in window`,
			b:    `<3> [timescale] <TS> UTC [<PID>] LOG: continuous aggregate refresh on "ca_ovpnrw_connections_hourly_count" in window`,
		},
		{
			name: "openldap customer domain",
			a:    `<4> [api-moduled] agent.ldapproxy: domain angolodelpane.<NUM>.neth.eu should not be used`,
			b:    `<4> [api-moduled] agent.ldapproxy: domain areaprotech.<NUM>.neth.eu should not be used`,
		},
		{
			name: "crowdsec geoip country code",
			a:    `<3> [crowdsec] ssh-time-based-bf by ip <IP> (US/<NUM>)`,
			b:    `<3> [crowdsec] ssh-time-based-bf by ip <IP> (DE/<NUM>)`,
		},
		{
			name: "crowdsec ban duration",
			a:    `<3> [crowdsec] ban on ip <IP> for 4m`,
			b:    `<3> [crowdsec] ban on ip <IP> for 392m`,
		},
		{
			name: "sshd sequence counter",
			a:    `<3> [sshd-session] error: kex_protocol_error: type <NUM> seq 2 [preauth]`,
			b:    `<3> [sshd-session] error: kex_protocol_error: type <NUM> seq 4 [preauth]`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca, cb := CanonicalTemplate(tc.a), CanonicalTemplate(tc.b)
			if ca != cb {
				t.Errorf("templates did not collapse:\n a=%q\n b=%q", ca, cb)
			}
		})
	}
}

// The rules must not merge conditions an administrator would act on
// differently. Each case here is a rule that was deliberately narrowed, or
// rejected outright, for exactly this reason.
func TestCanonicalTemplateKeepsDistinctConditionsApart(t *testing.T) {
	cases := []struct {
		name string
		a, b string
	}{
		{
			name: "different source files are different conditions",
			a:    `<3> [prometheus] time=<TS> level=INFO source=head.go:<NUM> msg="Head GC completed"`,
			b:    `<3> [prometheus] time=<TS> level=INFO source=compact.go:<NUM> msg="Head GC completed"`,
		},
		{
			name: "different log messages are different conditions",
			a:    `<3> [prometheus] time=<TS> level=INFO msg="write block" component=tsdb`,
			b:    `<3> [prometheus] time=<TS> level=INFO msg="compact blocks" component=tsdb`,
		},
		{
			name: "different first path segment",
			a:    `<6> [insights] msg=request method=GET path=/v1/findings status=<NUM>`,
			b:    `<6> [insights] msg=request method=GET path=/v2/findings status=<NUM>`,
		},
		{
			name: "different syslog priority",
			a:    `<3> [sshd-session] Connection closed by <IP>`,
			b:    `<6> [sshd-session] Connection closed by <IP>`,
		},
		{
			name: "different service",
			a:    `<3> [sshd-session] Connection closed by <IP>`,
			b:    `<3> [systemd] Connection closed by <IP>`,
		},
		{
			name: "hex words that are ordinary English are not collapsed",
			a:    `<3> [webapp] cache added to pool`,
			b:    `<3> [webapp] cache faded from pool`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if ca, cb := CanonicalTemplate(tc.a), CanonicalTemplate(tc.b); ca == cb {
				t.Errorf("templates were merged but must stay distinct: %q", ca)
			}
		})
	}
}

// The priority marker is part of the collector's own grouping key and must
// survive verbatim, or every template collapses onto its neighbours.
func TestCanonicalTemplateKeepsPriorityMarker(t *testing.T) {
	for _, in := range []string{
		`<3> [sshd] failed for user <USER>`,
		`<6> [systemd] Started something`,
	} {
		if got := CanonicalTemplate(in); got[:3] != in[:3] {
			t.Errorf("priority marker rewritten: %q -> %q", in, got)
		}
	}

	// A line without a marker is canonicalized whole rather than rejected.
	if got := CanonicalTemplate("plain line with 3 digits"); got != "plain line with <NUM> digits" {
		t.Errorf("unmarked line: got %q", got)
	}
}

func TestCanonicalTemplateIsIdempotent(t *testing.T) {
	in := `<3> [postgres-app] LOG: checkpoint complete: wrote <NUM> buffers (0.3%); 0 removed; write=4.5 s`
	once := CanonicalTemplate(in)
	if twice := CanonicalTemplate(once); twice != once {
		t.Errorf("not idempotent:\n once=%q\ntwice=%q", once, twice)
	}
}

// The module is part of the key: system_templates used to be keyed on the
// template text alone, so the same line seen in two modules became one row and
// a genuinely new line in one module looked known because another had it.
func TestCanonicalKeySeparatesModules(t *testing.T) {
	tpl := `<3> [postgres-app] LOG: checkpoint complete`
	if CanonicalKey("mattermost1", tpl) == CanonicalKey("nextcloud1", tpl) {
		t.Error("keys from different modules collided")
	}
	if CanonicalKey("mattermost1", tpl) != CanonicalKey("mattermost1", tpl+" ") {
		t.Log("trailing whitespace is significant; the collector already trims it")
	}
}
