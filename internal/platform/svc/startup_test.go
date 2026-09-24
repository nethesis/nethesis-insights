// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package svc

import "testing"

func TestIsLoopbackBind(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:9596", true},
		{"127.1.2.3:9596", true},
		{"[::1]:9596", true},
		// Every interface: the case the startup warning exists for.
		{":9596", false},
		{"0.0.0.0:9596", false},
		{"[::]:9596", false},
		{"10.0.0.5:9596", false},
		// Not a literal IP, so not provably loopback.
		{"localhost:9596", false},
		// Unparseable: warn rather than assume the safe answer.
		{"9596", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsLoopbackBind(c.addr); got != c.want {
			t.Errorf("IsLoopbackBind(%q): got %v, want %v", c.addr, got, c.want)
		}
	}
}

// SecretState is the only thing standing between a secret and an
// unauthenticated status page.
func TestSecretStateNeverCarriesAValue(t *testing.T) {
	if got := SecretState(true); got != "set" {
		t.Fatalf("SecretState(true): got %q, want %q", got, "set")
	}
	if got := SecretState(false); got != "unset" {
		t.Fatalf("SecretState(false): got %q, want %q", got, "unset")
	}
}
