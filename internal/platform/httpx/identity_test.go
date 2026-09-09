// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package httpx

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The proxy has already validated the credential; this only reads the
// identity out of it. That makes the trusted-proxy check the whole security
// boundary -- reaching the container directly must not let a caller name any
// system_id it likes.
func TestSystemID(t *testing.T) {
	trusted, err := ParseTrustedProxies("127.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}

	cases := []struct {
		name       string
		remoteAddr string
		user, pass string
		setAuth    bool
		want       string
		wantErr    error
	}{
		{name: "trusted proxy, valid basic", remoteAddr: "127.0.0.1:1", user: "sys-1", pass: "t", setAuth: true, want: "sys-1"},
		{name: "direct connection is refused", remoteAddr: "203.0.113.7:1", user: "sys-1", pass: "t", setAuth: true, wantErr: ErrUntrustedProxy},
		{name: "no credential", remoteAddr: "127.0.0.1:1", setAuth: false, wantErr: ErrNoCredential},
		{name: "empty username", remoteAddr: "127.0.0.1:1", user: "", pass: "t", setAuth: true, wantErr: ErrNoCredential},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/v1/bundles", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.setAuth {
				r.SetBasicAuth(tc.user, tc.pass)
			}
			got, err := SystemID(r, trusted)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("SystemID = %q, want %q", got, tc.want)
			}
		})
	}
}
