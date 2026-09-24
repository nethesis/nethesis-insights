// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package svc

import (
	"strings"
	"testing"
	"time"
)

func TestGetenv(t *testing.T) {
	t.Setenv("SVC_TEST_STR", "")
	if got := Getenv("SVC_TEST_STR", "def"); got != "def" {
		t.Errorf("Getenv on an unset var = %q, want the fallback %q", got, "def")
	}
	t.Setenv("SVC_TEST_STR", "value")
	if got := Getenv("SVC_TEST_STR", "def"); got != "value" {
		t.Errorf("Getenv = %q, want %q", got, "value")
	}
}

func TestGetenvInt(t *testing.T) {
	t.Setenv("SVC_TEST_INT", "")
	if got := GetenvInt("SVC_TEST_INT", 7); got != 7 {
		t.Errorf("GetenvInt on an unset var = %d, want the fallback 7", got)
	}
	t.Setenv("SVC_TEST_INT", "42")
	if got := GetenvInt("SVC_TEST_INT", 7); got != 42 {
		t.Errorf("GetenvInt = %d, want 42", got)
	}
	t.Setenv("SVC_TEST_INT", "not-a-number")
	if got := GetenvInt("SVC_TEST_INT", 7); got != 7 {
		t.Errorf("GetenvInt on an unparseable value = %d, want the fallback 7", got)
	}
}

func TestGetenvDuration(t *testing.T) {
	t.Setenv("SVC_TEST_DUR", "")
	if got := GetenvDuration("SVC_TEST_DUR", 5*time.Minute); got != 5*time.Minute {
		t.Errorf("GetenvDuration on an unset var = %v, want the fallback 5m", got)
	}
	t.Setenv("SVC_TEST_DUR", "90s")
	if got := GetenvDuration("SVC_TEST_DUR", 5*time.Minute); got != 90*time.Second {
		t.Errorf("GetenvDuration = %v, want 90s", got)
	}
	t.Setenv("SVC_TEST_DUR", "not-a-duration")
	if got := GetenvDuration("SVC_TEST_DUR", 5*time.Minute); got != 5*time.Minute {
		t.Errorf("GetenvDuration on an unparseable value = %v, want the fallback 5m", got)
	}
}

func TestGetenvFloat(t *testing.T) {
	t.Setenv("SVC_TEST_FLOAT", "")
	if got := GetenvFloat("SVC_TEST_FLOAT", 1.5); got != 1.5 {
		t.Errorf("GetenvFloat on an unset var = %v, want the fallback 1.5", got)
	}
	t.Setenv("SVC_TEST_FLOAT", "0.25")
	if got := GetenvFloat("SVC_TEST_FLOAT", 1.5); got != 0.25 {
		t.Errorf("GetenvFloat = %v, want 0.25", got)
	}
	t.Setenv("SVC_TEST_FLOAT", "not-a-number")
	if got := GetenvFloat("SVC_TEST_FLOAT", 1.5); got != 1.5 {
		t.Errorf("GetenvFloat on an unparseable value = %v, want the fallback 1.5", got)
	}
}

// The strict variants exist because the lenient ones above make a typo
// indistinguishable from an unset variable: THREAT_EVENT_RETENTION=30d (Go
// has no 'd' unit) must stop threatd, not silently become the default.
func TestGetenvIntStrict(t *testing.T) {
	cases := []struct {
		name    string
		value   string // "" leaves the variable unset
		def     int
		want    int
		wantErr bool
	}{
		{"unset falls back to the default", "", 7, 7, false},
		{"a valid value overrides the default", "42", 7, 42, false},
		{"a negative value still parses", "-3", 7, -3, false},
		{"unparseable is an error, not the default", "not-a-number", 7, 7, true},
		{"trailing space is unparseable", "5 ", 7, 7, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SVC_TEST_INT_STRICT", tc.value)
			got, err := GetenvIntStrict("SVC_TEST_INT_STRICT", tc.def)
			if tc.wantErr && err == nil {
				t.Fatalf("GetenvIntStrict(%q) returned nil error, want one naming the variable", tc.value)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("GetenvIntStrict(%q) returned unexpected error: %v", tc.value, err)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "SVC_TEST_INT_STRICT") {
				t.Fatalf("error %q does not name the variable", err)
			}
			if got != tc.want {
				t.Fatalf("GetenvIntStrict(%q) = %d, want %d", tc.value, got, tc.want)
			}
		})
	}
}

func TestGetenvDurationStrict(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		def     time.Duration
		want    time.Duration
		wantErr bool
	}{
		{"unset falls back to the default", "", 5 * time.Minute, 5 * time.Minute, false},
		{"a valid value overrides the default", "90s", 5 * time.Minute, 90 * time.Second, false},
		{"unparseable is an error, not the default", "not-a-duration", 5 * time.Minute, 5 * time.Minute, true},
		// Go's ParseDuration has no bare "day" unit -- the documented reason
		// THREAT_EVENT_RETENTION=30d must not silently become the default.
		{"an unknown unit is unparseable", "30d", 5 * time.Minute, 5 * time.Minute, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SVC_TEST_DUR_STRICT", tc.value)
			got, err := GetenvDurationStrict("SVC_TEST_DUR_STRICT", tc.def)
			if tc.wantErr && err == nil {
				t.Fatalf("GetenvDurationStrict(%q) returned nil error, want one naming the variable", tc.value)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("GetenvDurationStrict(%q) returned unexpected error: %v", tc.value, err)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "SVC_TEST_DUR_STRICT") {
				t.Fatalf("error %q does not name the variable", err)
			}
			if got != tc.want {
				t.Fatalf("GetenvDurationStrict(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}
