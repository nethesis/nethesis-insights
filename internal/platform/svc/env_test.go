// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package svc

import (
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
