// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"encoding/hex"
	"os"
	"testing"
	"time"
)

func TestGetenvFallsBackToDefaultWhenUnset(t *testing.T) {
	_ = os.Unsetenv("AUTHD_TEST_GETENV_UNSET")
	if got := getenv("AUTHD_TEST_GETENV_UNSET", "fallback"); got != "fallback" {
		t.Errorf("getenv = %q, want %q", got, "fallback")
	}
}

func TestGetenvPrefersTheEnvironment(t *testing.T) {
	t.Setenv("AUTHD_TEST_GETENV_SET", "configured")
	if got := getenv("AUTHD_TEST_GETENV_SET", "fallback"); got != "configured" {
		t.Errorf("getenv = %q, want %q", got, "configured")
	}
}

func TestGetenvIntFallsBackOnUnsetOrUnparseable(t *testing.T) {
	_ = os.Unsetenv("AUTHD_TEST_GETENVINT")
	if got := getenvInt("AUTHD_TEST_GETENVINT", 7); got != 7 {
		t.Errorf("getenvInt(unset) = %d, want fallback 7", got)
	}

	t.Setenv("AUTHD_TEST_GETENVINT", "not-a-number")
	if got := getenvInt("AUTHD_TEST_GETENVINT", 7); got != 7 {
		t.Errorf("getenvInt(garbage) = %d, want fallback 7", got)
	}

	t.Setenv("AUTHD_TEST_GETENVINT", "42")
	if got := getenvInt("AUTHD_TEST_GETENVINT", 7); got != 42 {
		t.Errorf("getenvInt = %d, want 42", got)
	}
}

func TestGetenvDurationFallsBackOnUnsetOrUnparseable(t *testing.T) {
	_ = os.Unsetenv("AUTHD_TEST_GETENVDUR")
	if got := getenvDuration("AUTHD_TEST_GETENVDUR", 3*time.Second); got != 3*time.Second {
		t.Errorf("getenvDuration(unset) = %v, want fallback 3s", got)
	}

	t.Setenv("AUTHD_TEST_GETENVDUR", "not-a-duration")
	if got := getenvDuration("AUTHD_TEST_GETENVDUR", 3*time.Second); got != 3*time.Second {
		t.Errorf("getenvDuration(garbage) = %v, want fallback 3s", got)
	}

	t.Setenv("AUTHD_TEST_GETENVDUR", "9s")
	if got := getenvDuration("AUTHD_TEST_GETENVDUR", 3*time.Second); got != 9*time.Second {
		t.Errorf("getenvDuration = %v, want 9s", got)
	}
}

// randomPepper is what main() falls back to when AUTH_PEPPER is unset,
// instead of defaulting to an empty (and therefore offline-computable) HMAC
// key -- see the comment in main() explaining why an unset pepper must not
// mean "no pepper". Pin the two properties that fallback depends on: a real
// 32-byte key every time, and a fresh one every call, matching the promise
// "ephemeral... for this process's lifetime" rather than a second fixed
// constant that would be exactly as guessable as an empty one.
//
// main()'s branch that decides *whether* to call randomPepper (AUTH_PEPPER
// == "") is inline in main() itself and not exposed as a separate function,
// so it is not reachable from a _test.go file without a production-code
// change (factoring pepper selection into something like
// `resolvePepper(getenv string) (pepper, source string)`); this test covers
// the unit main() delegates to, which is as much of the fallback as can be
// exercised without that change.
func TestRandomPepperIsFreshAndCorrectLength(t *testing.T) {
	a := randomPepper()
	b := randomPepper()

	decoded, err := hex.DecodeString(a)
	if err != nil {
		t.Fatalf("randomPepper did not return hex: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("pepper length = %d bytes, want 32", len(decoded))
	}
	if a == b {
		t.Error("two calls to randomPepper returned the same value -- it must be fresh per process, not a fixed fallback")
	}
}
