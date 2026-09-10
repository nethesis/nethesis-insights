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

// randomPepper is what resolvePepper falls back to when AUTH_PEPPER is
// unset, instead of defaulting to an empty (and therefore offline-computable)
// HMAC key -- see the comment on resolvePepper explaining why an unset
// pepper must not mean "no pepper". Pin the two properties that fallback
// depends on: a real 32-byte key every time, and a fresh one every call,
// matching the promise "ephemeral... for this process's lifetime" rather
// than a second fixed constant that would be exactly as guessable as an
// empty one.
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

// fakeGetenv builds a getenv func(string, string) string, the same shape as
// the package-level getenv, backed by a map instead of the real environment
// -- so resolvePepper can be tested without t.Setenv (which would mutate
// process state a parallel package test could observe).
func fakeGetenv(vars map[string]string) func(string, string) string {
	return func(key, def string) string {
		if v, ok := vars[key]; ok {
			return v
		}
		return def
	}
}

// When AUTH_PEPPER is set, resolvePepper must use that exact value --
// verbatim, not rehashed or truncated -- and report it as "configured". This
// is the branch that keeps the validation cache warm across a restart: if
// resolvePepper silently ignored a configured pepper and generated a random
// one instead, every deployment that believes it configured AUTH_PEPPER
// would in fact run ephemeral, invisibly.
func TestResolvePepperUsesTheConfiguredValueVerbatim(t *testing.T) {
	getenv := fakeGetenv(map[string]string{"AUTH_PEPPER": "my-configured-pepper"})

	pepper, source := resolvePepper(getenv)

	if pepper != "my-configured-pepper" {
		t.Errorf("pepper = %q, want the configured value verbatim", pepper)
	}
	if source != "configured" {
		t.Errorf("source = %q, want %q", source, "configured")
	}
}

// When AUTH_PEPPER is unset, resolvePepper must report "ephemeral" and, more
// importantly, must actually generate a fresh pepper each call -- not a
// fixed fallback constant. A fixed fallback would satisfy a naive test (it
// is non-empty, it is "ephemeral") while defeating the entire point: the
// validation cache's HMAC key would be the same across every authd process
// that ever ran unconfigured, i.e. computable offline by anyone, exactly the
// empty-key failure this mechanism exists to avoid.
func TestResolvePepperGeneratesAFreshPepperWhenUnset(t *testing.T) {
	getenv := fakeGetenv(map[string]string{})

	pepperA, sourceA := resolvePepper(getenv)
	pepperB, sourceB := resolvePepper(getenv)

	if sourceA != "ephemeral" || sourceB != "ephemeral" {
		t.Errorf("source = (%q, %q), want (%q, %q)", sourceA, sourceB, "ephemeral", "ephemeral")
	}
	if pepperA == pepperB {
		t.Error("two calls to resolvePepper with AUTH_PEPPER unset returned the same pepper -- " +
			"it must be fresh per call, not a fixed fallback, or the cache key becomes offline-computable")
	}
}
