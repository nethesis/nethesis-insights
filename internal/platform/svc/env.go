// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package svc holds the small binary-startup helpers that used to be copied
// byte-for-byte into every daemon's main.go: parsing environment variables
// into typed config, and running a periodic background pass on a ticker
// until context cancellation. It sits next to internal/platform/httpx and
// internal/platform/sqlitex rather than under any one pipeline, for the same
// reason those do -- any binary may import it, and no pipeline owns it.
//
// GetenvInt/GetenvDuration/GetenvFloat fall back to def on a parse error as
// well as on an unset variable, which makes a typo indistinguishable from
// leaving the setting alone. GetenvIntStrict and GetenvDurationStrict are a
// stricter mode for a binary that wants a set-but-unparseable value to be a
// startup error instead: threatd uses them for every numeric and duration
// variable it reads; the other three binaries keep the lenient functions
// above.
package svc

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Getenv reads key from the environment, falling back to def when the
// variable is unset or empty.
func Getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// GetenvDuration reads key as a time.Duration (time.ParseDuration syntax),
// falling back to def when the variable is unset or fails to parse.
func GetenvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// GetenvInt reads key as an int, falling back to def when the variable is
// unset or fails to parse.
func GetenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// GetenvFloat reads key as a float64, falling back to def when the variable
// is unset or fails to parse.
func GetenvFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

// GetenvIntStrict is GetenvInt, except a variable that is set but fails to
// parse returns an error naming key instead of silently falling back to
// def -- an unset or empty variable still means def, nil. def is returned
// alongside the error too, so a caller that only wants to collect every
// problem before exiting can keep building its config without a second
// branch on error.
func GetenvIntStrict(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def, fmt.Errorf("%s: invalid integer %q", key, v)
	}
	return n, nil
}

// GetenvDurationStrict is GetenvIntStrict's counterpart for a
// time.ParseDuration value.
func GetenvDurationStrict(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def, fmt.Errorf("%s: invalid duration %q", key, v)
	}
	return d, nil
}
