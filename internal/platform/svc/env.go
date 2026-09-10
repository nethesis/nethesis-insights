// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package svc holds the small binary-startup helpers that used to be copied
// byte-for-byte into every daemon's main.go: parsing environment variables
// into typed config, and running a periodic background pass on a ticker
// until context cancellation. It sits next to internal/platform/httpx and
// internal/platform/sqlitex rather than under any one pipeline, for the same
// reason those do -- any binary may import it, and no pipeline owns it.
package svc

import (
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
