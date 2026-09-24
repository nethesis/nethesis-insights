// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package svc

import (
	"log/slog"
	"net"
	"os"
)

// SetupLogger installs the process's default logger at LOG_LEVEL
// (debug|info|warn|error); anything unparseable means info. Debug adds the
// detail needed to explain a rejected or slow request; it never adds
// credentials.
func SetupLogger(level string) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})))
}

// SecretState reduces a secret to its mere presence. The status pages and the
// logs get this, never the value.
func SecretState(set bool) string {
	if set {
		return "set"
	}
	return "unset"
}

// IsLoopbackBind reports whether addr binds a loopback address only. It is
// deliberately strict: anything that is not a literal loopback IP -- an empty
// host (":9596", which binds every interface), a name, an unparseable value --
// is treated as a wider bind, because the failure mode of a false "yes" is a
// silently exposed fleet-wide page.
func IsLoopbackBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// WarnIfNotLoopback warns when an operator UI is bound anywhere other than a
// loopback address. Every operator UI's GET is unauthenticated and
// fleet-wide, so a wider bind must never happen silently. It is not refused:
// the operator asked for the choice to be theirs.
func WarnIfNotLoopback(addr string) {
	if IsLoopbackBind(addr) {
		return
	}
	slog.Warn("the operator UI is unauthenticated and fleet-wide but is not bound to a loopback address; "+
		"bind it to 127.0.0.1 or a trusted management network",
		"ui_listen_addr", addr)
}
