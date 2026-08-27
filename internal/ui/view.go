// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package ui

import (
	"fmt"
	"html/template"
	"runtime/debug"
	"strings"
	"time"
)

// funcMap is shared by every page template. Every timestamp the UI renders
// arrives as a unix-millis INTEGER (project invariant) -- formatting happens
// here, in Go, never in SQL and never with a native date type.
var funcMap = template.FuncMap{
	"fmtTime":       FmtTime,
	"fmtOptTime":    FmtOptTime,
	"fmtAgo":        FmtAgo,
	"fmtCost":       FmtCost,
	"truncate":      Truncate,
	"short":         Short,
	"join":          strings.Join,
	"reasonsOrNone": ReasonsOrNone,
	"moduleLabel":   ModuleLabel,
}

// FmtTime renders a unix-millis timestamp as an ISO-8601-ish UTC string. A
// zero value means "never recorded" and renders as an em dash rather than
// the misleading 1970-01-01 that time.UnixMilli(0) would otherwise produce.
func FmtTime(millis int64) string {
	if millis == 0 {
		return "—"
	}
	return time.UnixMilli(millis).UTC().Format("2006-01-02 15:04:05Z")
}

// FmtOptTime is FmtTime for the handful of columns (reopened_at) that are a
// nullable timestamp rather than a zero-valued one.
func FmtOptTime(millis *int64) string {
	if millis == nil {
		return "—"
	}
	return FmtTime(*millis)
}

// FmtAgo renders a unix-millis timestamp as a coarse relative duration
// ("3m ago", "2d ago") for last_seen columns and process uptime. It is
// deliberately coarse -- this is a dashboard, not a log line.
func FmtAgo(millis int64) string {
	if millis == 0 {
		return "—"
	}
	d := time.Since(time.UnixMilli(millis))
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d/time.Minute))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d/time.Hour))
	default:
		return fmt.Sprintf("%dd ago", int(d/(24*time.Hour)))
	}
}

// FmtCost renders cost_micros (millionths of a USD) as USD with enough
// precision to be useful at these magnitudes -- individual windows can cost
// well under a cent. Zero renders as an em dash: the ledger uses 0 for "no
// LLM call was made", not "$0.00 was spent".
func FmtCost(micros int64) string {
	if micros == 0 {
		return "—"
	}
	return fmt.Sprintf("$%.6f", float64(micros)/1_000_000)
}

// Truncate shortens s to at most n runes, appending an ellipsis marker when
// it does. Callers pair this with a title="" attribute carrying the full
// text (in the templates), so nothing is actually lost -- only the table
// layout is protected from a single very long template or error string.
func Truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// Short is Truncate without the ellipsis, for IDs and fingerprints where a
// fixed-width prefix is the point -- the same 8-character prefix the shell
// helper this UI replaced used to print.
func Short(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// ReasonsOrNone renders a gate-reason set for the /gate rollup. nil means
// "no reasons fired" after store.GateRollup has already normalized the three
// stored spellings of that (”, 'null', '[]') into a nil/empty slice.
func ReasonsOrNone(reasons []string) string {
	if len(reasons) == 0 {
		return "(none)"
	}
	return strings.Join(reasons, ", ")
}

// ModuleLabel renders the empty-string module bucket as "(host)" rather than
// a blank table cell -- module_id: "" is a real, load-bearing bucket (host
// journal records), not missing data, and the blank cell reads as an error
// otherwise.
func ModuleLabel(moduleID string) string {
	if moduleID == "" {
		return "(host)"
	}
	return moduleID
}

// BuildInfo reads runtime/debug.ReadBuildInfo and returns the VCS revision
// if present, else the Go module version, else "unknown". It never invents a
// version string: the container build copies only cmd/ and internal/, with
// no .git, so vcs.revision is legitimately absent there.
func BuildInfo() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	var revision string
	var modified bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if revision != "" {
		if len(revision) > 12 {
			revision = revision[:12]
		}
		if modified {
			revision += "-dirty"
		}
		return revision
	}
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "unknown"
}
