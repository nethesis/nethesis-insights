// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nethesis/nethesis-insights/internal/blocklist"
	"github.com/nethesis/nethesis-insights/internal/platform/metrics"
	threatstore "github.com/nethesis/nethesis-insights/internal/store/threat"
)

type fixedActive int

func (f fixedActive) ActiveSystems(context.Context, int64) (int, error) { return int(f), nil }

func (f fixedActive) RegularSystems(context.Context, string, int) (int, error) { return int(f), nil }

func scrape(t *testing.T, reg *metrics.Registry) string {
	t.Helper()
	rec := httptest.NewRecorder()
	metrics.Handler(reg).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, err := io.ReadAll(rec.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func feedWith(t *testing.T, ips ...string) *blocklist.Snapshot {
	t.Helper()
	snap := blocklist.NewSnapshot()
	rows := make([]threatstore.BlocklistRow, 0, len(ips))
	for _, ip := range ips {
		rows = append(rows, threatstore.BlocklistRow{AttackerIP: ip, DistinctSystems: 3})
	}
	if err := snap.Generate(rows, blocklist.Rule{MinSystems: 3, Window: time.Hour, TTL: 24 * time.Hour}, false, 1); err != nil {
		t.Fatal(err)
	}
	return snap
}

// threatd_blocklist_entries carries one series per feed, and is left out
// entirely until both feeds are ready: with a closed label set a missing
// feed would otherwise be exported as an empty blocklist.
func TestBlocklistEntriesGaugeIsPerFeed(t *testing.T) {
	newGauges := func() (*metrics.Registry, *metrics.StoreGauges) {
		reg := metrics.NewRegistry("threatd")
		return reg, metrics.NewStoreGauges(reg,
			metrics.StoreGauge{Name: "active_systems", Help: "h"},
			metrics.StoreGauge{Name: "regular_systems", Help: "h"},
			metrics.StoreGauge{Name: "blocklist_entries", Help: "h", Label: "feed", Values: []string{"full", "basic"}},
		)
	}

	reg, g := newGauges()
	full := feedWith(t, "203.0.113.1", "203.0.113.2", "203.0.113.3")
	basic := feedWith(t, "203.0.113.1")
	if err := threatGauges(fixedActive(7), full, basic, g)(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	body := scrape(t, reg)
	for _, want := range []string{
		`threatd_blocklist_entries{feed="full"} 3`,
		`threatd_blocklist_entries{feed="basic"} 1`,
		`threatd_active_systems 7`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("scrape is missing %q:\n%s", want, body)
		}
	}

	reg, g = newGauges()
	if err := threatGauges(fixedActive(7), full, blocklist.NewSnapshot(), g)(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if body := scrape(t, reg); strings.Contains(body, "threatd_blocklist_entries") {
		t.Fatalf("a basic feed not generated yet was exported:\n%s", body)
	}
}
