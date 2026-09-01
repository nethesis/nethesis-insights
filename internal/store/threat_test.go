// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package store

import (
	"context"
	"testing"
	"time"

	"github.com/nethesis/nethesis-insights/internal/model"
)

func threatEvent(ip, scenario string, observedAt int64, hits int64) model.ThreatEvent {
	return model.ThreatEvent{
		AttackerIP: ip,
		Scenario:   scenario,
		ObservedAt: observedAt,
		HitCount:   hits,
		Metadata:   map[string]any{"duration_seconds": float64(14400)},
	}
}

// Every threat read must answer empty-and-nil on a fresh database, mirroring
// TestUIMethodsOnEmptyDatabase: an operator page that 503s on a new
// deployment is indistinguishable from one that is broken.
func TestThreatMethodsOnEmptyDatabase(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UnixMilli()

	if rows, err := s.ConsensusCandidates(ctx, 0); err != nil || len(rows) != 0 {
		t.Fatalf("ConsensusCandidates: %v, %d rows", err, len(rows))
	}
	if rows, err := s.ThreatAllowlist(ctx, now); err != nil || len(rows) != 0 {
		t.Fatalf("ThreatAllowlist: %v, %d rows", err, len(rows))
	}
	if rows, err := s.ListBlocklist(ctx, now, 0); err != nil || len(rows) != 0 {
		t.Fatalf("ListBlocklist: %v, %d rows", err, len(rows))
	}
	if rows, err := s.ListBlocklistEntries(ctx, 0); err != nil || len(rows) != 0 {
		t.Fatalf("ListBlocklistEntries: %v, %d rows", err, len(rows))
	}
	if rows, err := s.ListThreatEvents(ctx, "", "", 0); err != nil || len(rows) != 0 {
		t.Fatalf("ListThreatEvents: %v, %d rows", err, len(rows))
	}
	if rows, err := s.ThreatDailyStats(ctx, 0); err != nil || len(rows) != 0 {
		t.Fatalf("ThreatDailyStats: %v, %d rows", err, len(rows))
	}
	if rows, err := s.ThreatIngestStats(ctx, 0); err != nil || len(rows) != 0 {
		t.Fatalf("ThreatIngestStats: %v, %d rows", err, len(rows))
	}
	if rows, err := s.ListThreatAllowlist(ctx); err != nil || len(rows) != 0 {
		t.Fatalf("ListThreatAllowlist: %v, %d rows", err, len(rows))
	}
	if err := s.RollupThreatDailyStats(ctx); err != nil {
		t.Fatalf("RollupThreatDailyStats: %v", err)
	}
}

// The whole point of the unique index: a reporter that retries a batch must
// not be able to inflate its own contribution to consensus.
func TestInsertThreatEventsIsIdempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	batch := []model.ThreatEvent{
		threatEvent("203.0.113.7", "ssh_bruteforce", 1000, 3),
		threatEvent("203.0.113.8", "port_scan", 1000, 1),
	}

	inserted, duplicates, err := s.InsertThreatEvents(ctx, "sys-a", batch)
	if err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if inserted != 2 || duplicates != 0 {
		t.Fatalf("first insert: inserted=%d duplicates=%d, want 2/0", inserted, duplicates)
	}

	inserted, duplicates, err = s.InsertThreatEvents(ctx, "sys-a", batch)
	if err != nil {
		t.Fatalf("redelivery: %v", err)
	}
	if inserted != 0 || duplicates != 2 {
		t.Fatalf("redelivery: inserted=%d duplicates=%d, want 0/2", inserted, duplicates)
	}

	rows, err := s.ListThreatEvents(ctx, "", "", 0)
	if err != nil {
		t.Fatalf("ListThreatEvents: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("stored rows: got %d, want 2", len(rows))
	}
	for _, r := range rows {
		if r.AttackerIP == "203.0.113.7" && r.HitCount != 3 {
			t.Fatalf("hit_count was inflated by redelivery: got %d, want 3", r.HitCount)
		}
		if r.Metadata["duration_seconds"] != float64(14400) {
			t.Fatalf("metadata round trip: got %v", r.Metadata)
		}
	}
}

// The same address reported by a different system is a different row -- that
// is what makes distinct-system counting possible at all.
func TestInsertThreatEventsSeparatesSystems(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	ev := []model.ThreatEvent{threatEvent("203.0.113.7", "ssh_bruteforce", 1000, 1)}

	if _, _, err := s.InsertThreatEvents(ctx, "sys-a", ev); err != nil {
		t.Fatalf("sys-a: %v", err)
	}
	inserted, _, err := s.InsertThreatEvents(ctx, "sys-b", ev)
	if err != nil {
		t.Fatalf("sys-b: %v", err)
	}
	if inserted != 1 {
		t.Fatalf("inserted: got %d, want 1", inserted)
	}
}

func TestListThreatEventsFilters(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_, _, _ = s.InsertThreatEvents(ctx, "sys-a", []model.ThreatEvent{
		threatEvent("203.0.113.7", "ssh_bruteforce", 1000, 1),
		threatEvent("203.0.113.8", "port_scan", 2000, 1),
	})
	_, _, _ = s.InsertThreatEvents(ctx, "sys-b", []model.ThreatEvent{
		threatEvent("203.0.113.7", "ssh_bruteforce", 3000, 1),
	})

	all, _ := s.ListThreatEvents(ctx, "", "", 0)
	if len(all) != 3 {
		t.Fatalf("unfiltered: got %d, want 3", len(all))
	}
	// Newest first.
	if all[0].ObservedAt != 3000 {
		t.Fatalf("order: got observed_at %d first, want 3000", all[0].ObservedAt)
	}
	bySystem, _ := s.ListThreatEvents(ctx, "sys-a", "", 0)
	if len(bySystem) != 2 {
		t.Fatalf("by system: got %d, want 2", len(bySystem))
	}
	byIP, _ := s.ListThreatEvents(ctx, "", "203.0.113.7", 0)
	if len(byIP) != 2 {
		t.Fatalf("by ip: got %d, want 2", len(byIP))
	}
	both, _ := s.ListThreatEvents(ctx, "sys-b", "203.0.113.7", 0)
	if len(both) != 1 {
		t.Fatalf("by system and ip: got %d, want 1", len(both))
	}
}

// Candidates come back as (ip, scenario, system) triples so that Go can count
// distinct systems per IP without double counting a system that reported the
// same address under two scenarios.
func TestConsensusCandidatesGroupsToTheSystem(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_, _, _ = s.InsertThreatEvents(ctx, "sys-a", []model.ThreatEvent{
		threatEvent("203.0.113.7", "ssh_bruteforce", 1000, 2),
		threatEvent("203.0.113.7", "ssh_bruteforce", 2000, 3),
		threatEvent("203.0.113.7", "port_scan", 1500, 1),
	})
	_, _, _ = s.InsertThreatEvents(ctx, "sys-b", []model.ThreatEvent{
		threatEvent("203.0.113.7", "ssh_bruteforce", 2500, 4),
	})

	rows, err := s.ConsensusCandidates(ctx, 0)
	if err != nil {
		t.Fatalf("ConsensusCandidates: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows: got %d, want 3 (two scenarios for sys-a, one for sys-b)", len(rows))
	}
	for _, r := range rows {
		if r.SystemID == "sys-a" && r.Scenario == "ssh_bruteforce" {
			if r.Hits != 5 {
				t.Fatalf("sys-a ssh hits: got %d, want 5", r.Hits)
			}
			if r.LastSeen != 2000 {
				t.Fatalf("sys-a ssh last seen: got %d, want 2000", r.LastSeen)
			}
		}
	}
}

func TestConsensusCandidatesHonoursTheWindow(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_, _, _ = s.InsertThreatEvents(ctx, "sys-a", []model.ThreatEvent{
		threatEvent("203.0.113.7", "ssh_bruteforce", 1000, 1),
		threatEvent("203.0.113.8", "ssh_bruteforce", 5000, 1),
	})

	rows, _ := s.ConsensusCandidates(ctx, 4000)
	if len(rows) != 1 || rows[0].AttackerIP != "203.0.113.8" {
		t.Fatalf("windowed candidates: got %+v", rows)
	}
}

// first_listed_at records when the fleet first agreed. A refresh is not a new
// listing, so it must survive the upsert untouched.
func TestUpsertBlocklistEntriesPreservesFirstListedAt(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	first := BlocklistRow{
		AttackerIP: "203.0.113.7", FirstListedAt: 1000, LastSeenAt: 1000, ExpiresAt: 5000,
		DistinctSystems: 3, Scenarios: []string{"ssh_bruteforce"},
		Reason: ListingReason{Systems: 3, Hits: 12, Rule: "v1"},
	}
	if err := s.UpsertBlocklistEntries(ctx, []BlocklistRow{first}); err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	refresh := first
	refresh.FirstListedAt = 9999 // a caller passing a later value must not win
	refresh.LastSeenAt = 4000
	refresh.ExpiresAt = 8000
	refresh.DistinctSystems = 5
	refresh.Scenarios = []string{"port_scan", "ssh_bruteforce"}
	if err := s.UpsertBlocklistEntries(ctx, []BlocklistRow{refresh}); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	rows, err := s.ListBlocklist(ctx, 0, 0)
	if err != nil {
		t.Fatalf("ListBlocklist: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows: got %d, want 1", len(rows))
	}
	got := rows[0]
	if got.FirstListedAt != 1000 {
		t.Fatalf("first_listed_at: got %d, want it untouched at 1000", got.FirstListedAt)
	}
	if got.LastSeenAt != 4000 || got.ExpiresAt != 8000 || got.DistinctSystems != 5 {
		t.Fatalf("refresh did not apply: %+v", got)
	}
	if len(got.Scenarios) != 2 {
		t.Fatalf("scenarios: got %v, want 2", got.Scenarios)
	}
	if got.Reason.Rule != "v1" || got.Reason.Hits != 12 {
		t.Fatalf("listing reason round trip: %+v", got.Reason)
	}
}

func TestListBlocklistExcludesExpiredAndExpireDeletes(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_ = s.UpsertBlocklistEntries(ctx, []BlocklistRow{
		{AttackerIP: "203.0.113.7", FirstListedAt: 1, LastSeenAt: 1, ExpiresAt: 5000, DistinctSystems: 3},
		{AttackerIP: "203.0.113.8", FirstListedAt: 1, LastSeenAt: 1, ExpiresAt: 2000, DistinctSystems: 3},
	})

	live, _ := s.ListBlocklist(ctx, 3000, 0)
	if len(live) != 1 || live[0].AttackerIP != "203.0.113.7" {
		t.Fatalf("live entries: got %+v", live)
	}

	// The operator page still sees the not-yet-swept entry.
	all, _ := s.ListBlocklistEntries(ctx, 0)
	if len(all) != 2 {
		t.Fatalf("operator listing: got %d, want 2", len(all))
	}

	n, err := s.ExpireBlocklist(ctx, 3000)
	if err != nil {
		t.Fatalf("ExpireBlocklist: %v", err)
	}
	if n != 1 {
		t.Fatalf("expired: got %d, want 1", n)
	}
	remaining, _ := s.ListBlocklistEntries(ctx, 0)
	if len(remaining) != 1 {
		t.Fatalf("after expiry: got %d, want 1", len(remaining))
	}
}

func TestThreatAllowlistHonoursExpiry(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	// No admin API by design: rows arrive by hand, so the test inserts them
	// the same way an operator would.
	mustExec(t, s, `INSERT INTO threat_allowlist (cidr, reason, created_by, created_at, expires_at)
		VALUES ('203.0.113.0/24', 'partner scanner', 'ops', 1, NULL)`)
	mustExec(t, s, `INSERT INTO threat_allowlist (cidr, reason, created_by, created_at, expires_at)
		VALUES ('198.51.100.0/24', 'temporary', 'ops', 1, 2000)`)

	active, err := s.ThreatAllowlist(ctx, 3000)
	if err != nil {
		t.Fatalf("ThreatAllowlist: %v", err)
	}
	if len(active) != 1 || active[0].CIDR != "203.0.113.0/24" {
		t.Fatalf("active allowlist: got %+v", active)
	}
	if active[0].ExpiresAt != nil {
		t.Fatalf("permanent entry should have a nil ExpiresAt, got %v", *active[0].ExpiresAt)
	}

	all, err := s.ListThreatAllowlist(ctx)
	if err != nil {
		t.Fatalf("ListThreatAllowlist: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("operator allowlist listing: got %d, want 2 (expired entries stay visible)", len(all))
	}
}

func TestRecordIngestCountersAccumulates(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	c := model.ThreatCounters{Accepted: 5, DroppedOrigin: 2, DroppedPrivateIP: 1, Truncated: 3}

	if err := s.RecordIngestCounters(ctx, "2026-08-28", "sys-a", c, 1); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := s.RecordIngestCounters(ctx, "2026-08-28", "sys-a", c, 1); err != nil {
		t.Fatalf("second: %v", err)
	}

	rows, err := s.ThreatIngestStats(ctx, 0)
	if err != nil {
		t.Fatalf("ThreatIngestStats: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows: got %d, want 1", len(rows))
	}
	got := rows[0]
	if got.Accepted != 10 || got.DroppedOrigin != 4 || got.DroppedPrivateIP != 2 ||
		got.Truncated != 6 || got.Duplicates != 2 {
		t.Fatalf("counters did not accumulate: %+v", got)
	}
}

// ListThreatSystems must be driven by threat_ingest_daily, not threat_events,
// so a system whose every report was a duplicate or dropped -- and therefore
// never produced a threat_events row -- still shows up.
func TestListThreatSystemsIncludesSystemsWithNoStoredEvents(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// sys-a: two accepted events, one duplicate retry.
	_, _, _ = s.InsertThreatEvents(ctx, "sys-a", []model.ThreatEvent{
		threatEvent("203.0.113.7", "ssh_bruteforce", 1000, 4),
		threatEvent("203.0.113.8", "port_scan", 2000, 6),
	})
	if err := s.RecordIngestCounters(ctx, "2026-08-28", "sys-a", model.ThreatCounters{Accepted: 2}, 0); err != nil {
		t.Fatalf("record sys-a: %v", err)
	}
	if err := s.RecordIngestCounters(ctx, "2026-08-29", "sys-a", model.ThreatCounters{Accepted: 0}, 1); err != nil {
		t.Fatalf("record sys-a dup: %v", err)
	}

	// sys-b: every report dropped, nothing ever reached threat_events.
	if err := s.RecordIngestCounters(ctx, "2026-08-28", "sys-b", model.ThreatCounters{DroppedPrivateIP: 3}, 0); err != nil {
		t.Fatalf("record sys-b: %v", err)
	}

	rows, err := s.ListThreatSystems(ctx)
	if err != nil {
		t.Fatalf("ListThreatSystems: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 systems, got %d: %+v", len(rows), rows)
	}

	byID := map[string]ThreatSystemRow{}
	for _, r := range rows {
		byID[r.SystemID] = r
	}

	a, ok := byID["sys-a"]
	if !ok {
		t.Fatalf("sys-a missing: %+v", rows)
	}
	if a.Accepted != 2 || a.Duplicates != 1 || a.Events != 2 || a.DistinctIPs != 2 ||
		a.DistinctScenarios != 2 || a.TotalHits != 10 || a.LastEventAt == nil || *a.LastEventAt != 2000 {
		t.Fatalf("sys-a aggregate wrong: %+v", a)
	}

	b, ok := byID["sys-b"]
	if !ok {
		t.Fatalf("sys-b missing (dropped-only system must still appear): %+v", rows)
	}
	if b.Accepted != 0 || b.Dropped != 3 || b.Events != 0 || b.LastEventAt != nil {
		t.Fatalf("sys-b aggregate wrong: %+v", b)
	}
}

// The rollup is what turns a blocklist into fleet threat-trend data, and it
// only works if it runs before the prune.
func TestRollupSurvivesThePrune(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	day1 := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC).UnixMilli()
	day2 := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC).UnixMilli()
	_, _, _ = s.InsertThreatEvents(ctx, "sys-a", []model.ThreatEvent{
		threatEvent("203.0.113.7", "ssh_bruteforce", day1, 4),
		threatEvent("203.0.113.8", "ssh_bruteforce", day1+1000, 6),
		threatEvent("203.0.113.9", "port_scan", day2, 2),
	})

	if err := s.RollupThreatDailyStats(ctx); err != nil {
		t.Fatalf("RollupThreatDailyStats: %v", err)
	}
	// Recomputing must converge, not double count.
	if err := s.RollupThreatDailyStats(ctx); err != nil {
		t.Fatalf("second rollup: %v", err)
	}

	pruned, err := s.PruneThreatEvents(ctx, day2)
	if err != nil {
		t.Fatalf("PruneThreatEvents: %v", err)
	}
	if pruned != 2 {
		t.Fatalf("pruned: got %d, want 2", pruned)
	}

	stats, err := s.ThreatDailyStats(ctx, 0)
	if err != nil {
		t.Fatalf("ThreatDailyStats: %v", err)
	}
	if len(stats) != 2 {
		t.Fatalf("daily stats: got %+v, want 2 rows", stats)
	}
	var found bool
	for _, r := range stats {
		if r.Day == "2026-08-20" && r.Scenario == "ssh_bruteforce" {
			found = true
			if r.DistinctIPs != 2 || r.TotalHits != 10 {
				t.Fatalf("2026-08-20 rollup: got %+v, want 2 ips / 10 hits", r)
			}
		}
	}
	if !found {
		t.Fatalf("the pruned day lost its rollup: %+v", stats)
	}
}

func TestCountsIncludeThreatTables(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_, _, _ = s.InsertThreatEvents(ctx, "sys-a", []model.ThreatEvent{
		threatEvent("203.0.113.7", "ssh_bruteforce", 1000, 1),
	})
	_ = s.UpsertBlocklistEntries(ctx, []BlocklistRow{
		{AttackerIP: "203.0.113.7", FirstListedAt: 1, LastSeenAt: 1, ExpiresAt: 5000, DistinctSystems: 3},
	})

	c, err := s.Counts(ctx)
	if err != nil {
		t.Fatalf("Counts: %v", err)
	}
	if c.ThreatEvents != 1 || c.BlocklistEntries != 1 {
		t.Fatalf("counts: got %+v", c)
	}
}

func mustExec(t *testing.T, s *SQLiteStore, query string) {
	t.Helper()
	if _, err := s.db.ExecContext(context.Background(), query); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}
