// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package blocklist

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nethesis/nethesis-insights/internal/model"
	threatstore "github.com/nethesis/nethesis-insights/internal/store/threat"
)

const (
	minute = int64(60 * 1000)
	hour   = 60 * minute
)

var now = time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC).UnixMilli()

func testConfig() Config {
	return Config{
		Window:     time.Hour,
		MinSystems: 3,
		TTL:        24 * time.Hour,
		MaxEntries: 50000,
		Retention:  168 * time.Hour,
	}
}

// Consensus is the logic that decides whether a third party's address is
// published, so it is tested against a real database rather than a mock: the
// grouping *is* the SQL.
func newTestStore(t *testing.T) *threatstore.Store {
	t.Helper()
	s, err := threatstore.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := s.Init(context.Background()); err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// report stores one sighting of ip by systemID, observedAt millis before now.
func report(t *testing.T, s *threatstore.Store, systemID, ip, scenario string, ago int64) {
	t.Helper()
	_, _, err := s.InsertThreatEvents(context.Background(), systemID, []model.ThreatEvent{{
		AttackerIP: ip,
		Scenario:   scenario,
		ObservedAt: now - ago,
		HitCount:   1,
	}})
	if err != nil {
		t.Fatalf("insert threat events: %v", err)
	}
}

func runPass(t *testing.T, s *threatstore.Store, cfg Config) (*Runner, *Snapshot) {
	t.Helper()
	snap := NewSnapshot()
	r := New(s, snap, cfg)
	if err := r.Run(context.Background(), now); err != nil {
		t.Fatalf("Run: %v", err)
	}
	return r, snap
}

func listed(t *testing.T, s *threatstore.Store) []string {
	t.Helper()
	rows, err := s.ListBlocklist(context.Background(), now, 0)
	if err != nil {
		t.Fatalf("ListBlocklist: %v", err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.AttackerIP)
	}
	return out
}

// The rule is three distinct systems. Two is not consensus, however loudly
// they report.
func TestPromotionRequiresTheMinimumDistinctSystems(t *testing.T) {
	s := newTestStore(t)
	report(t, s, "sys-a", "203.0.113.7", "ssh_bruteforce", 10*minute)
	report(t, s, "sys-b", "203.0.113.7", "ssh_bruteforce", 9*minute)

	runPass(t, s, testConfig())
	if got := listed(t, s); len(got) != 0 {
		t.Fatalf("two systems promoted %v, want nothing", got)
	}

	report(t, s, "sys-c", "203.0.113.7", "ssh_bruteforce", 8*minute)
	runPass(t, s, testConfig())
	if got := listed(t, s); len(got) != 1 || got[0] != "203.0.113.7" {
		t.Fatalf("three systems: got %v, want [203.0.113.7]", got)
	}
}

// It is distinct systems, not row count: one noisy node is not a fleet.
func TestOneSystemReportingRepeatedlyDoesNotPromote(t *testing.T) {
	s := newTestStore(t)
	for i := int64(1); i <= 5; i++ {
		report(t, s, "sys-a", "203.0.113.7", "ssh_bruteforce", i*minute)
	}

	runPass(t, s, testConfig())

	if got := listed(t, s); len(got) != 0 {
		t.Fatalf("one system promoted %v, want nothing", got)
	}
}

// A system reporting the same address under two scenarios is still one
// system -- the reason candidates are grouped down to system_id rather than
// counted per scenario.
func TestOneSystemAcrossTwoScenariosIsStillOneSystem(t *testing.T) {
	s := newTestStore(t)
	report(t, s, "sys-a", "203.0.113.7", "ssh_bruteforce", 5*minute)
	report(t, s, "sys-a", "203.0.113.7", "port_scan", 4*minute)
	report(t, s, "sys-b", "203.0.113.7", "ssh_bruteforce", 3*minute)

	runPass(t, s, Config{Window: time.Hour, MinSystems: 3, TTL: 24 * time.Hour, MaxEntries: 100})

	if got := listed(t, s); len(got) != 0 {
		t.Fatalf("got %v, want nothing: two systems cannot become three by scenario", got)
	}
}

func TestPromotionIgnoresSightingsOutsideTheWindow(t *testing.T) {
	s := newTestStore(t)
	report(t, s, "sys-a", "203.0.113.7", "ssh_bruteforce", 5*minute)
	report(t, s, "sys-b", "203.0.113.7", "ssh_bruteforce", 5*minute)
	report(t, s, "sys-c", "203.0.113.7", "ssh_bruteforce", 3*hour) // stale

	runPass(t, s, testConfig())

	if got := listed(t, s); len(got) != 0 {
		t.Fatalf("got %v, want nothing: the third sighting is outside the window", got)
	}
}

func TestPromotedEntryCarriesItsEvidence(t *testing.T) {
	s := newTestStore(t)
	report(t, s, "sys-a", "203.0.113.7", "ssh_bruteforce", 10*minute)
	report(t, s, "sys-b", "203.0.113.7", "ssh_bruteforce", 9*minute)
	report(t, s, "sys-c", "203.0.113.7", "port_scan", 8*minute)

	runPass(t, s, testConfig())

	rows, _ := s.ListBlocklist(context.Background(), now, 0)
	if len(rows) != 1 {
		t.Fatalf("rows: got %d, want 1", len(rows))
	}
	got := rows[0]
	if got.DistinctSystems != 3 {
		t.Fatalf("distinct_systems: got %d, want 3", got.DistinctSystems)
	}
	if len(got.Scenarios) != 2 {
		t.Fatalf("scenarios: got %v, want both", got.Scenarios)
	}
	if got.Reason.Systems != 3 || got.Reason.Hits != 3 || got.Reason.Rule != "v1" {
		t.Fatalf("listing reason: %+v", got.Reason)
	}
	if got.Reason.MinSystems != 3 || got.Reason.WindowMinutes != 60 {
		t.Fatalf("listing reason should snapshot the rule in force: %+v", got.Reason)
	}
	// expires_at hangs off the last sighting, not off the pass.
	wantExpiry := now - 8*minute + (24 * time.Hour).Milliseconds()
	if got.ExpiresAt != wantExpiry {
		t.Fatalf("expires_at: got %d, want %d", got.ExpiresAt, wantExpiry)
	}
}

// A refresh extends the TTL but does not restart the listing history.
func TestRefreshExtendsTTLButKeepsFirstListedAt(t *testing.T) {
	s := newTestStore(t)
	report(t, s, "sys-a", "203.0.113.7", "ssh_bruteforce", 30*minute)
	report(t, s, "sys-b", "203.0.113.7", "ssh_bruteforce", 30*minute)
	report(t, s, "sys-c", "203.0.113.7", "ssh_bruteforce", 30*minute)

	snap := NewSnapshot()
	r := New(s, snap, testConfig())
	if err := r.Run(context.Background(), now); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	first, _ := s.ListBlocklist(context.Background(), now, 0)

	// Ten minutes later, all three report again.
	later := now + 10*minute
	for _, sys := range []string{"sys-a", "sys-b", "sys-c"} {
		_, _, err := s.InsertThreatEvents(context.Background(), sys, []model.ThreatEvent{{
			AttackerIP: "203.0.113.7", Scenario: "ssh_bruteforce", ObservedAt: later, HitCount: 1,
		}})
		if err != nil {
			t.Fatalf("second round insert: %v", err)
		}
	}
	if err := r.Run(context.Background(), later); err != nil {
		t.Fatalf("second pass: %v", err)
	}

	second, _ := s.ListBlocklist(context.Background(), later, 0)
	if len(second) != 1 {
		t.Fatalf("rows: got %d, want 1", len(second))
	}
	if second[0].FirstListedAt != first[0].FirstListedAt {
		t.Fatalf("first_listed_at changed on refresh: %d -> %d",
			first[0].FirstListedAt, second[0].FirstListedAt)
	}
	if second[0].ExpiresAt <= first[0].ExpiresAt {
		t.Fatalf("expires_at did not refresh: %d -> %d", first[0].ExpiresAt, second[0].ExpiresAt)
	}
}

func TestExpiryRemovesTheEntry(t *testing.T) {
	s := newTestStore(t)
	report(t, s, "sys-a", "203.0.113.7", "ssh_bruteforce", 30*minute)
	report(t, s, "sys-b", "203.0.113.7", "ssh_bruteforce", 30*minute)
	report(t, s, "sys-c", "203.0.113.7", "ssh_bruteforce", 30*minute)

	cfg := testConfig()
	snap := NewSnapshot()
	r := New(s, snap, cfg)
	if err := r.Run(context.Background(), now); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	if len(listed(t, s)) != 1 {
		t.Fatal("entry was not promoted")
	}

	// Two days on, nothing has been reported since.
	later := now + 2*24*hour
	if err := r.Run(context.Background(), later); err != nil {
		t.Fatalf("second pass: %v", err)
	}

	rows, _ := s.ListBlocklistEntries(context.Background(), 0)
	if len(rows) != 0 {
		t.Fatalf("expired entry survived: %+v", rows)
	}
	if snap.Entries() != 0 {
		t.Fatalf("snapshot entries: got %d, want 0", snap.Entries())
	}
}

// The allowlist is applied at promotion, so adding an entry retroactively
// unlists the address on the next pass instead of merely hiding it.
func TestAllowlistedAddressNeverPromotes(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertThreatAllowlistEntry(ctx, threatstore.AllowlistRow{
		CIDR: "203.0.113.0/24", Reason: "partner scanner", CreatedBy: "ops", CreatedAt: 1,
	}); err != nil {
		t.Fatalf("seed allowlist: %v", err)
	}
	for _, sys := range []string{"sys-a", "sys-b", "sys-c", "sys-d"} {
		report(t, s, sys, "203.0.113.7", "ssh_bruteforce", 5*minute)
		report(t, s, sys, "198.51.100.9", "ssh_bruteforce", 5*minute)
	}

	runPass(t, s, testConfig())

	got := listed(t, s)
	if len(got) != 1 || got[0] != "198.51.100.9" {
		t.Fatalf("got %v, want only the non-allowlisted address", got)
	}
}

// The second lock, on the side that reads addresses back out of the store.
// netip.Prefix.Contains is false for any address carrying an IPv6 zone,
// because a prefix has none to compare -- so an attacker_ip stored as
// "2001:db8::9%eth0" would clear an allowlist entry that plainly covers it.
// Ingest refuses a zoned address outright (see threat.publicUnicast), which
// is why such a row should never exist; promote normalizes anyway, because
// the cost of being wrong here is publishing an address someone explicitly
// exempted, under a spelling the operator UI does not show.
func TestAllowlistCoversZonedAddresses(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertThreatAllowlistEntry(ctx, threatstore.AllowlistRow{
		CIDR: "2001:db8::/48", Reason: "customer range", CreatedBy: "ops", CreatedAt: 1,
	}); err != nil {
		t.Fatalf("seed allowlist: %v", err)
	}
	for _, sys := range []string{"sys-a", "sys-b", "sys-c"} {
		report(t, s, sys, "2001:db8::9%eth0", "ssh_bruteforce", 5*minute)
		report(t, s, sys, "2001:db8::9", "ssh_bruteforce", 5*minute)
	}

	runPass(t, s, testConfig())

	if got := listed(t, s); len(got) != 0 {
		t.Fatalf("got %v, want nothing -- both spellings fall inside 2001:db8::/48", got)
	}
}

// A malformed allowlist row must stop the pass, not be skipped: skipping it
// would publish an address someone had explicitly excluded.
func TestAMalformedAllowlistRowAbortsThePass(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertThreatAllowlistEntry(ctx, threatstore.AllowlistRow{
		CIDR: "not-a-cidr", Reason: "typo", CreatedBy: "ops", CreatedAt: 1,
	}); err != nil {
		t.Fatalf("seed allowlist: %v", err)
	}
	for _, sys := range []string{"sys-a", "sys-b", "sys-c"} {
		report(t, s, sys, "203.0.113.7", "ssh_bruteforce", 5*minute)
	}

	snap := NewSnapshot()
	r := New(s, snap, testConfig())
	if err := r.Run(ctx, now); err == nil {
		t.Fatal("Run: got nil error, want the pass to abort on an unparseable allowlist entry")
	}
	if len(listed(t, s)) != 0 {
		t.Fatal("the aborted pass promoted anyway")
	}
	if snap.Ready() {
		t.Fatal("the aborted pass replaced the snapshot")
	}
}

func TestRunRollsUpStatsAndPrunes(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	// Older than the retention window, so the pass must roll it up and then
	// drop it.
	old := now - 200*hour
	if _, _, err := s.InsertThreatEvents(ctx, "sys-a", []model.ThreatEvent{{
		AttackerIP: "203.0.113.50", Scenario: "port_scan", ObservedAt: old, HitCount: 7,
	}}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	runPass(t, s, testConfig())

	events, _ := s.ListThreatEvents(ctx, "", "", 0)
	if len(events) != 0 {
		t.Fatalf("the stale event was not pruned: %+v", events)
	}
	stats, _ := s.ThreatDailyStats(ctx, 0)
	if len(stats) != 1 || stats[0].TotalHits != 7 {
		t.Fatalf("the rollup did not run before the prune: %+v", stats)
	}
}

// A store failure must leave the last good snapshot in place. Subscribers get
// a stale list, never a blank one.
func TestAFailedPassKeepsThePreviousSnapshot(t *testing.T) {
	fake := &failingReader{
		rows: []threatstore.BlocklistRow{{AttackerIP: "203.0.113.7", ExpiresAt: now + hour}},
	}
	snap := NewSnapshot()
	r := New(fake, snap, testConfig())

	if err := r.Run(context.Background(), now); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	firstBody := string(snap.Body())
	firstGenerated := snap.GeneratedAt()
	if !strings.Contains(firstBody, "203.0.113.7") {
		t.Fatalf("first snapshot: %q", firstBody)
	}

	fake.fail = true
	if err := r.Run(context.Background(), now+hour); err == nil {
		t.Fatal("second pass: got nil error, want failure")
	}

	if string(snap.Body()) != firstBody {
		t.Fatalf("the failed pass replaced the body: %q", snap.Body())
	}
	if snap.GeneratedAt() != firstGenerated {
		t.Fatalf("the failed pass moved generated_at: %d -> %d", firstGenerated, snap.GeneratedAt())
	}
}

// failingReader serves one fixed blocklist row and can be switched to fail.
type failingReader struct {
	rows             []threatstore.BlocklistRow
	fail             bool
	failRequestPrune bool
}

var errBoom = errors.New("store unavailable")

func (f *failingReader) ConsensusCandidates(context.Context, int64) ([]threatstore.ThreatCandidateRow, error) {
	if f.fail {
		return nil, errBoom
	}
	return nil, nil
}
func (f *failingReader) ThreatAllowlist(context.Context, int64) ([]threatstore.AllowlistRow, error) {
	return nil, nil
}
func (f *failingReader) UpsertBlocklistEntries(context.Context, []threatstore.BlocklistRow) error {
	return nil
}
func (f *failingReader) ExpireBlocklist(context.Context, int64) (int, error) { return 0, nil }
func (f *failingReader) ListBlocklist(context.Context, int64, int) ([]threatstore.BlocklistRow, error) {
	return f.rows, nil
}
func (f *failingReader) RollupThreatDailyStats(context.Context) error          { return nil }
func (f *failingReader) PruneThreatEvents(context.Context, int64) (int, error) { return 0, nil }
func (f *failingReader) PruneAllowlistRequests(context.Context, int64) (int, error) {
	if f.failRequestPrune {
		return 0, errBoom
	}
	return 0, nil
}

// The review queue's retention prune is a step in this pass, for the same
// reason the events prune is: it is the only periodic job threatd runs, and
// a table nothing ever prunes is a table that grows for the life of the
// deployment.
func TestRunPrunesStaleAllowlistRequests(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.UpsertAllowlistRequest(ctx, "203.0.113.0/24", "sys-a", "old ask", now-200*hour, 0); err != nil {
		t.Fatalf("seed old: %v", err)
	}
	if _, err := s.UpsertAllowlistRequest(ctx, "198.51.100.0/24", "sys-a", "recent ask", now-hour, 0); err != nil {
		t.Fatalf("seed recent: %v", err)
	}

	cfg := testConfig()
	cfg.AllowlistRequestRetention = 168 * time.Hour
	runPass(t, s, cfg)

	rows, err := s.PendingAllowlistRequests(ctx, 0)
	if err != nil {
		t.Fatalf("PendingAllowlistRequests: %v", err)
	}
	if len(rows) != 1 || rows[0].CIDR != "198.51.100.0/24" {
		t.Fatalf("after the pass: got %+v, want only the recent request", rows)
	}
}

// Housekeeping is logged and skipped, never fatal: it must not stop the feed
// being regenerated with the promotions this pass just made. (The malformed
// allowlist row is the deliberate exception, and it aborts for the opposite
// reason -- skipping it would fail open.)
func TestAllowlistRequestPruneFailureDoesNotAbortThePass(t *testing.T) {
	fake := &failingReader{
		rows:             []threatstore.BlocklistRow{{AttackerIP: "203.0.113.7", ExpiresAt: now + hour}},
		failRequestPrune: true,
	}
	snap := NewSnapshot()
	cfg := testConfig()
	cfg.AllowlistRequestRetention = 168 * time.Hour
	r := New(fake, snap, cfg)

	if err := r.Run(context.Background(), now); err != nil {
		t.Fatalf("Run: got %v, want the pass to survive a failed request prune", err)
	}
	if !strings.Contains(string(snap.Body()), "203.0.113.7") {
		t.Fatalf("the snapshot was not regenerated: %q", snap.Body())
	}
}
