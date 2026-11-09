// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package blocklist

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"sort"
	"time"

	threatstore "github.com/nethesis/nethesis-insights/internal/store/threat"
	"github.com/nethesis/nethesis-insights/internal/threat"
)

// Reader is the slice of threatstore.Store consensus needs. Declared here,
// like ui.Reader, so this package is testable with a fake and the layering
// stays a DAG. *threatstore.Store satisfies it.
type Reader interface {
	ConsensusCandidates(ctx context.Context, since int64) ([]threatstore.ThreatCandidateRow, error)
	ThreatAllowlist(ctx context.Context, now int64) ([]threatstore.AllowlistRow, error)
	UpsertBlocklistEntries(ctx context.Context, rows []threatstore.BlocklistRow) error
	ExpireBlocklist(ctx context.Context, now int64) (int, error)
	ListBlocklist(ctx context.Context, now int64, limit int) ([]threatstore.BlocklistRow, error)
	ListBlocklistListedBy(ctx context.Context, now, listedBy int64, limit int) ([]threatstore.BlocklistRow, error)
	ListBlocklistIPs(ctx context.Context, now int64) ([]string, error)
	DeleteBlocklistEntries(ctx context.Context, ips []string) (int, error)
	PruneThreatEvents(ctx context.Context, olderThan int64) (int, error)
	PruneThreatIngestDaily(ctx context.Context, olderThan int64) (int, error)
	PruneFeedDownloadsDaily(ctx context.Context, olderThan int64) (int, error)
	PruneAllowlistRequests(ctx context.Context, olderThan int64) (int, error)
	DownloadWriter
}

// MinSystemsFloor is the fewest distinct systems threatd will start with as
// its promotion rule. It may be raised, never lowered: below it one noisy
// fleet, or one subscriber with a second credential, publishes an address to
// every entitled node.
const MinSystemsFloor = 3

// Config is the consensus rule plus its housekeeping windows.
//
// Runner trusts a validated Config: threatd's startup validation
// (validateConfig in cmd/threatd/main.go) refuses to start with a
// non-positive MaxEntries, Retention, IngestRetention,
// AllowlistRequestRetention, BasicDelay or BasicMaxEntries, so Run does not guard any of
// them a second time. A test that builds a Config literal must therefore set every field
// it exercises -- see testConfig in consensus_test.go -- rather than lean on
// a zero value silently skipping a step.
type Config struct {
	Window     time.Duration // rolling observation window
	MinSystems int           // distinct systems required to promote
	TTL        time.Duration // how long an entry survives its last sighting
	MaxEntries int           // hard cap on the served feed
	Retention  time.Duration // how long raw events are kept

	// IngestRetention is how long per-system ingest-accounting rows
	// (threat_ingest_daily) are kept. It is deliberately independent of
	// Retention: a system that has gone quiet should still show up on
	// /systems for a while after its raw events have already aged out of
	// threat_events, which is why threatd defaults it far longer.
	IngestRetention time.Duration

	// AllowlistRequestRetention is how long an unreviewed client allowlist
	// request is kept. It rides along in this pass because this pass is the
	// only periodic job threatd runs, and the table is client-fed: handling
	// a request deletes its rows, so without this an unreviewed one lives
	// for the life of the deployment.
	AllowlistRequestRetention time.Duration

	// BasicDelay is how long an entry must have been listed before the
	// basic feed publishes it (BLOCKLIST_BASIC_DELAY). It is read only when
	// Runner has a basic snapshot to fill; see BasicCutoff.
	BasicDelay time.Duration

	// BasicMaxEntries is the hard cap on the basic feed
	// (BLOCKLIST_BASIC_MAX_ENTRIES), applied after the delay filter.
	// threatd refuses to start with it above MaxEntries.
	BasicMaxEntries int
}

func (c Config) rule() Rule {
	return Rule{MinSystems: c.MinSystems, Window: c.Window, TTL: c.TTL}
}

// Runner performs one consensus pass.
type Runner struct {
	store     Reader
	snap      *Snapshot
	basic     *Snapshot
	downloads *Downloads
	cfg       Config
}

// New builds a Runner that regenerates snap on every pass and, when basic
// is non-nil, the basic feed alongside it (see BasicCutoff).
func New(r Reader, snap, basic *Snapshot, cfg Config) *Runner {
	return &Runner{store: r, snap: snap, basic: basic, cfg: cfg}
}

// WithDownloads makes every pass flush d's feed-download counts to the
// store, as housekeeping. It returns r for chaining; without it the pass
// flushes nothing.
func (r *Runner) WithDownloads(d *Downloads) *Runner {
	r.downloads = d
	return r
}

// BasicCutoff is the latest first_listed_at the basic feed publishes at
// now: a live entry is on the basic feed once it has been listed for at
// least delay, i.e. iff first_listed_at <= now - delay. Each address waits
// out the delay from its own listing, so additions reach the basic feed
// spread over the day as they were promoted, not all at one fleet-wide
// boundary, and the delay is the same for every address rather than
// anywhere between zero and a whole interval.
//
// Only additions are delayed. The basic feed is read on every pass from the
// same table state the full feed is rendered from, so an address
// that expires or is newly allowlisted leaves both feeds on the same pass:
// holding a wrong entry back for a day would make the free tier the one
// that keeps blocking a legitimate address after an operator exempted it.
//
// It is computed from first_listed_at rather than from a copy kept in
// memory so that it survives a restart unchanged -- an in-memory copy would
// hand every subscriber the full list each time threatd restarted. An entry
// that expires and is later promoted again gets a new first_listed_at and
// waits out the whole delay again, which is correct: it was off the list.
//
// A delay under one millisecond fails closed: the cutoff is the minimum
// int64, so nothing qualifies and the basic feed is empty. The check is on
// the truncated millisecond value, not on the Duration: first_listed_at is
// in milliseconds, so 500us would otherwise become a cutoff of now -- the
// live list. threatd refuses to start with such a delay, but a caller that
// skipped that check must not hand the live list out without the
// entitlement.
func BasicCutoff(now int64, delay time.Duration) int64 {
	ms := delay.Milliseconds()
	if ms <= 0 {
		return math.MinInt64
	}
	return now - ms
}

// candidate is one attacker address folded across every system that reported
// it inside the window.
type candidate struct {
	addr      netip.Addr
	systems   map[string]bool
	scenarios map[string]bool
	hits      int64
	lastSeen  int64
}

// Run executes promote -> expire -> unlist -> prune -> regenerate (the full
// feed, then the basic one).
//
// Order matters twice: the unlist must precede the ListBlocklist that feeds
// Generate so an exempted address leaves the served feed on the same pass it
// leaves the table, and the snapshot is regenerated last so it reflects the
// expiries and unlistings this pass performed. The prunes and the
// feed-download flush have no such constraint and sit together as
// housekeeping.
func (r *Runner) Run(ctx context.Context, now int64) error {
	rows, err := r.store.ConsensusCandidates(ctx, now-r.cfg.Window.Milliseconds())
	if err != nil {
		return fmt.Errorf("blocklist: candidates: %w", err)
	}

	allow, err := r.allowlist(ctx, now)
	if err != nil {
		return err
	}

	promoted := r.promote(rows, allow, now)
	if err := r.store.UpsertBlocklistEntries(ctx, promoted); err != nil {
		return fmt.Errorf("blocklist: promote: %w", err)
	}

	expired, err := r.store.ExpireBlocklist(ctx, now)
	if err != nil {
		return fmt.Errorf("blocklist: expire: %w", err)
	}

	unlisted, err := r.unlist(ctx, allow, now)
	if err != nil {
		return err
	}

	// Housekeeping failures are logged, not fatal: they must not stop the
	// feed from being regenerated with the promotions this pass just made.
	// cfg is validated at startup (see the doc comment on Config), so none
	// of the three windows below is ever non-positive in production; a test
	// that wants a step to no-op sets that field to a duration past its own
	// data instead of relying on a zero value to skip the call.
	if pruned, err := r.store.PruneThreatEvents(ctx, now-r.cfg.Retention.Milliseconds()); err != nil {
		slog.Error("blocklist: prune failed", "error", err)
	} else if pruned > 0 {
		slog.Debug("blocklist: pruned expired threat events", "rows", pruned)
	}

	// Same convention: logged and skipped, never fatal. Without this,
	// threat_ingest_daily grows one row per reporting system per day
	// forever, and ListThreatSystems aggregates the whole table on every
	// GET /systems.
	if pruned, err := r.store.PruneThreatIngestDaily(ctx, now-r.cfg.IngestRetention.Milliseconds()); err != nil {
		slog.Error("blocklist: ingest-daily prune failed", "error", err)
	} else if pruned > 0 {
		slog.Debug("blocklist: pruned stale ingest-accounting rows", "rows", pruned)
	}

	// Same convention. Feed-download counts are flushed from memory, then
	// pruned on the same retention as ingest accounting: both are per-system
	// daily accounting, read on the same /stats page. A failed flush keeps
	// its counts in memory for the next pass.
	if dropped, err := r.downloads.Flush(ctx, r.store); err != nil {
		slog.Error("blocklist: feed download flush failed", "error", err)
	} else if dropped > 0 {
		slog.Warn("blocklist: feed download counts dropped past MaxDownloadKeys", "requests", dropped)
	}
	if pruned, err := r.store.PruneFeedDownloadsDaily(ctx, now-r.cfg.IngestRetention.Milliseconds()); err != nil {
		slog.Error("blocklist: feed-downloads prune failed", "error", err)
	} else if pruned > 0 {
		slog.Debug("blocklist: pruned stale feed-download rows", "rows", pruned)
	}

	// Same convention: logged and skipped, never fatal. A review queue that
	// keeps a few stale asks is a smaller problem than a feed that stopped
	// being regenerated.
	if pruned, err := r.store.PruneAllowlistRequests(ctx, now-r.cfg.AllowlistRequestRetention.Milliseconds()); err != nil {
		slog.Error("blocklist: allowlist request prune failed", "error", err)
	} else if pruned > 0 {
		slog.Debug("blocklist: pruned stale allowlist requests", "rows", pruned)
	}

	// One row past the cap is asked for only to learn whether the cap binds.
	// The store orders most recently seen first, so what is cut is what the
	// fleet saw longest ago: a feed that outgrows its consumers' memory is
	// worse than a truncated one, but the truncation must be visible.
	// MaxEntries is validated positive at startup, so this never asks for
	// an uncapped list.
	live, err := r.store.ListBlocklist(ctx, now, r.cfg.MaxEntries+1)
	if err != nil {
		return fmt.Errorf("blocklist: list: %w", err)
	}
	capped := len(live) > r.cfg.MaxEntries
	if capped {
		live = live[:r.cfg.MaxEntries]
		slog.Warn("blocklist: feed capped at BLOCKLIST_MAX_ENTRIES; the least recently seen addresses are left out",
			"max_entries", r.cfg.MaxEntries)
	}
	if err := r.snap.Generate(live, r.cfg.rule(), capped, now); err != nil {
		return err
	}
	attrs := []any{
		"candidates", len(rows), "promoted", len(promoted), "expired", expired,
		"unlisted", unlisted, "entries", r.snap.View().Entries,
	}
	if r.basic != nil {
		if err := r.generateBasic(ctx, now); err != nil {
			return err
		}
		attrs = append(attrs, "basic_entries", r.basic.View().Entries)
	}
	attrs = append(attrs, "min_systems", r.cfg.MinSystems)

	slog.Info("blocklist consensus pass", attrs...)
	return nil
}

// generateBasic renders the basic feed: the live entries listed for at
// least BasicDelay, capped at BasicMaxEntries.
//
// The delay is applied in SQL, before the cap, and the cap is the basic
// feed's own. Filtering the full feed's already-capped rows instead would
// starve it whenever BLOCKLIST_MAX_ENTRIES binds: the full cap keeps the
// most recently seen rows, which are disproportionately the newly listed
// ones the basic feed may not publish yet, so eligible rows would lose
// their slots to rows it then drops.
//
// What this guarantees: every basic entry is a live, non-allowlisted row
// listed at least BasicDelay ago, read after this pass's expiry and
// unlisting, so a removal reaches both feeds on the same pass. While the
// full feed is not capped, the basic feed is a subset of it. When the full
// feed is capped, the basic feed may carry an eligible address the full
// cap cut for being seen longer ago -- the two caps rank different sets --
// which is the price of not starving it, and harmless: it is an address
// the fleet agreed on, not one anybody removed.
func (r *Runner) generateBasic(ctx context.Context, now int64) error {
	rule := r.cfg.rule()
	rule.Delay = r.cfg.BasicDelay
	cutoff := BasicCutoff(now, r.cfg.BasicDelay)
	if cutoff == math.MinInt64 {
		// Fail closed without asking the store: an empty, ready feed.
		return r.basic.Generate(nil, rule, false, now)
	}
	// One row past the cap, as for the full feed, only to learn whether
	// it binds.
	rows, err := r.store.ListBlocklistListedBy(ctx, now, cutoff, r.cfg.BasicMaxEntries+1)
	if err != nil {
		return fmt.Errorf("blocklist: list basic: %w", err)
	}
	capped := len(rows) > r.cfg.BasicMaxEntries
	if capped {
		rows = rows[:r.cfg.BasicMaxEntries]
		slog.Warn("blocklist: basic feed capped at BLOCKLIST_BASIC_MAX_ENTRIES; the least recently seen addresses are left out",
			"max_entries", r.cfg.BasicMaxEntries)
	}
	return r.basic.Generate(rows, rule, capped, now)
}

// allowlist loads the hand-maintained exclusions.
//
// A malformed row aborts the pass rather than being skipped. An allowlist
// that silently loses an entry fails open -- it would publish an address
// someone had explicitly excluded -- and a stale feed is the safer failure.
func (r *Runner) allowlist(ctx context.Context, now int64) (threat.Allowlist, error) {
	rows, err := r.store.ThreatAllowlist(ctx, now)
	if err != nil {
		return threat.Allowlist{}, fmt.Errorf("blocklist: allowlist: %w", err)
	}
	cidrs := make([]string, 0, len(rows))
	for _, row := range rows {
		cidrs = append(cidrs, row.CIDR)
	}
	allow, err := threat.ParseAllowlist(cidrs)
	if err != nil {
		return threat.Allowlist{}, fmt.Errorf("blocklist: %w", err)
	}
	return allow, nil
}

// unlist deletes the live blocklist rows the allowlist now covers.
//
// promote applies the allowlist too, but promotion can only decline to *add*
// a row -- an address the fleet already agreed about keeps its row, and
// ExpireBlocklist deletes on expires_at alone, so without this step an
// exemption added now would not take effect for up to BLOCKLIST_TTL.
//
// It is keyed on the live blocklist rather than on this pass's candidates,
// which is the whole reason it cannot be folded into promote: the TTL
// outlives the observation window many times over, so by the time an
// operator exempts a listed address its events have usually aged out and the
// candidate set holds nothing at all for it.
//
// A store error aborts the pass, like every other step on the critical path.
// Continuing would regenerate a feed that still carried the address anyway,
// and the previous snapshot is the honest thing to keep serving until the
// database answers again.
func (r *Runner) unlist(ctx context.Context, allow threat.Allowlist, now int64) (int, error) {
	if allow.Len() == 0 {
		return 0, nil
	}
	ips, err := r.store.ListBlocklistIPs(ctx, now)
	if err != nil {
		return 0, fmt.Errorf("blocklist: live entries: %w", err)
	}
	var covered []string
	for _, ip := range ips {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			// A corrupted row, not untrusted input -- the addresses were
			// parsed before they were written. ExpireBlocklist will reap it.
			continue
		}
		// Allowlist.Contains unmaps and unzones, so a row stored under a
		// second spelling of an exempted address is still covered.
		if allow.Contains(addr) {
			covered = append(covered, ip)
		}
	}
	if len(covered) == 0 {
		return 0, nil
	}
	n, err := r.store.DeleteBlocklistEntries(ctx, covered)
	if err != nil {
		return 0, fmt.Errorf("blocklist: unlist: %w", err)
	}
	slog.Info("blocklist: unlisted allowlisted addresses", "rows", n)
	return n, nil
}

// promote folds candidate triples per address and returns the entries
// clearing the rule.
func (r *Runner) promote(rows []threatstore.ThreatCandidateRow, allow threat.Allowlist, now int64) []threatstore.BlocklistRow {
	folded := map[netip.Addr]*candidate{}
	for _, row := range rows {
		addr, err := netip.ParseAddr(row.AttackerIP)
		if err != nil {
			continue
		}
		// Unmapped and unzoned before it is used as a map key, so two
		// spellings of one address cannot fold into two candidates and so
		// the allowlist check below -- netip.Prefix.Contains, which is false
		// for any zoned address -- cannot be evaded by a "%1" suffix. Ingest
		// already refuses both spellings; this is the second lock, on the
		// side that reads them back out of the store.
		addr = addr.Unmap().WithZone("")
		c, seen := folded[addr]
		if !seen {
			c = &candidate{addr: addr, systems: map[string]bool{}, scenarios: map[string]bool{}}
			folded[addr] = c
		}
		c.systems[row.SystemID] = true
		c.scenarios[row.Scenario] = true
		c.hits += row.Hits
		if row.LastSeen > c.lastSeen {
			c.lastSeen = row.LastSeen
		}
	}

	out := make([]threatstore.BlocklistRow, 0, len(folded))
	for addr, c := range folded {
		// Applied at promotion rather than at read. This half only declines
		// to list; unlist above is what removes an address the fleet had
		// already agreed about.
		if allow.Contains(addr) {
			continue
		}
		if len(c.systems) < r.cfg.MinSystems {
			continue
		}
		// Clamped at now: the feed is ordered by last_seen_at DESC and
		// BLOCKLIST_MAX_ENTRIES cuts on that order, so a reporter with a fast
		// clock posting sightings dated hours into the future would put its
		// addresses first under the cap and, since expires_at hangs off the
		// same value, extend their listing by the same margin. Only the
		// derived blocklist row is clamped -- the underlying threat_events
		// row keeps whatever timestamp it was stored with.
		lastSeen := c.lastSeen
		if lastSeen > now {
			lastSeen = now
		}
		scenarios := keys(c.scenarios)
		out = append(out, threatstore.BlocklistRow{
			AttackerIP: addr.String(),
			// Ignored by the upsert when the row already exists: a refresh is
			// not a new listing.
			FirstListedAt:   now,
			LastSeenAt:      lastSeen,
			ExpiresAt:       lastSeen + r.cfg.TTL.Milliseconds(),
			DistinctSystems: len(c.systems),
			Scenarios:       scenarios,
			Reason: threatstore.ListingReason{
				Systems:       len(c.systems),
				Hits:          c.hits,
				Scenarios:     scenarios,
				WindowMinutes: int(r.cfg.Window.Minutes()),
				MinSystems:    r.cfg.MinSystems,
				Rule:          "v1",
				DecidedAt:     now,
			},
		})
	}
	// Deterministic upsert order keeps the write log readable and the tests
	// stable.
	sort.Slice(out, func(i, j int) bool { return out[i].AttackerIP < out[j].AttackerIP })
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
