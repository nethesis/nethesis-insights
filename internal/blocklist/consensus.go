// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package blocklist

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"time"

	"github.com/nethesis/nethesis-insights/internal/store"
	"github.com/nethesis/nethesis-insights/internal/threat"
)

// Reader is the slice of store.Store consensus needs. Declared here, like
// ui.Reader, so this package is testable with a fake and the layering stays a
// DAG. *store.SQLiteStore satisfies it.
type Reader interface {
	ConsensusCandidates(ctx context.Context, since int64) ([]store.ThreatCandidateRow, error)
	ThreatAllowlist(ctx context.Context, now int64) ([]store.AllowlistRow, error)
	EgressIPs(ctx context.Context) ([]string, error)
	UpsertBlocklistEntries(ctx context.Context, rows []store.BlocklistRow) error
	ExpireBlocklist(ctx context.Context, now int64) (int, error)
	ListBlocklist(ctx context.Context, now int64, limit int) ([]store.BlocklistRow, error)
	RollupThreatDailyStats(ctx context.Context) error
	PruneThreatEvents(ctx context.Context, olderThan int64) (int, error)
}

// Config is the consensus rule plus its housekeeping windows.
type Config struct {
	Window     time.Duration // rolling observation window
	MinSystems int           // distinct systems required to promote
	TTL        time.Duration // how long an entry survives its last sighting
	MaxEntries int           // hard cap on the served feed
	Retention  time.Duration // how long raw events are kept
}

func (c Config) rule() Rule {
	return Rule{MinSystems: c.MinSystems, Window: c.Window, TTL: c.TTL}
}

// Runner performs one consensus pass.
type Runner struct {
	store Reader
	snap  *Snapshot
	cfg   Config
}

func New(r Reader, snap *Snapshot, cfg Config) *Runner {
	return &Runner{store: r, snap: snap, cfg: cfg}
}

// candidate is one attacker address folded across every system that reported
// it inside the window.
type candidate struct {
	addr       netip.Addr
	systems    map[string]bool
	categories map[string]bool
	hits       int64
	lastSeen   int64
}

// Run executes promote -> expire -> roll up -> prune -> regenerate.
//
// Order matters twice: the rollup must precede the prune or the dropped day
// loses its history, and the snapshot is regenerated last so it reflects the
// expiries this pass performed.
func (r *Runner) Run(ctx context.Context, now int64) error {
	rows, err := r.store.ConsensusCandidates(ctx, now-r.cfg.Window.Milliseconds())
	if err != nil {
		return fmt.Errorf("blocklist: candidates: %w", err)
	}

	allow, err := r.allowlist(ctx, now)
	if err != nil {
		return err
	}
	egress, err := r.egressSet(ctx)
	if err != nil {
		return err
	}

	promoted := r.promote(rows, allow, egress, now)
	if err := r.store.UpsertBlocklistEntries(ctx, promoted); err != nil {
		return fmt.Errorf("blocklist: promote: %w", err)
	}

	expired, err := r.store.ExpireBlocklist(ctx, now)
	if err != nil {
		return fmt.Errorf("blocklist: expire: %w", err)
	}

	// Housekeeping failures are logged, not fatal: they must not stop the
	// feed from being regenerated with the promotions this pass just made.
	if err := r.store.RollupThreatDailyStats(ctx); err != nil {
		slog.Error("blocklist: daily rollup failed", "error", err)
	} else if r.cfg.Retention > 0 {
		// Only prune when the rollup that protects the history succeeded.
		if pruned, err := r.store.PruneThreatEvents(ctx, now-r.cfg.Retention.Milliseconds()); err != nil {
			slog.Error("blocklist: prune failed", "error", err)
		} else if pruned > 0 {
			slog.Debug("blocklist: pruned expired threat events", "rows", pruned)
		}
	}

	live, err := r.store.ListBlocklist(ctx, now, r.cfg.MaxEntries)
	if err != nil {
		return fmt.Errorf("blocklist: list: %w", err)
	}
	if err := r.snap.Generate(live, r.cfg.rule(), r.cfg.MaxEntries, now); err != nil {
		return err
	}

	slog.Info("blocklist consensus pass",
		"candidates", len(rows), "promoted", len(promoted), "expired", expired,
		"entries", r.snap.Entries(), "min_systems", r.cfg.MinSystems)
	return nil
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

// egressSet is the fleet self-protection exclusion: the union of the
// addresses reporters were seen from. It closes the worst failure mode --
// one customer's misconfigured appliance getting the fleet's own WAN address
// listed -- without depending on inventory contents.
func (r *Runner) egressSet(ctx context.Context) (map[netip.Addr]bool, error) {
	ips, err := r.store.EgressIPs(ctx)
	if err != nil {
		return nil, fmt.Errorf("blocklist: egress ips: %w", err)
	}
	set := make(map[netip.Addr]bool, len(ips))
	for _, ip := range ips {
		if a, err := netip.ParseAddr(ip); err == nil {
			set[a.Unmap()] = true
		}
	}
	return set, nil
}

// promote folds candidate triples per address and returns the entries
// clearing the rule.
func (r *Runner) promote(rows []store.ThreatCandidateRow, allow threat.Allowlist, egress map[netip.Addr]bool, now int64) []store.BlocklistRow {
	folded := map[netip.Addr]*candidate{}
	for _, row := range rows {
		addr, err := netip.ParseAddr(row.AttackerIP)
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		c, seen := folded[addr]
		if !seen {
			c = &candidate{addr: addr, systems: map[string]bool{}, categories: map[string]bool{}}
			folded[addr] = c
		}
		c.systems[row.SystemID] = true
		c.categories[row.Category] = true
		c.hits += row.Hits
		if row.LastSeen > c.lastSeen {
			c.lastSeen = row.LastSeen
		}
	}

	out := make([]store.BlocklistRow, 0, len(folded))
	for addr, c := range folded {
		// Both exclusions are applied at promotion rather than at read, so
		// adding an allowlist entry retroactively unlists the address on this
		// pass instead of merely hiding it.
		if allow.Contains(addr) || egress[addr] {
			continue
		}
		if len(c.systems) < r.cfg.MinSystems {
			continue
		}
		categories := keys(c.categories)
		out = append(out, store.BlocklistRow{
			AttackerIP: addr.String(),
			// Ignored by the upsert when the row already exists: a refresh is
			// not a new listing.
			FirstListedAt:   now,
			LastSeenAt:      c.lastSeen,
			ExpiresAt:       c.lastSeen + r.cfg.TTL.Milliseconds(),
			DistinctSystems: len(c.systems),
			Categories:      categories,
			Reason: store.ListingReason{
				Systems:       len(c.systems),
				Hits:          c.hits,
				Categories:    categories,
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
