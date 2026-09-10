// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package logs

import (
	"context"
	"fmt"

	"github.com/nethesis/nethesis-insights/internal/model"
)

// pruneBatchSize bounds how many rows one DELETE statement removes.
//
// insightsd has never pruned anything until this file, so the first maint
// pass against a live deployment can face months of unpruned history --
// hundreds of thousands of `analyses` rows alone, at one per system per
// 15-minute window across the fleet. A single unbounded `DELETE ... WHERE
// created_at < ?` would hold the write mutex (SetMaxOpenConns(1) plus
// sqlitex.DB's lock) for as long as that delete takes, and every bundle the
// ingest queue's workers try to record in the meantime blocks behind it.
// Looping in bounded batches, releasing the lock between them, turns that
// into many small write-mutex holds an ingest write can always interleave
// with -- the same "bounded, not one transaction" trade-off
// internal/baseline makes for its pressure_version catch-up
// (baseline.DefaultRecomputeBatch), and the same order of magnitude (5000).
//
// A var, not a const, so TestPruneLoopsAcrossMultipleBatches can shrink it
// and prove pruneLoop actually iterates instead of asserting that only on a
// 5000-row fixture.
var pruneBatchSize = 5000

// pruneLoop repeatedly runs deleteSQL -- a DELETE whose last placeholder is a
// row-count LIMIT applied through a subquery, e.g.
//
//	DELETE FROM t WHERE pk IN (SELECT pk FROM t WHERE <condition> LIMIT ?)
//
// -- until a batch deletes fewer than pruneBatchSize rows, taking and
// releasing the write lock once per batch. The subquery-with-LIMIT shape
// (rather than SQLite's non-standard `DELETE ... LIMIT`, which is a build
// option many SQLite builds omit) is the portable spelling, and standard SQL
// is this repo's convention even now that Postgres has been dropped as a
// goal -- it costs nothing here and does not depend on a compile-time
// option.
func (s *Store) pruneLoop(ctx context.Context, deleteSQL string, args ...any) (int, error) {
	batchArgs := append(append([]any{}, args...), pruneBatchSize)

	total := 0
	for {
		s.db.Lock()
		res, err := s.db.ExecContext(ctx, deleteSQL, batchArgs...)
		s.db.Unlock()
		if err != nil {
			return total, fmt.Errorf("store: prune: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("store: prune rows affected: %w", err)
		}
		total += int(n)
		if n < int64(pruneBatchSize) {
			return total, nil
		}
		// A cancelled pass stops between batches rather than mid-delete; the
		// batches already committed stay deleted, since each is a
		// self-contained statement, not one long transaction.
		if err := ctx.Err(); err != nil {
			return total, err
		}
	}
}

// PruneTemplates deletes system_templates rows not seen since olderThan.
//
// This is the gate's "have I seen this template before" memory
// (gate.Evaluate fires new_templates when a line's key is absent here), so
// olderThan must be comfortably longer than the longest gap a real recurring
// line can have -- see maint.Config.TemplateRetention for the default and
// its justification. Pruned too eagerly, a monthly cron or a quarterly
// certificate renewal looks "new" every time it recurs and pays for an LLM
// call it would not otherwise have caused.
//
// module_baselines describes the same (system_id, module_id) buckets as
// system_templates but is deliberately NOT pruned here: unlike this table it
// does not grow with each distinct template ever seen, only with the number
// of distinct buckets a system has (upserted in place, never appended), so
// it stays small on its own and has no comparable backlog problem. If a
// future change does prune it, its retention must be at least
// TemplateRetention -- the two describe the same buckets, and a baseline
// that outlives the templates it was computed from silently orphans them.
func (s *Store) PruneTemplates(ctx context.Context, olderThan int64) (int, error) {
	return s.pruneLoop(ctx, `
		DELETE FROM system_templates
		WHERE (system_id, module_id, template_key) IN (
			SELECT system_id, module_id, template_key FROM system_templates
			WHERE last_seen < ?
			LIMIT ?
		)
	`, olderThan)
}

// PruneFindings deletes findings rows past olderThan (by last_seen) that are
// NOT open. An open finding is current by definition, however old its
// first_seen is, and is never a candidate no matter how far olderThan
// reaches back -- see TestPruneFindingsSparesOpenOnes.
//
// A pruned finding's fingerprint is not remembered afterwards: if the same
// condition recurs, UpsertFinding sees no prior row and reports
// OutcomeInserted rather than OutcomeReopened, so occurrence_count and
// first_seen restart. That is a display/continuity cost, not a financial
// one -- unlike system_templates, losing this history does not make the
// gate fire again -- which is why FindingRetention is allowed to be shorter
// than TemplateRetention.
func (s *Store) PruneFindings(ctx context.Context, olderThan int64) (int, error) {
	return s.pruneLoop(ctx, `
		DELETE FROM findings WHERE id IN (
			SELECT id FROM findings WHERE status != ? AND last_seen < ? LIMIT ?
		)
	`, model.StatusOpen, olderThan)
}

// PruneAnalyses deletes analyses rows created before olderThan.
//
// This is the cost ledger and the gate-reason record; the operator UI's
// /cost and /gate pages are both built by rolling this table up (CostRollup
// has no time bound at all -- see internal/store/logs/ui.go). There is no
// rollup table for the logs pipeline (out of scope for this change, unlike
// threatd's threat_daily_stats and sizingd's sizing_node_monthly, both
// written before their own prune specifically so a dropped day's history
// survives it), so every row this deletes is gone permanently: /cost's spend
// history and /gate's reason history both truncate at olderThan with no way
// to recover what came before. AnalysisRetention is chosen with that in
// mind -- see maint.Config.
func (s *Store) PruneAnalyses(ctx context.Context, olderThan int64) (int, error) {
	return s.pruneLoop(ctx, `
		DELETE FROM analyses WHERE id IN (
			SELECT id FROM analyses WHERE created_at < ? LIMIT ?
		)
	`, olderThan)
}
