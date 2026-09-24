<!--
Copyright (C) 2026 Nethesis S.r.l.
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Trigger memory and operator review — plan

Goal: stop paying for LLM calls on conditions already analysed, let an
operator review each condition once fleet-wide, and measure prompt changes
against operator judgement.

How it works and why each rule exists: `docs/architecture.md` § "Cost
control: trigger memory". Operator view: `docs/admin-guide.md` § 3b.

## Done

### Phase 0 — measurement (dev fleet, 4 clusters, 7 days to 2026-09-24)

1,814 LLM calls; the gate fired on ~70% of windows.

| Question | Result |
|---|---|
| (a) calls by gate reason | deviation on 72.7% of calls, new_templates 54.4%, security_surge 5.8%, security_new 1.5%. Deviation alone: 43% of calls, 37% of cost |
| (b) novelty calls whose key was seen earlier on another system | 29 of 995 (3%); 949 distinct keys — the key almost never repeats across systems |
| (c) deviation calls repeating a bucket on the same system with a finding open | 537 of 1,316, 25.8% of spend. Replayed with the Phase 1 key: 39% of spend |

The trigger memory saves money on (c) only; on (b) only through ignores, and
only once keys repeat. The masking leaks were the bigger and prior win: 6,768
templates were "new" in seven days, and 90% of new findings had
`occurrence_count = 1`.

### Collector masking v5 — `ns8-loki` `bb9bb3c`, branch `anomaly_detector`

Whole-line folds for echoed spans (rspamd symbol lists and message ids,
kamailio/rsyslog/tancredi payloads, HTTP bodies, coredump traces, byte dumps,
PHP truncated arguments), token rules (ctime/Tomcat dates, `0x` pointers,
ULIDs, mixed-case opaque ids with a class-switch floor, rspamd tags, SIP
call-ids and dialog tags, nethcti user names) and collapse of repeated
placeholders. Replay: 6,768 → 2,246 new templates; novelty stops firing on
812 of 996 novelty calls; 425 calls (23% of spend) not made at all — a floor,
since the stored text already carries v4's per-window `<*>` wildcards.

Deployed: `loki1` on rl1 runs `ghcr.io/nethserver/loki:anomaly_detector`
with the collector on; the server receives its windows.

### Phase 1 — key, tables, lookup, ignore, reuse — `753fc14`

- `internal/trigger` (pure): key over novel canonical keys *when novelty
  fired*, deviating `(family, priority)` buckets, one security bit; no
  `system_id`; `trigger.Version = "t1"`.
- `gate.Decision` exposes `NoveltyFired`, `SecurityNew`, `SecuritySurge`,
  `DeviatingBuckets`.
- Tables `triggers`, `system_triggers`, `trigger_aliases`,
  `trigger_decisions`; columns `findings.trigger_key`, `analyses.trigger_key`.
- `analyzer.Process`, between gate and render: unexpired ignore (never a
  security trigger) → `trigger_ignored`; paid for on this system within
  `TRIGGER_REUSE_WINDOW` (24h) of the last *paid* call, with every finding
  that call raised still open or none raised → `trigger_hit`. Suppressed
  windows keep their reasons and record templates and baselines.
- `IgnoreTrigger` in the store (audit row; refuses security triggers and past
  expiries) — no route yet.
- Invariant amended: non-empty reasons and empty `suppressed_by` ⇒ a call;
  `/gate` shows a Suppressed column.
- `insightsd_trigger_suppressions_total{reason}`; maint prunes
  `system_triggers` (finding retention) and undecided, unreferenced
  `triggers` (template retention).

### Findings page — `53da242`

Nodes shown as `id · fqdn`; the row was one cell short of the header since
the Nodes column was added, which shifted every column after Occurrences.

## Next

### Now: let v5 settle, then re-measure

After a few days of v5 data from rl1 (and any other cluster moved to the
`anomaly_detector` image), re-run the Phase 0 queries and the replay. Expect
the one-time v5 burst in the first windows. Decide from the numbers whether
`TRIGGER_REUSE_WINDOW` stays at 24h.

### Phase 2 — visibility, review, merge, stats

- **Visibility in the read API.** `ListFindings` filters on the root trigger's
  `visibility = 'customer'` in SQL, one join through the flattened
  `trigger_aliases`. New non-security triggers start `pending`, so this
  withholds every new non-security finding until reviewed — confirm that is
  wanted before shipping. Open findings keep reaching `prompt.Render`
  whatever their visibility. `TestOperatorOnlyFindingsNeverReachTheReadAPI`.
- **Review routes on `ui/logs`**, copying `internal/ui/threat`: enumerated
  `writableRoutes`, POST only, `chrome.AuthenticateWrite`, `sameOriginWrite`,
  registered only with `ADMIN_API_KEY`, one `trigger_decisions` row per
  action in the same transaction as the change.
  - `/review`: pending triggers ranked by `distinct_systems` then `count`,
    bounded queries like `PendingAllowlistRequests`. Actions: deliver,
    internal, ignore (with expiry), merge into, set severity, set `doc_ref`.
  - `/review/stats`: per `prompt.Version`, new triggers and the share
    delivered, internal, ignored, merged.
- **Merge.** Rewrite every alias of the merged key to the new root; reject
  cycles and merges across different security bits.
  `TestMergeResolvesToRootAndRejectsCycles`, and the merge half of
  `TestSecurityTriggersAreNeverQueuedIgnoredOrMerged`.
- **Severity override and `doc_ref`** applied when findings are read for the
  customer, never written into `findings.severity` (which `Render` prints).
  Remediation text lives in `docs/`, referenced by `doc_ref`.

### Smaller follow-ups

- Collector: stdout is block-buffered under systemd, so "shipped" lines reach
  the journal only when the unit stops (`PYTHONUNBUFFERED=1` or
  `flush=True`).
- Deviation fires at a flat rate at every hour on ~15 nethvoice buckets —
  a steady state being scored as a surge; look at the gate's baseline or the
  edge's `expected` for those buckets.
- The deployed logs database got `trigger_key` by a one-off `ALTER TABLE`, as
  `nodes` did before; a fresh database gets it from `store.Init`.

### Out of scope

Embeddings, a wiki or any export of template text, fleet-shared finding
prose, seed files, fine-tuning, Postgres, a second model.
