# NS8 fleet sizing pipeline in `nethesis-insights`

## Context

`perfmance_estimator.md` proposes a fleet sizing engine: NS8 nodes push 24 h aggregated
workload and performance metrics, a central server scores each node 0–100, and an ML job
derives per-module hardware baselines. The goal is real and unserved — Nethesis has no
fleet-wide answer to "how much RAM does a node running NethVoice need".

The document was written without reference to this repository or to what NS8 actually
exposes, so as written it cannot be built: Bearer-token auth against a server that uses
HTTP Basic forward-auth; a Postgres-native schema that violates this repo's portability
invariants line by line; per-product columns for metrics no NS8 exporter emits; and a
Python/scikit-learn training job for a repository that ships as one Go binary in a podman
quadlet.

This plan keeps the goal and replaces what does not survive contact with the code. The
result is a **third independent pipeline** beside the log-bundle pipeline and Threat
Shield, sharing only the HTTP listener, `internal/auth`, the SQLite file — and
`model.ModuleFamily`, deliberately, because that is already the single definition of
module identity and a second one would eventually disagree. No LLM, no gate, no
fingerprint, no queue.

### Decisions taken with the user

| Question | Decision |
|---|---|
| Workload source | A reporter running as the **cluster agent in `ns8-core`**, so it can call every module's `get-facts` |
| Server scope for v1 | Ingest + score + **cohort baseline pass** + operator UI |
| Score shape | **Split**: a `pressure` number (undersizing) + stored utilization percentiles (headroom), versioned |

---

## Ground truth established on `rl1` (read-only, 2026-09-02)

| Fact | Value |
|---|---|
| Prometheus | `http://127.0.0.1:9091`, loopback, **no auth**, route prefix `/${PROMETHEUS_PATH}/` |
| Scrape / retention | 1 m / 15 d — both Prometheus *defaults*; nothing in `ns8-metrics` pins them |
| `ns8-metrics` | `core_module`, auto-installed on every leader by ns8-core's `update-core-post-modules.d/70metrics` → **Prometheus is fleet-wide** |
| node_exporter | every node, via WireGuard IP `:9100`, labels `node`, `instance`, `target_type="node"` |
| Per-container metrics | **none** — no cAdvisor, no cgroup exporter, `processes` collector off |
| PSI (`node_pressure_*`) | collector enabled but `/proc/pressure` **absent** on Rocky 9 → series empty. Do not use |
| `cluster/subscription` fields | `system_id`, `auth_token`, `provider`, `support_user`, `vpn_cert_cn` |
| Redis reach | `cluster/default_instance/{loki,metrics}` and other modules' `environment` hashes are readable |

The last row **closes an open question in CLAUDE.md** ("Exact field names in the NS8
`cluster/subscription` Redis hash … must be read from a live node") and makes
`SUBSCRIPTION_SECRET_FIELDS = ("auth_token", "secret", "password")` at
`ns8-loki/imageroot/bin/insights-collector:77` dead code — `secret`/`password` are never
written by ns8-core's `set-subscription`.

---

## What the draft gets wrong

**Blocking.**

1. **Auth and transport.** `POST /api/v1/sizing/report` with Bearer auth does not exist
   here. Every endpoint is `/v1/…` over HTTP Basic `system_id:auth_token` through
   `internal/auth.ForwardAuth`, fail-closed (`401` invalid, `503` validator unreachable).
2. **The schema violates every portability invariant** (CLAUDE.md:350–359): `DATE`,
   `TIMESTAMPTZ`, `BIGINT`, `FLOAT` are all disallowed.
3. **`instance_id` is the wrong unit.** An NS8 `system_id` is a **cluster**. Prometheus on
   the leader holds `node_*` series for every node, labelled `node="<numeric id>"`. One
   report carries N nodes; the key is `(system_id, node_id, day)`.
4. **The workload fields do not exist as metrics.** Nothing exports `mail_users`,
   `pbx_active_calls_p95` etc. Those counts come from module `get-facts` over the NS8
   agent bus — which is why the reporter must be the cluster agent.
5. **The ML engine cannot live in this repo** — single Go binary, rootful quadlet.

**Substantive.**

6. **No per-module resource attribution exists, and none is coming from this stack.**
   Per-module cost can only be *inferred* from variation across nodes. The draft reads as
   though it were measurable; the UI must not.
7. **The score saturates.** `min(S_RAM, S_CPU)` is 100 for everything below 0.85/0.80, so
   right-sized and 4× over-provisioned are identical — while the scale labels 80–100
   "Optimal / **Over-sized**". Hence the split.
8. **Two of three stress terms are noise amplifiers.** `max_iowait` is a 24 h *max* of a
   5 min average, so one nightly backup pins it and drives a 50-point penalty;
   `P_swap = 20 if swap_rate > 0` fires on a single page-in. This is the failure the log
   gate already suffered and was fixed for (`deploy.md`, "Deviation on noise"). **The
   general fix: replace every "max over 24 h" with a duration or a high percentile.** A
   duration has a denominator — a 25-minute backup is 1.7 % of the day, a starved node is
   30 %; `max` cannot tell them apart.
9. **`P_iowait + P_load` double-counts** — Linux load includes uninterruptible sleep, so a
   disk-bound node inflates both, reaching 80 penalty points from one cause.
10. **Unguarded arithmetic.** No branch for `U > 1`; division by `cpu_cores` /
    `ram_bytes` with no zero guard. A zero denominator means a broken scrape, and a score
    from missing data is worse than no score — so it must yield `NULL`, not a clamp.
11. **`load15_avg` is named an average and used as a peak.**
12. **A single day is not a verdict**, and an average across days is the wrong aggregator
    twice: it washes out one catastrophic day and inflates 28 mediocre ones.
13. **Disk fill is absent** — the most common real capacity failure, with
    `node_filesystem_avail_bytes` right there and already alerted on by ns8-metrics.
14. **No formula version.** Changing a weight silently re-ranks all history.
15. **Three sends a day + a relative `[24h]` query = an undefined report.** With
    `send-inventory`-style scheduling, three overlapping windows upsert the same row and
    the stored "day" becomes a random 24 h slice. The report must cover the **last
    complete UTC day**, queried over an absolute range, carrying `day` explicitly.
16. **Node identity is not stable.** `node` is a small integer scoped to the cluster: a
    rebuilt cluster reuses `system_id` with fresh ids, a replaced machine keeps its id
    with different hardware. Percentiles then straddle two physical machines.

**Data protection.** The metrics carry identifying labels — `ns8_node_info{fqdn}`,
`ns8_node_main_ip_address{address}`, DMI `serial` / `board_asset_tag`,
`node_uname_info{nodename}`. The `internal/threat` precedent applies: drop at **ingest**,
never at read, in a pure package, exhaustively tested. The report also carries
per-customer commercial data (mailbox and PBX user counts, product mix) and the operator
UI's `GET` is unauthenticated and fleet-wide — consistent with the existing decision, but
it must be recorded explicitly for this pipeline rather than inherited by accident.

---

## Design

### 1. Wire contract — `docs/specs/2026-09-02-sizing-ingest-contract.md`

Written first, shaped like `docs/specs/2026-08-07-threat-events-ingest-contract.md`,
because it is what ns8-core builds against. Rename the source document to
`docs/specs/2026-09-02-fleet-sizing-design.md` (fixing the `perfmance` typo) and keep it
as the *why*.

`POST /v1/sizing-reports`, Basic auth, optional gzip, 8 MiB cap, `202 Accepted`. Rules
carried over from the threat contract because they were already right: fail-closed on
auth, fail-open on content; `system_id` optional and `403` on mismatch; its own
`model.SizingSchemaVersion`; a `dropped` counter object returned *and* persisted; safe
redelivery.

One report = one cluster = N nodes, each covering **one complete UTC day**:

```json
{"schema_version": 1, "system_id": "…", "reporter_version": "1.0.0",
 "days": [{"day": "2026-09-01",
   "nodes": [{"node_id": 1, "metrics_present": true, "sample_coverage": 0.998,
     "hardware": {"cpu_cores": 4, "mem_total_bytes": 8054087680, "cpu_model": "…"},
     "resources": {"ram_util_p95": 0.41, "ram_used_bytes_p95": 3300000000, "…": 0},
     "stress":    {"iowait_busy_frac": 0.01, "oom_kills": 0, "…": 0},
     "modules": [{"family": "nethvoice", "instances": 2, "facts_ok": 2,
                  "workload": {"users": 130, "trunks": 4}}]}],
   "cluster": {"user_domains": [{"total_users": 210, "total_groups": 18}]}}]}
```

Because a day is an absolute fact, the three daily sends are byte-identical restatements:
retries are free and the upsert **recomputes** rather than accumulates. `days` is an array
so a node that was offline can backfill up to 7 days. A `day` outside
`[now − 15 d, now − 1 d]` is rejected — older than Prometheus retention means it cannot
have been computed from real data.

**`workload` is an open `string → number` map, and "number" is the entire privacy
control.** Open vocabulary for the same reason Threat Shield accepts every scenario: the
NS8 module set grows continuously, and a typed column per product means every new
product's metric is silently discarded until a server release. Numbers-only because *an
FQDN, an IP, a hostname or a DMI serial cannot be encoded in a float* — a stronger
guarantee than any field blocklist that has to be maintained. Values must be finite,
non-negative and **extensive** (summable across instances of a family: counts, bytes,
rates — not versions, ratios or ids). Caps are on shape, not vocabulary: key
`^[a-z][a-z0-9_]{0,39}$`, ≤ 32 metrics/family, ≤ 64 families/node, ≤ 16 nodes/report,
truncating and counting rather than rejecting.

The only free-text fields in the whole payload are `cpu_model`, `os_id`, `os_version`,
`kernel_release`, `virtualization` — each trimmed, control-stripped and length-capped, the
`threat.CleanText` treatment. Never `nodename`, never serial, never asset tag.

`facts_ok` is load-bearing: `get-facts` fails per instance, and a zero mailbox count from
a failed call is indistinguishable from a genuinely empty mail server. The cohort pass's
idle handling depends on the difference.

### 2. Storage

Day key is **`day INTEGER` = UTC day index (`unix_millis / 86400000`)**, labelled in Go
via `store.DayString(dayIdx * dayMillis)`. This diverges from `threat_daily_stats`'s
`day TEXT` on purpose and the DDL comment must say so: those are display rollups read
whole, while these tables are range-queried constantly (28-day pass, 90-day UI, prune
below a cutoff). An integer index does all three with the arithmetic the codebase already
performs (`threat.go:416`) and removes the bug class where a formatter with the wrong
location writes two rows for one day. The monthly rollup goes the other way —
`month TEXT 'YYYY-MM'` — because nothing does arithmetic on months.

**No surrogate ULIDs on these tables.** CLAUDE.md bans `AUTOINCREMENT`/`SERIAL`; it does
not mandate a surrogate, and `threat_daily_stats` already uses a bare composite PK. Say so
in a comment, because a reader will over-apply the rule.

Tables, all `CREATE TABLE IF NOT EXISTS` in `store.Init`'s statement slice
(`internal/store/store.go:152`):

| Table | Key | Notes |
|---|---|---|
| `sizing_node_daily` | `(system_id, node_id, day)` | hardware, per-axis percentiles, stress durations, derived `pressure`/`p_*`/`pressure_reasons`/`pressure_version`. **Recompute** upsert |
| `sizing_module_daily` | `+ module_family` | `instances`, `facts_ok`, `versions` (JSON, display only) |
| `sizing_module_metric` | `+ metric` | the open map, normalised to rows so SQL can group it. `value REAL` |
| `sizing_node` | `(system_id, node_id)` | dimension: `first_seen`/`last_seen`/`cpu_cores`/`mem_total_bytes`/`hw_changed_at`. Fixes the unstable-identity problem |
| `sizing_ingest_daily` | `(day, system_id)` | per-rule drop accounting. **Accumulate** upsert |
| `sizing_node_monthly` | `(system_id, node_id, month)` | kept indefinitely |
| `sizing_node_verdict` | `(system_id, node_id)` | multi-day verdict + `top_axis` |
| `sizing_cohort_baseline` | `(cohort_kind, cohort_key)` | published baselines |
| `sizing_workload_bucket` | `(module_family, metric, bucket)` | deterministic t-shirt sizes |

The **normalised metric table replaces a `workload TEXT` JSON blob**: CLAUDE.md forbids
`json1`/`jsonb`, so a blob would force the cohort pass to pull ~1.4 M rows through a
`SetMaxOpenConns(1)` connection and JSON-parse each one, hourly. The `threat` precedent
parses JSON in Go for *display* fields only and groups in SQL, because the grouping is the
correctness.

Mixing the accumulate and recompute upsert idioms would be silent; comment each.

**Volume and retention.** ~4 050 node-days/day → `sizing_node_daily` ≈ 500 MB/yr,
`sizing_module_daily` ≈ 1.2 GB/yr, `sizing_module_metric` ≈ 220 MB/yr. Unmanageable at
365 days on a shared single-writer SQLite file; comfortable at **100 days**, which still
covers the 28-day verdict window and the cohort window with a quarter of slack. Monthly
rollups (~49 k rows/yr) are kept indefinitely.

Two index notes: `idx_sizing_node_daily_day` for the range queries, and
`idx_sizing_node_daily_version` so a `pressure_version` bump can find rows to recompute
without a full scan.

### 3. The score: `pressure`

Pure, in `internal/sizing`, server-side only — never computed on the edge, or the edge
becomes an uncoordinated second implementation. One shape for every term, so each is
monotone, zero below its knee, saturated above its ceiling, and defined for all inputs:

```
clamp(x, lo, hi)     = min(hi, max(lo, x))
ramp(x, x0, x1, cap) = cap * clamp((x - x0) / (x1 - x0), 0, 1)
```

`x1 > x0` asserted in an init test. A missing input makes a term **absent**, not zero.

**Coverage gate, first.** `metrics_present == 0`, `sample_coverage < 0.80`,
`cpu_cores < 1` or `mem_total_bytes <= 0` ⇒ `pressure = NULL`, reason
`insufficient_coverage`. A node that was off for 18 hours is not a low-pressure node.

```
p_mem  = max( ramp(ram_util_p95,        0.85, 0.97, 60),
              ramp(swapin_pps_p95,      1.0,  200,  60),
              oom_kills == 0 ? 0 : 40 + ramp(oom_kills, 1, 5, 60) )
p_cpu  = max( ramp(cpu_util_p95,        0.80, 0.95, 40),
              ramp(load15_per_core_p95, 1.0,  4.0,  40) )
p_io   =      ramp(iowait_busy_frac,    0.05, 0.40, 40)
p_disk = max( ramp(fs_used_frac_max,    0.85, 0.97, 70),
              fs_used_frac_max >= 0.98 ? 100 : 0,
              fs_days_to_full == nil || >= 90 ? 0 : ramp(90 - days, 0, 75, 60) )

worst    = max(p_mem, p_cpu, p_io, p_disk)
pressure = clamp(worst + 0.5 * (sum - worst), 0, 100)
```

Why each departure from the draft: `max` **within** an axis because `cpu_util_p95` and
`load15_per_core_p95` measure one saturation through two lenses (this is the
double-counting fix); the OOM term is discontinuous because a kill is proof, not a
gradient, and capped short of 100 at one kill because a runaway process is not undersizing;
`swapin` not `swapout`, because eviction is routine and a page read back is the one that
proves a stall; `iowait_busy_frac` (a duration) not `max_iowait`; `fs_days_to_full` is the
only genuinely predictive term and is what "sizing" should mean. Combination is worst axis
at full weight plus the rest at half — a plain sum over-penalises correlated axes, plain
`max` ranks three-axis trouble level with one.

`disk_io_util_p95` is stored but **not scored**: `io_time` saturation is meaningless on
NVMe. Keep it as a diagnostic.

**Name the column `pressure`, 0 = none, 100 = severe, and drop "score" from the number** —
`pressure_score` reads either way depending on which word is the noun, and that ambiguity
produces an inverted comparison within a month. Assert the direction in a boundary test.

**Reasons are sorted, value-free codes** (`ram_headroom`, `swap_in`, `oom_kill`,
`cpu_util`, `runqueue`, `iowait`, `fs_level`, `fs_full`, `fs_trend`) — the gate-reasons
lesson: embedded floats made every deviating window a rollup group of one. Any rollup over
them must be time-bounded.

**Versioning diverges from `fingerprint.Version` on purpose, and the plan must say why.**
Fingerprints are never backfilled because identity must change visibly. `pressure` is a
derived analytic over inputs that are all stored as first-class columns, so leaving 100
days of mixed-definition scores would make every trailing verdict wrong and every cohort
statistic incomparable. The pass therefore **recomputes** rows whose `pressure_version`
is stale, in a bounded batch, before building cohorts.

**Threshold honesty.** Physically grounded: `ram_util 0.97`, `fs 0.98`, `load/core 1.0`.
Grounded by convention: `fs 0.85` — align the constant with ns8-metrics' `DiskSpaceLow`
and cite it, so the fleet report and the node's own alert never disagree. Deliberately
calibrated: `iowait_busy_frac 0.05` (72 min/day, above a nightly backup) — that
calibration is the whole point of the term. **Guesses, to be calibrated once ~30 days of
fleet data exist:** `ram 0.85`, `cpu 0.80/0.95`, swap-in `1→200 pps`, `load/core →4.0`,
`days_to_full 90/15`, all four axis caps, the `0.5` compounding factor and the `p_oom`
step. Say so in the UI rather than presenting a guess as advice. Calibration procedure:
set each noisy `x0` at the fleet p90 and `x1` at the fleet p99, leave the physical knees
fixed, bump `pressure_version`, recompute. Storing the inputs as columns is what makes
that a one-pass operation needing no fleet cooperation.

**PromQL** runs over the absolute range `[D 00:00 UTC, D+1 00:00 UTC)` per `node="N"`,
using `quantile_over_time(0.95, …[1d:5m])` for percentiles and
`avg_over_time((expr > bool T)[1d:5m])` for durations. Cores from
`count(count by (cpu) (node_cpu_seconds_total))` rather than `node_cpu_info` (no collector
flag needed). Memory from **`MemAvailable`**, not `MemFree`, or every healthy Linux box
reads as full — worth a code comment. `increase()` extrapolates across counter resets, so
store `reboots` (`changes(node_boot_time_seconds[1d])`) and let the verdict discount those
days rather than trying to correct `oom_kills`.

**Multi-day verdict** — k-of-n with hysteresis, because undersizing is recurrence:
28-day window; `< 14` days present ⇒ `insufficient_data`; `≥ 7` days at `pressure ≥ 50` ⇒
`undersized`; `≥ 14` days at `≥ 25` ⇒ `at_risk`; else `ok`; once `undersized`, holds until
bad days `≤ 3`. Two guards the draft cannot express:

- **Axis agreement.** If no single axis is the top penalty on at least half the bad days,
  downgrade to `at_risk` with `top_axis = "mixed"`. Seven bad days from seven unrelated
  causes is not one verdict, and recommending RAM on that evidence would be wrong.
- **Placement, not sizing.** With `node_count ≥ 2`, compute `ram_util_spread` (max − min
  of per-node `ram_util_p95`); at `≥ 0.50` the cluster advice is "rebalance", not "buy
  hardware". This output only exists because `system_id` is a cluster, and it is the
  highest-value thing that falls out of that framing.

### 4. The cohort baseline pass — `internal/baseline`

Mirrors `internal/blocklist`: narrow `Reader`, `Config`, `Runner.Run(ctx, now) error`,
documented step order, housekeeping logged not fatal.

**The defect the draft does not see is censoring.** An undersized node's observed RAM use
is capped by the RAM it has: a node needing 12 GB but holding 8 reports ~7.6 GB. Feed that
into any estimator of "how much RAM does a mail node need" and the answer comes out too
small — which then declares more nodes adequately sized, the exact inverse of the
feature's purpose. This is systematic bias, not noise; no volume of data or choice of
model removes it. So:

- **Exclude from demand estimation** nodes with `ram_util_p95 ≥ 0.90`, `swapin_pps_p95 > 0`
  or `oom_kills > 0` — their true demand is unobservable — but **count and publish
  `censored_nodes` per cohort**. A cohort that is 40 % censored means the fleet's own
  hardware for that profile is systematically too small, which is the most valuable
  finding the pass can produce.
- Exclude `sample_coverage < 0.80` / `pressure IS NULL` (not measured) and nodes whose
  `hw_changed_at` falls inside the window (two machines).
- **Do not** exclude `max_iowait > 0.15` as the draft does — that removes precisely the
  disk-bound nodes whose existence is the answer, and iowait is not a covariate of a
  RAM/CPU baseline anyway.
- **Do not** exclude "unhealthy" nodes generally. "What a healthy node uses", derived by
  deleting the unhealthy ones, is survivorship bias with extra steps. Censoring is the
  only health-shaped exclusion and it is justified by measurability, not by health.
- **Idle instances are bucketed, not dropped.** A mail server with 0 mailboxes gives the
  floor cost of running the module, which people want; it just is not a "mail node". Use
  `facts_ok > 0` to tell "zero mailboxes" from "the facts call failed".

**Two-stage aggregation.** One node contributing 28 daily rows must count once, or
always-online nodes and one MSP's 40 identical clusters dominate. Reduce each node to the
**p90 across its daily `ram_used_bytes_p95`** — not the median, because a 28-day window
holds 8 weekend days on which a business workload is idle and the median then reads a mail
server ~25 % low — then take percentiles across nodes. Name every column so the
composition is unambiguous (`ram_util_p95_med` vs `ram_util_p95_max`); `load15_avg`
holding a peak is exactly this bug. The floor counts **distinct `system_id`**, the same
rule and the same reason as Threat Shield's promotion.

**Three keyings from one pass**, sharing all machinery:

| `cohort_kind` | key | answers |
|---|---|---|
| `family` | family name | "what does a node that runs mail look like" — co-tenanted, and must be labelled as such |
| `family_solo` | family name | "what does a node running only mail (plus lite modules) need" — the only one safe to quote as a recommendation |
| `profile` | sorted non-lite family list | surfaces the real common deployments; the long tail never clears the floor |

Publish **p50/p75/p90 of absolute `ram_used_bytes` and `cpu_cores_used`**, plus the
distribution of *installed* RAM/cores. Absolute, not utilization: utilization is a
property of hardware someone happened to buy, and the deliverable is advice on what to
buy. The recommendation is p90 of observed peak demand among uncensored nodes. Publishing
`installed_ram_p50` alongside makes the residual bias (`MemTotal − MemAvailable` scales
mildly with installed RAM) visible rather than hidden.

**Floor `distinct_systems ≥ 20` and `nodes ≥ 30`** — both guesses, this pipeline's
analogue of "never serve blank". Below the floor publish nothing, and **delete** a cohort
that has fallen below it rather than leaving a stale row, mirroring `ExpireBlocklist`.

**No ridge, no k-means in v1.** Not on implementation cost — a Cholesky solve is ~150
lines. Ridge handles collinearity (`openldap` ships with `samba`, `traefik` is
everywhere) by shrinking, which destroys the interpretation of a coefficient as "the cost
of module X" — and that interpretation is the entire product. It also does nothing about
censoring, and it will happily publish `openldap: −312 MB`, since neither OLS nor ridge
enforces `β ≥ 0`. If a regression ever ships it should be **non-negative least squares**
on the uncensored subset, labelled as an estimate distinct from the measured percentiles.
k-means is rejected outright: quantile bucketing gives the same t-shirt sizes and is
deterministic run to run, and a number published to customers must not change without the
data changing.

**The lite/medium/heavy prior goes in the code exactly once, as cohort assignment and
presentation order — never as a weight inside a published number.** The pass exists to
measure module cost; baking a cost prior into the estimator and publishing the result as
evidence for that prior is circular. A `sizing.FamilyClass` map, with an explicit
`unknown` default so a new module is not silently classed lite, used only to pick a node's
primary family, decide which families are ignorable when testing "solo", and order the UI.
**And the prior as given is already wrong in one instructive case:** "samba without file
shares = lite, with shares = medium" is not a family distinction but a *workload* one —
exactly what the metric map is for. So the class is **derived**, `class(family, workload)`,
with `samba` + `shared_folders_count > 0` resolving to medium (the real
`ns8-samba` `get-facts` key; the legacy `shared_folders` is accepted too). One rule instead of two, and it
stops being wrong for a whole product the moment anyone configures it.

**Pass step order**, commented on `Run` in the style of `consensus.go`:

```
1. Recompute pressure where pressure_version is stale (bounded batch)  -- before 4
2. Recompute node verdicts over the trailing 28 days
3. Recompute cluster imbalance for multi-node clusters
4. Build cohorts: per-node reduction, then across-node percentiles; apply and
   count the censoring / coverage / hardware-change exclusions
5. Upsert baselines and workload buckets that clear the floor
6. DELETE cohorts that no longer clear it
7. RollupSizingMonthly            housekeeping: log on error, never abort
8. PruneSizingDaily(now - Retention)   -- only if 7 returned nil
```

Two constraints are load-bearing: **1 before 4**, or a version bump publishes a baseline
mixing two score definitions; **7 before 8**, or the dropped day loses its history
permanently.

### 5. Server wiring

New packages: `sizing` (PURE — sanitize, score, percentiles, cohort keying, family class)
and `baseline` (the pass), appended to CLAUDE.md's layering DAG.

| File | What |
|---|---|
| `internal/model/sizing.go` | wire + sanitized types, `SizingSchemaVersion`, `SizingCounters` — the `threat.go` wire→sanitized→counters split |
| `internal/sizing/{sanitize,score,cohort}.go` + tests | pure |
| `internal/api/sizing.go` | narrow `SizingStore` iface in-package, `SizingConfig` whose zero value disables the route, own size cap, handler. Copy `internal/api/threat.go:68-149` |
| `internal/store/sizing.go`, `sizing_ui.go` | writers (mutex, tx, `ON CONFLICT DO UPDATE`); UI reads (no mutex, `clampLimit`) |
| `internal/baseline/pass.go` | `Reader`/`Config`/`Runner.Run` |
| `internal/ui/templates/{sizing,cohorts}.html` | two pages under a new "Sizing Pipeline" nav group |

Edits: `internal/api/api.go:102-119`; `internal/store/store.go:64` (interface block) and
`:152` (DDL); `internal/ui/ui.go` at `:56`, `:161`, `:260`, `:327`;
`cmd/insightsd/main.go` env block (~`:269`), wiring (~`:350`), `cfgItems` (~`:413`), loop
start (`:506`), shutdown (`:538`).

**Generalise `runConsensusLoop`** (`cmd/insightsd/main.go:546-564`) to take a small
`interface{ Run(context.Context, int64) error }` instead of `*blocklist.Runner`, and reuse
it — a two-line refactor, versus copying a second loop.

`docs/api/openapi.yaml` gets the path item and operation; `docs/api/openapi_test.go` gets
`/v1/sizing-reports` in `expectedPaths` (`:142`) and the `POST` pair in
`expectedOperations` (`:163`), or the build fails in both directions.

New env vars, documented only in the README table (`README.md:121-159`):
`SIZING_RETENTION` (100 d), `SIZING_PASS_INTERVAL` (1 h — daily inputs make faster
pointless), `SIZING_WINDOW_DAYS` (28), `SIZING_MIN_DISTINCT_SYSTEMS` (20),
`SIZING_MIN_NODES` (30), `SIZING_MAX_NODES_PER_REPORT` (16).

### 6. Edge — `ns8-core` cluster reporter

| File | What |
|---|---|
| `cluster/bin/print-sizing-report` | builds the JSON: PromQL over the last complete UTC day, module inventory + `get-facts`, `cluster/get-facts`' `user_domains` counters |
| `cluster/bin/send-sizing-report` | ships it — `redis-hgetall cluster/subscription` + `curl --user "${system_id}:${auth_token}"`, exactly `cluster/bin/send-inventory:21-50` |
| `etc/systemd/system/send-sizing-report.{service,timer}` | `OnCalendar=03:00`, `RandomizedDelaySec=2h`, `Persistent=true` — the draft's staggering requirement met by the mechanism ns8-core already uses |
| `node/bin/check-subscription` | enable under `is_leader` in `enable_nsent`/`enable_nscom`, disable in the worker and no-provider branches (`:33-62`, `:69-74`) |

Reuse rather than reinvention:

- **Prometheus URL discovery** — `discover_prom_query_url()` already exists at
  `cluster/actions/list-nodes/10list_nodes:14-30`, and `:98-191` is already a per-node
  hardware snapshot in PromQL. Extend that vocabulary.
- **Prometheus path prefix** — `PROMETHEUS_PATH` from
  `module/$(get cluster/default_instance/metrics)/environment`.
- **Insights endpoint** — `INSIGHTS_SERVER_URL` / `INSIGHTS_VERIFY_TLS` from
  `module/$(get cluster/default_instance/loki)/environment`. Verified readable. This makes
  the existing `set-insights` action the single on/off switch: turning insights off in the
  Logs UI turns sizing off too. No new config action, no second place to point at a
  different server.
- **Credentials** — `cluster/subscription`, never module config, the reasoning at
  `insights-collector:1160-1163`.
- **`get-facts` collection** — the loop at `cluster/bin/print-phonehome:60-117`, including
  its `list-actions` probe and its per-module exception isolation.

Guards: leader only; skip with no subscription, with `INSIGHTS_SERVER_URL` unset, or with
the metrics module absent; ship a partial result rather than failing the timer.

**Degraded reports.** Prometheus is fleet-wide (`core_module`), so this is robustness, not
the main path — but when Prometheus is unreachable or the metrics module has been removed,
send a facts-only report: hardware read from the node itself, OS, module inventory,
workload counts, `metrics_present = 0`, `pressure` left `NULL`. That still answers "what
is deployed on what hardware", and it keeps ingest volume honest instead of silently
biasing the fleet view toward metrics-healthy clusters.

### 7. Workload coverage in module repos (separate releases, not blocking)

| Class | Module | `get-facts` today |
|---|---|---|
| lite | `openldap` | **absent** — but `cluster/get-facts`' `user_domains` already carries `total_users`/`active_users`/`total_groups` via `cluster/inventory.py:72-87`. No module work needed |
| lite | `samba` | present — `shared_folders_count`, `has_file_server_flag`: the with/without-shares split |
| lite | `traefik` | present |
| medium | `mail` | present — mailboxes, domains, addresses |
| medium | `imapsync` | **absent** — `list-tasks` exists; a `get-facts` returning the task count is a few lines |
| medium | `nextcloud` | present — total/active users |
| heavy | `nethvoice` | present — `nethvoice_users_count`, trunks, queues, IVRs |
| heavy | `loki`, `nethsecurity-controller` | present |
| heavy | `webtop` | **absent** — needs writing |

Two modules need a new `get-facts`; `openldap` needs none. Not blocking: the server accepts
an empty `workload` map, and such a node is still scored and still contributes to its
cohort.

---

## Order of work

1. Contract spec + renamed design doc — everything else is written against it.
2. `internal/model/sizing.go` + `internal/sizing` (pure, fully tested) — no I/O, so it can
   be finished and trusted before anything touches the DB.
3. `internal/store` tables, writers, UI reads, with `newTestStore(t)` tests against real
   SQLite (`internal/store/store_test.go:16-28`).
4. `internal/api/sizing.go` + wiring + openapi + its test entries.
5. `internal/baseline` + the generalised loop in `cmd/insightsd`.
6. Two UI pages.
7. `ns8-core` reporter, timer, `check-subscription` wiring.
8. `get-facts` for `webtop` and `imapsync`.
9. Docs: `docs/architecture.md` (layering, a "Sizing ingest" and "Cohort pass" flow
   section, storage), `docs/user-guide.md` (what a sizing report, a pressure number and a
   cohort baseline are, plus the two new pages), `README.md` env table, and `CLAUDE.md` —
   a Threat-Shield-style paragraph stating sizing is a third pipeline sharing only the
   listener, the `Authenticator`, the SQLite file and `model.ModuleFamily`, with its
   load-bearing rules: numbers-only workload, absolute-day reports, recompute-on-version-
   bump, censoring exclusion, distinct-system floors, roll up before pruning.
10. Close the CLAUDE.md open question on `cluster/subscription` field names and delete the
    dead `SUBSCRIPTION_SECRET_FIELDS` fallback in `ns8-loki`.

---

## Verification

```bash
go build ./... && go vet ./...
go test ./... -race -count=1
go test ./internal/sizing/ -v     # ramps, coverage gate, sanitizer tables
go test ./internal/baseline/ -v   # real temp-file SQLite: the exclusions are the SQL
go test ./docs/api/ -v            # openapi paths/operations match
```

Load-bearing cases, mirroring the depth CLAUDE.md already demands elsewhere:

- `TestSanitizeAcceptsEveryMetricKey` and `TestSanitizeRejectsEveryNonNumericValue` — the
  executable form of the privacy rule, the `TestSanitizeAcceptsEveryScenario` precedent.
- Every penalty term at `x < x0`, `x == x0`, mid-ramp, `x == x1`, `x > x1`, and absent.
- A fully idle node scores `pressure == 0` — the direction test.
- A zero `cpu_cores` or `mem_total_bytes` yields `pressure = NULL`, not a division.
- A malformed node entry is dropped and counted while its siblings store.
- The same day posted three times converges on identical columns and does not double any
  counter; `sizing_ingest_daily` accumulates while `sizing_node_daily` recomputes.
- A `day` older than 15 days or in the future is rejected and counted.
- 19 distinct systems publishes no cohort and 20 does; one system with 40 nodes does not;
  a cohort that falls below the floor is deleted, not left stale.
- A censored-heavy cohort publishes with `censored_nodes` set rather than a silently low
  percentile.
- A `pressure_version` bump recomputes before cohorts are built; the monthly rollup
  precedes the prune and a prune failure does not abort the pass.

End to end on `rl1`:

1. Run `insightsd` locally with `DB_PATH=/tmp/insights.db`, `UI_LISTEN_ADDR=127.0.0.1:9596`.
2. On `rl1`, run `print-sizing-report` by hand under `runagent` and read the JSON —
   confirm no FQDN, IP, serial or asset tag appears anywhere, and that every `workload`
   value is a number.
3. `curl -u <system_id>:<auth_token> -X POST <server>/v1/sizing-reports -d @report.json`;
   check the `202` counters. `scripts/insights-api.sh raw` covers the call shape.
4. Post it twice more; confirm restatement counters move and nothing doubles.
5. Open the Sizing page: node rows, `pressure`, per-axis penalties and utilization
   percentiles render. The Cohorts page must say "insufficient fleet data" — `rl1` is one
   node and will never clear the floor, and that is the correct output, not a bug.

`rl1` proves the round trip, not the statistics. Every guessed threshold stays labelled as
a guess in the UI until ~30 days of fleet data allow the calibration pass described above.
