<!--
Copyright (C) 2026 Nethesis S.r.l.
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Architecture

This document describes how `nethesis-insights` is built: package layout, data
flow, storage, and the invariants that keep the pipeline correct and cheap to
run. It documents the **prototype as it exists today** — see the "Prototype
vs. design" table in `CLAUDE.md` for what is deliberately not built yet.

For *why* each design decision was made, read
`docs/specs/2026-08-05-nethesis-insights-design.md`. This document explains
*how* the current code implements that design.

> **Keep this file in sync.** Any change to package boundaries, the analyzer's
> step order, the wire protocol, storage schema, or the gate/fingerprint
> formulas must update this document in the same change.

## System context

```
edge (ns8-loki)          edge (ns8-crowdsec)         edge (ns8-core, leader)
   │ /logs/v1/bundles       │ /blocklist/v1/events       │ /sizing/v1/reports
   ▼                        ▼                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│                               Traefik                                 │
│  strips the pipeline prefix; forwardAuth → authd on every /v1/* route;│
│  BasicAuth (ADMIN_API_KEY as the htpasswd password) on every UI path  │
└──────────┬────────────────────────┬───────────────────────┬──────────┘
           │ /v1/bundles            │ /v1/events            │ /v1/reports
           │ /v1/findings           │ /v1/feed              │
           │                        │ /v1/allowlist-requests│
           ▼                        ▼                       ▼
   ┌────────────────┐      ┌─────────────────┐      ┌─────────────────┐
   │    insightsd     │      │     threatd      │      │     sizingd      │
   │ api/logs         │      │ api/threat       │      │ api/sizing       │
   │ queue → analyzer │      │ threat (sanitize)│      │ sizing (sanitize)│
   │ gate/fingerprint │      │ blocklist        │      │ baseline         │
   │ prompt / llm     │      │ consensus pass   │      │ cohort pass      │
   │ store/logs       │      │ store/threat     │      │ store/sizing     │
   │ (SQLite: logs)   │      │ (SQLite: threat) │      │ (SQLite: sizing) │
   │ ui/logs (/logs)  │      │ ui/threat        │      │ ui/sizing        │
   └────────────────┘      │ (/blocklist)      │      │ (/sizing)        │
                             └─────────────────┘      └─────────────────┘
                    ▲
                    │ GET /auth (forwardAuth request)
             ┌──────┴──────┐
             │    authd     │──► AUTH_VALIDATE_URL (external,
             │ cache + TTL  │    default https://my.nethesis.it/auth)
             └─────────────┘
```

One edge node ships one bundle per 15-minute window. The server never
initiates contact with a node. All five containers — Traefik, `authd` and the
three pipelines — share one podman pod and therefore one network namespace, so
Traefik's connection to a backend is a genuine loopback connection with no NAT
in the path; see "Authentication" below for why that is load-bearing.

**Three independent pipelines, one proxy, one auth cache, three databases.**
The bundle path spends money per call, so everything in it exists to avoid
spending it. Threat Shield and fleet sizing are both high-volume factual data
with no LLM anywhere in them: ingest is synchronous, there is no gate and no
fingerprint. Each pipeline is its own binary with its own SQLite file; the
only things shared across all three are Traefik, `authd` and
`internal/platform/{auth,httpx,sqlitex}`. They are described separately
throughout this document for that reason.

## Package layering

```
cmd/authd  cmd/insightsd  cmd/threatd  cmd/sizingd    four binaries; authd owns
                                                       no pipeline of its own

internal/platform/auth  httpx  sqlitex   shared: ForwardAuth+cache, HTTP
                                          plumbing (ClientIP, SystemID,
                                          Logging, Healthz), SQLite Open

model                       no deps; imported by everything
fingerprint  gate  prompt   PURE — no I/O, no clock beyond an injected now() — logs only
threat                      PURE — the Threat Shield sanitizer and allowlist
sizing                      PURE — the sizing sanitizer, pressure score, cohort keying
llm  queue  budget          logs only; interfaces where I/O is needed
analyzer                    the bundle pipeline; depends on all of the above
blocklist                   Threat Shield consensus + the served snapshot
baseline                    fleet-sizing cohort pass; same shape as blocklist

store/logs  store/threat  store/sizing   one store package per pipeline,
                                          each its own SQLite file
api/logs  api/threat  api/sizing         HTTP: ingest + read, per pipeline
ui/chrome                                shared layout, static assets, write
                                          auth, base-path-aware links
ui/logs  ui/threat  ui/sizing            per-pipeline operator dashboard,
                                          off by default
```

This is a strict DAG — nothing lower in the list imports anything above it.
Each pipeline's binary imports exactly one of `store/*`, `api/*` and `ui/*`;
`ui/{logs,threat,sizing}` do not import `api/*` or `analyzer`.

| Package | Responsibility |
|---|---|
| `internal/model` | Wire types (`Bundle`, `Finding`, `Template`, …) and the pure helpers (`SortFindings`, `SeverityRank`) that operate on them. |
| `internal/platform/auth` | `ForwardAuth` — forwards `Authorization: Basic` to an external validator, with a pepper-hashed TTL cache and fail-closed behaviour. Used only by `cmd/authd` now; moved from `internal/auth`. |
| `internal/platform/httpx` | `ClientIP`/`SystemID` (the trusted-proxy boundary every pipeline relies on), `Logging` (the request logger, wrapped around every binary's mux) and `Healthz`. |
| `internal/platform/sqlitex` | `Open` — WAL, `busy_timeout=5000`, `SetMaxOpenConns(1)` — plus the write mutex every `store/*` package embeds. |
| `internal/gate` | `gate.Evaluate` — decides whether a bundle is worth an LLM call. Pure function of `(Bundle, SystemState, Config)`. |
| `internal/fingerprint` | `fingerprint.Compute` — the server-computed identity of a finding. Pure, sha256-based. |
| `internal/prompt` | Selects which templates are worth showing (`prompt.Select`), renders the deterministic LLM prompt, and parses/validates the strict-JSON response. Owns `prompt.Version`. |
| `internal/llm` | `llm.Client` interface; `openai.go` is the real OpenAI-compatible implementation, `stub.go` a test double. |
| `internal/store/logs` | insightsd's only store package: ingest bookkeeping (systems, templates, baselines), the analyses cost ledger, findings, plus the cross-system reads the operator UI needs (`ui.go`). A separate SQLite file from threat and sizing, sharing nothing with them but the `sqlitex` runtime settings. |
| `internal/budget` | `budget.Controller` — the fleet-level ceiling the gate cannot provide: an in-flight concurrency bound, a per-system daily call cap, and a daily spend cap that degrades the gate to security-only. Counts off the `analyses` ledger, never an in-process counter. |
| `internal/analyzer` | `Analyzer.Process` — the pipeline that ties budget, gate, fingerprint, prompt, llm and `store/logs` together for one bundle. |
| `internal/queue` | In-memory bounded channel decoupling ingest from analysis, plus in-flight dedup so a resend never starts a second LLM call for the same window. |
| `internal/threat` | Threat Shield's pure half: `Sanitize` (every ingest drop rule) and `Allowlist` (portable CIDR containment). It deliberately holds no scenario allowlist — see "Scenarios are not interpreted". |
| `internal/blocklist` | `Runner.Run` — one consensus pass: promote, expire, roll up, prune, regenerate. `Snapshot` holds the rendered feed behind an `RWMutex`. |
| `internal/store/threat` | threatd's only store package: ingest, consensus inputs, the promoted blocklist, the allowlist and its client-facing review queue, the append-only allowlist audit trail, and the rollups that outlive the raw events. |
| `internal/sizing` | Fleet sizing's pure half: `Sanitize` (every ingest drop rule, including the numbers-only workload rule), `Evaluate` (the `pressure` score), `EvaluateVerdict` (the multi-day k-of-n verdict), `ClusterPlacement`, the two cohort keyings and `IsPlatform` (which families are ignorable when testing "solo"). Owns `PressureVersion`. |
| `internal/baseline` | `Runner.Run` — one cohort pass: recompute stale pressure, verdicts, cluster imbalance, cohorts, publish, expire, roll up, prune. Deliberately the same shape as `internal/blocklist`. |
| `internal/store/sizing` | sizingd's only store package: ingest, the cohort pass's inputs and outputs, and the rollups that outlive the daily rows. |
| `internal/api/logs` | HTTP handlers for `POST /v1/bundles`, `GET /v1/findings`, `/healthz` (registered unprefixed; Traefik adds `/logs`). |
| `internal/api/threat` | HTTP handlers for `POST /v1/events`, `GET /v1/feed`, `POST /v1/allowlist-requests`, `/healthz` (Traefik adds `/blocklist`). |
| `internal/api/sizing` | HTTP handler for `POST /v1/reports`, `/healthz` (Traefik adds `/sizing`). |
| `internal/ui/chrome` | Everything the three operator dashboards share: layout and stylesheet, the formatters in `view.go`, the GET-only-plus-enumerated-POST route discipline, `AuthenticateWrite`/`CanWrite` (HTTP Basic against `ADMIN_API_KEY`), and `Link` — the one place that knows the deployment's base path exists, since Traefik strips the prefix before a handler ever sees a request. |
| `internal/ui/logs` | insightsd's operator dashboard: findings, systems, the analyses cost ledger, the gate rollup, per-day spend, templates, baselines. Read-only — no write routes. |
| `internal/ui/threat` | threatd's operator dashboard: the blocklist and its allowlist, per-system ingest accounting, the raw event stream, the daily rollup, the allowlist review queue, and `/audit` — the only reader of the allowlist audit trail. Its four write routes (`writableRoutes`) are threatd's only writes anywhere in the deployment. |
| `internal/ui/sizing` | sizingd's operator dashboard: per-node pressure and verdicts, published cohort baselines, pipeline status. Read-only — sizingd has no write routes at all. |
| `cmd/authd` | A thin HTTP shell over `internal/platform/auth`: `GET /auth` for Traefik's `forwardAuth`, `GET /healthz`. Owns no store and no UI. |
| `cmd/insightsd` | Reads environment config, wires `api/logs`, `ui/logs`, `store/logs` and the bundle pipeline together, runs graceful shutdown. |
| `cmd/threatd` | Same shape for Threat Shield: `api/threat`, `ui/threat`, `store/threat`, the consensus ticker. |
| `cmd/sizingd` | Same shape for fleet sizing: `api/sizing`, `ui/sizing`, `store/sizing`, the cohort-pass ticker. |

The purity of `gate`, `fingerprint`, `prompt`, `threat` and `sizing` is
deliberate: each holds all the correctness and privacy logic for its concern,
and is table-driven-testable with no fixtures, no clock, no I/O. `llm` and
every `store/*` package being interfaces at the consumer is what lets
`analyzer_test.go` and each pipeline's `api`/`ui` tests run end to end with
nothing running — there is no longer one combined `Store` interface; each
consumer declares its own narrow one over its own pipeline's store package.

`internal/threat` is pure for a sharper reason than cost: everything deciding
whether a third party's IP address is stored and published lives there, so a
bug in it is a data-protection incident rather than a wrong answer.

`internal/sizing` is pure for both reasons at once. It decides what a sizing
report is allowed to store — per-customer commercial data, derived from metrics
that carry identifying labels — and it holds the whole `pressure` formula,
which is computed **server-side only**: scoring at the edge would make every
node an uncoordinated second implementation, and then a threshold
recalibration would need the fleet's cooperation instead of one recompute pass.
It imports `threat.CleanText` rather than declaring a second free-text
sanitizer; that is the only edge between the two pure packages.

`internal/blocklist`, `internal/baseline`, `internal/api/threat` and
`internal/api/sizing` each declare their own narrow interface over their
pipeline's store (`blocklist.Reader`, `baseline.Reader`, `threatapi.Store`,
`sizingapi.Store`) rather than taking the whole store package, so each stays
testable with a small fake and the layering stays a DAG.
`internal/ui/{logs,threat,sizing}` do the same on the read side (`Reader`) and,
for threatd only, on the write side (`Writer`). `ui/logs` declares a local
`Runtime` interface (`Depth`/`Cap`, satisfied by `*queue.Queue`) for live queue
state; `ui/threat` declares a local `Feed` interface over the blocklist
snapshot's state — the UI learns how many entries are served and when, never
the body.

## Request flow

### Ingest: `POST /v1/bundles` (public path `/logs/v1/bundles`)

1. `logs.handleBundles` reads the system identity via `httpx.SystemID`, which
   trusts the already-forwarded `Authorization: Basic` header's username only
   when the request arrived from `TRUSTED_PROXY_CIDRS` — the credential itself
   was validated upstream by Traefik's `forwardAuth` call to `authd`, not here.
   See "Authentication" below.
2. The body is decoded (gzip-aware, size-capped at 8 MiB) into a
   `model.Bundle` and validated: schema version, `system_id` matches the
   authenticated identity, a sane window, a template-count ceiling.
3. Modules named by `PIPELINE_EXCLUDE_MODULES` (default `crowdsec1`) are
   stripped by `model.Bundle.ExcludeModules` — templates, digest entries and
   truncation records together. This happens here, before the queue, so that
   the gate, the prompt, `system_templates` and `module_baselines` all read
   the same filtered bundle and cannot disagree about which modules are in
   scope. CrowdSec is excluded by default because it already has its own
   pipeline (`POST /blocklist/v1/events` → the blocklist); analysing its log
   lines as well pays twice for one signal. `PIPELINE_EXCLUDE_SERVICES`
   (default `insights`) then filters on a second axis — the `[service]` tag
   `model.ServiceTag` reads off each masked host record — because host records
   all carry `module_id: ""` and the module filter cannot reach them. A line
   whose shape `ServiceTag` does not recognise is kept, and digest entries are
   not filtered by service since they carry no service dimension.
4. The bundle is handed to `queue.Publish`, which either enqueues it or
   returns `queue.ErrFull`.
5. The handler answers **immediately** — `202 Accepted` on success, `503` if
   the queue is full or the bundle is a duplicate still in flight. It never
   waits for analysis. This is what lets `ANALYSIS_TIMEOUT` be minutes long
   without ever risking the edge's own HTTP client timeout.

### The queue

`queue.Queue` is a bounded Go channel plus an `inflight` set keyed by
`(system_id, window_start)`. The `inflight` set exists because the store
deliberately keeps a window claimable until analysis *completes* (so a retry
after a transient LLM failure isn't rejected as a duplicate) — without it, a
resend while analysis is still running would start a second, wasted LLM call.
`Queue.Stop` closes the channel and drains what's buffered before exiting,
since those bundles were already acknowledged to an edge that won't resend
them.

### Analysis: `analyzer.Process`

This is the pipeline's core, and its step order is a correctness
requirement — see `CLAUDE.md` § "The analyzer's step order is a correctness
requirement" for the two rules that must never move, and why. In order:

1. **Claim the window** (`BeginAnalysis`) — a duplicate is a no-op.
2. **Register the system** (`UpsertSystem`).
3. **Read prior state** — `KnownTemplates` and `Baselines` — *before* writing
   anything. `KnownTemplates` is keyed by `model.CanonicalKey`, not by raw
   template text.
4. **Ask the budget** (`budget.Check`) what this system may spend. A window
   over the per-system daily cap is recorded with `gated = 1`,
   `suppressed_by = "system_call_cap"` and **no** gate reasons, and returns.
   Over the daily spend cap the gate is narrowed to security-only instead.
5. **Gate** (`gate.Evaluate`) using that prior state.
6. If the gate declines: **record** bookkeeping (templates, baselines, stale
   sweep, the `analyses` ledger row) and return. No LLM call, no cost.
7. If the gate fires: build one `prompt.Selection` from what the gate found,
   render the prompt (`prompt.Render`, including currently-open findings so the
   model doesn't re-report them), take a slot from the budget's concurrency
   bound, and call the LLM.
   - A **transient** failure (`RecordAttemptError`) leaves the window
     claimable for retry.
   - A **permanent** failure (`llm.HTTPError.Permanent()`, or a schema/parse
     failure) finalizes and closes the window — retrying would hit the same
     wall forever.
8. Parse the strict-JSON response (`prompt.Parse`), resolve each finding's
   cited template IDs back to real templates (`prompt.ResolveEvidence`, given
   the **same** `Selection` used to render) — this is the *only* path from
   model output to stored data, and it is what keeps model-authored prose out
   of the fingerprint.
9. Compute the fingerprint (`fingerprint.Compute`) and `UpsertFinding` —
   insert, bump the occurrence count, or reopen a stale finding.
10. **Record** bookkeeping now that the whole analysis succeeded — this is the
   only path that writes templates/baselines after an LLM call, and it is
   what makes a failed call retry-safe: nothing looks "known" that wasn't
   actually processed.

### Read: `GET /v1/findings` (public path `/logs/v1/findings`)

Authenticates the same way as ingest, then `store.ListFindings` returns that
system's findings (optionally filtered by `since`/`status`), sorted by
`model.SortFindings` — severity descending, then most-recently-seen first.

### Threat ingest: `POST /v1/events` (public path `/blocklist/v1/events`)

Synchronous end to end — no queue, because there is no LLM call to outlive the
client's timeout.

1. `threat.handleEvents` reads the system identity via `httpx.SystemID`, the
   same trusted-proxy rule as the bundle path.
2. The body is decoded (gzip-aware, 8 MiB cap) into a `model.ThreatReport` and
   checked for `schema_version`, plus the same "body `system_id` must match the
   credential when present" rule as bundles.
3. `threat.Sanitize` turns raw CrowdSec decisions into `model.ThreatEvent`s,
   dropping and counting anything that fails a rule. The reporter's own source
   address is passed in and excluded.
4. `InsertThreatEvents` stores the batch and the per-day ingest counters are
   recorded.
5. `202` with `stored`, `duplicates` and the full drop accounting.

**Fail-closed on authentication, fail-open on content.** Only a store failure
turns into a `503`; accounting failures are logged and the `202` still goes
out, because the evidence is already committed and losing the reporter's
watermark would cost more than the counters are worth.

**The reporter's source address is `httpx.ClientIP`, not bare `r.RemoteAddr`** —
this reverses the prototype's rule. Behind Traefik, `RemoteAddr` is always the
proxy's own address, which used to make step 3's reporter-own-address check
permanently dead: the address it compared against was never the reporter's, it
was Traefik's. `ClientIP` instead reads `X-Forwarded-For`, and only when
`RemoteAddr` is inside `TRUSTED_PROXY_CIDRS` — Traefik is configured to
overwrite that header with the connection it actually accepted, so a caller
that reaches the container directly (never a trusted proxy) still cannot spoof
its way past the check with a forged header. In the deployed shape all
containers share one podman pod's network namespace, so Traefik's connection
to `threatd` is a genuine loopback connection and `RemoteAddr` really is
`127.0.0.1` by construction — see "Authentication" below.

### Consensus: `blocklist.Runner.Run`

Driven by a ticker in `cmd/threatd` at `BLOCKLIST_CONSENSUS_INTERVAL`, with
one pass run immediately at startup so a restart does not leave the feed
answering `503` while the database is full of live entries. The order is
load-bearing:

1. `ConsensusCandidates(now - BLOCKLIST_WINDOW)` returns
   `(attacker_ip, scenario, system_id)` triples.
2. Go folds them per address into a distinct-system set, a scenario set, a hit
   sum and the latest sighting.
3. Allowlisted addresses are dropped — **at promotion, not at read**, so
   adding an entry unlists an address rather than hiding it.
4. Addresses with at least `BLOCKLIST_MIN_SYSTEMS` distinct systems are
   upserted with `expires_at = last_seen + BLOCKLIST_TTL` and a
   `listing_reason` snapshot of the evidence.
5. Expired entries are deleted.
6. `RollupThreatDailyStats` **then** `PruneThreatEvents` — reversing these two
   loses the dropped day's history permanently.
7. The snapshot is regenerated from the live entries.

An error in steps 1–4 or 7 aborts the pass and returns; the rollup and prune
are logged and skipped instead, because housekeeping must not stop the feed
reflecting promotions already made. A malformed allowlist row is the one
housekeeping-shaped thing that *does* abort: skipping it would fail open and
publish an address someone had explicitly excluded.

### Feed: `GET /v1/feed` (public path `/blocklist/v1/feed`)

`blocklist.Snapshot` holds the body, its gzip encoding and its `ETag`
(`sha256` of the body) behind an `RWMutex`. Serving never touches the database,
so the cost of the feed is flat regardless of subscriber count, and only a
successful generation replaces what is held — a failed pass keeps serving the
previous list with its original `generated:` timestamp.

Before the first successful pass the snapshot is not ready and the handler
answers `503`. That distinction matters: to a client importing the list, an
empty body means "no threats" and silently disables protection.

### Sizing ingest: `POST /v1/reports` (public path `/sizing/v1/reports`)

Fleet sizing is a **third independent pipeline**, beside the bundle path and
Threat Shield, and it is `sizingd`, a separate binary with its own SQLite file.
It shares Traefik, `authd` and `model.ModuleFamily` with the other two —
deliberately, because that is already the single definition of module identity
and a second one would eventually disagree — and nothing else: no LLM call, no
gate, no fingerprint, no queue.

```
handleReports
  ├── read system identity (httpx.SystemID; fail-closed on an untrusted proxy)
  ├── 413 if Content-Length exceeds 8 MiB (declared over-cap, not truncated)
  ├── gunzip if Content-Encoding: gzip, capped at 8 MiB
  ├── decode; 400 on bad JSON or schema_version != model.SizingSchemaVersion
  ├── 403 if body system_id is present and is not the authenticated system
  ├── sizing.Sanitize   ← every drop rule, fail-open on content
  ├── sizing.Evaluate   ← the pressure score, per node-day, server-side only
  ├── store.UpsertSizingDays      (recompute)
  ├── store.RecordSizingIngest    (accumulate; a failure never costs the 202)
  └── 202 with the counters
```

Three rules are load-bearing:

- **The unit is a cluster-day, and a day is absolute.** `day` is sent
  explicitly and every value in it is computed over
  `[day 00:00 UTC, day+1 00:00 UTC)`. That is what makes the reporter's three
  daily sends byte-identical restatements — the upsert recomputes rather than
  accumulates, so redelivery is free. A `day` outside `[today-15, today-1]` is
  rejected: yesterday is the newest complete day, and older than Prometheus'
  retention cannot have been computed from real data.
- **`modules[].workload` is an open `string → number` map, and "number" is the
  entire privacy control.** Open vocabulary for the same reason Threat Shield
  accepts every scenario. Numbers-only because an FQDN, an IP address, a
  hostname or a DMI serial cannot be encoded in a float — a stronger guarantee
  than any field blocklist someone has to maintain. Caps bound shape, never
  vocabulary, and truncate rather than reject.
- **A coverage gate precedes the score.** `metrics_present == false`,
  `sample_coverage < 0.80`, `cpu_cores < 1` or `mem_total_bytes <= 0` yields
  `pressure = NULL`, not a clamped number: a node that was off for eighteen
  hours is not a low-pressure node, and a score from missing data is worse than
  no score. A missing individual input makes its penalty term **absent**, which
  is not the same as zero.

The contract clients build against is
`docs/specs/2026-09-02-sizing-ingest-contract.md`; the reasoning is
`docs/plans/2026-09-02-fleet-sizing-server.md`.

### Cohort pass: `baseline.Runner.Run`

Runs every `SIZING_PASS_INTERVAL` (default 1h — the inputs are whole days, so
faster cannot produce a different answer), started after the listeners, first
pass immediately, in `cmd/sizingd`. Same shape as the consensus pass's loop in
`cmd/threatd`: each binary's own `runPassLoop` takes an
`interface{ Run(context.Context, int64) error }`, which both runners satisfy —
the two binaries cannot share the unexported helper, only the shape.

```
1. recompute pressure where pressure_version is stale (bounded batch)
2. recompute node verdicts over the trailing SIZING_WINDOW_DAYS
3. recompute cluster imbalance for multi-node clusters
4. build cohorts: per-node reduction, then across-node percentiles, applying
   and counting the censoring / coverage / hardware-change exclusions
5. upsert the baselines that clear the floor
6. DELETE the cohorts that no longer clear it
7. RollupSizingMonthly          housekeeping: logged, never fatal
8. PruneSizingDaily             only if 7 succeeded
```

Two orderings must not move. **1 before 4**, or a `pressure_version` bump
publishes a baseline mixing two score definitions. **7 before 8**, or the day
being dropped loses its history permanently — the same constraint, and the same
reason, as `RollupThreatDailyStats` before `PruneThreatEvents`. Steps 2, 3 and 4
all read one `SizingWindow` query, because a second query would be a second
chance for them to disagree.

The correctness of the pass is in three places:

- **Censoring.** An undersized node's memory demand is capped by the memory it
  has: a node needing 12 GiB but holding 8 reports ~7.6 GiB. Feeding that into
  an estimator of "how much RAM does a mail node need" biases the answer *down*,
  which then declares more nodes adequately sized — the exact inverse of the
  feature's purpose. That is systematic bias, not noise, so censored nodes are
  excluded from the percentiles and **published as `censored_nodes`**. Nodes are
  not excluded for being unhealthy in general, and disk-bound nodes stay in:
  "what a healthy node uses", derived by deleting the unhealthy ones, is
  survivorship bias with extra steps.
- **Two-stage aggregation.** Each node is reduced to the p90 across its daily
  `ram_used_bytes_p95` (p90, not the median: a 28-day window holds eight weekend
  days on which a business workload is idle) and only then do percentiles run
  across nodes. Without it, always-online nodes and one MSP's forty identical
  clusters dominate every published number.
- **The floor counts distinct `system_id`**, the same rule and the same reason as
  Threat Shield's promotion, and a cohort that falls below it is **deleted**
  rather than left stale — mirroring `ExpireBlocklist`.

`pressure`'s versioning deliberately diverges from `fingerprint.Version`. A
fingerprint is an identity and is never backfilled, because the point of a bump
is that the change is visible. `pressure` is a derived analytic over inputs that
are all stored as first-class columns, so leaving 100 days of mixed-definition
scores would make every trailing verdict wrong and every cohort statistic
incomparable — hence step 1.

### Operator UI

Three separate dashboards now, one per binary — `internal/ui/logs`,
`internal/ui/threat`, `internal/ui/sizing` — each a second, independent HTTP
server on its own listener (`UI_LISTEN_ADDR`, off by default) built on the
shared `internal/ui/chrome`. Each depends only on `model` and its own
`store/*` package (through a local `Reader` interface, plus a local `Writer`
for threatd's write routes); `ui/logs` adds a local `Runtime` interface
(`Depth`/`Cap`, satisfied by `*queue.Queue`) for queue state, `ui/threat` adds
a local `Feed` interface (satisfied by `*blocklist.Snapshot`) for the
blocklist's live state, and `ui/sizing` imports `internal/sizing` for the
score's threshold table and its constants. None imports `api/*`, `analyzer`,
`blocklist` or `baseline`.

In front of all three sits Traefik, serving them at `/logs`, `/blocklist` and
`/sizing` and BasicAuth-protecting every request with `ADMIN_API_KEY` as the
htpasswd password. That layer is **additive, not a replacement**: each app's
own `GET` remains unauthenticated at the app layer (so a direct connection —
bypassing Traefik — still reaches it, which is why the pod publishes no port
for these listeners in the deployed shape), and threatd's write routes still
authenticate against `ADMIN_API_KEY` and refuse cross-site requests inside the
app, because Traefik BasicAuth is still Basic auth and a browser replays it on
a forged cross-site POST exactly as it would replay credentials cached against
the app directly. See `README.md` § "Operator UI" for routes and exposure
guidance, and the "what is a finding / template / baseline" explanations in
`docs/user-guide.md`.

## Data model and storage

SQLite via `bun` + `modernc.org/sqlite` (pure Go, no cgo), one file, one
connection (`SetMaxOpenConns(1)`), WAL mode, `busy_timeout=5000`, writes
serialized by an in-process mutex — the spec's "single writer" guarantee
without a goroutine to leak.

| Table | Purpose |
|---|---|
| `systems` | One row per system seen; first/last-seen timestamps, collector version. |
| `system_templates` | Every masked log-line template ever seen for a system — the gate's "is this new" memory. Keyed `(system_id, module_id, template_key)`, where `template_key` is `model.CanonicalTemplate` of the raw text and `module_id` is the module **family** (`model.ModuleFamily`) rather than the instance, so 82 `nethvoice*` instances emitting one cron line are one row. `template` keeps the raw text of the last variant seen, which is what the UI shows. |
| `module_baselines` | Per-`(system_id, module_id, priority)` EWMA rate — the gate's deviation fallback when a bundle carries no `expected`. Keyed on the module **instance**, deliberately: one instance flooding is signal about that instance, and this is where per-instance attribution survives the family collapse elsewhere. |
| `analyses` | One row per `(system_id, window_start)` — the cost/decision ledger: gated or not, `gate_reasons`, tokens (including `cached_tokens`), cost, duration, error, and `suppressed_by` when a budget limit refused the window. Unique on that key for idempotency; `completed` distinguishes a claimable retry from a finished window. |
| `findings` | One row per `(system_id, fingerprint)` — unique so a repeat detection bumps the same row instead of inserting a duplicate. |
| `threat_events` | One sanitized CrowdSec sighting. Unique on `(system_id, attacker_ip, scenario, observed_at)`, which is what makes redelivery safe. Pruned past `THREAT_EVENT_RETENTION`. |
| `threat_blocklist` | One row per published address, with `first_listed_at`, the refreshing `expires_at`, and the `listing_reason` evidence snapshot. |
| `threat_allowlist` | Hand-maintained CIDRs that must never be promoted. Written only through `internal/ui/threat`'s write routes — there is no separate admin plane or admin API any more. |
| `threat_daily_stats` | Per day and scenario rollup, written before the prune so the trend outlives the raw events. |
| `threat_ingest_daily` | Per day and system ingest accounting — accepted, duplicates, and every drop reason. |
| `sizing_node_daily` | One node-day of measurements plus the derived `pressure`, its four axis penalties, `pressure_reasons` and `pressure_version`. Keyed `(system_id, node_id, day)` — a `system_id` is a *cluster*, so one report writes N rows. Every measurement column is nullable and `NULL` means **not measured**, never zero. |
| `sizing_module_daily` | One module family per node-day: `instances`, plus a display-only `facts_ok` and `versions` JSON array. Nothing derived reads either. |
| `sizing_module_metric` | The open workload map, **normalised to rows** so the cohort pass groups it in SQL. The pass reads a value only through `sizing.IsPlatform`, which decides whether a family is ignorable when testing "solo" (samba's answer turns on its share count). A JSON blob would force ~1.4M rows through the single-writer connection and a JSON parse each, hourly. |
| `sizing_cluster_daily` | Cluster-wide counters belonging to no single node — the summed `user_domains` totals from `cluster/get-facts`. |
| `sizing_node` | The `(system_id, node_id)` dimension, and the fix for unstable node identity: `hw_changed_at` records when installed capacity last changed under a stable id, which is how the cohort pass excludes a node whose percentiles would straddle two physical machines. |
| `sizing_ingest_daily` | Per day and cluster ingest accounting. The one sizing table that **accumulates**. |
| `sizing_node_monthly` | Monthly rollup, `month TEXT 'YYYY-MM'`, kept indefinitely so history survives `SIZING_RETENTION`. |
| `sizing_node_verdict` | The multi-day verdict per node, plus its cluster's placement answer denormalised onto every node of that cluster so one query renders the page. |
| `sizing_cohort_baseline` | Published baselines per `(cohort_kind, cohort_key)` — absolute bytes and cores, with `censored_nodes` alongside. Two kinds only: `family_solo` (the quotable one — nodes running no other *chosen* workload, so the number includes the platform modules every cluster runs) and `family` (co-tenanted, context). |

`attacker_ip` is stored as a normalized `netip.Addr.String()`, so text equality
is address identity — that is what lets a portable `TEXT` column stand in for
Postgres `INET`.

The two day keys differ on purpose. `threat_daily_stats` uses `day TEXT
'YYYY-MM-DD'`; every `sizing_*` daily table uses `day INTEGER`, a UTC day index
(`unix_millis / 86400000`). `threat_daily_stats` is a display rollup read whole,
while the sizing tables are range-queried constantly (a 28-day verdict window, a
90-day UI, a prune below a cutoff) — an integer index does all three with the
arithmetic this codebase already performs, and removes the bug class where a
formatter with the wrong location writes two rows for one day. The monthly
rollup goes back the other way (`month TEXT`) because nothing does arithmetic on
months. The `sizing_*` tables also carry **no surrogate ULID**: the project bans
`AUTOINCREMENT`/`SERIAL` but does not mandate a surrogate, and
`threat_daily_stats` already uses a bare composite primary key.

Two upsert idioms coexist in the sizing tables and the difference is
load-bearing: the measurement tables **recompute** (a day is an absolute fact,
so a reporter's second and third daily sends are byte-identical restatements)
and `sizing_ingest_daily` **accumulates** (its counters count requests). Each
table's DDL says which it is, because mixing them would be silent.

Schema portability rules (SQLite today, Postgres later — see `CLAUDE.md` §
Invariants) apply to every table: ULIDs generated in Go rather than
autoincrement primary keys, unix-millis integers rather than native date
types, `ON CONFLICT … DO UPDATE` rather than `INSERT OR REPLACE`, JSON stored
as `TEXT` and parsed in Go.

Raw `samples` from the bundle are **never** persisted — the DB and the UI can
only ever show masked templates.

### The EWMA baseline formula

`store.UpsertBaselines` maintains one exponentially-weighted moving average
per `(system_id, module_id, priority)`:

```
newRate = EWMA_ALPHA * observed + (1 - EWMA_ALPHA) * prevRate   // prevRate exists
newRate = observed                                              // first sample
```

This is the standard EWMA recurrence, and the implementation matches it
exactly (verified against `internal/store/store.go`). Two things worth being
precise about, since the name invites confusion:

- **`EWMA_ALPHA` itself must be in `(0, 1]`** — it is a blend weight, not the
  baseline. The code does not clamp or validate it (`cmd/insightsd`'s
  `getenvFloat` accepts any parseable float), so an operator-supplied value
  outside that range would silently produce a nonsensical baseline (e.g. a
  negative or diverging `ewma_rate`). Keep it in `(0, 1]` when configuring.
- **`ewma_rate` (the baseline itself) is not bounded to `[0, 1]`.** It is in
  the same units as `observed` — a line count for one window — so it can
  legitimately be 0, or in the thousands, depending on the module.

### Scenarios are not interpreted

`threat_events.scenario` holds the CrowdSec scenario name verbatim, and there
is no fixed category set behind it.

An earlier revision mapped scenarios onto four categories (`ssh_bruteforce`,
`http_exploit`, `port_scan`, `sip_probe`) and dropped anything unmapped, per
the design's D3. That was removed. CrowdSec's hub grows continuously, nodes run
third-party collections (`LePresidente/http-generic-401-bf` is a real example
from a live NS8 node) and operators write local rules, so a fixed allowlist
silently discards real evidence until somebody notices and ships a release —
and "silently discards evidence" is the failure this pipeline exists to avoid.

Consequences worth knowing:

- The scenario is free text from the edge. It is trimmed, stripped of control
  characters and capped at `threat.MaxScenarioLen` before storage, because it
  reaches an HTML page and a log line. It is never judged on content.
- It is part of the `threat_events` unique key and of the consensus grouping,
  so two nodes reporting one address under different scenarios are still two
  distinct systems — promotion counts systems, never scenario agreement.
- `threat_blocklist.scenarios` and the daily rollup therefore carry whatever
  the fleet actually reported, which is more useful than four buckets and is
  what makes the rollup a real threat-trend asset.

### The allowlist write routes

Two surfaces write to `threat_allowlist`, and exactly one thing is true of
both: **no path promotes a customer request automatically.** A client's
`POST /v1/allowlist-requests` is a ranked queue entry, nothing more; only an
explicit approval creates an entry. `TestClientRequestsNeverAutoPromoteToTheAllowlist`
and `TestAllowlistRequestsNeverAutoPromote` are the executable form of that
rule.

**The separate admin plane is gone.** `internal/admin`, `ADMIN_LISTEN_ADDR` and
the `X-Admin-Actor` header no longer exist. `internal/ui/threat`'s four write
routes (`writableRoutes` — add/update an entry, delete one, approve a request,
reject one) are now the only writer anywhere in the deployment, gated behind
`ADMIN_API_KEY` and HTTP Basic (`chrome.AuthenticateWrite`); the Basic username
becomes the actor recorded on every write, exactly as `X-Admin-Actor` used to
be. With `ADMIN_API_KEY` unset those routes are never registered — a missing
route, not a guessable credential. In the deployed shape Traefik additionally
BasicAuths the whole `/blocklist` subtree with the same key value as the
htpasswd password; that layer is additive, not a replacement — see "Operator
UI" above for why the app-level check has to stay regardless.

Three tables sit behind it, and `/audit` is the only reader of the third.
`threat_allowlist_requests` is keyed
`(cidr, system_id)` so one system counts once, mirroring the blocklist's
distinct-system rule; `threat_allowlist_reviews` records the latest human
verdict; `threat_allowlist_audit` is append-only and exists because `DELETE`
destroys the row that would otherwise hold the trail.

**A handled request is deleted, not masked.** Approving or rejecting records
the verdict, appends the audit row, and then calls `DeleteAllowlistRequests`
to drop every ask for that CIDR — in that order, so a failed delete leaves the
request pending to be decided again rather than losing the ask with nothing
recorded. `PendingAllowlistRequests` therefore means exactly "a request row
exists" and does not consult `threat_allowlist_reviews` at all.

The reason is not tidiness. Masking the queue on a per-CIDR review row — the
earlier design — made a decision permanent in the wrong direction: an address
rejected once on thin evidence could never be raised again, however many
systems went on to ask for it, and nobody was told it was being swallowed.
Deleting the asks instead loses nothing, because the verdict is in
`threat_allowlist_reviews` and the append-only audit trail holds who decided
what with their note, while a later ask is reviewed on its own merits.
`TestAFreshAskAfterADecisionReturnsToTheQueue` is the executable form of that.
A consequence to keep in mind: re-approving an address that is already
allowlisted is an idempotent no-op, so a fresh ask for one is harmless noise in
the queue rather than a problem.

**The operator UI's GET-only invariant has changed.** It used to be "every
route answers GET, anything else is 405, enforced once, centrally" — the reason
an unauthenticated fleet-wide page was safe to run. It is now:

> Every route answers GET. A small, explicit, enumerated set of routes also
> answers POST, and every one of those authenticates before doing anything.

The enumeration (`writableRoutes`) lives next to the central check in
`route()`, so "which routes can write" is answerable by reading one function.
Writes are registered only when `ADMIN_API_KEY` is set.

Write routes additionally refuse cross-site requests. This is not boilerplate
CSRF hygiene: the routes authenticate with HTTP Basic, and a browser replays a
cached Basic credential automatically on every later same-origin request,
including a form POST from an unrelated page the operator visits afterwards.
Without the check any site could add an attacker's address to the fleet
allowlist silently and permanently — the exact harm the no-automatic-promotion
rule exists to prevent. `sameOriginWrite` requires `Sec-Fetch-Site:
same-origin`/`none` and an `Origin` matching the host, and allows a request
carrying neither header, which is a non-browser client with no ambient
credential to abuse.

## Finding identity: the fingerprint

`fingerprint.Compute(systemID, modules, evidence, category)` hashes
length-prefixed, sorted, deduplicated fields with sha256 and a version
prefix. A `strings.Join` is deliberately avoided — an unprefixed separator is
forgeable (`"ab"+"c"` could collide with `"a"+"bc"`).

The critical invariant: **no model-authored string ever reaches the
fingerprint**. The LLM cites templates by identifier only (`T1`, `T2`, …,
assigned by `prompt.TemplateID` in the exact order `prompt.Select`
renders them); `prompt.ResolveEvidence` maps those IDs back to the server's
own template records, and the server derives the evidence text, module set
and category from that — never from the model's prose. This is what makes
the same recurring problem collapse onto the same finding even when the model
words its restatement differently each time.

Refusing model-authored *text* is not enough on its own, because the model
still chooses *which* templates to cite. `v1` hashed the whole cited set, so
the same SSH brute-force condition cited as `(BG/…) (DE/…) (NL/…)` in one
window and `(CA/…) (HK/…)` in the next produced two different fingerprints and
two findings, each stuck at `occurrence_count=1`.

`v3` therefore hashes a single derived key — `fingerprint.EvidenceKey` — in
three layers:

1. `fingerprint.Normalize` collapses the fields the collector's masking leaves
   literal. It is `model.CanonicalTemplate`, the same collapse the gate's
   novelty check and the `system_templates` key use, and the module set hashed
   alongside it is folded to families by `model.ModuleFamily` for the same
   reason — one definition, because
   if novelty and identity disagreed about whether two lines are the same
   condition, a window could pay for a template the store already knew and the
   finding would land on a fresh fingerprint each time. Fixing the masking
   belongs in the collector; this exists so a leak there cannot silently split
   identity here. The stored evidence text shown to the operator is never
   rewritten — only the identity path.
2. If every cited template shares one `(module_id, priority)` bucket, the key
   is that bucket. Text variance *within* a bucket the model already chose to
   cite as one condition is noise.
3. Otherwise the key is the canonical primary template: the first of the
   normalized set under `model.LessTemplate`.

`model.LessTemplate` is the single definition of template order, used by both
`prompt.Select` (to number the identifiers the model cites) and
`EvidenceKey` (to pick the primary). If those two ever disagreed, a finding's
identity would stop matching the evidence the operator is shown for it.

Changing the fingerprint formula changes every existing finding's identity
fleet-wide — that must be a deliberate versioned migration (bump the
`fingerprint.Version` prefix), never a silent behavior change.

## Cost control: the gate

`gate.Evaluate` is the only thing standing between this design and the ~$16k/
month it would cost to send every window to an LLM (`gpt-4o-mini` pricing).
It fires (returns `Call: true`) if any of:

- at least `GATE_MIN_NEW_TEMPLATES` (default 3) templates are new for this
  system. Novelty is counted over `model.CanonicalKey`, so the many spellings
  the collector's masking leaks produce for one line count once, and a quorum
  is required because a real new condition arrives as a cluster of lines, not
  as one Postgres checkpoint line with a different percentage;
- a digest entry's observed/expected ratio exceeds `GATE_TOLERANCE` **and** the
  bucket clears both absolute floors, `GATE_MIN_EXPECTED` (default 10) and
  `GATE_MIN_OBSERVED` (default 20). A ratio is not evidence when the
  denominator is 2: on the dev fleet the median bucket baseline was 3.1 lines
  per window, 207 of 587 buckets were under 2, and the buckets that fired most
  often were the smallest ones. `expected` is the edge-supplied value if
  present, otherwise the server's own EWMA baseline, and the floors apply
  identically to both;
- a **new** security-category template appears, or a **known** one whose
  module is deviating (`security_new` / `security_surge`). The category is
  assigned by the edge, never computed server-side. Mere presence does not
  fire: `sshd` auth failures arrive continuously on any internet-facing node,
  so the earlier unconditional form made the gate a no-op — 352 LLM calls out
  of 352 windows on the dev fleet — and made the spend-cap degrade path
  (`SystemState.SecurityOnly`) cost exactly as much as not degrading;
- a module is both truncated (the edge dropped lines to stay under its line
  budget) **and** deviating — truncation alone never fires.

A **new security-category template always fires on its own**, before and
independent of the novelty quorum: one is the entire signal that condition
exists for.

**A bundle is sent to the LLM if and only if `gate.Evaluate` returns
`Call: true`** — i.e. at least one condition above holds. Otherwise the
window is *gated out*: `analyzer.Process` step 6 records it and returns
without ever calling `llm.Client.Complete`.

Every window — gated out or sent to the LLM — gets exactly one row in the
`analyses` table (`store.Analysis`), with `gated` (bool) and `gate_reasons`
(the sorted reason list) always populated, and `llm_called`/`input_tokens`/
`output_tokens`/`cost_micros` populated only when the LLM was actually
called. This row is where a gated analysis "lives" — there is no separate
gated-vs-analyzed table, only this one flag. So both "why did this cost
money" and "why was this potentially missed" are answerable from stored data
alone — see the `/gate` and `/analyses` routes in the operator UI.

A third state exists alongside "gated out" and "called": a window the budget
refused. It is stored with `gated = 1`, `suppressed_by` naming the limit, and
**no** gate reasons — see "Cost control: the ceiling" below.

Two consequences for anything that reads `gate_reasons` back:

- **`llm_called` is derivable from the reason set, and `cost_micros` is not
  derivable from `llm_called`.** `Call == len(Reasons) > 0` is a `gate.Evaluate`
  invariant, so a non-empty reason set always means a call — never present
  windows and calls as independent columns. `llm_called` counts *attempts*: the
  transient-error, permanent-error and response-parse paths all set it with
  `cost_micros = 0`, so "called and paid" needs a separate count
  (`store.GateRow.PaidCalls`).
- **Any rollup over `gate_reasons` must be time-bounded.** Reasons are stored as
  the formula that produced them spelled them, and a rule change is a deliberate
  visible break with no backfill (the same principle as `fingerprint.Version`).
  `store.GateRollup(ctx, since)` takes an explicit bound and `/gate` defaults to
  7 days; unbounded, the page groups two gates at once and is dominated by
  whichever era has more rows.

### What the prompt carries

The gate decides *whether* to pay; `prompt.Select` decides *how much*.

A bundle from a real multi-module node carries 160-190 templates and rendered a
32 KB prompt, of which roughly 70% was template text — almost none of it the
reason the call happened. `Select` therefore shows: every novel template, every
security-classified one, everything in a deviating module, and then the top
`PROMPT_MAX_AMBIENT` (default 60) of the remainder by count as context.

Before selecting, it **collapses**: templates sharing a canonical key within
one `(module family, priority)` become one line carrying the summed count, the
number of variants folded, and the text of the busiest variant. Showing a model
65 spellings of one Prometheus message invites 65 findings, and showing it the
same line once per module instance invites 82.

Because the group is a family and `gate.Decision.DeviatingModules` is a set of
instances, `Select` folds that set to families itself before asking whether a
group deviates. Skipping that would demote the very line that paid for the call
into the ambient pool, where `PROMPT_MAX_AMBIENT` can drop it.

`prompt.TemplateID` numbers whatever `Select` returns, so `Render` and
`ResolveEvidence` must be given the **same** `Selection` — otherwise the
identifiers the model cites resolve to different templates than the ones it was
shown. `analyzer.Process` builds it once, from `gate.Decision.Novel` and
`gate.Decision.DeviatingModules`, and passes that one value to both.

## Cost control: the ceiling

The gate is a per-window judgement and cannot answer the fleet-level question:
what is the most this can cost if the judgement is wrong, or if a collector
upgrade changes the masking rules and every node's templates go novel in the
same window (spec §9.3). `internal/budget` answers it with three limits, each
counted off the `analyses` ledger for the current UTC day — never an
in-process counter, which a crash loop would reset:

| Limit | Effect on breach |
|---|---|
| `LLM_MAX_CONCURRENCY` (default 4) | calls wait for a slot; the bounded queue absorbs the rest and ingest answers 503 when it fills |
| `LLM_MAX_CALLS_PER_SYSTEM_PER_DAY` (default 12) | the window is recorded `gated = 1`, `suppressed_by = "system_call_cap"`, no reasons, no cost |
| `LLM_DAILY_SPEND_CAP_USD` (default 0 = off) | `gate.SystemState.SecurityOnly` is set: novel and surging security templates still fire, everything else declines |

The per-system cap is the one that makes the worst case arithmetic rather than
emergent. The spend cap deliberately degrades rather than stops: a cap that
blinded the fleet to a break-in would be worse than the invoice it prevents.

A suppressed window still records its templates and baselines. Skipping that
would leave the system never learning what it saw, so every later window would
look novel — the cap would make the next day more expensive, not less.

## Determinism

Identical bundle input must produce byte-identical prompts and stable gate
reasons, because the whole cost/identity model depends on it:

- `prompt.Select` sorts `(module_id, priority, template)`, and breaks ties in
  the ambient ranking on the same order so equal counts cannot depend on input
  order.
- Digest entries are sorted `(module_id, priority)` in both `gate.Evaluate`
  and `prompt.Render`.
- Gate reasons are appended in a fixed order (security first, then
  new-templates, then deviation, then truncated+deviating).
- Gate reasons carry no computed values. `new_templates` has no count and
  `deviation:<module>/<priority>` has no ratio, because the operator UI's
  `/gate` rollup groups on the stored `gate_reasons` string: with the ratio
  embedded, every deviating window became a group of one and the page that
  exists to answer "why are we paying" answered nothing. The ratio is kept
  nowhere: per-window numbers are in the rendered prompt, per-bucket normals
  on `/baselines`.
- `fingerprint.writeList` sorts and dedups before hashing.

`prompt` has golden-file tests asserting byte-identical output for identical
input; `gate` and `fingerprint` are table-driven over every condition alone
and in combination.

## LLM integration

`internal/llm` is a small interface (`Complete(ctx, Request) (Response,
error)`) with one real implementation (`openai.go`, any OpenAI-compatible
`chat/completions`-style endpoint) and one stub (`stub.go`) used by
`analyzer_test.go`. Requests use `response_format: json_schema` with
`strict: true` against `prompt.Schema`, and **never** send a `temperature`
field — some providers reject any non-default value outright.

`llm.HTTPError.Permanent()` distinguishes errors the analyzer should finalize
(4xx-shaped, schema rejections) from transient ones it should leave
retryable (timeouts, 5xx, connection failures).

`Response.CachedTokens` carries `usage.prompt_tokens_details.cached_tokens`
where the provider reports it. Cached input is billed at half rate, and
`analyzer.Process` prices it that way; a provider that reports nothing leaves
it zero, which prices the call as if nothing was cached — the safe direction
for a cost figure. Earning those hits is why `prompt.Render` opens with an
invariant header and ends with the per-window one: a provider caches the
longest shared prefix of a request, and a prompt starting with
`start_ms=1788269400000` shares nothing beyond the system message.

## Authentication

Authentication moved to the proxy. `cmd/authd` is a thin HTTP shell over
`internal/platform/auth.ForwardAuth`, which forwards the edge's
`Authorization: Basic` header verbatim to `AUTH_VALIDATE_URL` (default
`https://my.nethesis.it/auth`) and caches the outcome, keyed by
`HMAC(AUTH_PEPPER, "system_id:secret")` so the in-memory cache cannot be
reverse-engineered into a credential list. Positive and negative TTLs are
independently configurable (`AUTH_CACHE_TTL`/`AUTH_NEG_CACHE_TTL`). `authd`
exists rather than pointing Traefik's `forwardAuth` straight at
`my.nethesis.it` because Traefik has no cache of its own — at ~2700 nodes an
uncached forward-auth call is roughly one upstream request per bundle — and
because a cache-less proxy call would collapse the validator-unreachable case
into a plain `500`, losing the distinction below. One `authd` now serves all
three pipelines instead of each running its own cache.

The validator being unreachable is a distinct case from it rejecting
credentials: `ErrUnavailable` maps to `503` (fail closed — an edge retries a
gap, but a false `401` is a customer-visible outage), while
`ErrInvalidCredentials` maps to `401`. A stale cache entry is preferred over
`ErrUnavailable` when the validator is down and something was cached before.
Traefik's `forwardAuth` middleware calls `GET /auth` on `authd` and passes its
status straight back to the client on anything but `2xx`, which is what keeps
this `401`/`503` distinction visible at the edge instead of being collapsed.

**The validator only ever answered yes/no; it never returned an identity.**
Traefik forwards the original `Authorization` header through to the pipeline
unchanged, so each pipeline still parses it itself — `httpx.SystemID` reads the
Basic username as the `system_id`, without re-checking the secret, because
`authd` already did that. This is why every `/v1/*` request must arrive from a
trusted proxy address: `SystemID` returns `ErrUntrustedProxy` unless
`r.RemoteAddr` is inside `TRUSTED_PROXY_CIDRS` (default `127.0.0.0/8`), and a
request that reaches a pipeline directly — bypassing Traefik and `authd` — is
refused rather than trusted on an unverified credential.

The same trusted-proxy set gates `httpx.ClientIP`, which Threat Shield's
reporter-own-address check depends on (see "Threat ingest" above): the header
is client-controlled, so `X-Forwarded-For` is believed only from a configured
proxy, and only its rightmost value. In the deployed shape all five containers
— Traefik, `authd` and the three pipelines — share one podman pod and
therefore one network namespace, so Traefik's connection to a backend never
crosses a NAT boundary and `RemoteAddr` really is `127.0.0.1` by construction,
which is what makes the default `TRUSTED_PROXY_CIDRS=127.0.0.0/8` correct
without a per-deployment value.

`api.StaticAuth`, the hardcoded system/secret pair used before this split for
tests and local development, no longer exists: a pipeline no longer holds an
`Authenticator` at all, only the trusted-proxy check.

## Configuration and wiring

Each binary's `main.go` (`cmd/authd`, `cmd/insightsd`, `cmd/threatd`,
`cmd/sizingd`) is the only place that binary reads environment variables (see
`README.md` for the full table, split by binary) and the only place its own
packages are constructed and connected — there is no shared wiring code
between binaries beyond the `internal/platform` packages themselves. Each
pipeline binary also builds its operator UI's `ConfigItem` list *explicitly*,
field by field — never by iterating `os.Environ()` — so an unrelated secret
added to the process environment can never leak onto the unauthenticated
status page by accident.

Graceful shutdown order, in each of `insightsd`/`threatd`/`sizingd`: stop
accepting HTTP, shut down both that binary's HTTP servers (API and UI), *then*
drain whatever in-flight work it owns — `insightsd` drains the queue, because
buffered bundles were already acknowledged to an edge that won't resend them
and must still be processed before exit — and only then cancel and wait for
that binary's own background pass (the consensus loop in `threatd`, the cohort
pass in `sizingd`). The pass loop goes last because it holds no acknowledged
work: a cancelled pass simply leaves the previous snapshot in place, which is
its designed failure mode anyway. `authd` has no pass loop and no queue, so its
shutdown is just the HTTP server.

## Testing strategy

See `CLAUDE.md` § "Testing expectations" for the specifics per package. The
short version: `gate`/`fingerprint`/`prompt` are pure and table/golden-file
tested with no fixtures; `analyzer` runs the real pipeline against a stub LLM
and a temp-file SQLite store, and its tests are what encode the step-order
invariants above as executable checks rather than just comments.

Threat Shield follows the same split. `threat` is pure and carries the deepest
table in the repository — every IP class, every origin, every malformed field
— because that is where a bug becomes a data-protection incident. `blocklist`
is tested against a temp-file SQLite store rather than a mock, because the
grouping *is* the SQL: the boundary cases (two systems do not promote, three
do; one system reporting three times does not; one system across two
categories is still one system) cannot be checked against a fake that
reimplements the query.

## Known limits

- **Single instance, per pipeline.** Neither the consensus pass (`threatd`) nor
  the cohort pass (`sizingd`) takes a distributed lock, so two processes of
  either against one database would both generate. The lock question returns
  with multi-instance deployment.
- **No organization identity.** Promotion counts distinct systems only; the
  design's cross-organization requirement (D5) cannot be expressed until the
  authenticator returns a tenant. Three systems in one fleet therefore count
  as consensus, and the hand-maintained allowlist is the compensating control.
- **The admin actor is self-declared.** One shared `ADMIN_API_KEY` has no
  identity behind it, so the HTTP Basic username recorded on a write — the
  same value Traefik's htpasswd layer would show — is a readable trail, not an
  authorization boundary: anyone with the key can claim any name.
