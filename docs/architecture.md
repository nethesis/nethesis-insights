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
 edge node (ns8-loki collector)        edge node (ns8-crowdsec)
        │  POST /v1/bundles                    │  POST /v1/threat-events
        ▼                                      ▼
 ┌───────────────────────────────────────────────────────────┐
 │                        insightsd                          │
 │                                                             │
 │  api ── auth.ForwardAuth ──► AUTH_VALIDATE_URL (external)  │
 │   │                                  │                      │
 │   ▼                                  ▼                      │
 │  queue (in-memory bounded channel)  threat (pure sanitizer) │
 │   │                                  │                      │
 │   ▼                                  ▼                      │
 │  analyzer ── gate ── fingerprint ── store ◄── blocklist      │
 │              prompt ── llm          (SQLite)   consensus     │
 │                                                + snapshot    │
 │  ui (optional, read-only, own listener)                    │
 └───────────────────────────────────────────────────────────┘
        ▲                                      ▲
        │  GET /v1/findings  (same auth)       │  GET /v1/blocklist
 edge node / operator                    edge node
```

One edge node ships one bundle per 15-minute window. The server never
initiates contact with a node.

**Two independent pipelines share this process, and only this process.** The
bundle path (left) spends money per call, so everything in it exists to avoid
spending it. The Threat Shield path (right) is high-volume factual data with no
LLM anywhere in it: ingest is synchronous, there is no gate and no fingerprint,
and the only shared components are the listener, the `Authenticator` and the
SQLite file. They are described separately throughout this document for that
reason.

## Package layering

```
model                       no deps; imported by everything
fingerprint  gate  prompt   PURE — no I/O, no clock beyond an injected now()
threat                      PURE — the Threat Shield sanitizer and allowlist
llm  store                  interfaces, each with a real and a stub impl
budget                      the ceiling under LLM spend; reads the cost ledger
analyzer                    the bundle pipeline; depends on all of the above
blocklist                   Threat Shield consensus + the served snapshot
api                         HTTP: ingest + read, auth via the Authenticator iface
admin                       HTTP: allowlist admin plane, own listener, off by default
ui                          HTTP: optional operator dashboard, off by default
cmd/insightsd                env config, wiring, graceful shutdown
```

This is a strict DAG — nothing lower in the list imports anything above it,
and `ui` does not import `api` or `analyzer`.

| Package | Responsibility |
|---|---|
| `internal/model` | Wire types (`Bundle`, `Finding`, `Template`, …) and the pure helpers (`SortFindings`, `SeverityRank`) that operate on them. |
| `internal/gate` | `gate.Evaluate` — decides whether a bundle is worth an LLM call. Pure function of `(Bundle, SystemState, Config)`. |
| `internal/fingerprint` | `fingerprint.Compute` — the server-computed identity of a finding. Pure, sha256-based. |
| `internal/prompt` | Selects which templates are worth showing (`prompt.Select`), renders the deterministic LLM prompt, and parses/validates the strict-JSON response. Owns `prompt.Version`. |
| `internal/llm` | `llm.Client` interface; `openai.go` is the real OpenAI-compatible implementation, `stub.go` a test double. |
| `internal/store` | `store.Store` interface; `SQLiteStore` is the only implementation today. `store/ui.go` adds the cross-system, read-only queries the operator UI needs. |
| `internal/budget` | `budget.Controller` — the fleet-level ceiling the gate cannot provide: an in-flight concurrency bound, a per-system daily call cap, and a daily spend cap that degrades the gate to security-only. Counts off the `analyses` ledger, never an in-process counter. |
| `internal/analyzer` | `Analyzer.Process` — the pipeline that ties budget, gate, fingerprint, prompt, llm and store together for one bundle. |
| `internal/queue` | In-memory bounded channel decoupling ingest from analysis, plus in-flight dedup so a resend never starts a second LLM call for the same window. |
| `internal/auth` | `ForwardAuth` — forwards `Authorization: Basic` to an external validator, with a pepper-hashed TTL cache and fail-closed behaviour. |
| `internal/threat` | Threat Shield's pure half: `Sanitize` (every ingest drop rule) and `Allowlist` (portable CIDR containment). It deliberately holds no scenario allowlist — see "Scenarios are not interpreted". |
| `internal/blocklist` | `Runner.Run` — one consensus pass: promote, expire, roll up, prune, regenerate. `Snapshot` holds the rendered feed behind an `RWMutex`. |
| `internal/api` | HTTP handlers for `POST /v1/bundles`, `GET /v1/findings`, `POST /v1/threat-events`, `GET /v1/blocklist`, `/healthz`. |
| `internal/admin` | The allowlist admin plane: bearer-key auth, the seven `/admin/v1/allowlist*` handlers, on its own listener. A separate package from `internal/api` so the public ingest surface and the admin surface can never accidentally share a route table. |
| `internal/ui` | Optional, zero-JavaScript operator dashboard on its own listener. `GET` is unauthenticated; an enumerated set of `POST` routes authenticates against `ADMIN_API_KEY`. |
| `cmd/insightsd` | Reads environment config, wires every package together, runs the consensus ticker, runs graceful shutdown. |

The purity of `gate`, `fingerprint` and `prompt` is deliberate: they hold all
the correctness and all the cost logic, and are table-driven-testable with no
fixtures, no clock, no I/O. `llm` and `store` being interfaces is what lets
`analyzer_test.go` run the whole pipeline end to end with nothing running.

`internal/threat` is pure for a sharper reason than cost: everything deciding
whether a third party's IP address is stored and published lives there, so a
bug in it is a data-protection incident rather than a wrong answer.

`internal/blocklist` and `internal/api` each declare their own narrow interface
over the store (`blocklist.Reader`, `api.ThreatStore`, `api.Feed`) rather than
taking `store.Store`, so both stay testable with a small fake and the layering
stays a DAG. `ui.Feed` does the same for the snapshot's state — `ui` learns how
many entries are served and when, never the body.

## Request flow

### Ingest: `POST /v1/bundles`

1. `api.handleBundles` authenticates via the injected `Authenticator`
   (`auth.ForwardAuth` in production, `api.StaticAuth` in tests).
2. The body is decoded (gzip-aware, size-capped at 8 MiB) into a
   `model.Bundle` and validated: schema version, `system_id` matches the
   authenticated identity, a sane window, a template-count ceiling.
3. Modules named by `PIPELINE_EXCLUDE_MODULES` (default `crowdsec1`) are
   stripped by `model.Bundle.ExcludeModules` — templates, digest entries and
   truncation records together. This happens here, before the queue, so that
   the gate, the prompt, `system_templates` and `module_baselines` all read
   the same filtered bundle and cannot disagree about which modules are in
   scope. CrowdSec is excluded by default because it already has its own
   pipeline (`POST /v1/threat-events` → the blocklist); analysing its log
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

### Read: `GET /v1/findings`

Authenticates the same way as ingest, then `store.ListFindings` returns that
system's findings (optionally filtered by `since`/`status`), sorted by
`model.SortFindings` — severity descending, then most-recently-seen first.

### Threat ingest: `POST /v1/threat-events`

Synchronous end to end — no queue, because there is no LLM call to outlive the
client's timeout.

1. `api.handleThreatEvents` authenticates exactly as ingest does.
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

The source address comes from `r.RemoteAddr` and never from
`X-Forwarded-For`. That value feeds `threat.Sanitize`'s reporter-own-address
check (step 3 above), and the header is client-controlled: honouring it would
let an authenticated edge spoof its way past that check with a forged header.
Behind a reverse proxy this records the proxy, which makes the check useless
but never wrong.

### Consensus: `blocklist.Runner.Run`

Driven by a ticker in `cmd/insightsd` at `BLOCKLIST_CONSENSUS_INTERVAL`, with
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

### Feed: `GET /v1/blocklist`

`blocklist.Snapshot` holds the body, its gzip encoding and its `ETag`
(`sha256` of the body) behind an `RWMutex`. Serving never touches the database,
so the cost of the feed is flat regardless of subscriber count, and only a
successful generation replaces what is held — a failed pass keeps serving the
previous list with its original `generated:` timestamp.

Before the first successful pass the snapshot is not ready and the handler
answers `503`. That distinction matters: to a client importing the list, an
empty body means "no threats" and silently disables protection.

### Operator UI

`internal/ui` is a second, independent HTTP server on its own listener
(`UI_LISTEN_ADDR`, off by default). It depends only on `model` and `store`
(through a local `Reader` interface) plus a local `Runtime` interface
(`Depth`/`Cap`, satisfied by `*queue.Queue`) and a local `Feed` interface
(satisfied by `*blocklist.Snapshot`) for live process state. It never imports
`api`, `analyzer` or `blocklist`, and it never writes. See `README.md` §
"Operator UI" for routes and exposure guidance, and the "what is a finding /
template / baseline" explanations in `docs/user-guide.md`.

## Data model and storage

SQLite via `bun` + `modernc.org/sqlite` (pure Go, no cgo), one file, one
connection (`SetMaxOpenConns(1)`), WAL mode, `busy_timeout=5000`, writes
serialized by an in-process mutex — the spec's "single writer" guarantee
without a goroutine to leak.

| Table | Purpose |
|---|---|
| `systems` | One row per system seen; first/last-seen timestamps, collector version. |
| `system_templates` | Every masked log-line template ever seen for a system — the gate's "is this new" memory. Keyed `(system_id, module_id, template_key)`, where `template_key` is `model.CanonicalTemplate` of the raw text; `template` keeps the raw text of the last variant seen, which is what the UI shows. |
| `module_baselines` | Per-`(system_id, module_id, priority)` EWMA rate — the gate's deviation fallback when a bundle carries no `expected`. |
| `analyses` | One row per `(system_id, window_start)` — the cost/decision ledger: gated or not, `gate_reasons`, tokens (including `cached_tokens`), cost, duration, error, and `suppressed_by` when a budget limit refused the window. Unique on that key for idempotency; `completed` distinguishes a claimable retry from a finished window. |
| `findings` | One row per `(system_id, fingerprint)` — unique so a repeat detection bumps the same row instead of inserting a duplicate. |
| `threat_events` | One sanitized CrowdSec sighting. Unique on `(system_id, attacker_ip, scenario, observed_at)`, which is what makes redelivery safe. Pruned past `THREAT_EVENT_RETENTION`. |
| `threat_blocklist` | One row per published address, with `first_listed_at`, the refreshing `expires_at`, and the `listing_reason` evidence snapshot. |
| `threat_allowlist` | Hand-maintained CIDRs that must never be promoted. No HTTP surface — this server has no admin auth plane. |
| `threat_daily_stats` | Per day and scenario rollup, written before the prune so the trend outlives the raw events. |
| `threat_ingest_daily` | Per day and system ingest accounting — accepted, duplicates, and every drop reason. |

`attacker_ip` is stored as a normalized `netip.Addr.String()`, so text equality
is address identity — that is what lets a portable `TEXT` column stand in for
Postgres `INET`.

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

### The allowlist admin plane

Three surfaces now write to `threat_allowlist`, and exactly one thing is true
of all of them: **no path promotes a customer request automatically.** A
request is a ranked queue entry; only an explicit approval creates an entry.
`TestClientRequestsNeverAutoPromoteToTheAllowlist` and
`TestAllowlistRequestsNeverAutoPromote` are the executable form of that rule.

`internal/admin` is a separate package from `internal/api`, and a separate
listener from the ingest socket. On `:9595` the API key would be the entire
defence; on a normally loopback-bound admin port it is the second layer behind
the network. With `ADMIN_API_KEY` or `ADMIN_LISTEN_ADDR` unset the listener
never starts, so "unconfigured" means a closed port rather than a guessable
credential.

Three tables sit behind it. `threat_allowlist_requests` is keyed
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

`v2` therefore hashes a single derived key — `fingerprint.EvidenceKey` — in
three layers:

1. `fingerprint.Normalize` collapses the fields the collector's masking leaves
   literal. It is `model.CanonicalTemplate`, the same collapse the gate's
   novelty check and the `system_templates` key use — one definition, because
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
one `(module_id, priority)` become one line carrying the summed count, the
number of variants folded, and the text of the busiest variant. Showing a model
65 spellings of one Prometheus message invites 65 findings.

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

`internal/auth.ForwardAuth` forwards the edge's `Authorization: Basic` header
verbatim to `AUTH_VALIDATE_URL` (default `https://my.nethesis.it/auth`) and
caches the outcome, keyed by `HMAC(AUTH_PEPPER, "system_id:secret")` so the
in-memory cache cannot be reverse-engineered into a credential list. Positive
and negative TTLs are independently configurable
(`AUTH_CACHE_TTL`/`AUTH_NEG_CACHE_TTL`).

The validator being unreachable is a distinct case from it rejecting
credentials: `ErrUnavailable` maps to `503` (fail closed — an edge retries a
gap, but a false `401` is a customer-visible outage), while
`ErrInvalidCredentials` maps to `401`. A stale cache entry is preferred over
`ErrUnavailable` when the validator is down and something was cached before.

`api.StaticAuth` is a second `Authenticator` implementation — a hardcoded
system/secret pair compared in constant time — that exists for tests and
local development only; it is never wired up by `cmd/insightsd`.

## Configuration and wiring

`cmd/insightsd/main.go` is the only place that reads environment variables
(see `README.md` for the full table) and is the only place every package is
constructed and connected. It also builds the operator UI's `ConfigItem`
list *explicitly*, field by field — never by iterating `os.Environ()` — so
an unrelated secret added to the process environment can never leak onto the
unauthenticated status page by accident.

Graceful shutdown order: stop accepting HTTP, shut down both HTTP servers,
*then* drain the queue — buffered bundles were already acknowledged to an
edge that won't resend them, so they must still be processed before exit —
and only then cancel and wait for the consensus loop. The consensus loop goes
last because it holds no acknowledged work: a cancelled pass simply leaves the
previous snapshot in place, which is its designed failure mode anyway.

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

- **Single instance.** The consensus pass takes no distributed lock, so two
  `insightsd` processes against one database would both generate. The lock
  question returns with multi-instance deployment.
- **No organization identity.** Promotion counts distinct systems only; the
  design's cross-organization requirement (D5) cannot be expressed until the
  authenticator returns a tenant. Three systems in one fleet therefore count
  as consensus, and the hand-maintained allowlist is the compensating control.
- **The admin actor is self-declared.** One shared `ADMIN_API_KEY` has no
  identity behind it, so `X-Admin-Actor` is a readable trail, not an
  authorization boundary — anyone with the key can claim any name.
