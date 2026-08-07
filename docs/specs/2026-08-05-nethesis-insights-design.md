# Nethesis Insights — Design

**Date:** 2026-08-05
**Status:** Approved design, pending implementation plan
**Project:** `nethesis-insights` — new repo, Go
**Related:** [2026-07-29 Loki Anomaly Detector Design](2026-07-29-loki-anomaly-detector-design.md)

## 1. Context

The anomaly detector shipped in `ns8-loki` runs entirely on the edge node. One
Python job (`imageroot/bin/anomaly-detector`, 787 lines) queries Loki, builds a
digest, fetches log lines, scrubs them, calls an LLM directly, and emits findings
to journald. Every node holds an LLM API key and every node pays for its own
inference.

That design does not survive contact with a fleet. Three problems:

- **Credential sprawl.** An OpenAI or OpenRouter key on 2700 customer machines
  is 2700 places for it to leak, and no way to rotate centrally.
- **No cross-window memory.** The edge recalls prior findings from its own
  journal, so the same insight is re-raised whenever the journal rolls or the
  node reboots.
- **Uncontrolled cost.** Each node decides independently to spend money. There
  is no fleet-wide view, no ceiling, and no way to suppress duplicate spend.

This spec moves analysis to a central server. The edge is reduced to collection:
filter, deduplicate, ship. The server owns inference, identity, dedup and cost.

## 2. Scope

**In scope:** the Go server — ingest, authentication, queueing, gating, LLM
call, finding identity and dedup, storage, read API, container packaging.

**Out of scope, deliberately:**

- **Edge collector v2** (filtering, template masking, per-module fairness,
  digest-driven selection). Separate spec. The edge keeps calling the LLM
  directly until the server is live; see §12 for the cutover.
- **Operator dashboard / UI.** The read API is the only consumer surface here.
- **Operator-wide (cross-system) queries.** The API is per-system only.
- **Finding acknowledgement / mutation.** The API is read-only.

The edge is out of scope but not unconstrained: §4 defines the protocol the
edge must produce, and §6 explains why the edge's template masking is
load-bearing for server-side dedup.

## 3. Architecture

### 3.1 Topology

One container, three processes, supervised by `s6-overlay`.

```
                     ┌──────────── container ─────────────┐
edge (2700 nodes)    │                                    │
  bundle/15min ──────┼─► ingest HTTP ─► topic: bundles ──┐ │
   POST /v1/bundles  │      (auth)      (48h retention)  │ │
                     │                                   ▼ │
   GET /v1/findings ─┼─◄─ read API ◄─ SQLite ◄── analyzer  │
                     │                            │       │
                     └────────────────────────────┼───────┘
                                                  ▼
                                       OpenAI / OpenRouter
```

`s6-overlay` rather than a bash `&` because the container needs correct signal
forwarding, PID-1 zombie reaping, and independent restart of Redpanda without
killing the Go binary. Redpanda runs single-node: `--smp 1 --memory 1G
--overprovisioned`.

### 3.2 Sizing

2700 systems × 4 bundles/hour = **3 requests/second**. Redpanda is not present
for throughput — at this rate a database table would serve. It is present for
durable buffering, replay from offset, and decoupling ingest latency from
multi-second LLM calls. Sizing the deployment for a higher load would be
sizing for a load that does not exist.

Redpanda's practical floor is ~1–2 GB RAM even idle; budget for it.

### 3.3 Packages

| Package | Purpose | Depends on |
|---|---|---|
| `cmd/insightsd` | wiring, config, graceful shutdown | all |
| `internal/model` | `Bundle`, `Digest`, `Template`, `Finding` types | — |
| `internal/auth` | forward-auth client + TTL cache | — |
| `internal/ingest` | HTTP handler: validate, produce | `auth`, `queue` |
| `internal/queue` | franz-go produce/consume, interface-typed | — |
| **`internal/gate`** | **pure**: `(Bundle, SystemState) → Decision` | — |
| `internal/llm` | OpenAI-compatible client, strict `json_schema` | — |
| **`internal/fingerprint`** | **pure**: `Finding → stable hash` | — |
| `internal/analyzer` | consume → gate → llm → store | all above |
| `internal/store` | `bun` queries + migrations, sole schema owner | — |
| `internal/api` | read handlers | `auth`, `store` |
| `internal/maint` | daily pruning job | `store` |

The two packages carrying correctness and cost — `gate` and `fingerprint` — are
pure functions with no I/O, so they are table-driven tests with no fixtures.
`llm`, `queue` and `store` are interfaces, so `analyzer` is testable end-to-end
against stubs with no container running.

### 3.4 Storage: SQLite now, external database later

`internal/store` is an interface with a `sqliteStore` implementation today and a
`pgStore` implementation when an external database is required. Query code is
written once using **`uptrace/bun`**, which is dialect-aware and thin over
`database/sql`, so the SQL stays visible in review.

Alternatives rejected: `sqlc` would require two query sets to keep in sync,
which is the exact portability tax being avoided; `GORM` generates opaque SQL,
making write-path behaviour hard to verify under load; `ent` is heavyweight for
six tables.

**Portability rules the schema follows from day one** — cheap now, expensive to
retrofit:

- IDs generated in Go (ULID). Never `AUTOINCREMENT` or `SERIAL`.
- Timestamps stored as `INTEGER` unix-millis. Never native date types.
- `ON CONFLICT … DO UPDATE` only. Never `INSERT OR REPLACE`.
- JSON held as `TEXT` and parsed in Go. No `jsonb` operators, no SQLite `json1`.
- Migrations via `golang-migrate`, one dialect-agnostic SQL directory.

Concurrency differs per implementation, and the interface hides it: `sqliteStore`
runs WAL mode with `busy_timeout=5000` and a single writer goroutine owning all
writes; `pgStore` uses a normal connection pool. Callers see one interface.

## 4. Authentication

The server never stores or verifies secrets. The edge sends
`Authorization: Basic base64(system_id:secret)`, sourced from the node's
existing NethServer subscription identity (the `cluster/subscription` Redis
hash). `internal/auth` forwards the credential to an external validator, the
Traefik `forwardAuth` pattern:

```
ingest ──► $AUTH_VALIDATE_URL   (Authorization header forwarded verbatim)
       ◄── 200      → valid; tenant/org id captured if returned
       ◄── 401/403  → reject
       ◄── other/timeout → treat as unavailable (see fail-closed below)
```

Four requirements:

- **Caching is mandatory, not an optimization.** 3 req/s uncached is ~10,800
  validator calls per hour for credentials that essentially never change.
  Positive TTL ~5 min, negative TTL ~30 s to blunt credential-stuffing
  amplification.
- **Cache keys are `HMAC(pepper, system_id + ":" + secret)`.** The raw secret is
  never stored, never logged, never written to the database.
- **Fail closed.** If the validator is unreachable and there is no cache hit,
  respond `503`. Failing open on an auth path would let anyone write into
  another tenant's stream. The cost of failing closed is an ingestion gap the
  edge retries — recoverable. The cost of failing open is not.
- **Bind the identity.** The `system_id` in the request body must equal the
  authenticated `system_id`, or reject `403`. Otherwise a node holding valid
  credentials can attribute bundles to another system.

`internal/auth` therefore has no `store` dependency: an HTTP client plus a TTL
cache, stubbable in tests.

## 5. Wire protocol

`POST /v1/bundles` · `Authorization: Basic` · `Content-Encoding: gzip` ·
body cap 1 MB · → `202 Accepted`

```json
{
  "schema_version": 1,
  "system_id": "abc123",
  "collector_version": "2.0.0",
  "masking_version": 1,
  "window": { "start": 1754380800000, "end": 1754381700000 },
  "digest": [
    { "module_id": "traefik1", "priority": 3,
      "observed": 42, "expected": 3.2, "ratio": 13.1 }
  ],
  "templates": [
    { "template": "<3> [n1:traefik1:traefik] connection refused to <IP>:<NUM>",
      "count": 37, "module_id": "traefik1", "priority": 3,
      "category": "security",
      "first_seen": 1754380811000, "last_seen": 1754381690000,
      "samples": ["<3> [n1:traefik1:traefik] connection refused to 10.0.0.4:8080"] }
  ],
  "budget": {
    "max_lines": 500, "lines_seen": 4210, "lines_kept": 500,
    "truncated_modules": [ { "module_id": "traefik1", "dropped": 3200 } ]
  }
}
```

### 5.1 Template identity is the template text

There is no template hash. `system_templates` is keyed on
`(system_id, template)` and the novelty gate is an indexed lookup. Templates are
~150 bytes; 2700 systems × ~500 distinct templates ≈ 200 MB.

This is a deliberate simplification over hashing. A hash column buys nothing at
this scale and costs readability: `SELECT template FROM system_templates WHERE
system_id = ?` tells an operator what a system looks like, which a hash never
does.

`masking_version` is recorded metadata only — it computes nothing. Its purpose
is diagnostic: when a collector upgrade changes the masking rules, every
template's text changes, so every template looks novel and every fingerprint
changes, producing a one-time duplicate-insight burst across the fleet. The
recorded version makes that burst explainable rather than mysterious. See §9.3
for why this is also a thundering-herd risk.

### 5.2 Idempotency

The key is `(system_id, window.start)`. Edge retries after a 5xx are certain;
without this a retry double-counts the digest and re-raises findings. A
duplicate window returns `200 {"duplicate": true}`.

### 5.3 Drop statistics, not a boolean

`budget.truncated_modules` reports which modules lost lines and how many:

```json
{ "module_id": "traefik1", "dropped": 3200, "truncated": true }
```

The gate reads it: truncation alone is noise, but truncation *plus* deviation
means an incident is being under-sampled, which is a stronger signal than
either alone.

`truncated` is carried separately from `dropped` because the two can disagree.
`dropped` is derived from the digest, and the digest is the query that fails on
a busy cluster. When it is unavailable the collector still knows it hit the
line cap but cannot say by how much, so it reports `dropped: 0` with
`truncated: true`. Without the flag, that module would be indistinguishable
from a healthy one — read as nominal precisely when the cluster is busiest.

### 5.3.1 The host bucket

`module_id` is a stream label present only on module streams. Every host-level
journal record — `sshd`, `systemd`, `runagent` — carries no `module_id` at all.
Verified on a live cluster: `label/module_id/values` returned only
`['ldapproxy1', 'loki1', 'metrics1', 'traefik1']`, while the SSH traffic that
dominates the security signal appeared under no module at all.

Those records travel with `module_id: ""`, which the server must treat as an
ordinary module for baselines, allocation and findings. It is a real bucket,
not a missing value, and rejecting an empty `module_id` would discard the most
security-relevant stream on the node.

### 5.4 Validation before produce

Never poison the topic. Rejected with `400`, logged with `system_id`, not
retried:

- unknown `schema_version`
- `window.end - window.start` outside tolerance
- window in the future, or `window.start` older than 6 hours
- `templates` longer than 1000
- more than 2 `samples` per template
- compressed body over 1 MB, or decompressed body over 8 MB (decompression is
  bounded by `io.LimitReader`, so a zip bomb is rejected rather than buffered)

The 6-hour acceptance window is what gives the edge room to retry across
several failed cycles without the server rejecting recovered data.

### 5.5 Topics

| Topic | Key | Partitions | Retention | Purpose |
|---|---|---|---|---|
| `bundles` | `system_id` | 12 | 48 h, zstd | ingest → analyzer, per-system ordering |
| `bundles.dlq` | `system_id` | 1 | 7 d | permanently failed bundles |

Consumer group `analyzer`, manual commit **after** the store write —
at-least-once delivery, made harmless by the `(system_id, window_start)`
uniqueness constraint.

### 5.6 Read API

`GET /v1/findings?since=<unix_ms>&status=<open|stale>` — scoped to the
authenticated `system_id`. Returns findings sorted severity-descending, then
`last_seen` descending.

## 6. Data model

Six tables.

| Table | Key | Contents |
|---|---|---|
| `systems` | `system_id` PK | tenant_id, collector_version, first_seen, last_seen |
| `system_templates` | UNIQUE `(system_id, template)` | first_seen, last_seen, total_count |
| `module_baselines` | UNIQUE `(system_id, module_id, priority)` | ewma_rate, updated_at |
| `findings` | UNIQUE `(system_id, fingerprint)` | severity, title, summary, suggested_action, modules (JSON TEXT), evidence (JSON TEXT), status, occurrence_count, first_seen, last_seen, reopened_at, llm_model, prompt_version |
| `analyses` | UNIQUE `(system_id, window_start)` | window_end, gated, gate_reasons (JSON TEXT), llm_called, input_tokens, output_tokens, cost_micros, model, duration_ms, error |
| `schema_migrations` | — | `golang-migrate` state |

There is no `bundles` table. Per §10, bundles are not persisted: they live only
in the topic under 48-hour retention. `analyses` records that a window was
processed and what it cost; the digest is absorbed into `module_baselines`.

### 6.1 Why a server-side baseline exists

The edge sends `expected` from a Loki metric query that is known to fail on busy
clusters — the `max_query_series` limit, handled by graceful degradation in
`ns8-loki` commit `4b6971f`. When the edge degrades, `expected` is absent and a
deviation gate relying on it goes blind exactly when the cluster is busiest.

`module_baselines` holds a server-computed EWMA over received `observed` counts.
Edge `expected` is preferred when present; server EWMA is the fallback.

### 6.2 Finding identity

One hash, in one place, `internal/fingerprint`:

```go
// A finding's identity is the set of evidence templates it cites.
sha256("v1\x00" + system_id + "\x00" + module_id + "\x00" + category + "\x00" +
       strings.Join(sortedEvidenceTemplates, "\x1f"))
```

A variable-length set of templates needs a fixed-width dedup key, so this hash
is earned where the template hash was not.

The `v1` prefix is also earned: if the formula ever changes, every existing
finding's identity changes with it, and that must be a deliberate versioned
migration rather than a silent re-raise of every open insight on the fleet.

Identity is computed **server-side from evidence**, never from model-authored
text. An inconsistently worded restatement of a known problem therefore
collapses onto the same fingerprint.

### 6.3 Finding lifecycle

```
open ──(no recurrence for 24 h / 96 windows)──► stale
stale ──(recurrence)──► open, reopened_at stamped
```

Recurrence never inserts a row. It bumps `last_seen` and `occurrence_count`.
Consumers treat a reopen as alert-worthy and a bump as not. There is no
`acknowledged` state — the API is read-only — but the `status` column is a
string enum so one can be added without a schema change.

## 7. Analyzer pipeline

```
consume bundle
 1. INSERT analyses(system_id, window_start)   → conflict? commit offset, done
 2. read known templates + baselines → compute novel set, deviations
 3. gate(bundle, state) → Decision
 4. gated out? → record decision, commit offset, done      ← zero LLM cost
 5. build prompt (deterministic assembly, §8.2)
 6. LLM call (strict json_schema, no temperature)
 7. parse, validate, sort severity-descending
 8. per finding: fingerprint → INSERT, or bump/reopen
 9. upsert system_templates + module_baselines              ← only now
10. mark absent open findings stale
11. finalize analyses row (tokens, cost, model), commit offset
```

**Step ordering is a correctness requirement, not style.** Two constraints:

- Novelty must be read (step 2) before templates are recorded, or every
  template looks known and the gate never fires.
- Templates must be written only after a successful analysis (step 9). If the
  LLM call fails at step 6 with templates already recorded, the retry sees them
  as known, the gate declines, and the anomaly is lost permanently. Deferring
  the write makes an LLM failure a clean nack-and-retry.

## 8. Gating and inference

### 8.1 The gate

A pure function. It calls the LLM if **any** condition holds:

- a template is new for this `system_id`
- a digest ratio exceeds tolerance (default 3.0), from edge `expected` or
  server EWMA
- any template carries `category=security` (edge-assigned in the bundle; the
  server does not classify)
- a module appears in `truncated_modules` **and** deviates

Every decision records `gate_reasons` in `analyses`, so both "why did this cost
money" and "why was this not caught" are answerable from stored data.

The gate is the primary cost control, not an optimization. At 15-minute
cadence, 2700 systems calling the LLM on every bundle is ~$16,000/month on
`gpt-4o-mini` (§11). Steady-state systems must cost approximately zero.

### 8.2 Consistency of model output

Five levers:

1. `prompt_version` is a constant in code, stamped on every finding.
2. Strict `response_format: json_schema` with `strict: true`. **No
   `temperature` field** — some models reject any non-default value outright,
   as seen in `ns8-loki` commit `6ef8fd0`.
3. Deterministic prompt assembly: templates sorted by
   `(module_id, priority, template)`, digest sorted likewise. Identical input
   produces byte-identical prompts.
4. Currently-open findings are included in the prompt with an explicit
   instruction to report only new or changed conditions.
5. Identity is server-computed (§6.2), so consistency of *wording* is not
   relied upon for dedup — only consistency of *evidence*.

## 9. Error handling

### 9.1 Ingest

| Condition | Response | Edge behaviour |
|---|---|---|
| validation failure | `400` | do not retry |
| `system_id` mismatch | `403` | do not retry |
| invalid credentials | `401` | do not retry |
| validator unreachable, no cache hit | `503` | retry with backoff |
| Redpanda produce failure | `503` | retry with backoff |
| duplicate window | `200 {"duplicate": true}` | treat as success |

### 9.2 Analyzer

| Condition | Action |
|---|---|
| LLM `4xx` (bad request, schema rejection) | DLQ immediately — deterministic, retry cannot help |
| LLM `429` / `5xx` / timeout | retry with exponential backoff, max 5, then DLQ |
| response parse or schema-validation failure | retry once, then DLQ |
| store write failure | nack, redeliver |
| SQLite busy | `busy_timeout` then bounded retry |

Every DLQ message carries the failure reason and the original bundle. A
non-empty DLQ is an operational alert, not a normal state.

### 9.3 Thundering herd

Two events can make the whole fleet's templates novel at the same moment: a
fleet-wide collector upgrade that changes masking rules, and a `prompt_version`
or fingerprint-formula change. Either would put all 2700 bundles of a single
window (10,800/hour) through the gate with the novelty condition satisfied for
every one.

Three defences, all required:

- **Global LLM concurrency cap** (`LLM_MAX_CONCURRENCY`). The analyzer is one
  consumer group; excess work waits in the topic, which is what the topic is
  for.
- **Daily spend ceiling** (`LLM_DAILY_SPEND_CAP_USD`) computed from the
  `analyses` cost ledger. On breach, the gate degrades to
  security-category-only and logs loudly. Degraded is better than a surprise
  invoice, and better than silence.
- **Per-system ingest rate limit** — roughly 10 bundles/hour burst, so one
  misbehaving node cannot flood the topic.

### 9.4 Degradation summary

The system is designed so each dependency failure costs one capability, not the
run:

| Failure | Consequence |
|---|---|
| edge metric query fails | server EWMA covers the deviation gate (§6.1) |
| validator down | ingestion pauses, edge retries within the 6 h window |
| LLM provider down | bundles accumulate in the topic, analysed on recovery |
| spend cap hit | gate narrows to security only |
| Redpanda restart | s6 restarts it; ingest returns 503 meanwhile |

## 10. Data protection

Log lines now leave customer premises. The persisted surface is deliberately
minimal:

- The edge scrubs before shipping (existing `SCRUB_RULES` in
  `imageroot/bin/anomaly-detector`) and masks lines to templates.
- The server persists **only** template text, counts, digests and findings.
- Representative raw `samples` exist only in the `bundles` topic under 48-hour
  retention and are **never** copied into the database.
- Secrets (`LLM_API_KEY`, `AUTH_PEPPER`) come from the environment, are never
  written to the database, and are never logged.
- The auth cache stores credential HMACs, never secrets (§4).

## 11. Cost model

Measured input is ~12.4k tokens per call at `max_lines=500`, ~300 output tokens
blended. At 15-minute cadence that is 96 calls/day per system, 2920/month.

| Model | Per call | Per system/month | 2700 systems/month |
|---|---|---|---|
| `gpt-4o-mini` | ~$0.0020 | ~$5.96 | **~$16,100** |
| `gpt-4o` | ~$0.034 | ~$99 | ~$268,000 |

Those are ungated upper bounds. The gate (§8.1) is what makes the number real:
steady-state systems should gate out almost every bundle, and template
deduplication at the edge shrinks per-call input for exactly the noisiest
windows.

`gpt-4o-mini` is the recommended tier. The task is bounded, schema-constrained
log classification — the same complexity class already validated against free
models on OpenRouter.

The OpenRouter Batch API was evaluated and rejected: its documentation
advertises no discount versus synchronous calls, and its 24-hour completion
window is incompatible with 15-minute detection latency.

## 12. Configuration

| Variable | Purpose |
|---|---|
| `LISTEN_ADDR` | ingest + read API bind address |
| `AUTH_VALIDATE_URL` | external forward-auth endpoint |
| `AUTH_CACHE_TTL`, `AUTH_NEG_CACHE_TTL` | positive/negative cache lifetimes |
| `AUTH_PEPPER` | HMAC pepper for cache keys — secret |
| `DB_DRIVER` | `sqlite` or `postgres` |
| `DB_DSN` | connection string |
| `REDPANDA_BROKERS`, `TOPIC_BUNDLES`, `TOPIC_DLQ` | queue wiring |
| `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY` | provider — key is secret |
| `LLM_MAX_CONCURRENCY` | global inference cap |
| `LLM_DAILY_SPEND_CAP_USD` | spend ceiling, gate degrades on breach |
| `GATE_TOLERANCE` | deviation ratio threshold, default 3.0 |
| `STALE_AFTER` | finding staleness threshold, default 24 h |
| `LOG_LEVEL` | — |

`PROMPT_VERSION` is a code constant, not configuration. It must change with the
prompt, and an environment variable would let the two drift apart.

## 13. Testing

**Unit** — no I/O, table-driven:

- `gate`: every condition in isolation and in combination; absent `expected`
  falling back to EWMA; truncation with and without deviation
- `fingerprint`: stability under evidence reordering; distinctness across
  systems, modules and categories
- protocol validation: each `400` condition
- prompt assembly: golden files proving byte-identical output for identical
  input
- `auth`: cache hit/miss, negative caching, fail-closed on validator error

**Integration** — stub `llm` via `httptest`, temp-file SQLite, in-memory queue:

- gated-out bundle writes an `analyses` row and never calls the LLM
- new finding inserts; recurrence bumps `occurrence_count` without inserting
- absence past `STALE_AFTER` marks stale; later recurrence reopens with
  `reopened_at`
- LLM failure leaves templates unrecorded, so the retry still sees them as
  novel — the §7 correctness constraint, asserted directly
- duplicate `(system_id, window_start)` is idempotent

**Container** — real Redpanda via compose: post bundles with `curl`, assert
findings through the read API.

**Migration** — run `golang-migrate` against both SQLite and Postgres in CI, so
the portability rules in §3.4 are enforced by the build rather than by memory.

**Load smoke** — sustain 3 req/s for several minutes; assert no SQLite
`database is locked` errors and no consumer lag growth.

## 14. Cutover

| Phase | Edge | Server |
|---|---|---|
| 1 | unchanged, calls LLM directly | built and deployed, receiving nothing |
| 2 | `anomaly-detector` **replaced** by `insights-collector` | sole analysis path |

There is no `ANOMALY_MODE` and no dual-running phase. The edge is replaced
outright: the LLM call, prompt rendering, findings parsing, webhook and
`recall_findings()` are deleted from the node, and with them the API key.

Keeping both paths alive would mean every prompt or schema change landing in
two places — a Python edge implementation and a Go server one — which is how
they drift into two different definitions of a finding. It would also leave the
LLM API key on 2700 machines, the credential-sprawl problem in §1 that this
work exists to remove.

The cost of replacement is a window where a node ships to a server that may not
yet be reachable. That is absorbed by the collector's spool (§5.2 idempotency
plus the 6-hour acceptance window), and by the collector doing nothing at all
until `INSIGHTS_SERVER_URL` is configured.

Phase 2 depends on the edge collector spec, which is separate work. The server
is useful and testable before that spec exists, which is why it is built first.

## 15. Items to verify during planning

- **Exact field names in the `cluster/subscription` Redis hash.** The module
  reads it today (`imageroot/actions/set-clm-forwarder/10set:16`) but only tests
  truthiness, so the `system_id` / secret field names are unconfirmed. Must be
  read from a live node.
- **The external validator's contract**: endpoint, method, response codes, and
  whether it returns a tenant or organisation identifier the server can use for
  scoping.
