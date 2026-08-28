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
 edge node (ns8-loki collector)
        │  POST /v1/bundles  (HTTP Basic auth)
        ▼
 ┌───────────────────────────────────────────────────────────┐
 │                        insightsd                          │
 │                                                             │
 │  api ── auth.ForwardAuth ──► AUTH_VALIDATE_URL (external)  │
 │   │                                                         │
 │   ▼                                                         │
 │  queue (in-memory bounded channel)                         │
 │   │                                                         │
 │   ▼                                                         │
 │  analyzer ── gate ── fingerprint ── prompt ── llm ── store  │
 │                                                     (SQLite)│
 │  ui (optional, read-only, own listener)                    │
 └───────────────────────────────────────────────────────────┘
        ▲
        │  GET /v1/findings  (same auth)
 edge node / operator
```

One edge node ships one bundle per 15-minute window. The server never
initiates contact with a node.

## Package layering

```
model                       no deps; imported by everything
fingerprint  gate  prompt   PURE — no I/O, no clock beyond an injected now()
llm  store                  interfaces, each with a real and a stub impl
analyzer                    the pipeline; depends on all of the above
api                         HTTP: ingest + read, auth via the Authenticator iface
ui                          HTTP: optional operator dashboard, off by default
cmd/insightsd                env config, wiring, graceful shutdown
```

This is a strict DAG — nothing lower in the list imports anything above it,
and `ui` does not import `api` or `analyzer`.

| Package | Responsibility |
|---|---|
| `internal/model` | Wire types (`Bundle`, `Finding`, `Template`, …) and the pure helpers (`SortFindings`, `SeverityRank`) that operate on them. |
| `internal/gate` | `gate.Evaluate` — decides whether a bundle is worth an LLM call. Pure function of `(Bundle, SystemState, tolerance)`. |
| `internal/fingerprint` | `fingerprint.Compute` — the server-computed identity of a finding. Pure, sha256-based. |
| `internal/prompt` | Renders the deterministic LLM prompt from a bundle, and parses/validates the strict-JSON response. Owns `prompt.Version`. |
| `internal/llm` | `llm.Client` interface; `openai.go` is the real OpenAI-compatible implementation, `stub.go` a test double. |
| `internal/store` | `store.Store` interface; `SQLiteStore` is the only implementation today. `store/ui.go` adds the cross-system, read-only queries the operator UI needs. |
| `internal/analyzer` | `Analyzer.Process` — the pipeline that ties gate, fingerprint, prompt, llm and store together for one bundle. |
| `internal/queue` | In-memory bounded channel decoupling ingest from analysis, plus in-flight dedup so a resend never starts a second LLM call for the same window. |
| `internal/auth` | `ForwardAuth` — forwards `Authorization: Basic` to an external validator, with a pepper-hashed TTL cache and fail-closed behaviour. |
| `internal/api` | HTTP handlers for `POST /v1/bundles`, `GET /v1/findings`, `/healthz`. |
| `internal/ui` | Optional, read-only, zero-JavaScript operator dashboard on its own listener. |
| `cmd/insightsd` | Reads environment config, wires every package together, runs graceful shutdown. |

The purity of `gate`, `fingerprint` and `prompt` is deliberate: they hold all
the correctness and all the cost logic, and are table-driven-testable with no
fixtures, no clock, no I/O. `llm` and `store` being interfaces is what lets
`analyzer_test.go` run the whole pipeline end to end with nothing running.

## Request flow

### Ingest: `POST /v1/bundles`

1. `api.handleBundles` authenticates via the injected `Authenticator`
   (`auth.ForwardAuth` in production, `api.StaticAuth` in tests).
2. The body is decoded (gzip-aware, size-capped at 8 MiB) into a
   `model.Bundle` and validated: schema version, `system_id` matches the
   authenticated identity, a sane window, a template-count ceiling.
3. The bundle is handed to `queue.Publish`, which either enqueues it or
   returns `queue.ErrFull`.
4. The handler answers **immediately** — `202 Accepted` on success, `503` if
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
   anything.
4. **Gate** (`gate.Evaluate`) using that prior state.
5. If the gate declines: **record** bookkeeping (templates, baselines, stale
   sweep, the `analyses` ledger row) and return. No LLM call, no cost.
6. If the gate fires: render the prompt (`prompt.Render`, including
   currently-open findings so the model doesn't re-report them), call the
   LLM.
   - A **transient** failure (`RecordAttemptError`) leaves the window
     claimable for retry.
   - A **permanent** failure (`llm.HTTPError.Permanent()`, or a schema/parse
     failure) finalizes and closes the window — retrying would hit the same
     wall forever.
7. Parse the strict-JSON response (`prompt.Parse`), resolve each finding's
   cited template IDs back to real templates (`prompt.ResolveEvidence`) —
   this is the *only* path from model output to stored data, and it is what
   keeps model-authored prose out of the fingerprint.
8. Compute the fingerprint (`fingerprint.Compute`) and `UpsertFinding` —
   insert, bump the occurrence count, or reopen a stale finding.
9. **Record** bookkeeping now that the whole analysis succeeded — this is the
   only path that writes templates/baselines after an LLM call, and it is
   what makes a failed call retry-safe: nothing looks "known" that wasn't
   actually processed.

### Read: `GET /v1/findings`

Authenticates the same way as ingest, then `store.ListFindings` returns that
system's findings (optionally filtered by `since`/`status`), sorted by
`model.SortFindings` — severity descending, then most-recently-seen first.

### Operator UI

`internal/ui` is a second, independent HTTP server on its own listener
(`UI_LISTEN_ADDR`, off by default). It depends only on `model` and `store`
(through a local `Reader` interface) plus a local `Runtime` interface
(`Depth`/`Cap`, satisfied by `*queue.Queue`) for live process state. It never
imports `api` or `analyzer`, and it never writes. See `README.md` §
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
| `system_templates` | Every masked log-line template ever seen for a system — the gate's "is this new" memory. |
| `module_baselines` | Per-`(system_id, module_id, priority)` EWMA rate — the gate's deviation fallback when a bundle carries no `expected`. |
| `analyses` | One row per `(system_id, window_start)` — the cost/decision ledger: gated or not, `gate_reasons`, tokens, cost, duration, error. Unique on that key for idempotency; `completed` distinguishes a claimable retry from a finished window. |
| `findings` | One row per `(system_id, fingerprint)` — unique so a repeat detection bumps the same row instead of inserting a duplicate. |

Schema portability rules (SQLite today, Postgres later — see `CLAUDE.md` §
Invariants) apply to every table: ULIDs generated in Go rather than
autoincrement primary keys, unix-millis integers rather than native date
types, `ON CONFLICT … DO UPDATE` rather than `INSERT OR REPLACE`, JSON stored
as `TEXT` and parsed in Go.

Raw `samples` from the bundle are **never** persisted — the DB and the UI can
only ever show masked templates.

## Finding identity: the fingerprint

`fingerprint.Compute(systemID, modules, evidence, category)` hashes
length-prefixed, sorted, deduplicated fields with sha256 and a version
prefix. A `strings.Join` is deliberately avoided — an unprefixed separator is
forgeable (`"ab"+"c"` could collide with `"a"+"bc"`).

The critical invariant: **no model-authored string ever reaches the
fingerprint**. The LLM cites templates by identifier only (`T1`, `T2`, …,
assigned by `prompt.TemplateID` in the exact order `prompt.SortedTemplates`
renders them); `prompt.ResolveEvidence` maps those IDs back to the server's
own template records, and the server derives the evidence text, module set
and category from that — never from the model's prose. This is what makes
the same recurring problem collapse onto the same finding even when the model
words its restatement differently each time.

Changing the fingerprint formula changes every existing finding's identity
fleet-wide — that must be a deliberate versioned migration (bump the
`fingerprint.Version` prefix), never a silent behavior change.

## Cost control: the gate

`gate.Evaluate` is the only thing standing between this design and the ~$16k/
month it would cost to send every window to an LLM (`gpt-4o-mini` pricing).
It fires (returns `Call: true`) if any of:

- a template is new for this system (never seen before in `system_templates`);
- a digest entry's observed/expected ratio exceeds `GATE_TOLERANCE` — using
  the edge-supplied `expected` if present, otherwise the server's own EWMA
  baseline;
- any template in the bundle carries `category=security` (assigned by the
  edge, never computed server-side);
- a module is both truncated (the edge dropped lines to stay under its line
  budget) **and** deviating — truncation alone never fires.

**A bundle is sent to the LLM if and only if `gate.Evaluate` returns
`Call: true`** — i.e. at least one condition above holds. Otherwise the
window is *gated out*: `analyzer.Process` step 5 records it and returns
without ever calling `llm.Client.Complete`.

Every window — gated out or sent to the LLM — gets exactly one row in the
`analyses` table (`store.Analysis`), with `gated` (bool) and `gate_reasons`
(the sorted reason list) always populated, and `llm_called`/`input_tokens`/
`output_tokens`/`cost_micros` populated only when the LLM was actually
called. This row is where a gated analysis "lives" — there is no separate
gated-vs-analyzed table, only this one flag. So both "why did this cost
money" and "why was this potentially missed" are answerable from stored data
alone — see the `/gate` and `/analyses` routes in the operator UI.

## Determinism

Identical bundle input must produce byte-identical prompts and stable gate
reasons, because the whole cost/identity model depends on it:

- `prompt.SortedTemplates` sorts `(module_id, priority, template)`.
- Digest entries are sorted `(module_id, priority)` in both `gate.Evaluate`
  and `prompt.Render`.
- Gate reasons are appended in a fixed, sorted order (security first, then
  new-templates, then deviation, then truncated+deviating).
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
edge that won't resend them, so they must still be processed before exit.

## Testing strategy

See `CLAUDE.md` § "Testing expectations" for the specifics per package. The
short version: `gate`/`fingerprint`/`prompt` are pure and table/golden-file
tested with no fixtures; `analyzer` runs the real pipeline against a stub LLM
and a temp-file SQLite store, and its tests are what encode the step-order
invariants above as executable checks rather than just comments.
