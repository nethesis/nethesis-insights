# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`nethesis-insights` is a central log-anomaly analysis server for NethServer fleets
(~2700 nodes). Edge nodes ship deduplicated, masked log bundles every 15 minutes;
the server gates each bundle against novelty and deviation, calls an LLM **only**
when the gate fires, and stores findings keyed by a server-computed fingerprint so
the same problem is never re-raised.

## Design documents (authoritative)

Both live in this repository:

- Spec: `docs/specs/2026-08-05-nethesis-insights-design.md`
- Plan: `docs/plans/2026-08-05-nethesis-insights.md` (Tasks 1–10)

Two more docs describe the system as it stands today, not just why it was
designed this way, and **must be kept up to date as part of every change that
affects what they describe** — package boundaries, the analyzer's step order,
the wire protocol, storage schema, the gate/fingerprint formulas, or the
operator UI's pages:

- `docs/architecture.md` — package layout, request flow, storage, and the
  correctness invariants, for engineers working on the code.
- `docs/user-guide.md` — plain-language explanation of the system for anyone
  who isn't reading Go: what a finding/analysis/template/baseline is, and how
  to use the operator UI.

Read the spec before changing gating, fingerprinting, the wire protocol, or the analyzer's step
order — those sections explain *why* each rule exists, and the reasons are not
reconstructible from the code.

A related, separate feature also lives here and is **implemented**:
`docs/specs/2026-07-28-threat-shield-design.md` (rules),
`docs/plans/2026-08-07-threat-shield-server.md` (this repo's flavour) and
`docs/specs/2026-08-07-threat-events-ingest-contract.md` (the wire contract
`ns8-crowdsec` builds against — keep it in step with
`internal/threat/sanitize.go`'s drop rules). Server-side fleet-wide CrowdSec ban sharing:
`POST /v1/threat-events` in, `GET /v1/blocklist` out. It is **not** part of the
ingest/gate/LLM pipeline above and changes no rule in this section — no LLM call, no
gate, no fingerprint, no queue. Treat it as a distinct pipeline sharing only the
listener, the `Authenticator` and the SQLite file; do not use it as context for changes
to bundles, gating or findings, and do not conflate the two when editing either.

Threat Shield rules that are as load-bearing as the gate's:

- `internal/threat` is **pure**, like `gate`/`fingerprint`/`prompt`, for a sharper
  reason: it decides whether a third party's IP address is stored and published, so a
  bug there is a data-protection incident. Non-public addresses are dropped **at
  ingest**, never merely at read.
- **Local-origin only.** `origin` must be `crowdsec` or `cscli`. Re-reporting CrowdSec's
  CAPI/community list would manufacture agreement between systems that never
  independently observed anything, and consensus over manufactured agreement is
  worthless (spec §7.2).
- **Every CrowdSec scenario is accepted — never add an allowlist.** There is no
  category map and no known-scenario list; the design's D3 category set was removed
  during implementation. The hub grows continuously and nodes run third-party and local
  collections, so a fixed set silently discards real evidence until someone notices.
  The scenario is trimmed, stripped of control characters and capped at
  `threat.MaxScenarioLen`, then stored verbatim and used as the grouping key.
- **Distinct systems, not row count.** Promotion counts `COUNT(DISTINCT system_id)`;
  candidates are therefore grouped down to `system_id` in SQL and folded in Go, because
  per-scenario counts do not sum and `ARRAY_AGG`/`GROUP_CONCAT` are not portable.
  Promotion never depends on scenario agreement, which is why accepting an unfamiliar
  scenario cannot weaken the rule.
- **Allowlist and fleet egress are applied at promotion, not at read**, so adding an
  entry unlists an address on the next pass instead of hiding it. A malformed allowlist
  row aborts the pass rather than being skipped — skipping fails open.
- **Roll up before pruning.** `RollupThreatDailyStats` must precede
  `PruneThreatEvents`, or the dropped day loses its history permanently.
- **Never serve blank.** `GET /v1/blocklist` answers 503 before the first successful
  pass, and a failed pass keeps serving the previous snapshot with its original
  `generated_at`. An empty body means "no threats" to every client that imports it.
- **The reporter's source IP comes from `RemoteAddr`, never `X-Forwarded-For`.** It
  feeds the egress exclusion set and the header is client-controlled. Consequence:
  behind a reverse proxy the exclusion records the proxy and stops being useful.
- `threat_allowlist` has **no HTTP surface** — this server has no admin auth plane.
  `store.UpsertThreatAllowlistEntry` / `DeleteThreatAllowlistEntry` are the supported
  out-of-band seam.

`docs/runbooks/dev-machine-rl1.md` rebuilds the dev machine (see "Dev machine" below) from
scratch when it has been torn down — start there instead of re-deriving the NS8 cluster
setup from memory.

## Current state: prototype, not the designed system

The prototype does a full round trip — authenticated ingest → queue → gate →
LLM → fingerprint → read API — but takes deliberate shortcuts. Know which parts
of the spec are **not** built before assuming a bug:

| Area | Prototype (built) | Design (Task 11+) |
|---|---|---|
| Ingest → analysis | asynchronous: `internal/queue`, an in-memory bounded channel — this is the permanent design | same |
| Auth | `internal/auth.ForwardAuth`: forward-auth to `AUTH_VALIDATE_URL` (default `https://my.nethesis.it/auth`), TTL cache keyed on `HMAC(pepper, cred)`, fail-closed 503 — this is the permanent design; `api.StaticAuth` still exists for tests only | same |
| Schema | `CREATE TABLE IF NOT EXISTS` in `store.Init` | `golang-migrate`, one dialect-agnostic SQL dir, dual-dialect CI test |
| Backends | SQLite only | `Store` iface already in place; `pgStore` added later |
| Cost control | `gate` only | `internal/budget`: `LLM_MAX_CONCURRENCY`, `LLM_DAILY_SPEND_CAP_USD` (`gate.SystemState.SecurityOnly` is the degrade hook, currently never set) |
| Missing packages | — | `ingest` (rate limit, full §5.4 validation), `budget`, `maint`, `version` |
| Missing tooling | — | `Makefile`, `.golangci.yml`, `.github/workflows/ci.yml` |
| Operator UI | `internal/ui`: read-only, zero-JavaScript dashboard on its own listener, off unless `UI_LISTEN_ADDR` is set — unauthenticated and fleet-wide, so bind it to loopback (a wider bind warns, never refuses). Backed by the cross-system read methods in `internal/store/ui.go` and `internal/store/threat_ui.go` | same; the spec's §2 non-goal covers a *consumer* dashboard, not this |
| Threat Shield | built: `internal/threat` (pure), `internal/store/threat.go`, `internal/blocklist`, `internal/api/threat.go`, three UI pages. Single-instance only — the consensus pass takes no distributed lock | multi-instance locking; cross-org promotion (D5) once auth returns a tenant |

The prototype's `internal/api` currently carries both ingest and read handlers;
the design splits ingest into `internal/ingest`.

`internal/queue`'s in-memory bounded channel is the permanent queue design, not
a placeholder. The traded risk — a crash drops whatever is buffered, bounded by
`QUEUE_SIZE` — is accepted and documented in spec §3.1/§3.2/§9.4.

## Commands

```bash
go build ./...
go vet ./...
go test ./... -race -count=1

go test ./internal/gate/ -run TestSecurityAlwaysCalls -v   # single package / single test
```

Once Task 1's tooling lands, prefer `make check` (license headers + lint + tests),
`make test`, `make build`. Lint is `golangci-lint run` with `bodyclose`,
`sqlclosecheck`, `rowserrcheck` and `gosec` enabled — HTTP bodies and DB rows are
where the real leaks are in this codebase.

Manual round trip against a real model (README has the full OpenRouter/NVIDIA
free-tier walkthrough):

```bash
LLM_BASE_URL=https://openrouter.ai/api/v1 LLM_MODEL=nvidia/nemotron-3-ultra-550b-a55b:free \
LLM_API_KEY=<an OpenRouter API key> \
DB_PATH=/tmp/insights.db \
  go run ./cmd/insightsd
curl -u <system_id>:<auth_token> -X POST localhost:9595/v1/bundles -d @bundle.json
curl -u <system_id>:<auth_token> 'localhost:9595/v1/findings?since=0'
```

`system_id`/`auth_token` must be a credential the configured `AUTH_VALIDATE_URL`
(default `https://my.nethesis.it/auth`) accepts — a real NethServer subscription
pair, or point `AUTH_VALIDATE_URL` at a private validator for isolated testing.

`scripts/insights-api.sh` wraps the same calls (`health`, `findings`, `open`,
`post <bundle.json>`, `raw <path>`); it defaults to `http://localhost:9595`.

To inspect what the server stored, add `UI_LISTEN_ADDR=127.0.0.1:9596` and open
the operator UI — findings, the cost ledger with its `gate_reasons`, the gate
rollup, templates and baselines, plus queue depth and effective config. It
replaces the old `scripts/insights-sql.sh`, which needed `sqlite3`, root on the
node and the podman volume path (it is still in git history if the deleted
`sql "SELECT …"` escape hatch is ever needed offline).

Environment variables are documented in `README.md` — do not duplicate that table
here.

## Architecture

### Package layering

```
model                       no deps; imported by everything
fingerprint  gate  prompt   PURE — no I/O, no clock beyond an injected now()
threat                      PURE — Threat Shield's sanitizer, category map, allowlist
llm  store                  interfaces, each with a real and a stub impl
analyzer                    the bundle pipeline; depends on all of the above
blocklist                   Threat Shield consensus + the served snapshot
api                         HTTP: ingest + read, auth via the Authenticator iface
ui                          HTTP: optional operator dashboard, off by default
cmd/insightsd               env config, wiring, graceful shutdown
```

`ui` sits beside `api`, not under it: it depends on `store` + `model` only, and
never on `api`, `analyzer` or `queue`. Live process state reaches it through a
local `Runtime` interface (`Depth`/`Cap`, which `*queue.Queue` satisfies) and the
store through a local `Reader` interface, so the package stays testable with a
fake and the layering stays a DAG. It deliberately copies `api`'s ~30-line
logging handler rather than importing it.

The purity of `gate`, `fingerprint` and `prompt` is the point: they hold all the
correctness and all the cost logic, and they are table-driven-testable with no
fixtures. `llm` and `store` being interfaces is what lets `analyzer_test.go` run
the whole pipeline end to end with nothing running.

### The analyzer's step order is a correctness requirement

`analyzer.Process` (see `internal/analyzer/analyzer.go`) follows a fixed order and
two of the steps must not move:

1. **Read prior state before writing any.** `KnownTemplates` must be read before
   `UpsertTemplates`, or every template looks known and the gate never fires.
2. **Record templates only after a fully successful analysis.** `record()` is the
   sole caller of `UpsertTemplates`/`UpsertBaselines`, and it runs only on a
   gated-out bundle or after the LLM call succeeded. If templates were written
   before a failed call, the retry would see them as known, the gate would
   decline, and the anomaly would be lost permanently. There is a test asserting
   exactly this.

Related: on a **transient** LLM error the code calls `RecordAttemptError`, which
deliberately leaves the window *claimable* — otherwise the edge's retry is
rejected as a duplicate and the window is lost. On a **permanent** error
(`llm.HTTPError.Permanent()`) it finalizes the row and closes the window.

### Finding identity is server-computed

`fingerprint.Compute(systemID, modules, evidence, category)` — sha256 over
length-prefixed fields, sorted/deduped lists, `"v1"` prefix. Never a `strings.Join`
(a separator is forgeable). Consequences to preserve:

- The LLM cites templates by **ID** (`T1`, `T2`, … from `prompt.TemplateID`); the
  server resolves them via `prompt.ResolveEvidence` and derives evidence text,
  module set and category itself. **No model-authored string ever reaches the
  fingerprint** — an inconsistently worded restatement collapses onto the same
  finding.
- Changing the formula changes every existing finding's identity fleet-wide. That
  is a deliberate versioned migration (bump the `v1` prefix), never a silent
  re-raise.

### Gate = the cost control, not an optimization

`gate.Evaluate` fires the LLM if any of: a template is new for this system; a
digest ratio exceeds `GATE_TOLERANCE` (edge `expected` preferred, server EWMA
baseline as fallback); any template carries `category=security`; or a module is
both truncated **and** deviating. Every decision writes `gate_reasons` into the
`analyses` row, so "why did this cost money" and "why was this missed" are both
answerable from stored data. Ungated, the fleet is ~$16k/month on `gpt-4o-mini`.

The server never classifies — `category=security` is assigned by the edge and
propagated.

### `module_id: ""` is a real bucket

Host-level journal records (`sshd`, `systemd`, `runagent`) carry no `module_id`.
Verified on a live cluster: that stream dominates the security signal. Treat the
empty string as an ordinary module for baselines, gating and findings; never
reject or skip it.

## Invariants

These come from the spec's Global Constraints. CI enforces some; the rest are on
you.

**License header on every source file**, above the `package` clause, blank line
after:

```go
// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later
```

`#`-comment form for SQL, YAML, Makefile and shell; `<!-- … -->` for HTML
templates; `/* … */` for CSS. In `internal/ui/templates/layout.html` the header
sits outside any `{{define}}` block, so it is emitted into the served page
source — that is correct and intended for GPL.

**Vendored third-party files are exempt and must stay exempt.** Anything under
`internal/ui/static/` that is not ours — today `pico.min.css` and `pico.LICENSE`
(Pico CSS v2.1.1, MIT) — keeps its own upstream copyright and permission notice
byte-for-byte and must **never** receive the Nethesis GPL header: we did not
write them, and MIT requires the original notice ship intact. MIT is
GPL-3.0-compatible, so combining is fine; misattributing is not.

`scripts/check-license-headers.sh` fails the build on any miss (Task 1, still
unwritten) and must therefore learn both the two new comment forms and this
vendored-file exemption.

**Schema portability** — SQLite today, Postgres later, so from day one:

- IDs generated in Go as ULID. Never `AUTOINCREMENT` / `SERIAL`.
- Timestamps as `INTEGER` unix-millis. Never native date types.
- `ON CONFLICT … DO UPDATE` only. Never `INSERT OR REPLACE`.
- JSON as `TEXT`, parsed in Go. No `jsonb`, no SQLite `json1`.

**SQLite runtime**: WAL, `busy_timeout=5000`, `SetMaxOpenConns(1)` plus a mutex
serializing writes (the spec says "single writer goroutine"; a mutex gives the same
guarantee with no lifecycle to leak).

**LLM calls**: strict `response_format: json_schema` with `strict: true`, and
**never send a `temperature` field** — some providers reject any non-default value
outright. `prompt.Version` is a code constant, never configuration, so it cannot
drift from the prompt it stamps.

**Secrets and data protection**: `LLM_API_KEY` / `AUTH_PEPPER` come from the
environment only, are never written to the DB and never logged (the request logger
must never touch the `Authorization` header). Raw `samples` live only in the
bundle in flight and are **never** persisted.

**Determinism**: identical bundle input must produce byte-identical prompts.
Templates sorted `(module_id, priority, template)`, digest sorted
`(module_id, priority)`. Gate reasons are sorted for the same reason.

**Findings ordering**: severity-descending (`critical > high > medium > low`), then
`last_seen` descending — `model.SortFindings`.

**Idempotency**: `(system_id, window_start)` is the key. A duplicate window is a
successful no-op, not an error.

## Testing expectations

- `gate` and `fingerprint`: table-driven, every condition alone and in
  combination; absent `expected` falling back to EWMA; truncation with and without
  deviation; fingerprint stability under evidence reordering and distinctness
  across systems/modules/categories.
- `prompt`: golden files proving byte-identical output for identical input.
- `analyzer`: stub `llm`, temp-file SQLite. The load-bearing cases are — gated-out
  bundle writes an `analyses` row and never calls the LLM; recurrence bumps
  `occurrence_count` without inserting; absence past `STALE_AFTER` marks stale and
  later recurrence reopens with `reopened_at`; an LLM failure leaves templates
  unrecorded so the retry still sees them as novel.
- `threat`: the deepest table in the repo, because a bug here is a data-protection
  incident — every IP class (RFC1918, CGNAT, IMDS, multicast, IPv6 ULA, loopback,
  unspecified, benchmark, IPv4-mapped, the reporter's own address), documentation
  ranges *kept*, CAPI-origin rejection, non-`ban`/non-`Ip`, unparseable and future
  timestamps, the metadata allowlist, in-batch duplicate collapse, and the cap
  truncating rather than rejecting. Plus `TestSanitizeAcceptsEveryScenario`, which
  is the executable form of "never add a scenario allowlist".
- `blocklist`: temp-file SQLite, not a mock — the grouping *is* the SQL. Boundary
  fixtures: 2 distinct systems does not promote and 3 does; one system reporting
  three times does not; one system across two categories is still one system;
  allowlisted and fleet-egress addresses never promote; `expires_at` refreshes while
  `first_listed_at` holds; a failed pass keeps the previous snapshot.

## Conventions

- [Conventional Commits](https://www.conventionalcommits.org/) for every commit.
- **Never put an issue reference in an individual commit message.** Issue refs go
  in the merge/squash commit body only.
- Work on a branch, never commit directly to `main`. Stage explicit paths, not
  `git add .`.
- GPL-3.0-or-later, matching `ns8-loki`.

## Dev machine

The plan runs all work on `root@rl1.leader.default.gs.nethserver.net` (Rocky 9),
under `/root/nethesis-insights`, because the operator has a local bandwidth limit
and this project pulls a Go module cache plus a Postgres image.
`rl1` is a **shared live NS8 cluster** — other modules (`nethvoice2`, `crowdsec1`,
`samba2`, `metrics1`, `traefik1`) run on it. Never restart another module's
services; bind containers to high ports. If the machine has been torn down,
`docs/runbooks/dev-machine-rl1.md` rebuilds it end to end.

## Open questions from the spec

- Exact field names in the NS8 `cluster/subscription` Redis hash (the edge's
  `system_id` / secret source) — must be read from a live node.
- The external validator's contract: endpoint, method, response codes, and whether
  it returns a tenant/org id the server can scope on.
