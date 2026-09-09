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
`POST /blocklist/v1/events` in, `GET /blocklist/v1/feed` out. It is **not** part of the
ingest/gate/LLM pipeline above and changes no rule in this section — no LLM call, no
gate, no fingerprint. Treat it as a distinct pipeline — its own binary,
`threatd`, with its own SQLite file — sharing only Traefik, the `authd` forward-auth
cache and the SQLite runtime settings (`internal/platform/sqlitex`); do not use it as
context for changes to bundles, gating or findings, and do not conflate the two when
editing either.

`threatd` does have an ingest queue (`internal/platform/ingestq`, distinct from the
log pipeline's `internal/queue`), but not for the log pipeline's reason: there is no
LLM call here to keep off the request goroutine. `POST /v1/events` sanitizes
synchronously and then queues the write, bounding how many decoded, sanitized
reports can be waiting on the single-writer database at once — the queue exists to
bound concurrency against that single writer, not to hide latency. See "Ingest is
bounded, not serialized" below.

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
- **The allowlist is applied at promotion, not at read**, so adding an entry unlists
  an address on the next pass instead of hiding it. A malformed allowlist row aborts
  the pass rather than being skipped — skipping fails open. (Fleet egress — an
  earlier, automatic promotion exclusion keyed on each reporter's observed source
  address — was removed as too complex and too easy to get wrong for what it bought;
  the allowlist is now the only promotion exclusion.)
- **Roll up before pruning.** `RollupThreatDailyStats` must precede
  `PruneThreatEvents`, or the dropped day loses its history permanently.
- **Ingest is bounded, not serialized.** The database already has exactly one
  writer — `SetMaxOpenConns(1)` plus the store's write mutex, and
  `InsertThreatEvents` already wraps a whole report in one transaction with
  `ON CONFLICT … DO NOTHING` — so `internal/platform/ingestq` in front of
  `POST /v1/events` does not introduce single-writer semantics; those hold
  regardless. What it adds is a bound: without it, a burst of reporters
  produces one blocked goroutine per in-flight request, each holding a
  decoded, sanitized report, all queued on the mutex with no limit and no way
  to shed load. `threat.Sanitize` still runs synchronously in the handler —
  so the `202`'s `dropped` counters stay accurate and the queue only ever
  holds clean events — and only the `InsertThreatEvents`/`RecordIngestCounters`
  write (`api/threat.NewConsumer`) moves behind `Publish`. Past capacity,
  `Publish` returns `ErrFull` and the handler answers `503` for the reporter to
  retry, instead of the process growing until it dies. `stored` and
  `duplicates` are consequently gone from the `202` body — they are
  post-write facts and cannot survive an asynchronous ingest — leaving
  `accepted` and `dropped`. A batch dropped from the queue on a crash needs no
  compensation: `(system_id, attacker_ip, scenario, observed_at)` is unique,
  so the reporter's next-cycle redelivery is a no-op. This is a different
  queue type from the log pipeline's `internal/queue` — no window claim, no
  idempotency logic, because threat events don't need it and rewriting
  working code for symmetry buys nothing.
- **Never serve blank.** `GET /blocklist/v1/feed` answers 503 before the first successful
  pass, and a failed pass keeps serving the previous snapshot with its original
  `generated_at`. An empty body means "no threats" to every client that imports it.
- **`X-Forwarded-For` is trusted, but only from a configured proxy address.** This
  reverses the prototype's rule. Traefik now sits in front of every pipeline, so
  `RemoteAddr` is always the proxy — which made `threat.Sanitize`'s
  reporter-own-address check (a decision naming the reporter's own address is
  dropped as a misconfiguration) permanently dead: the address it compared against
  was never the reporter's, it was Traefik's. The header is client-controlled, so it
  is believed only when `RemoteAddr` is inside `TRUSTED_PROXY_CIDRS`, and then only
  its rightmost value. In the deployed shape all five containers share one podman
  pod and therefore one network namespace, so Traefik's connection to a backend is a
  genuine loopback connection with no NAT in the path — `RemoteAddr` really is
  `127.0.0.1` by construction, not merely by convention, which is what makes the
  default `TRUSTED_PROXY_CIDRS=127.0.0.0/8` correct without a per-deployment value.
- **Nothing is ever allowlisted automatically.** A client request
  (`POST /blocklist/v1/allowlist-requests`) is a ranked review queue entry and nothing else; only
  an explicit admin approval creates an entry. Never add a consensus threshold that
  promotes one. A wrong blocklist entry blocks a legitimate address loudly and expires;
  a wrong allowlist entry exempts an attacker silently and permanently, so the two
  consensus rules are not symmetric however much they look it.
- **The separate admin plane is gone.** `internal/admin`, `ADMIN_LISTEN_ADDR` and
  `X-Admin-Actor` no longer exist. The operator UI's write routes are now the only
  writer, and they exist only when `ADMIN_API_KEY` is set — never a default key.
  Every write authenticates against that key (HTTP Basic; the username is the actor)
  and is recorded in an append-only audit table — which exists because `DELETE`
  destroys the row that would hold the trail — readable on threatd's `/audit` page.
  The actor is not a security control, since anyone holding the key can claim any
  name; say so wherever it is documented.
- **The operator UI's GET-only rule is now GET-plus-an-enumerated-POST-list.** Every
  write route authenticates against `ADMIN_API_KEY` (Basic; the username is the actor)
  and refuses cross-site requests — a browser replays cached Basic credentials
  automatically, so without that check any page could exempt an attacker's address.
  Keep the enumeration in `writableRoutes`, next to the central check. Traefik also
  BasicAuths every operator UI request, using the same `ADMIN_API_KEY` value as the
  htpasswd password. That layer is **additive, not a replacement**: `ADMIN_API_KEY`
  and the cross-site check stay in the app, because Traefik BasicAuth is still Basic
  auth, and a browser replays it on a forged cross-site POST exactly as it would
  replay credentials cached against the app directly.
- **Allowlist prefixes wider than `/24` (v4) or `/48` (v6) need an explicit `force`.**
  `0.0.0.0/0` on the allowlist silently disables the whole feed.
- **Every endpoint must appear in `docs/api/openapi.yaml`**, whose schemas mirror
  `internal/model` field-for-field. `docs/api/openapi_test.go` fails the build on a
  missing or stale path. The operator UI is deliberately not documented there.

A **third** separate pipeline also lives here and is **implemented server-side**:
`docs/plans/2026-09-02-fleet-sizing-server.md` (the *why*, including everything
the source draft got wrong) and
`docs/specs/2026-09-02-sizing-ingest-contract.md` (the wire contract `ns8-core`
builds against — keep it in step with `internal/sizing/sanitize.go`'s drop
rules). NS8 cluster leaders post one complete-UTC-day workload and performance
report per cluster; the server scores each node, folds a multi-day verdict, and
publishes cohort hardware baselines. `POST /sizing/v1/reports` in, three operator
UI pages out. It is its own binary, `sizingd`, with its own SQLite file, sharing
only Traefik, the `authd` forward-auth cache, the SQLite runtime settings
(`internal/platform/sqlitex`) and `model.ModuleFamily` — deliberately, because
that is already the single definition of module identity and a second one
would eventually disagree. **No LLM call, no gate, no fingerprint, no queue.**
Do not use it as context for changes to bundles, gating or findings.

Fleet-sizing rules that are as load-bearing as the gate's:

- `internal/sizing` is **pure**, for both of the reasons `threat` and `gate`
  are: it decides what a report is allowed to store (per-customer commercial
  data, derived from metrics that carry identifying labels) *and* it holds the
  whole `pressure` formula. It imports `threat.CleanText` rather than declaring
  a second free-text sanitizer; that is the only edge between the two pure
  packages.
- **`pressure` is computed server-side only.** Scoring at the edge would make
  every node an uncoordinated second implementation of the formula, and then a
  threshold recalibration would need the fleet's cooperation instead of one
  recompute pass.
- **Workload metrics are an open `string → number` map, and "number" is the
  entire privacy control.** Open vocabulary for the same reason Threat Shield
  accepts every scenario — the NS8 module set grows continuously, and a typed
  column per product silently discards every new product's metric until a
  server release. Numbers-only because an FQDN, an IP address, a hostname or a
  DMI serial cannot be encoded in a float, which is stronger than any field
  blocklist somebody has to maintain. Caps bound *shape*, never vocabulary, and
  truncate rather than reject. **Never add a metric allowlist or a family
  allowlist.**
- **A day is an absolute fact.** `day` is sent explicitly and every value in it
  is computed over `[day 00:00 UTC, day+1 00:00 UTC)`, never a relative
  `[24h]`. That is what makes the reporter's three daily sends byte-identical
  restatements, so measurement rows **recompute** and redelivery is free. A
  `day` outside `[today-15, today-1]` is rejected. `sizing_ingest_daily` is the
  one sizing table that **accumulates**; the DDL comments say which is which,
  because mixing them would be silent.
- **Absent is not zero.** Every measurement column is nullable and `NULL` means
  "not measured"; a zero says "measured, and fine". A missing input makes its
  penalty term absent, and the coverage gate (`metrics_present`,
  `sample_coverage < 0.80`, `cpu_cores < 1`, `mem_total_bytes <= 0`) yields
  `pressure = NULL` rather than a clamp — a node off for eighteen hours is not
  a low-pressure node, and a score from missing data is worse than no score.
- **Never a 24-hour max; a duration or a high percentile.** A max of a 5-minute
  average cannot tell a 25-minute nightly backup (1.7 % of the day) from a node
  starved for seven hours (30 %). This is the same failure the log gate suffered
  and was fixed for.
- **Pressure reasons carry no computed values**, exactly like gate reasons, and
  any rollup over them must be time-bounded for the same reason.
- **`pressure_version` is recomputed, unlike `fingerprint.Version`**, and the
  divergence is deliberate: a fingerprint is an identity and must change
  visibly, while `pressure` is a derived analytic over inputs stored as
  first-class columns — leaving 100 days of mixed-definition scores would make
  every trailing verdict wrong and every cohort statistic incomparable. Step 1
  of the pass recomputes stale rows, and it must run **before** cohorts are
  built.
- **Censoring, not health, is the only exclusion from demand estimation.** An
  undersized node's memory demand is capped by the memory it has, which is
  systematic bias rather than noise; such nodes are excluded from the
  percentiles and **published as `censored_nodes`**. Do not exclude disk-bound
  or otherwise "unhealthy" nodes: "what a healthy node uses", derived by
  deleting the unhealthy ones, is survivorship bias with extra steps.
- **Two-stage aggregation, and the floor counts distinct `system_id`.** Reduce
  each node to the p90 across its daily values first (p90, not the median: a
  28-day window holds eight weekend days on which a business workload is idle),
  then take percentiles across nodes. The floor counts distinct clusters, the
  same rule and reason as Threat Shield's promotion, and a cohort that falls
  below it is **deleted**, mirroring `ExpireBlocklist`.
- **Ignorability is keyed on ubiquity, not weight.** `sizing.platformFamilies`
  appears exactly once and lists the families a node runs because it is an NS8
  cluster (`loki`, `ldapproxy`, `metrics`, `crowdsec`, `traefik`, the account
  provider, and `nethvoice-proxy` as a module implied by another) — never as a
  weight inside a published number, which would be circular. It is **derived**
  (`IsPlatform(family, workload)`) because samba has two roles: the account
  provider, and a file server once shares exist — a workload distinction, not a
  family one. It is also the only reader of a stored workload value: nothing
  else in the pass looks at one. This replaced a lite/medium/heavy prior that
  treated "lite" as ignorable, which asked the wrong question and made
  `family_solo` unreachable: `loki` is on every cluster and was classed heavy,
  so every node had at least two non-ignorable families and no node was ever
  solo for anything — zero `family_solo` rows had ever published. Never key
  this on weight again, and never let an unlisted family default to ignorable.
- **A solo number includes the platform modules' cost**, because every node it
  was measured from was running them. Say so wherever one is shown (the
  `/cohorts` caption does); an unqualified "module X costs Y" overstates the
  measurement. It is still the useful reading — nobody deploys NS8 without them.
- **Roll up before pruning.** `RollupSizingMonthly` must precede
  `PruneSizingDaily`, or the dropped day loses its history permanently.
- **Two published cohort kinds, and no third.** `family_solo` (the only one
  quotable as a recommendation) and `family` (co-tenanted, context only). A
  `profile` keying over the sorted non-platform family list and a workload
  t-shirt-size table both shipped and were **removed**: the profile long tail
  never cleared the floor by design, and neither artifact had a consumer, so
  between them they cost ~350 lines and two more concepts for nothing. Do not
  reintroduce either without a consumer that needs it. Deleting `family_solo`
  was considered when it turned out to be publishing nothing and rejected: it
  is the only output of this pipeline that answers the question the pipeline
  exists for, and the cause was a fixable classification bug, not the idea.
- **No ridge, no k-means.** Ridge shrinkage destroys the interpretation of a
  coefficient as "the cost of module X", which is the entire product, and does
  nothing about censoring; k-means is not deterministic run to run, and a number
  published to customers must not change without the data changing. If a
  regression ever ships it must be non-negative least squares on the uncensored
  subset, labelled as an estimate distinct from the measured percentiles.
- **The operator UI renames, the code does not.** `pressure`, `axis`, `cohort`
  and `censored` are the stored names and stay; the two sizing pages translate
  them (`axisLabel`, "Capped", "Nodes running only this module") because a page
  that prints `io` and `censored` at an operator is not documentation. Page
  descriptions are one or two plain sentences — the reasoning behind a rule lives
  in the Go doc comments and in `docs/plans/2026-09-02-fleet-sizing-server.md`,
  never as an essay on the page.

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
| Auth | moved to the proxy: `cmd/authd` is a caching forward-auth service (`internal/platform/auth.ForwardAuth`) that Traefik calls as a `forwardAuth` middleware — forwards to `AUTH_VALIDATE_URL` (default `https://my.nethesis.it/auth`), TTL cache keyed on `HMAC(pepper, cred)`, fail-closed 503 — this is the permanent design. Each pipeline no longer validates a credential itself: it reads `system_id` from the already-forwarded Basic username via `httpx.SystemID`, trusting it only when the request arrived from `TRUSTED_PROXY_CIDRS` — that check is the whole security boundary, so a pipeline reached directly (bypassing authd/Traefik) accepts any password | same |
| Schema | `CREATE TABLE IF NOT EXISTS` in each pipeline's `store.Init` | `golang-migrate`, one dialect-agnostic SQL dir, dual-dialect CI test |
| Backends | SQLite only, one file per pipeline — three databases (logs, threat, sizing), nothing shared | per-pipeline `Store` iface already in place; `pgStore` added later |
| Cost control | `gate` plus `internal/budget`: `LLM_MAX_CONCURRENCY`, per-system daily call cap, `LLM_DAILY_SPEND_CAP_USD` (`gate.SystemState.SecurityOnly` is the degrade hook) | same |
| Missing packages | — | `ingest` (rate limit, full §5.4 validation), `maint`, `version` |
| Missing tooling | — | `Makefile`, `.golangci.yml`, `.github/workflows/ci.yml` |
| Operator UI | three separate dashboards, `internal/ui/{logs,threat,sizing}` on shared `internal/ui/chrome`, one per binary at `/logs`, `/blocklist`, `/sizing`, each off unless that binary's `UI_LISTEN_ADDR` is set. `GET` is unauthenticated and fleet-wide at the app layer, so bind it to loopback (a wider bind warns, never refuses) when not fronted by Traefik; in the deployed shape Traefik's BasicAuth (`ADMIN_API_KEY` as the htpasswd password) is what actually stands between it and the internet. threatd's enumerated `POST` routes additionally authenticate against `ADMIN_API_KEY` inside the app — that check and the cross-site check stay even behind Traefik's BasicAuth, since both are Basic auth and a browser replays either the same way. Backed by the cross-system read methods in `internal/store/{logs,threat,sizing}/ui.go` | same; the spec's §2 non-goal covers a *consumer* dashboard, not this |
| Allowlist management | built: `POST /blocklist/v1/allowlist-requests`, write routes in `internal/ui/threat` (add/delete allowlist, approve/reject a request) gated on `ADMIN_API_KEY`, an append-only audit table read on threatd's `/audit` page. `internal/admin` and `ADMIN_LISTEN_ADDR` no longer exist | cross-org scoping once auth returns a tenant |
| Fleet sizing | built server-side: `internal/sizing` (pure), `internal/store/sizing/{store.go,ui.go}`, `internal/api/sizing/{api.go,sizing.go}`, `internal/baseline`, three UI pages (`/`, `/cohorts`, `/status`) on `cmd/sizingd`. Single-instance only — the cohort pass takes no distributed lock. The `ns8-core` cluster reporter is **not** built | the reporter; `webtop` / `imapsync` `get-facts`; calibrated thresholds once ~30 days of fleet data exist |
| Threat Shield | built: `internal/threat` (pure), `internal/store/threat/{store.go,ui.go,allowlist.go}`, `internal/blocklist`, `internal/api/threat/{api.go,threat.go,allowlist.go}`, seven UI pages including `/audit`, on `cmd/threatd`. Single-instance only — the consensus pass takes no distributed lock | multi-instance locking; cross-org promotion (D5) once auth returns a tenant |

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

go test ./internal/gate/ -run TestKnownSecurityTemplateAloneNoCall -v  # one package / one test
go test ./internal/prompt/ -update                                    # regenerate prompt goldens
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

This runs `insightsd` standalone, with no Traefik and no `authd` in front of
it. `insightsd` no longer validates the credential itself — that moved to
`authd`, which Traefik calls as a `forwardAuth` middleware — so it only checks
that the request came from `TRUSTED_PROXY_CIDRS` (default `127.0.0.0/8`, which
already covers a local `curl`) and reads `system_id` off the Basic username
with **any** password. In the deployed shape these same two calls go to
`https://<host>/logs/v1/bundles` and `https://<host>/logs/v1/findings`, and
`system_id`/`auth_token` are then genuinely checked by `authd` against
`AUTH_VALIDATE_URL` (default `https://my.nethesis.it/auth`).

`scripts/insights-api.sh` wraps the same calls, plus threatd's and sizingd's
(`health`, `findings`, `open`, `post <bundle.json>`, `events`, `feed`,
`allowlist-request`, `raw <path>`); it defaults to `http://localhost`, using
each command's own prefixed path (`/logs`, `/blocklist`) against a
Traefik-fronted deployment.

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

Four binaries now, one per pipeline plus the shared forward-auth cache, behind
one Traefik proxy:

```
cmd/authd  cmd/insightsd  cmd/threatd  cmd/sizingd    four binaries; authd owns
                                                       no pipeline of its own

internal/platform/auth  httpx  sqlitex   shared: ForwardAuth+cache, HTTP
                                          plumbing (ClientIP, SystemID, Logging,
                                          Healthz), SQLite Open — the only
                                          packages every binary may import

model                       no deps; imported by everything
fingerprint  gate  prompt   PURE — no I/O, no clock beyond an injected now() — logs only
threat                      PURE — the Threat Shield sanitizer and allowlist
sizing                      PURE — the sizing sanitizer, pressure score, cohorts
llm  queue  budget          logs only; interfaces where I/O is needed
analyzer                    the bundle pipeline; depends on all of the above
blocklist                   Threat Shield consensus + the served snapshot
baseline                    fleet-sizing cohort pass; same shape as blocklist

store/logs  store/threat  store/sizing   one store package per pipeline, each
                                          its own SQLite file — no combined
                                          `Store` interface any more
api/logs  api/threat  api/sizing         HTTP: ingest + read, per pipeline
ui/chrome                                shared layout, static assets, write
                                          auth, base-path-aware `Link`
ui/logs  ui/threat  ui/sizing            per-pipeline operator dashboard,
                                          off by default
```

Each pipeline's binary imports exactly one of `store/*`, `api/*` and `ui/*` —
never another pipeline's. Traefik terminates the deploy-configured host, strips
a per-pipeline path prefix, and calls `authd` as a `forwardAuth` middleware
before any pipeline sees a request; `authd` is a thin HTTP shell over
`internal/platform/auth` and owns no store and no UI.

`ui/logs`, `ui/threat` and `ui/sizing` sit beside their pipeline's `api`
package, not under it: each depends on its own `store/*` package (through a
local, narrow `Reader`/`Writer` interface) plus `internal/ui/chrome` for
everything shared — layout, static assets, the GET-only-plus-enumerated-POST
discipline, write authentication, base-path-aware link building — and
`internal/platform/httpx` for the request logger and `/healthz`. Nothing under
`ui/*` copies another package's logging handler any more; `httpx.Logging`
removed the reason that copy existed.

The purity of `gate`, `fingerprint`, `prompt`, `threat` and `sizing` is the
point: each holds all the correctness and privacy logic for its concern and is
table-driven-testable with no fixtures. `llm` and every `store/*` package being
interfaces at the consumer is what lets `analyzer_test.go` and each pipeline's
`api`/`ui` tests run end to end with nothing running — there is no longer one
88-method `Store` interface; each consumer declares its own narrow one.

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
length-prefixed fields, sorted/deduped lists, `"v2"` prefix. Never a `strings.Join`
(a separator is forgeable). Consequences to preserve:

- The LLM cites templates by **ID** (`T1`, `T2`, … from `prompt.TemplateID`); the
  server resolves them via `prompt.ResolveEvidence` and derives evidence text,
  module set and category itself. **No model-authored string ever reaches the
  fingerprint** — an inconsistently worded restatement collapses onto the same
  finding.
- Refusing model-authored text is **not sufficient**: the model still chooses
  which templates to cite. `v1` hashed the whole cited set, so a changing mix of
  GeoIP country codes split one SSH condition into ~160 findings on the dev
  fleet, nearly all at `occurrence_count=1`. `v2` hashes one derived key from
  `fingerprint.EvidenceKey`: normalize the known masking leaks, key on the
  `(module_id, priority)` bucket when the cited set shares one, else on the
  canonical primary template.
- `model.LessTemplate` is the **single** definition of template order, shared by
  `prompt.SortedTemplates` and `EvidenceKey`. Two orderings that must agree will
  eventually disagree, and then a finding's identity stops matching the evidence
  shown for it.
- Changing the formula changes every existing finding's identity fleet-wide. That
  is a deliberate versioned migration (bump `fingerprint.Version`), never a
  silent re-raise. There is no backfill by design: the bump is what makes the
  change visible.

### Gate = the cost control, not an optimization

`gate.Evaluate` fires the LLM if any of: a template is new for this system; a
digest ratio exceeds `GATE_TOLERANCE` (edge `expected` preferred, server EWMA
baseline as fallback); a security-category template is **new** (`security_new`)
or **known but in a deviating module** (`security_surge`); or a module is both
truncated **and** deviating. Every decision writes `gate_reasons` into the
`analyses` row, so "why did this cost money" and "why was this missed" are both
answerable from stored data. Ungated, the fleet is ~$16k/month on `gpt-4o-mini`.

The server never classifies — `category=security` is assigned by the edge and
propagated.

**The security condition is novelty-scoped, and must stay that way.** It used to
fire on the mere presence of a security template. Since the host bucket
(`module_id: ""`, sshd) carries continuous failed-auth traffic on any
internet-facing node, that fired on every window: 352 LLM calls out of 352 on
the dev fleet, zero gated out. It also made spec §9.4's spend-cap degrade path
(`SystemState.SecurityOnly`) cost the same as not degrading. Never restore the
unconditional form.

**Modules with their own pipeline are excluded at ingest**, via
`PIPELINE_EXCLUDE_MODULES` (default `crowdsec1`) and
`model.Bundle.ExcludeModules`, applied in `api.handleBundles` before
`queue.Publish`. One place, so gate, prompt, `system_templates` and
`module_baselines` cannot disagree about scope. The filter drops from
`Templates`, `Digest` **and** `Budget.TruncatedModules` together — filtering
only templates leaves the digest firing deviation reasons for a module the
prompt never mentions.

**Services are excluded on a second axis**, `PIPELINE_EXCLUDE_SERVICES`
(default `insights`) via `model.Bundle.ExcludeServices`. Host records all carry
`module_id: ""`, so the module filter cannot reach them; the only service
dimension on the wire is the `[service]` tag the collector puts on each masked
host line (`model.ServiceTag`). This exists because a co-located deployment
analyses its own log output: on the dev machine 452 of 564 host templates were
`insights` lines, 204 of them its own `gate decision` messages, each new
template re-firing the gate that produced it. A line `ServiceTag` cannot parse
is **kept** — failing open toward analysis is the safe direction. Digest and
truncation records have no service dimension and are passed through, so an
excluded service still contributes to its bucket's volume.

**Gate reasons carry no computed values** — `new_templates` has no count,
`deviation:<module>/<priority>` no ratio. The UI's `/gate` rollup groups on the
stored string, and embedded floats made every deviating window a group of one.
The ratio is not kept anywhere: per-window numbers live in the prompt the
analyzer built, and per-bucket normals on the UI's `/baselines`.

**A gate reason is the trigger, not a description**: `gate.Evaluate` returns
`Call: len(reasons) > 0`, and every analyzer path that stores a non-empty
`gate_reasons` also stores `llm_called = 1`. So "windows" and "LLM calls" are the
same number for any reasoned row — never present them as independent columns.
`llm_called` counts *attempts*: the transient-, permanent- and parse-error paths
set it with `cost_micros = 0`. And because reasons are stored as the formula that
produced them spelled them, **any rollup over them must be time-bounded**
(`store.GateRollup(ctx, since)`, default 7 days on `/gate`) — an all-time
grouping mixes eras and is dominated by pre-fix spellings.

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
templates; `/* … */` for CSS. In `internal/ui/chrome/templates/layout.html` the header
sits outside any `{{define}}` block, so it is emitted into the served page
source — that is correct and intended for GPL.

**Vendored third-party files are exempt and must stay exempt.** Anything under
`internal/ui/chrome/static/` that is not ours — today `pico.min.css` and `pico.LICENSE`
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
- `sizing`: table-driven, no fixtures. `TestSanitizeAcceptsEveryMetricKey` and
  `TestSanitizeRejectsEveryNonNumericValue` are the executable form of the
  open-vocabulary and privacy rules, following the
  `TestSanitizeAcceptsEveryScenario` precedent. Every penalty term at `x < x0`,
  `x == x0`, mid-ramp, `x == x1`, `x > x1` and absent; a fully idle node scores
  `pressure == 0` (the direction test); the coverage gate yields `NULL` rather
  than a division; the day window at both edges; a malformed node dropped and
  counted while its siblings store; the verdict's main cause is the most
  frequent one and is stable across repeated runs, because it folds a map.
- `baseline`: temp-file SQLite, not a mock — the exclusions *are* the SQL and
  the folding. 19 distinct systems publishes nothing and 20 does; one system
  with 40 nodes does not; a cohort below the floor is deleted rather than left
  stale; a censored-heavy cohort publishes with `censored_nodes` set; a
  `pressure_version` bump recomputes before cohorts are built. The housekeeping
  order and its failure handling use a recording fake, because what is under
  test is the order of the calls.
- `blocklist`: temp-file SQLite, not a mock — the grouping *is* the SQL. Boundary
  fixtures: 2 distinct systems does not promote and 3 does; one system reporting
  three times does not; one system across two categories is still one system;
  allowlisted addresses never promote; `expires_at` refreshes while `first_listed_at`
  holds; a failed pass keeps the previous snapshot.

## Conventions

- [Conventional Commits](https://www.conventionalcommits.org/) for every commit.
- **Never put an issue reference in an individual commit message.** Issue refs go
  in the merge/squash commit body only.
- Work on a branch, never commit directly to `main`. Stage explicit paths, not
  `git add .`.
- GPL-3.0-or-later

## Dev machine

The plan runs all work on `root@rl1.leader.default.gs.nethserver.net` (Rocky 9),
under `/root/nethesis-insights`, because the operator has a local bandwidth limit
and this project pulls a Go module cache plus a Postgres image.
`rl1` is a **shared live NS8 cluster** — other modules (`nethvoice2`, `crowdsec1`,
`samba2`, `metrics1`, `traefik1`) run on it. Never restart another module's
services; bind containers to high ports. If the machine has been torn down,
`docs/runbooks/dev-machine-rl1.md` rebuilds it end to end.

