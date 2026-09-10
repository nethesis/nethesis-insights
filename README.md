# nethesis-insights

Central anomaly analysis for NethServer fleets. Receives deduplicated log
bundles from nodes, gates them against novelty and deviation before spending
any LLM call, and stores fingerprinted findings that do not repeat.

## Status

Working prototype, split into **four services behind one Traefik proxy**:
`authd` (a caching forward-auth service Traefik calls before any pipeline sees
a request), `insightsd` (the bundle/LLM pipeline), `threatd` (Threat Shield)
and `sizingd` (fleet sizing). Each pipeline owns its own SQLite file — three
databases, nothing shared but Traefik, `authd` and
`internal/platform/{auth,httpx,sqlitex}`. In the reference deployment all five
containers (Traefik plus the four binaries) run in one podman pod; see
`docs/runbooks/2026-09-09-insights-test-deploy.md`.

`insightsd` runs a full round trip — ingest, gating, an OpenAI-compatible LLM
call, server-computed finding identity, and a read API. Ingest is
asynchronous: `POST /v1/bundles` (public path `/logs/v1/bundles`) validates the
bundle, puts it on an in-memory queue and answers `202` right away, so an edge
node's HTTP timeout can never abort an analysis in flight. That in-memory queue
is the permanent design.

Authentication happens at the proxy. Traefik calls `authd` as a `forwardAuth`
middleware; `authd` forwards the edge's `Authorization: Basic` header verbatim
to an external validator (`AUTH_VALIDATE_URL`, default Nethesis's own
`https://my.nethesis.it/auth`) and caches the outcome. Each pipeline then
trusts the already-forwarded header's username as the `system_id`, but only
when the request arrived from a configured proxy address — see Configuration
below. The production design still adds an optional Postgres backend. See
the design doc referenced below.

Because analysis is asynchronous, the ingest response says only whether the
bundle was **accepted**. Analysis outcomes are visible in the findings API and
in the `analyses` ledger, not in the POST response. A `503` means the queue is
saturated and the edge should retry the window.

Two more independent pipelines run here, each its own binary and its own
database: **Threat Shield** (`threatd`) turns the fleet's CrowdSec ban
decisions into a consensus IP blocklist served back to the nodes, and
**fleet sizing** (`sizingd`) turns cluster hardware reports into per-node
verdicts and cohort baselines. Both share only Traefik, `authd` and the SQLite
runtime settings with `insightsd` — no LLM call, no gate, no fingerprint in
either. See [Threat Shield](#threat-shield) and [Fleet sizing](#fleet-sizing)
below.

Design documents live in this repository:

- Spec: `docs/specs/2026-08-05-nethesis-insights-design.md`
- Implementation plan: `docs/plans/2026-08-05-nethesis-insights.md` (Tasks 1–10)
- Pipeline-split plan: `docs/plans/2026-09-09-pipeline-split.md` (the four-binary/
  one-proxy shape) and `docs/runbooks/2026-09-09-insights-test-deploy.md` (deploying it)
- Threat Shield design: `docs/specs/2026-07-28-threat-shield-design.md`
- Threat Shield ingest contract: `docs/specs/2026-08-07-threat-events-ingest-contract.md`
- Fleet sizing plan: `docs/plans/2026-09-02-fleet-sizing-server.md`
- Fleet sizing ingest contract: `docs/specs/2026-09-02-sizing-ingest-contract.md`

## Development

    go build ./...
    go vet ./...
    go test ./... -race -count=1

Manual round trip against a real model, free of charge, using an OpenRouter
account and its free NVIDIA Nemotron tier:

    LLM_BASE_URL=https://openrouter.ai/api/v1 \
    LLM_MODEL=nvidia/nemotron-3-ultra-550b-a55b:free \
    LLM_API_KEY=<an OpenRouter API key> \
    DB_PATH=/tmp/insights.db \
      go run ./cmd/insightsd

    curl -u <system_id>:<auth_token> -X POST localhost:9595/v1/bundles -d @bundle.json
    curl -u <system_id>:<auth_token> 'localhost:9595/v1/findings?since=0'

This runs `insightsd` standalone, without Traefik or `authd` in front of it —
the fastest way to exercise the pipeline. Authentication moved to the proxy
(see Configuration below): `insightsd` no longer validates the credential
itself, it only reads `system_id` off the Basic username and trusts it when
the request arrived from `TRUSTED_PROXY_CIDRS` (default `127.0.0.0/8`, which
already covers a local `curl` to `localhost`). Run this way, **any password
works** — the credential is genuinely checked only when a request actually
passes through Traefik's `forwardAuth` call to `authd`. Testing a pipeline
from a machine other than the one it runs on, i.e. with no proxy in front of
it at all, needs `TRUSTED_PROXY_CIDRS` widened to whatever address the client
will actually connect from, or the pipeline answers `401` to a perfectly good
credential.

In the deployed shape, behind Traefik, these same two calls go to
`https://<host>/logs/v1/bundles` and `https://<host>/logs/v1/findings` — Traefik
strips the `/logs` prefix before proxying, and `system_id`/`auth_token` are
then actually validated by `authd` against `AUTH_VALIDATE_URL` (default
`https://my.nethesis.it/auth`). See
`docs/runbooks/2026-09-09-insights-test-deploy.md` for the full pod/Traefik
setup, or run `authd` alongside `insightsd` yourself to test the real
credential path without the proxy.

The provider is OpenAI-compatible, so no code change is needed — set the
three `LLM_*` variables above and run `insightsd` as usual. Two things to
know before assuming a bug:

- **It is slow, not hung.** The free model returns HTTP response headers
  immediately but the body only once generation finishes, commonly ~105s
  later. `LLM_TIMEOUT` (default `120s`) and `ANALYSIS_TIMEOUT` (default `5m`)
  are already sized to tolerate this; do not lower them for this provider.
  Since ingest is asynchronous (`POST /v1/bundles` returns `202`
  immediately), the delay is invisible at the HTTP layer — check
  `LOG_LEVEL=debug` output or poll `/v1/findings` to see when analysis lands.
- **Free tier, so it can rate-limit or be temporarily unavailable.** Treat
  provider errors as a signal to retry later, not as a code regression.

Get a key at <https://openrouter.ai>. `docs/runbooks/dev-machine-rl1.md`
covers the older single-binary systemd/quadlet setup on that machine;
`docs/runbooks/2026-09-09-insights-test-deploy.md` is the current, four-binary/
one-proxy deployment target.

### Testing the edge collector without installing ns8-loki fork

The collector script can be fetched and run standalone on any NS8 node — no
module install needed:

    runagent -m loki

    cd ../bin
    curl https://raw.githubusercontent.com/NethServer/ns8-loki/refs/heads/anomaly_detector/imageroot/bin/insights-collector > insights-collector
    INSIGHTS_SERVER_URL=https://<insights-server-host>/insights python3 insights-collector

`INSIGHTS_SERVER_URL` is the one required variable — without it the script
exits immediately with `INSIGHTS_SERVER_URL is not set`. On success it prints
what it shipped and the server's response:

    shipped 76 templates, 332 lines -> 202 {"accepted":true}

Point it at the target `insightsd` instance's `/v1/bundles` base path — on the
four-binary deployment that is `/logs/v1/bundles` behind Traefik (adjust for
whatever reverse-proxy prefix actually fronts it). This is the fastest way to
check ingest end to end against a real node's logs without deploying loki3
there.

## Container

One `Containerfile` builds all **four** binaries, selected by a `SERVICE`
build argument; `.github/workflows/image.yml`'s matrix invokes it once per
service and publishes each as its own public multi-arch (`linux/amd64`,
`linux/arm64`) image, on every push to `main` and on every tag:

    ghcr.io/nethesis/nethesis-insights-authd:latest
    ghcr.io/nethesis/nethesis-insights-insightsd:latest
    ghcr.io/nethesis/nethesis-insights-threatd:latest
    ghcr.io/nethesis/nethesis-insights-sizingd:latest

The reference deployment runs all five containers (Traefik plus these four) in
one podman pod from quadlet units under `deploy/quadlet/`, so that Traefik
reaches every backend over real loopback with no address translation in the
path — see `docs/runbooks/2026-09-09-insights-test-deploy.md` for the full
setup, including the Traefik configuration and the `TRUSTED_PROXY_CIDRS`
reasoning that depends on it.

To run one service standalone, e.g. for the manual round trip above:

    podman run -d --name insightsd -p 9595:9595 \
      -v insights-data:/var/lib/insights \
      -e LLM_BASE_URL=https://api.openai.com/v1 \
      -e LLM_MODEL=gpt-4o-mini -e LLM_API_KEY=sk-... \
      ghcr.io/nethesis/nethesis-insights-insightsd:latest

Every binary is static (`CGO_ENABLED=0`, `modernc.org/sqlite`) and runs as uid
1001; each pipeline's SQLite database lives in its own volume (`DB_PATH`
defaults to `/var/lib/insights/insights.db`, `/var/lib/threat/threat.db` and
`/var/lib/sizing/sizing.db` respectively). Build one locally with
`podman build --build-arg SERVICE=threatd -t nethesis-insights-threatd .`.

## Configuration

Four binaries, four sets of environment variables. `LOG_LEVEL` is read by all
four; the next group is common to the three pipelines (`insightsd`, `threatd`,
`sizingd`) but not `authd`; everything else is specific to one binary.

### Common

| Variable | Purpose |
|---|---|
| `LOG_LEVEL` | `debug`, `info`, `warn`, `error` (default `info`). Read by all four binaries. |

### Common to the three pipelines (`insightsd`, `threatd`, `sizingd`)

| Variable | Purpose |
|---|---|
| `LISTEN_ADDR` | HTTP bind address for that pipeline's client API (default `:9595`; the deployed shape gives each pipeline its own port — see `docs/runbooks/2026-09-09-insights-test-deploy.md`) |
| `UI_LISTEN_ADDR` | bind address for that pipeline's optional operator dashboard (default empty — **the dashboard is off**). See [Operator UI](#operator-ui) |
| `UI_BASE_PATH` | path prefix the dashboard's own links are built with, e.g. `/blocklist` (default empty). Set this to match whatever prefix a reverse proxy strips before forwarding — Traefik strips `/logs`, `/blocklist` and `/sizing` respectively |
| `DB_PATH` | this pipeline's SQLite file path (default `/var/lib/insights/insights.db`, `/var/lib/threat/threat.db`, `/var/lib/sizing/sizing.db` respectively) |
| `TRUSTED_PROXY_CIDRS` | comma-separated CIDRs (or bare addresses) whose `X-Forwarded-For` this pipeline believes, and whose connections it accepts as pre-authenticated by `authd` at all (default `127.0.0.0/8`). See [Authentication](#authentication-authd) below — this is the whole security boundary once a credential is no longer checked in-process |

### `authd`

The forward-auth cache Traefik calls before any pipeline sees a request. See
`docs/architecture.md` § Authentication for why it exists as its own service.

| Variable | Purpose |
|---|---|
| `AUTH_LISTEN_ADDR` | HTTP bind address (default `:9590`) |
| `AUTH_VALIDATE_URL` | forward-auth validator (default `https://my.nethesis.it/auth`) |
| `AUTH_PEPPER` | HMAC pepper for the auth cache — secret; unset gets a random, process-lifetime one |
| `AUTH_CACHE_TTL`, `AUTH_NEG_CACHE_TTL` | positive/negative validator-outcome cache lifetimes (default `5m`/`30s`) |
| `AUTH_CACHE_MAX_ENTRIES`, `AUTH_NEG_CACHE_MAX_ENTRIES` | cache size caps, counted separately so a flood of wrong credentials cannot evict the fleet's cached-valid entries (default `8192`/`4096`, about 3 MB in total) |
| `AUTH_TIMEOUT` | validator request timeout (default `5s`) |

### `insightsd`

| Variable | Purpose |
|---|---|
| `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY` | OpenAI-compatible provider |
| `LLM_TIMEOUT` | request timeout (default `120s`) |
| `GATE_TOLERANCE` | deviation ratio threshold (default `3.0`) |
| `GATE_MIN_EXPECTED` | smallest baseline a bucket needs before its ratio is trusted (default `10`) |
| `GATE_MIN_OBSERVED` | smallest observed line count that can be called a surge (default `20`) |
| `GATE_MIN_NEW_TEMPLATES` | novel templates required before novelty alone fires (default `3`); a new security template always fires on its own |
| `PROMPT_MAX_AMBIENT` | templates carried as context beyond the ones the gate fired on (default `60`) |
| `LLM_MAX_CONCURRENCY` | LLM calls in flight at once (default `4`) |
| `LLM_MAX_CALLS_PER_SYSTEM_PER_DAY` | hard per-system ceiling, UTC day (default `12`); over-cap windows are recorded with `suppressed_by` and cost nothing |
| `LLM_DAILY_SPEND_CAP_USD` | fleet spend ceiling for the UTC day (default `0` — off); on breach the gate narrows to security-only rather than stopping |
| `PIPELINE_EXCLUDE_MODULES` | comma-separated modules dropped from every bundle before analysis (default `crowdsec1`, which has its own pipeline); empty value analyses everything |
| `PIPELINE_EXCLUDE_SERVICES` | comma-separated syslog identifiers dropped the same way, matched against the `[service]` tag on host records (default `insights`, so a co-located server does not analyse its own logs) |
| `STALE_AFTER` | finding staleness threshold (default `24h`) |
| `EWMA_ALPHA` | server-side baseline smoothing factor (default `0.3`) |
| `LLM_PRICE_INPUT_PER_MTOK`, `LLM_PRICE_OUTPUT_PER_MTOK` | cost ledger prices (default `0`); e.g. gpt-4o-mini standard tier: `0.15`, `0.60` |
| `QUEUE_SIZE` | bundles buffered before ingest answers 503 (default `256`) |
| `QUEUE_WORKERS` | concurrent analyses (default `2`) |
| `ANALYSIS_TIMEOUT` | ceiling for one bundle's analysis (default `5m`) |

### `threatd`

| Variable | Purpose |
|---|---|
| `ADMIN_API_KEY` | HTTP Basic password for the dashboard's write routes (add/remove an allowlist entry, approve/reject a request) — secret; unset means those routes answer **`405`**, never a default credential. `threatd` is the only pipeline that reads this |
| `BLOCKLIST_CONSENSUS_INTERVAL` | how often consensus runs and the feed is regenerated (default `5m`) |
| `BLOCKLIST_WINDOW` | rolling observation window for promotion (default `1h`) |
| `BLOCKLIST_MIN_SYSTEMS` | distinct systems required to publish an address (default `3`) |
| `BLOCKLIST_TTL` | how long a listing survives its last sighting (default `24h`) |
| `BLOCKLIST_MAX_ENTRIES` | hard cap on the served feed (default `50000`) |
| `THREAT_EVENT_RETENTION` | how long raw threat events are kept (default `168h`) |
| `THREAT_MAX_DECISIONS_PER_REQUEST` | per-request decision cap; over-cap batches are truncated, not rejected (default `500`) |
| `THREAT_QUEUE_SIZE` | sanitized reports buffered before ingest answers 503 (default `256`) — bounds concurrency against the single-writer database, not an LLM call |
| `THREAT_QUEUE_WORKERS` | concurrent store writes (default `2`) |
| `THREAT_QUEUE_TIMEOUT` | ceiling for one report's store write (default `30s`) |

### `sizingd`

| Variable | Purpose |
|---|---|
| `SIZING_RETENTION` | how long fleet-sizing daily rows are kept (default `2400h`, 100 days); monthly rollups are kept indefinitely |
| `SIZING_PASS_INTERVAL` | how often the cohort pass runs (default `1h`); the inputs are whole days, so faster cannot produce a different answer |
| `SIZING_WINDOW_DAYS` | trailing window for node verdicts and cohort baselines (default `28`) |
| `SIZING_MIN_DISTINCT_SYSTEMS` | distinct clusters a cohort needs before any baseline is published (default `20`) |
| `SIZING_MIN_NODES` | nodes a cohort needs as well (default `30`); below either floor the cohort is deleted, not left stale |
| `SIZING_MIN_DAYS_PRESENT` | days of history a node needs before its verdict leaves `insufficient_data` (default `14`); a statistical significance floor, not a publication floor — lowering it on a real fleet weakens the k-of-n guard, not just how soon it answers |
| `SIZING_MAX_NODES_PER_REPORT` | per-report node cap; over-cap reports are truncated, not rejected (default `16`) |

### Deploy-time inputs, read by no binary

`INSIGHTS_HOST` (the served hostname) and `ACME_EMAIL` (Let's Encrypt's
contact address) live in `/etc/insights/deploy.env` on the deployment machine,
not in this repository, and are consumed only when rendering Traefik's
configuration — see `docs/runbooks/2026-09-09-insights-test-deploy.md` §3.
`ADMIN_LISTEN_ADDR` no longer exists: the separate admin plane it used to
enable is gone (Decision 6 of `docs/plans/2026-09-09-pipeline-split.md`).

`LOG_LEVEL=debug` adds request detail, the reason behind every 401/400/403,
the gate decision and its inputs (`insightsd`), prompt size, provider status
and timing, and queue depth. It never logs credentials: the LLM API key is
reported only as `llm_api_key_set=true`, and an authentication failure names
the presented `system_id` but never the secret.

## Authentication (`authd`)

Traefik calls `authd` as a `forwardAuth` middleware on every `/v1/*` request,
before the request reaches a pipeline at all. `authd` forwards the edge's
`Authorization: Basic` header to `AUTH_VALIDATE_URL` and caches the outcome; a
`2xx` lets Traefik proxy the original request through unchanged, a `401`
rejects it, and a `503` (validator unreachable) is retried by the edge rather
than treated as a rejected credential.

A pipeline reached this way never validates the secret itself — it reads
`system_id` off the same `Authorization` header's Basic username
(`httpx.SystemID`), trusting it *only* because the request arrived from a
proxy address in `TRUSTED_PROXY_CIDRS`. That check is the entire security
boundary: a request that reaches `insightsd`/`threatd`/`sizingd` directly,
bypassing Traefik and `authd`, is refused with `401` regardless of whether the
credential it carries is genuine, unless its source address happens to be
inside `TRUSTED_PROXY_CIDRS` — which is exactly the situation described under
[Development](#development) above for local testing.

In the reference pod deployment all five containers share one network
namespace, so Traefik's connection to a backend is a genuine loopback
connection with no NAT in the path and `RemoteAddr` really is `127.0.0.1` by
construction — which is what makes the default `TRUSTED_PROXY_CIDRS=127.0.0.0/8`
correct without a per-deployment value. See
`docs/runbooks/2026-09-09-insights-test-deploy.md` §4 for the full reasoning
and the one command that verifies it on a real deployment.

## Operator UI

Three separate, built-in dashboards now, one per pipeline: the logs dashboard
(`insightsd`), the blocklist dashboard (`threatd`) and the sizing dashboard
(`sizingd`). Each shows everything its own pipeline records about its own
behaviour, plus live process state its database cannot show (queue depth,
uptime, effective configuration), and each is **off unless you set that
binary's `UI_LISTEN_ADDR`**:

    UI_LISTEN_ADDR=127.0.0.1:9596 insightsd
    UI_LISTEN_ADDR=127.0.0.1:9606 threatd
    UI_LISTEN_ADDR=127.0.0.1:9616 sizingd

In the deployed shape, Traefik serves them at `/logs`, `/blocklist` and
`/sizing` respectively — set that binary's `UI_BASE_PATH` to match the prefix
Traefik strips, or every link the page emits (stylesheet, nav, forms) escapes
the subtree.

**Logs dashboard** (`/logs`):

| Route | |
|---|---|
| `/` | severity-ranked findings; filter by system, status and severity; each row expands to summary, evidence, suggested action and fingerprint |
| `/systems` | every system, with its template, finding, window, LLM-call and cost totals |
| `/analyses` | the cost ledger: window, gated, `llm_called`, tokens, cost, duration, `gate_reasons`, error |
| `/gate` | windows, LLM calls and cost per distinct gate-reason set — why you are paying |
| `/cost` | spend and tokens per UTC day and model |
| `/templates` | what the server already considers known for a system |
| `/baselines` | the EWMA rates the gate falls back on when a bundle carries no `expected` |
| `/status` | row counts, queue depth/capacity/workers, uptime, build, effective config |

**Blocklist dashboard** (`/blocklist`):

| Route | |
|---|---|
| `/` | the consensus feed with its promotion evidence, plus the allowlist exclusion set |
| `/systems` | every system that has ever reported a CrowdSec decision |
| `/events` | recent sanitized CrowdSec decisions; filter by system or attacker IP |
| `/stats` | daily threat rollup per scenario, and per-node ingest accounting |
| `/allowlist-requests` | the review queue: what customers asked to have exempted, ranked by how many distinct systems asked |
| `/audit` | the append-only trail of every allowlist add/remove/approve/reject, and who made it |
| `/status` | uptime, build, effective config |

**Sizing dashboard** (`/sizing`):

| Route | |
|---|---|
| `/` | per-node pressure, its axis penalties, the utilization percentiles, and the multi-day verdict |
| `/cohorts` | the published cohort baselines |
| `/status` | uptime, build, effective config |

### Read this before exposing it

**Each dashboard's `GET` is unauthenticated and fleet-wide at the app layer.**
It shows every system's findings, templates, baselines and spend, across
tenants. The ingest and read APIs are per-system and authenticated by
`authd`/Traefik; a dashboard's `GET` route is not, by itself.

So **bind each `UI_LISTEN_ADDR` to `127.0.0.1` or a trusted management
network** unless it sits behind Traefik. The binary will not refuse a wider
bind — a `0.0.0.0` bind is the administrator's call to make, not the server's
— but it logs a `WARN` at startup whenever the UI is bound anywhere other than
a loopback address, so the choice is never made by accident.

In the reference deployment, Traefik BasicAuths every request to any of the
three dashboards using `ADMIN_API_KEY` as the htpasswd password, and the pod
publishes no port for any of the three `UI_LISTEN_ADDR`s at all — the only way
to reach one is through Traefik. That proxy layer is **additive, not a
replacement**: the app-level checks below stay, because Traefik BasicAuth is
still Basic auth and a browser replays it on a forged cross-site POST exactly
as it would replay credentials cached against the app directly.

Everything else about a dashboard is constrained to match its exposure:

- **`GET` is read-only and unauthenticated at the app layer.** Every page
  answers `GET` with no credential.
- **Only the blocklist dashboard has writes**, and only when `ADMIN_API_KEY` is
  set, on a short enumerated list of `POST` routes, each authenticating with
  HTTP Basic against that key before doing anything. With no key they answer
  `405` — not "reachable but unauthorized". The Basic *username* becomes the actor recorded in the
  audit trail (`/audit`), which is why there is no separate actor field — the
  separate admin plane and its `X-Admin-Actor` header are gone. It is not a
  security control: anyone holding the key can claim any name. The logs and
  sizing dashboards have no write routes at all.
- **Cross-site writes are refused.** A browser replays a cached Basic
  credential automatically on every later request to the same origin — Traefik
  BasicAuth included — so without this any page could auto-submit a form at
  the dashboard and exempt an attacker's address. Writes require
  `Sec-Fetch-Site: same-origin` (or `none`) and an `Origin` matching the host;
  a request with neither header — a script, which has no ambient credential to
  abuse — is allowed.
- **No secrets.** The configuration table is built from an explicit list of
  fields, never by iterating the environment. `LLM_API_KEY` and `ADMIN_API_KEY`
  appear only as `set` / `unset`; `AUTH_PEPPER` no longer appears on any
  pipeline's status page at all, since it is `authd`'s secret now, not
  theirs.
- **Nothing unmasked.** Raw log samples are never persisted, so the logs
  dashboard can only ever render masked templates.
- **No JavaScript at all.** Auto-refresh is a `<meta http-equiv="refresh">`
  toggled by nav links, filters are plain `<form method="get">`, and row detail
  is a native `<details>` disclosure.
- **No arbitrary SQL.** Every page is a fixed query with a server-side limit.

[Pico CSS](https://picocss.com) (MIT) is vendored into every binary via the
shared `internal/ui/chrome` package, so a page fetches nothing from the
network at runtime — offline management networks are a supported deployment.

## Threat Shield

Each node's CrowdSec bans IPs from what that one node saw; the fleet has no
shared memory. Threat Shield gives it one: nodes report their ban decisions,
the server computes cross-system consensus, and every node can fetch the
resulting high-confidence blocklist.

It is a **separate pipeline** from the bundle path above — its own binary,
`threatd`, with its own SQLite file. No LLM call, no gate, no fingerprint, no
queue — threat evidence is high-volume factual data, and ingest is
synchronous.

| Endpoint | |
|---|---|
| `POST /blocklist/v1/events` | an edge reports CrowdSec ban decisions; answers `202` with per-rule drop counters |
| `GET /blocklist/v1/feed` | an edge fetches the consensus feed as `text/plain`, with `ETag`/`304` and gzip |

Both use the same HTTP Basic credential as `/logs/v1/bundles`, checked the same
way: Traefik's `forwardAuth` call to `authd`. The full wire contract — request
and response shapes, every drop rule — is
`docs/specs/2026-08-07-threat-events-ingest-contract.md`, which `ns8-crowdsec`
builds its notification template against. There is no scenario→category map:
every scenario CrowdSec reports is accepted and stored verbatim (see below).

An address is published once `BLOCKLIST_MIN_SYSTEMS` **distinct systems**
report it inside `BLOCKLIST_WINDOW`, and the listing expires `BLOCKLIST_TTL`
after the last sighting. The `threat_allowlist` table is applied at promotion,
so adding an entry unlists an address on the next pass; it is maintained
entirely through the blocklist dashboard's write routes (`/blocklist`,
`ADMIN_API_KEY`) — there is no separate admin API any more.

Ingest is fail-closed on authentication and fail-open on content: a malformed
decision is dropped and counted, and the rest of the batch is stored. Private,
loopback, CGNAT, link-local, multicast and ULA addresses are rejected at ingest,
so they never reach the database at all. Beyond the scenario name and the ban
duration nothing is kept — no usernames, no URIs, no user agents.

**Every CrowdSec scenario is accepted.** There is no category map and no
known-scenario allowlist: the hub grows continuously and nodes run third-party
and local collections, so a fixed set would silently discard real evidence. The
scenario is bounded and stripped of control characters, then stored verbatim
and used as-is for grouping and for the daily rollup.

`GET /blocklist/v1/feed` answers `503` until the first consensus pass
succeeds, and after a failed pass it keeps serving the previous snapshot with
its original `generated:` timestamp. It never serves an empty body, because to
a client that imports it an empty list means "no threats" and silently
disables protection.

Try it locally, with the promotion rule relaxed to a single system:

    BLOCKLIST_MIN_SYSTEMS=1 BLOCKLIST_CONSENSUS_INTERVAL=10s \
    UI_LISTEN_ADDR=127.0.0.1:9606 DB_PATH=/tmp/threat.db go run ./cmd/threatd

    INSIGHTS_URL=http://localhost:9595 INSIGHTS_CRED=<system_id>:<auth_token> \
      scripts/insights-api.sh raw /v1/events -X POST \
      -H 'Content-Type: application/json' --data @decisions.json
    INSIGHTS_URL=http://localhost:9595 INSIGHTS_CRED=<system_id>:<auth_token> \
      scripts/insights-api.sh raw /v1/feed

`threatd` run this way is standalone, with no Traefik in front, so it answers
on its own unprefixed routes — the `events`/`feed` subcommands default to
Traefik's prefixed paths on port 80 and cannot be pointed at a bare binary
(see the script's own header comment); `raw` with an explicit `INSIGHTS_URL`
is the way to drive one directly.

## Allowlist management

The allowlist keeps an address off the blocklist however many systems report
it — a shared resolver, a partner's scanner, a customer's own WAN range. It is
applied at promotion rather than at read, so adding an entry unlists the
address on the next consensus pass instead of merely hiding it.

One way in, plus the operator UI that decides:

| endpoint / page | who |
|---|---|
| `POST /blocklist/v1/allowlist-requests` | an edge asks for an address to be exempted |
| blocklist dashboard `/allowlist-requests` | an operator reviews the queue and approves or rejects |
| blocklist dashboard `/blocklist` | an operator adds or removes an allowlist entry directly |
| blocklist dashboard `/audit` | the append-only trail of every decision above |

**Nothing is ever allowlisted automatically.** A customer request is a ranked
review queue entry and nothing else; only an explicit approval creates an
entry. The two consensus rules look symmetric and are not — a wrong blocklist
entry blocks a legitimate address loudly and expires in `BLOCKLIST_TTL`, while
a wrong allowlist entry exempts an attacker silently and permanently. Blocklist
consensus counts nodes reporting *what they observed*; an allowlist request is
an opinion with a subscription credential behind it and nothing more.

**There is no separate admin API any more.** The dashboard's write routes are
the only writer, gated behind `ADMIN_API_KEY` and HTTP Basic:

    ADMIN_API_KEY=... threatd     # UI_LISTEN_ADDR must also be set

The HTTP Basic *username* typed at that prompt is recorded in the append-only
audit table (`/blocklist/audit`) — which exists because `DELETE` destroys the
row that would otherwise hold the trail, and "who removed the exemption that
let this through" is the question that gets asked. It is not a security
control: anyone holding the key can claim any name. In the reference
deployment, Traefik additionally BasicAuths the whole `/blocklist` subtree with
the same `ADMIN_API_KEY` value as the htpasswd password — additive, not a
replacement, since a browser replays either the same way on a forged
cross-site request.

A prefix broader than `/24` (IPv4) or `/48` (IPv6) is refused unless the caller
passes `force`. `0.0.0.0/0` on the allowlist silently disables the entire feed
and nothing anywhere would report it.

Deleting an entry **re-blocks nothing**: the address returns to the blocklist
only if enough distinct systems report it again.

## Fleet sizing

A **third independent pipeline** — its own binary, `sizingd`, its own SQLite
file. Once a day, each NS8 cluster's leader posts one report covering the last
complete UTC day: what each node's hardware is, how hard it worked, and what
it was running. The server scores each node-day (`pressure`, 0–100), folds a
multi-day verdict per node, and publishes cohort hardware baselines — what the
fleet's own machines say a given deployment actually needs. No LLM call, no
gate, no fingerprint, no queue.

| Endpoint | |
|---|---|
| `POST /sizing/v1/reports` | a cluster leader posts one or more complete UTC days; answers `202` with per-rule drop counters |

Same HTTP Basic credential and the same `authd`/Traefik check as the other two
pipelines. The full wire contract is
`docs/specs/2026-09-02-sizing-ingest-contract.md`; the reasoning — including
why `pressure` is computed server-side only, and why a cohort below the
evidence floor is deleted rather than left stale — is
`docs/plans/2026-09-02-fleet-sizing-server.md`. The `ns8-core` reporter that
will call this endpoint is **not yet built** — the sizing dashboard has
nothing to show yet on a fresh deployment.

## API reference

`docs/api/openapi.yaml` (OpenAPI 3.1) describes every HTTP endpoint across all
three pipelines — logs, Threat Shield and fleet sizing — at its public,
prefixed path (`/logs/v1/*`, `/blocklist/v1/*`, `/sizing/v1/*`), with the
schemas mirroring `internal/model` field-for-field. It is what `ns8-crowdsec`,
`ns8-loki` and (eventually) `ns8-core` build clients against. There is no
admin-plane surface to document any more — allowlist writes go through the
blocklist operator UI only.

`/healthz` is deliberately **not** documented: every binary registers it, but
Traefik never routes to it (only the quadlet `HealthCmd=` reaches it, inside
the container), so documenting it would describe an endpoint no client can
reach. The three operator dashboards are absent from it for a different
reason: that surface serves HTML to a human, has no stable contract, and
documenting it would invite scripting against it.

`docs/api/openapi_test.go` walks one expected route list per service and
fails the build if an endpoint is added to a service without being documented
at its prefixed path, documented without a route to back it, or if `/healthz`
ever appears there (`TestHealthzNotDocumented`).

## License

GPL-3.0-or-later. See `LICENSE`.
