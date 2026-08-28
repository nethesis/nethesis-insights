# nethesis-insights

Central anomaly analysis for NethServer fleets. Receives deduplicated log
bundles from nodes, gates them against novelty and deviation before spending
any LLM call, and stores fingerprinted findings that do not repeat.

## Status

Working prototype. It runs a full round trip — authenticated ingest, gating,
an OpenAI-compatible LLM call, server-computed finding identity, and a read
API — against a single SQLite file. Ingest is asynchronous: `POST /v1/bundles`
validates the bundle, puts it on an in-memory queue and answers `202` right
away, so an edge node's HTTP timeout can never abort an analysis in flight.
That in-memory queue is the permanent design.

Authentication forwards the edge's `Authorization: Basic` header verbatim to
an external validator (`AUTH_VALIDATE_URL`, default Nethesis's own
`https://my.nethesis.it/auth`) and caches the outcome — see Configuration
below. The production design still adds an optional Postgres backend. See
the design doc referenced below.

Because analysis is asynchronous, the ingest response says only whether the
bundle was **accepted**. Analysis outcomes are visible in the findings API and
in the `analyses` ledger, not in the POST response. A `503` means the queue is
saturated and the edge should retry the window.

A second, independent pipeline also runs here: **Threat Shield** turns the
fleet's CrowdSec ban decisions into a consensus IP blocklist served back to the
nodes. It shares this server's listener and credentials and nothing else — no
LLM call, no gate, no fingerprint. See [Threat Shield](#threat-shield).

Design documents live in this repository:

- Spec: `docs/specs/2026-08-05-nethesis-insights-design.md`
- Implementation plan: `docs/plans/2026-08-05-nethesis-insights.md` (Tasks 1–10)
- Threat Shield design: `docs/specs/2026-07-28-threat-shield-design.md`
- Threat Shield ingest contract: `docs/specs/2026-08-07-threat-events-ingest-contract.md`

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

`system_id`/`auth_token` are a real NethServer subscription pair — `insightsd`
authenticates by forwarding whatever `Authorization` header it receives to
`AUTH_VALIDATE_URL` (default `https://my.nethesis.it/auth`; see Configuration
below). To test against a private validator instead, set `AUTH_VALIDATE_URL`
to it before starting the server.

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

Get a key at <https://openrouter.ai>. This same combination is also what the
`rl1` dev deployment runs — see `docs/runbooks/dev-machine-rl1.md` for the
production-shaped systemd/quadlet setup instead of ad hoc `go run`.

## Container

Published on every push to `main` and on every tag as a public multi-arch
(`linux/amd64`, `linux/arm64`) image:

    ghcr.io/nethesis/nethesis-insights:latest

Run it:

    podman run -d --name insights -p 9595:9595 \
      -v insights-data:/var/lib/insights \
      -e LLM_BASE_URL=https://api.openai.com/v1 \
      -e LLM_MODEL=gpt-4o-mini -e LLM_API_KEY=sk-... \
      ghcr.io/nethesis/nethesis-insights:latest

The binary is static (`CGO_ENABLED=0`, `modernc.org/sqlite`) and runs as uid
1001; the SQLite database lives in the `/var/lib/insights` volume. Build
locally with `podman build -t nethesis-insights .`.

## Configuration

| Variable | Purpose |
|---|---|
| `LISTEN_ADDR` | HTTP bind address (default `:9595`) |
| `UI_LISTEN_ADDR` | bind address for the optional operator UI (default empty — **the UI is off**). See [Operator UI](#operator-ui) |
| `DB_PATH` | SQLite file path (default `/var/lib/insights/insights.db`) |
| `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY` | OpenAI-compatible provider |
| `LLM_TIMEOUT` | request timeout (default `120s`) |
| `AUTH_VALIDATE_URL` | forward-auth validator (default `https://my.nethesis.it/auth`) |
| `AUTH_PEPPER` | HMAC pepper for the auth cache — secret; unset gets a random, process-lifetime one |
| `AUTH_CACHE_TTL`, `AUTH_NEG_CACHE_TTL` | positive/negative validator-outcome cache lifetimes (default `5m`/`30s`) |
| `AUTH_TIMEOUT` | validator request timeout (default `5s`) |
| `GATE_TOLERANCE` | deviation ratio threshold (default `3.0`) |
| `STALE_AFTER` | finding staleness threshold (default `24h`) |
| `EWMA_ALPHA` | server-side baseline smoothing factor (default `0.3`) |
| `LLM_PRICE_INPUT_PER_MTOK`, `LLM_PRICE_OUTPUT_PER_MTOK` | cost ledger prices (default `0`); e.g. gpt-4o-mini standard tier: `0.15`, `0.60` |
| `LOG_LEVEL` | `debug`, `info`, `warn`, `error` (default `info`) |
| `QUEUE_SIZE` | bundles buffered before ingest answers 503 (default `256`) |
| `QUEUE_WORKERS` | concurrent analyses (default `2`) |
| `ANALYSIS_TIMEOUT` | ceiling for one bundle's analysis (default `5m`) |
| `BLOCKLIST_CONSENSUS_INTERVAL` | how often consensus runs and the feed is regenerated (default `5m`) |
| `BLOCKLIST_WINDOW` | rolling observation window for promotion (default `1h`) |
| `BLOCKLIST_MIN_SYSTEMS` | distinct systems required to publish an address (default `3`) |
| `BLOCKLIST_TTL` | how long a listing survives its last sighting (default `24h`) |
| `BLOCKLIST_MAX_ENTRIES` | hard cap on the served feed (default `50000`) |
| `THREAT_EVENT_RETENTION` | how long raw threat events are kept (default `168h`) |
| `THREAT_MAX_DECISIONS_PER_REQUEST` | per-request decision cap; over-cap batches are truncated, not rejected (default `500`) |
| `ADMIN_LISTEN_ADDR` | bind address for the allowlist admin API (default empty — **the admin plane is off**). Needs `ADMIN_API_KEY` too |
| `ADMIN_API_KEY` | bearer key for the admin API and for the operator UI's write forms — secret; unset means **no admin surface at all**, never a default credential |

`LOG_LEVEL=debug` adds request detail, the reason behind every 401/400/403,
the gate decision and its inputs, prompt size, provider status and timing, and
queue depth. It never logs credentials: the API key is reported only as
`llm_api_key_set=true`, and an authentication failure names the presented
`system_id` but never the secret.

## Operator UI

A built-in, read-only web dashboard over everything `insightsd` records about
its own behaviour — findings, the cost ledger and its `gate_reasons`, spend per
day, known templates, EWMA baselines — plus live process state the database
cannot show: queue depth, uptime, and the effective configuration.

It is **off unless you set `UI_LISTEN_ADDR`**:

    UI_LISTEN_ADDR=127.0.0.1:9596 insightsd

| Route | |
|---|---|
| `/` | row counts, queue depth/capacity/workers, uptime, build, effective config |
| `/systems` | every system, with its template, finding, window, LLM-call and cost totals |
| `/findings` | severity-ranked findings; filter by system, status and severity; each row expands to summary, evidence, suggested action and fingerprint |
| `/analyses` | the cost ledger: window, gated, `llm_called`, tokens, cost, duration, `gate_reasons`, error |
| `/gate` | windows, LLM calls and cost per distinct gate-reason set — why you are paying |
| `/cost` | spend and tokens per UTC day and model |
| `/templates` | what the server already considers known for a system |
| `/baselines` | the EWMA rates the gate falls back on when a bundle carries no `expected` |
| `/blocklist` | the consensus feed with its promotion evidence, plus the allowlist exclusion set |
| `/threat-events` | recent sanitized CrowdSec decisions; filter by system or attacker IP |
| `/threat-stats` | daily threat rollup per scenario, and per-node ingest accounting |
| `/allowlist-requests` | the review queue: what customers asked to have exempted, ranked by how many distinct systems asked |

### Read this before exposing it

**The UI is unauthenticated and fleet-wide.** It shows every system's findings,
templates, baselines and spend, across tenants. The ingest and read APIs are
per-system and authenticated; this is not.

So **bind it to `127.0.0.1` or a trusted management network.** `insightsd` will
not refuse a wider bind — a `0.0.0.0` bind is the administrator's call to make,
not the server's — but it logs a `WARN` at startup whenever the UI is bound
anywhere other than a loopback address, so the choice is never made by accident.

It runs on its own listener, deliberately: the public `:9595` ingest socket
never serves an unauthenticated fleet-wide page, so a reverse-proxy or firewall
mistake there cannot expose it. The container image `EXPOSE`s `9595` only —
publishing the UI port is a deliberate act:

    podman run -d --name insights -p 9595:9595 -p 127.0.0.1:9596:9596 \
      -v insights-data:/var/lib/insights \
      -e UI_LISTEN_ADDR=:9596 \
      -e LLM_BASE_URL=https://api.openai.com/v1 \
      -e LLM_MODEL=gpt-4o-mini -e LLM_API_KEY=sk-... \
      ghcr.io/nethesis/nethesis-insights:latest

Note the container must bind `:9596` internally while `podman` publishes it to
`127.0.0.1` on the host — that is what keeps it off the network.

Everything else about it is constrained to match that exposure:

- **`GET` is read-only and unauthenticated.** Every page answers `GET` with no
  credential, exactly as before.
- **Writes exist only when `ADMIN_API_KEY` is set**, on a short enumerated list
  of `POST` routes, each authenticating with HTTP Basic against that key before
  doing anything. With no key they are `405` — not "reachable but unauthorized".
  The Basic *username* becomes the actor recorded in the audit trail, which is
  why there is no separate actor field. It is not a security control: anyone
  holding the key can claim any name.
- **Cross-site writes are refused.** A browser replays a cached Basic
  credential automatically on every later request to the same origin, so
  without this any page could auto-submit a form at the UI and exempt an
  attacker's address. Writes require `Sec-Fetch-Site: same-origin` (or `none`)
  and an `Origin` matching the host; a request with neither header — a script,
  which has no ambient credential to abuse — is allowed.
- **No secrets.** The configuration table is built from an explicit list of
  fields, never by iterating the environment. `LLM_API_KEY` and `AUTH_PEPPER`
  appear only as `set` / `unset` (or `set (ephemeral)` for a generated pepper).
- **Nothing unmasked.** Raw log samples are never persisted, so the UI can only
  ever render masked templates.
- **No JavaScript at all.** Auto-refresh is a `<meta http-equiv="refresh">`
  toggled by nav links, filters are plain `<form method="get">`, and row detail
  is a native `<details>` disclosure.
- **No arbitrary SQL.** Every page is a fixed query with a server-side limit.

[Pico CSS](https://picocss.com) (MIT) is vendored into the binary, so the page
fetches nothing from the network at runtime — offline management networks are a
supported deployment.

## Threat Shield

Each node's CrowdSec bans IPs from what that one node saw; the fleet has no
shared memory. Threat Shield gives it one: nodes report their ban decisions,
the server computes cross-system consensus, and every node can fetch the
resulting high-confidence blocklist.

It is a **separate pipeline** from the bundle path above. No LLM call, no gate,
no fingerprint, no queue — threat evidence is high-volume factual data, and
ingest is synchronous.

| Endpoint | |
|---|---|
| `POST /v1/threat-events` | an edge reports CrowdSec ban decisions; answers `202` with per-rule drop counters |
| `GET /v1/blocklist` | an edge fetches the consensus feed as `text/plain`, with `ETag`/`304` and gzip |

Both use the same HTTP Basic credential and the same forward-auth validator as
`/v1/bundles`. The full wire contract — request and response shapes, the
scenario→category map, every drop rule — is
`docs/specs/2026-08-07-threat-events-ingest-contract.md`, which `ns8-crowdsec`
builds its notification template against.

An address is published once `BLOCKLIST_MIN_SYSTEMS` **distinct systems**
report it inside `BLOCKLIST_WINDOW`, and the listing expires `BLOCKLIST_TTL`
after the last sighting. The `threat_allowlist` table is applied at promotion,
so adding an entry unlists an address on the next pass; it is maintained
through the admin API (`internal/admin`) and the operator UI.

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

`GET /v1/blocklist` answers `503` until the first consensus pass succeeds, and
after a failed pass it keeps serving the previous snapshot with its original
`generated:` timestamp. It never serves an empty body, because to a client that
imports it an empty list means "no threats" and silently disables protection.

Try it locally, with the promotion rule relaxed to a single system:

    BLOCKLIST_MIN_SYSTEMS=1 BLOCKLIST_CONSENSUS_INTERVAL=10s \
    UI_LISTEN_ADDR=127.0.0.1:9596 DB_PATH=/tmp/insights.db go run ./cmd/insightsd

    scripts/insights-api.sh threat-events decisions.json
    scripts/insights-api.sh blocklist

## Allowlist management

The allowlist keeps an address off the blocklist however many systems report
it — a shared resolver, a partner's scanner, a customer's own WAN range. It is
applied at promotion rather than at read, so adding an entry unlists the
address on the next consensus pass instead of merely hiding it.

Two ways in, plus a customer-facing way to ask:

| endpoint | who |
|---|---|
| `POST /v1/allowlist-requests` | an edge asks for an address to be exempted |
| `/admin/v1/allowlist*` | an operator reviews and decides |
| operator UI `/allowlist-requests`, `/blocklist` | the same decisions, with buttons |

**Nothing is ever allowlisted automatically.** A customer request is a ranked
review queue entry and nothing else; only an explicit approval creates an
entry. The two consensus rules look symmetric and are not — a wrong blocklist
entry blocks a legitimate address loudly and expires in `BLOCKLIST_TTL`, while
a wrong allowlist entry exempts an attacker silently and permanently. Blocklist
consensus counts nodes reporting *what they observed*; an allowlist request is
an opinion with a subscription credential behind it and nothing more.

The admin API is bearer-authenticated with `ADMIN_API_KEY` on its own listener:

    ADMIN_LISTEN_ADDR=127.0.0.1:9597 ADMIN_API_KEY=... insightsd

    curl -H "Authorization: Bearer $KEY" -H 'X-Admin-Actor: alice' \
         -H 'Content-Type: application/json' \
         -d '{"cidr":"203.0.113.0/24","reason":"partner scanner"}' \
         127.0.0.1:9597/admin/v1/allowlist

`X-Admin-Actor` is required on every write and is recorded in an append-only
audit table — which exists because `DELETE` destroys the row that would
otherwise hold the trail, and "who removed the exemption that let this
through" is the question that gets asked. It is not a security control: anyone
holding the key can claim any name.

A prefix broader than `/24` (IPv4) or `/48` (IPv6) is refused unless the caller
passes `force`. `0.0.0.0/0` on the allowlist silently disables the entire feed
and nothing anywhere would report it.

Deleting an entry **re-blocks nothing**: the address returns to the blocklist
only if enough distinct systems report it again.

## API reference

`docs/api/openapi.yaml` (OpenAPI 3.1) describes every HTTP endpoint — the log
pipeline, Threat Shield, the admin plane and `/healthz` — with the schemas
mirroring `internal/model` field-for-field. It is what `ns8-crowdsec` and
`ns8-loki` build clients against.

The operator UI is deliberately absent from it: that surface serves HTML to a
human, has no stable contract, and documenting it would invite scripting
against it.

`docs/api/openapi_test.go` fails the build if an endpoint is added without
being documented.

## License

GPL-3.0-or-later. See `LICENSE`.
