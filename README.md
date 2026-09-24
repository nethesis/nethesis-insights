# nethesis-insights

Central log-anomaly analysis, threat-intelligence sharing and hardware sizing
for NethServer fleets. Nodes ship deduplicated, masked log bundles; the server
gates each one against novelty and deviation, calls an LLM **only** when the
gate fires, and stores findings under a server-computed identity so the same
problem is never raised twice.

## Contents

- [What runs](#what-runs)
- [Documentation](#documentation)
- [Build and test](#build-and-test)
- [Running a service locally](#running-a-service-locally)
- [Against a real model](#against-a-real-model)
- [Container images](#container-images)
- [License](#license)

## What runs

Four services behind one Traefik proxy, in one podman pod.

| Service | Does |
|---|---|
| `authd` | forward-auth cache. Traefik calls it before any pipeline sees a request; it validates the node's credential upstream and caches the outcome |
| `insightsd` | the log pipeline: ingest → queue → gate → LLM → fingerprinted findings, at `/logs` |
| `threatd` | Threat Shield: turns the fleet's CrowdSec ban decisions into a consensus IP blocklist served back to nodes, at `/blocklist` |
| `sizingd` | fleet sizing: scores each node's daily workload report and publishes cohort hardware baselines, at `/sizing` |

Three independent pipelines, three SQLite databases, nothing shared between
them but Traefik, `authd` and `internal/platform`. No LLM call, no gate and no
fingerprint outside `insightsd`.

`sizingd` is a **dev preview**: the server side is complete, but the NS8
cluster reporter that would feed it does not exist yet, so it stores nothing
on a fresh deployment.

## Documentation

| | |
|---|---|
| [`docs/admin-guide.md`](docs/admin-guide.md) | Install, remove, configure, and operate a server. Every environment variable. What a finding, template, baseline and cohort are, in plain language. **Start here.** |
| [`docs/architecture.md`](docs/architecture.md) | Package layout, request flow, storage, the gate and fingerprint formulas, and the rules that must not be broken. For changing the code. |
| [`docs/api/openapi.yaml`](docs/api/openapi.yaml) | Every HTTP endpoint, at its public prefixed path. |
| [`docs/api/threat-events-ingest.md`](docs/api/threat-events-ingest.md) | Wire contract `ns8-crowdsec` builds against. |
| [`docs/api/sizing-ingest.md`](docs/api/sizing-ingest.md) | Wire contract `ns8-core` builds against. |
| [`docs/todo.md`](docs/todo.md) | What is not built yet. |

## Build and test

    make build          # one static binary per service into bin/
    make test           # go test ./... -race -count=1
    make check          # license headers + golangci-lint + tests

Or directly:

    go build ./...
    go vet ./...
    go test ./... -race -count=1

    go test ./internal/gate/ -run TestKnownSecurityTemplateAloneNoCall -v
    go test ./internal/prompt/ -update      # regenerate prompt goldens

## Running a service locally

    DB_PATH=/tmp/insights.db UI_LISTEN_ADDR=127.0.0.1:9596 go run ./cmd/insightsd

    curl -u <system_id>:<anything> -X POST 127.0.0.1:9595/v1/bundles -d @bundle.json
    curl -u <system_id>:<anything> '127.0.0.1:9595/v1/findings?since=0'

This runs one service standalone, with no Traefik and no `authd` in front of
it, so it answers on its own unprefixed routes. **Any password works**: the
credential is checked by `authd` in a real deployment, and a standalone
service only checks that the request came from `TRUSTED_PROXY_CIDRS` (default
`127.0.0.0/8`) before reading the `system_id` off the Basic username. Call it
on `127.0.0.1`, not `localhost`: where `localhost` resolves to `::1` first, as
it does on Fedora, the request arrives from outside that range and is refused
with `401`. Calling it from another machine needs that
setting widened — see the admin guide's Authentication section for what that
grants.

`UI_LISTEN_ADDR` turns on the operator dashboard, which is the fastest way to
see what the server actually stored — findings, the cost ledger with its gate
reasons, templates, baselines, queue depth and the effective configuration.

`scripts/insights-api.sh` wraps the same calls for all three pipelines
(`health`, `findings`, `open`, `post <bundle.json>`, `events`, `feed`,
`allowlist-request`, `raw <path>`).

Threat Shield, with a fast consensus pass:

    BLOCKLIST_CONSENSUS_INTERVAL=10s \
    UI_LISTEN_ADDR=127.0.0.1:9606 DB_PATH=/tmp/threat.db go run ./cmd/threatd

The promotion rule cannot be relaxed: `threatd` refuses to start with
`BLOCKLIST_MIN_SYSTEMS` below 3. To see an address promoted, post a report
([format](docs/api/threat-events-ingest.md)) as three systems — standalone,
the Basic username is the system. Leave `system_id` out of the body (the
credential already identifies the reporter) and set `created_at` to now:
`BLOCKLIST_WINDOW` is only 1h, so the ingest doc's own fixed example date is
too old and would be dropped as `dropped_time`.

    now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    payload=$(cat <<EOF
    {
      "schema_version": 1,
      "decisions": [
        {
          "value": "203.0.113.7",
          "scope": "Ip",
          "type": "ban",
          "scenario": "crowdsecurity/ssh-bf",
          "origin": "crowdsec",
          "duration": "3h59m59s",
          "created_at": "$now"
        }
      ]
    }
    EOF
    )

    for s in sys-a sys-b sys-c; do
      curl -u $s:x -X POST -H 'Content-Type: application/json' \
        --data "$payload" 127.0.0.1:9595/v1/events
    done

After the next consensus pass (10s here), the address is on the feed:

    curl -u sys-a:x 127.0.0.1:9595/v1/feed

### The edge collector, without installing the module

The collector script runs standalone on any NS8 node:

    runagent -m loki
    cd ../bin
    curl -o insights-collector https://raw.githubusercontent.com/NethServer/ns8-loki/refs/heads/anomaly_detector/imageroot/bin/insights-collector
    INSIGHTS_SERVER_URL=https://<host> python3 insights-collector

`INSIGHTS_SERVER_URL` is the only required variable, and it takes the **bare
server root** — the collector appends `/logs/v1/bundles` itself. On success it
prints what it shipped:

    shipped 76 templates, 332 lines -> 202 {"accepted":true}

## Against a real model

Any OpenAI-compatible provider works with no code change:

    LLM_BASE_URL=https://openrouter.ai/api/v1 \
    LLM_MODEL=nvidia/nemotron-3-ultra-550b-a55b:free \
    LLM_API_KEY=<key> DB_PATH=/tmp/insights.db \
      go run ./cmd/insightsd

Two things to know before assuming a bug on a free tier:

- **It is slow, not hung.** Some providers return headers immediately and the
  body only when generation finishes, commonly ~105 s later. `LLM_TIMEOUT`
  (default `120s`) and `ANALYSIS_TIMEOUT` (default `5m`) are already sized for
  this — do not lower them. Ingest answers `202` immediately regardless, so
  the delay is invisible at the HTTP layer; watch `LOG_LEVEL=debug` or poll
  `/v1/findings`.
- **A free tier rate-limits and goes away.** Treat a provider error as a
  reason to retry later, not as a regression.

## Container images

One `Containerfile` builds all four binaries, selected by a `SERVICE` build
argument. CI publishes each as its own public multi-arch (`linux/amd64`,
`linux/arm64`) image on every push to `main` and every tag:

    ghcr.io/nethesis/nethesis-insights-authd:latest
    ghcr.io/nethesis/nethesis-insights-insightsd:latest
    ghcr.io/nethesis/nethesis-insights-threatd:latest
    ghcr.io/nethesis/nethesis-insights-sizingd:latest

Every binary is static (`CGO_ENABLED=0`, `modernc.org/sqlite`) and runs as uid
1001. Build one locally with:

    podman build --build-arg SERVICE=threatd -t nethesis-insights-threatd .

To deploy, see the admin guide — the quadlet units and proxy templates are in
`deploy/`.

## License

GPL-3.0-or-later. See [`LICENSE`](LICENSE).
