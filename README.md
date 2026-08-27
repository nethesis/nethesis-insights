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

Design documents live in this repository:

- Spec: `docs/specs/2026-08-05-nethesis-insights-design.md`
- Implementation plan: `docs/plans/2026-08-05-nethesis-insights.md` (Tasks 1–10)

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
| `LLM_PRICE_INPUT_PER_MTOK`, `LLM_PRICE_OUTPUT_PER_MTOK` | cost ledger prices (default `0`) |
| `LOG_LEVEL` | `debug`, `info`, `warn`, `error` (default `info`) |
| `QUEUE_SIZE` | bundles buffered before ingest answers 503 (default `256`) |
| `QUEUE_WORKERS` | concurrent analyses (default `2`) |
| `ANALYSIS_TIMEOUT` | ceiling for one bundle's analysis (default `5m`) |

`LOG_LEVEL=debug` adds request detail, the reason behind every 401/400/403,
the gate decision and its inputs, prompt size, provider status and timing, and
queue depth. It never logs credentials: the API key is reported only as
`llm_api_key_set=true`, and an authentication failure names the presented
`system_id` but never the secret.

## License

GPL-3.0-or-later. See `LICENSE`.
