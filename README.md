# nethesis-insights

Central anomaly analysis for NethServer fleets. Receives deduplicated log
bundles from nodes, gates them against novelty and deviation before spending
any LLM call, and stores fingerprinted findings that do not repeat.

## Status

Working prototype. It runs a full round trip — authenticated ingest, gating,
an OpenAI-compatible LLM call, server-computed finding identity, and a read
API — against a single SQLite file, with the LLM call made synchronously
inside the request. The production design adds Redpanda as a durable buffer
between ingest and analysis, an external forward-auth validator, and an
optional Postgres backend. See the design doc referenced below.

Design documents live in this repository:

- Spec: `docs/specs/2026-08-05-nethesis-insights-design.md`
- Implementation plan: `docs/plans/2026-08-05-nethesis-insights.md` (Tasks 1–10)

## Development

    go build ./...
    go vet ./...
    go test ./... -race -count=1

Manual round trip against a stub provider:

    go run ./hack/stubserver &                     # OpenAI-compatible stub on :8081
    LLM_BASE_URL=http://127.0.0.1:8081 LLM_MODEL=stub-model LLM_API_KEY=x \
    AUTH_SYSTEM_ID=abc123 AUTH_SECRET=s3cret DB_PATH=/tmp/insights.db \
      go run ./cmd/insightsd

    curl -u abc123:s3cret -X POST localhost:9595/v1/bundles -d @bundle.json
    curl -u abc123:s3cret 'localhost:9595/v1/findings?since=0'

## Container

Published on every push to `main` and on every tag as a public multi-arch
(`linux/amd64`, `linux/arm64`) image:

    ghcr.io/nethesis/nethesis-insights:latest

Run it:

    podman run -d --name insights -p 9595:9595 \
      -v insights-data:/var/lib/insights \
      -e AUTH_SYSTEM_ID=abc123 -e AUTH_SECRET=s3cret \
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
| `AUTH_SYSTEM_ID`, `AUTH_SECRET` | prototype static credential |
| `GATE_TOLERANCE` | deviation ratio threshold (default `3.0`) |
| `STALE_AFTER` | finding staleness threshold (default `24h`) |
| `EWMA_ALPHA` | server-side baseline smoothing factor (default `0.3`) |
| `LLM_PRICE_INPUT_PER_MTOK`, `LLM_PRICE_OUTPUT_PER_MTOK` | cost ledger prices (default `0`) |

## License

GPL-3.0-or-later. See `LICENSE`.
