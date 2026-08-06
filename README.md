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

Design: `docs/superpowers/specs/2026-08-05-nethesis-insights-design.md` and
`docs/superpowers/plans/2026-08-05-nethesis-insights.md` in the `ns8-loki`
repository.

## Development

    go build ./...
    go vet ./...
    go test ./... -race -count=1

## Configuration

| Variable | Purpose |
|---|---|
| `LISTEN_ADDR` | HTTP bind address (default `:9595`) |
| `DB_PATH` | SQLite file path |
| `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY` | OpenAI-compatible provider |
| `LLM_TIMEOUT` | request timeout |
| `AUTH_SYSTEM_ID`, `AUTH_SECRET` | prototype static credential |
| `GATE_TOLERANCE` | deviation ratio threshold (default 3.0) |
| `STALE_AFTER` | finding staleness threshold |
| `EWMA_ALPHA` | server-side baseline smoothing factor |
| `LLM_PRICE_INPUT_PER_MTOK`, `LLM_PRICE_OUTPUT_PER_MTOK` | cost ledger prices |

## License

GPL-3.0-or-later. See `LICENSE`.
