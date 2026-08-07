# Threat Shield server side in nethesis-insights

## Context

Each node's CrowdSec bans IPs from what that one node saw; the fleet has no shared
memory. `ns8-crowdsec` is ready to push every ban decision out over CrowdSec's
notification-http plugin (`/home/giacomo/projects/ns8/ns8-crowdsec/crowdsec.plan`),
but it is blocked on a server that accepts them — its "server contract" section is
an explicit stub and names this as a hard external dependency.

The design for that server is `docs/specs/2026-07-28-threat-shield-design.md` (copied
into this repo from `my`), written when the server was going to be the `my` platform:
Postgres with `INET`/`JSONB`/`ARRAY_AGG`, daily partitions, Redis materialization,
`collect`/`backend` split, org-scoped auth. Its §4 schema, §6 materialization and §9
`my` APIs/RBAC/UI do not apply here; its rules do.
nethesis-insights is now a standalone project with none of that — SQLite today and
Postgres later behind one `Store` interface, so the schema must stay dialect-agnostic,
and there is no Redis and no organization identity.

This plan implements the server side here: ingest of CrowdSec decisions, consensus
promotion, and the authenticated blocklist feed. It carries the design's *rules*
(promotion thresholds, sanitizer, allowlist-at-promotion, fleet self-protection,
dark launch, never-serve-blank) and re-expresses its *mechanics* in this codebase's
constraints.

Decisions taken with the user:

- Scope: ingest + consensus + feed. No allowlist/participation admin API — this repo
  has appliance Basic auth only, no admin plane.
- Wire format: raw CrowdSec decisions. The server owns the scenario→category map, so
  a new scenario is a server release, not a fleet-wide template change.
- Org identity: **out entirely.** Promotion counts distinct systems only. No
  `tenant_id`, no `distinct_orgs`, no cross-org flag — this server has no organization
  identity, and carrying a column that is always empty is worse than not having it. The
  design's cross-org requirement (D5) can be reintroduced with the column when auth
  starts returning a tenant; nothing here blocks that.
- Pipeline: fully separate from the bundle/gate/LLM path. No LLM call, no fingerprint,
  no gate. Threat evidence is high-volume factual data.

## API paths

Harmonized with the existing surface (`/v1/bundles`, `/v1/findings`, `/healthz`) —
flat `/v1/<plural-noun>`, HTTP Basic with the same `Authenticator`:

| method | path | who |
|---|---|---|
| `POST` | `/v1/threat-events` | edge (ns8-crowdsec) reports ban decisions |
| `GET`  | `/v1/blocklist` | edge fetches the consensus feed, `text/plain` |

This supersedes both `POST /v1/blocklist-evidence` (ns8-crowdsec's stub) and
`/api/systems/threat-events` + `/api/systems/threat-shield/blocklist` (the spec's
`my`-flavoured paths). Recording that rename in the ingest-contract doc below is part
of the work, since `ns8-crowdsec` must be told.

## Work

### 1. `internal/model/threat.go` — wire types

`Decision` (mirrors CrowdSec `models.Decision`: `value`, `scope`, `type`, `scenario`,
`origin`, `duration`, `created_at`), `ThreatReport` (`schema_version`, optional
`system_id`, `decisions[]`), and `ThreatEvent` (the sanitized internal form:
`attacker_ip`, `category`, `observed_at`, `hit_count`, `metadata`). Follow the
existing `model.Bundle`/`model.Finding` style — plain structs, JSON tags, no logic
beyond small helpers.

### 2. `internal/threat/` — pure, the highest-value surface

No I/O, no clock beyond an injected `now`, table-driven tests. Same purity contract as
`gate`/`fingerprint`/`prompt`, and for the same reason: this is where a bug becomes a
data-protection incident.

- `category.go` — `CategoryFor(scenario string) (string, bool)`. `crowdsecurity/ssh-bf`
  → `ssh_bruteforce`, `crowdsecurity/http-probing` and friends → `http_exploit`,
  port-scan scenarios → `port_scan`, asterisk/SIP → `sip_probe`. Unknown scenario is
  **dropped with a counter**, not mapped to a catch-all — D3 fixes the category set.
- `sanitize.go` — `Sanitize(r ThreatReport, opts) (events []ThreatEvent, dropped Counters)`:
  - `attacker_ip` must parse as a public unicast address via `net/netip`. Drop RFC1918,
    loopback, CGNAT `100.64/10`, link-local, IMDS `169.254.169.254`, multicast, IPv6 ULA,
    and the reporter's own source IP. Hard filter **at ingest**, so private addressing
    never reaches the store.
  - Only `type: ban`, `scope: Ip` decisions are kept.
  - **Local-origin only**: drop `origin` values that are CAPI/community
    (`CAPI`, `lists`, …), keeping `crowdsec`/`cscli`. Re-reporting CrowdSec's community
    list would manufacture cross-org agreement and poison the feed (spec §7.2).
  - Metadata reduced to a fixed typed allowlist (`scenario`, `duration_seconds`); no
    free-text, no usernames, no URIs.
  - Caps: 500 decisions per request, **truncate with a counter, never reject** — a probe
    under active attack must not lose its whole batch.
- `allowlist.go` — `Allowlist.Contains(ip)` over parsed `netip.Prefix`, used at
  promotion. Replaces the spec's PG-only `<<=` operator with portable Go.

### 3. `internal/store` — schema and queries

New tables in `store.Init` alongside the existing ones, obeying the repo's portability
rules (ULID ids in Go, `INTEGER` unix-millis, JSON as `TEXT`, `ON CONFLICT … DO UPDATE`,
no `INET`/`JSONB`/`ARRAY`/partitions):

```
threat_events(id TEXT PK, system_id TEXT, attacker_ip TEXT,
              category TEXT, observed_at INTEGER, hit_count INTEGER, metadata TEXT)
  UNIQUE (system_id, attacker_ip, category, observed_at)   -- redelivery idempotency
  INDEX (attacker_ip, observed_at), INDEX (observed_at)
threat_blocklist(attacker_ip TEXT PK, first_listed_at, last_seen_at, expires_at INTEGER,
                 distinct_systems INTEGER, categories TEXT, listing_reason TEXT)
threat_allowlist(cidr TEXT PK, reason TEXT, created_by TEXT, created_at, expires_at INTEGER)
threat_daily_stats(day TEXT, category TEXT, distinct_ips INTEGER, total_hits INTEGER,
                   PRIMARY KEY (day, category))
system_egress(system_id TEXT PK, source_ip TEXT, updated_at INTEGER)
```

`attacker_ip` is stored as the **normalized** `netip.Addr.String()` so text equality is
identity. `categories` and `listing_reason` are JSON `TEXT`, parsed in Go.

Store methods, added to the `Store` interface (its stub/fake in tests grows with it):

- `InsertThreatEvents(ctx, []ThreatEventRow) (inserted, duplicates int, err error)` —
  one transaction, `ON CONFLICT DO NOTHING`, so a redelivered batch cannot inflate
  `hit_count`.
- `RecordSystemEgress(ctx, systemID, sourceIP, now)` — fleet self-protection input.
- `ConsensusCandidates(ctx, since int64) ([]CandidateRow, error)` — `GROUP BY
  attacker_ip, category` returning `COUNT(DISTINCT system_id)`, `SUM(hit_count)`,
  `MAX(observed_at)`. Grouping per category keeps the SQL to
  `COUNT(DISTINCT)`/`SUM`, which both dialects share — the category list is assembled in
  Go rather than with `ARRAY_AGG`/`GROUP_CONCAT`/`STRING_AGG`, which do not.
- `UpsertBlocklistEntries`, `ExpireBlocklist(now)`, `ListBlocklist(now)`,
  `RollupDailyStats(day)`, `PruneThreatEvents(olderThan)`, `Allowlist(now)`,
  `EgressIPs()`.

### 4. `internal/blocklist/` — consensus and snapshot

- `consensus.go` — `Run(ctx, now)`: read candidates for the last `BLOCKLIST_WINDOW`,
  fold per IP in Go, drop anything in the allowlist or in the fleet-egress set, promote
  those clearing `MIN_SYSTEMS`, upsert with `expires_at = last_seen + TTL`, expire, roll
  up daily stats, prune events past retention, then rebuild the snapshot.
  `first_listed_at` is never touched on update; `listing_reason` snapshots the promotion
  evidence, because raw events expire in 7 days and "why is this IP listed?" gets asked
  later by whoever's customer just got blocked.
- `snapshot.go` — renders the sorted plain-text body with the header comment
  (`# generated: … entries: … rule: …`), computes the SHA-256 ETag, pre-gzips, holds it
  behind a `sync.RWMutex`. Replaces the in-memory `ts:blocklist:v1:*` Redis keys of the
  spec. **Only a successful generation replaces the snapshot**, so a store hiccup serves
  a stale list, never a blank one.
- Driven by a ticker in `cmd/insightsd` at `BLOCKLIST_CONSENSUS_INTERVAL`, started after
  the store opens and stopped before shutdown — same lifecycle shape as
  `queue.Start`/`Stop` in `cmd/insightsd/main.go`. No Redis `SET NX` lock is needed while
  this is one process; the lock question returns with multi-instance deployment and is
  called out in the doc.

### 5. `internal/api` — two handlers

New `internal/api/threat.go`, reusing `s.authenticate`, `reject` and `writeJSONError`
from `internal/api/api.go` so rejections stay explainable in the debug log exactly like
the bundle path:

- `POST /v1/threat-events` — authenticate, decode (8 MiB limit, gzip aware, same as
  bundles), `system_id` optional but must equal the authenticated one when present
  (consistent with `handleBundles`), sanitize, record egress IP, insert. Answers
  `202 {"accepted":true,"stored":N,"dropped":{...}}`. Fail-closed on auth, fail-open on
  content: a malformed decision is dropped with a counter, the rest of the batch is kept.
  Synchronous — no LLM, so no queue.
- `GET /v1/blocklist` — authenticate, serve the snapshot: `text/plain`, `ETag`,
  `Cache-Control`, `304` on `If-None-Match`, gzip when accepted. Returns `503` while
  `BLOCKLIST_PUBLISHED=false` (dark launch, D9/§8) — publishing a five-entry list to
  production firewalls teaches administrators to ignore it.

### 6. Wiring, config, docs

`cmd/insightsd/main.go` — new env, all with defaults so an existing deployment keeps
working untouched:

`BLOCKLIST_PUBLISHED` (false), `BLOCKLIST_CONSENSUS_INTERVAL` (5m), `BLOCKLIST_WINDOW`
(60m), `BLOCKLIST_MIN_SYSTEMS` (3), `BLOCKLIST_TTL` (24h),
`BLOCKLIST_MAX_ENTRIES` (50000), `THREAT_EVENT_RETENTION` (168h),
`THREAT_MAX_DECISIONS_PER_REQUEST` (500).

Docs: `README.md` config table plus an endpoint section, and a new
`docs/specs/2026-08-07-threat-events-ingest-contract.md` — the exact URL, auth, request
and response shapes, scenario→category map and drop rules. `ns8-crowdsec` builds its
Go template against that file, so it has to exist before that repo's work can ship.

## Files

| file | change |
|---|---|
| `internal/model/threat.go` | new — wire and internal types |
| `internal/threat/{category,sanitize,allowlist}.go` + tests | new — pure |
| `internal/store/store.go` | extend `Store` iface, add tables to `Init` |
| `internal/store/threat.go` + test | new — inserts, consensus query, feed reads, prune |
| `internal/blocklist/{consensus,snapshot}.go` + tests | new |
| `internal/api/threat.go`, `internal/api/api_test.go` | new handlers, routes in `NewServer` |
| `cmd/insightsd/main.go` | env, ticker start/stop, route wiring |
| `README.md`, `docs/specs/2026-08-07-threat-events-ingest-contract.md` | contract |

## Testing

- **Sanitizer** — table-driven over every IP class (RFC1918, CGNAT, IMDS, multicast,
  IPv6 ULA, loopback, reporter's own IP), CAPI-origin rejection, non-ban/non-Ip scopes,
  metadata allowlist, 500-cap truncation counting rather than rejecting. A sanitizer bug
  is a data-protection incident, so this is the deepest table.
- **Category map** — known scenarios map, unknown scenario drops and counts.
- **Consensus** — boundary fixtures against temp-file SQLite: 2 distinct systems does not
  promote and 3 does; the same system reporting three times does not (it is
  `COUNT(DISTINCT system_id)`, not row count); allowlisted IP never promotes;
  fleet-egress IP never promotes; `expires_at` refreshes on new hits while
  `first_listed_at` holds; expiry deletes.
- **Idempotency** — the same batch posted twice inserts once, asserting the unique index
  actually holds.
- **Feed** — ETag/`304`, gzip, entry cap, dark-launch `503`, and that a failed generation
  keeps serving the previous snapshot.
- **API** — `202` with counters, `401` unauthenticated, `403` on foreign `system_id`,
  malformed decision dropped while the batch survives.

Whole suite must stay green under `go test ./... -race -count=1`.

## Verification

1. `go build ./... && go vet ./... && go test ./... -race -count=1`.
2. Local round trip, no containers:
   ```
   BLOCKLIST_PUBLISHED=true BLOCKLIST_MIN_SYSTEMS=1 LOG_LEVEL=debug \
   AUTH_SYSTEM_ID=abc123 AUTH_SECRET=s3cret DB_PATH=/tmp/i.db go run ./cmd/insightsd
   curl -u abc123:s3cret -X POST localhost:9595/v1/threat-events -d @decisions.json
   curl -u abc123:s3cret -D- localhost:9595/v1/blocklist          # entry present, ETag set
   curl -u abc123:s3cret -H 'If-None-Match: "<etag>"' -o /dev/null -w '%{http_code}\n' \
        localhost:9595/v1/blocklist                                # 304
   ```
3. Sanitizer proof by hand: post a batch mixing `10.0.0.5`, `100.64.1.1`,
   `169.254.169.254` and one public IP → only the public one is stored
   (`hack/insights-sql.sh sql "SELECT attacker_ip FROM threat_events;"`).
4. Deploy to rl1 the established way (push to `main`, CI publishes, `podman pull` +
   `systemctl restart insights`), keep `BLOCKLIST_PUBLISHED=false` there so the feed
   stays dark, and confirm with `journalctl -u insights` that the consensus ticker runs
   every 5 minutes without touching the bundle pipeline.
5. End to end against the real `crowdsec1` module on rl1 once `ns8-crowdsec` implements
   its side against the contract doc: `cscli decisions add --ip <test-ip> --duration 1m`,
   then assert the row lands with the node's real `system_id`.

## Out of scope

Allowlist and participation admin APIs (no admin auth plane here), the feed importer and
forwarder inside `ns8-crowdsec` (that repo's own plan), NethSecurity's telegraf reporter,
multi-instance consensus locking, and un-darkening the feed — which waits on the §8
adoption floor, not on code.

Organization identity is out with it: without a cross-org requirement, three systems of
one fleet agreeing is treated as consensus, so a single misconfigured customer can list
an IP. The allowlist and the fleet-egress exclusion are the compensating controls until
auth supplies a tenant.
