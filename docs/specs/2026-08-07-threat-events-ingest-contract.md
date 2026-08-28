# Threat events ingest contract

**Status:** implemented
**Date:** 2026-08-07
**Server:** `nethesis-insights`
**Primary client:** `ns8-crowdsec` (CrowdSec `notification-http` plugin)

This is the wire contract between a NethServer 8 node's CrowdSec and the Threat
Shield pipeline in `nethesis-insights`. It is the authority for anything a client
needs to build a request; the rules behind it are in
`docs/specs/2026-07-28-threat-shield-design.md`.

These two paths supersede both `POST /v1/blocklist-evidence` (the stub in
`ns8-crowdsec`'s plan) and `POST /api/systems/threat-events` +
`GET /api/systems/threat-shield/blocklist` (the `my`-flavoured paths in the
design document).

| method | path | who |
|---|---|---|
| `POST` | `/v1/threat-events` | the edge reports ban decisions |
| `GET`  | `/v1/blocklist` | the edge fetches the consensus feed |

## Authentication

HTTP Basic, `system_id:auth_token`, the same credential and the same forward-auth
validator as `/v1/bundles`. There is no separate key, no API token and no
per-tier feed: every subscriber fetches the same global list.

Both endpoints are fail-closed on authentication: `401` on a rejected
credential, `503` when the validator itself is unreachable. A `503` is
retryable; a `401` is not.

## `POST /v1/threat-events`

Request body, `Content-Type: application/json`, optionally
`Content-Encoding: gzip`, at most 8 MiB:

```json
{
  "schema_version": 1,
  "system_id": "<system_id>",
  "decisions": [
    {
      "id": 1234,
      "value": "203.0.113.7",
      "scope": "Ip",
      "type": "ban",
      "scenario": "crowdsecurity/ssh-bf",
      "origin": "crowdsec",
      "duration": "3h59m59s",
      "created_at": "2026-08-07T14:00:00Z"
    }
  ]
}
```

The `decisions` array mirrors CrowdSec's `models.Decision`, exactly as
`cscli decisions list --output json` emits it, batched per `models.Alert` the
plugin fires on. Send the decisions verbatim: the server owns the
scenario→category map, so supporting a new scenario is a server release rather
than a fleet-wide template change.

- `schema_version` must be `1`. A different value is `400`.
- `system_id` is **optional**. The credential already identifies the reporter;
  when the field is present and names a different system the request is `403`,
  because that is a broken reporter rather than something to silently override.
- `id` is accepted and ignored — the server derives its own identity.

### Response

`202 Accepted`, always, unless the request was rejected outright:

```json
{
  "accepted": true,
  "stored": 3,
  "duplicates": 1,
  "dropped": {
    "accepted": 4,
    "dropped_type": 0,
    "dropped_scope": 0,
    "dropped_origin": 2,
    "dropped_bad_ip": 0,
    "dropped_private_ip": 1,
    "dropped_scenario": 5,
    "dropped_time": 0,
    "truncated": 0
  }
}
```

- `stored` — new rows written.
- `duplicates` — decisions that matched an existing row and were ignored.
- `dropped` — the full per-rule accounting for the batch, including `accepted`,
  the number of decisions that passed every filter. `stored` is normally lower
  than `accepted`, because decisions describing the same `(ip, category,
  second)` are folded into one row with a summed hit count.

| status | meaning |
|---|---|
| `202` | accepted (possibly with everything dropped — see the counters) |
| `400` | unparseable body, bad gzip, or wrong `schema_version` |
| `401` | invalid credential |
| `403` | `system_id` does not match the authenticated system |
| `405` | method other than `POST` |
| `503` | validator unreachable, or the store failed |

**Ingest is fail-closed on authentication and fail-open on content.** A
malformed decision is dropped and counted; the rest of the batch is stored. A
reporter under active attack must not lose its whole batch to one bad row.

**Advance the watermark only on `2xx`.** A server outage should produce delayed
events, not lost ones. Redelivery is safe: `(system_id, attacker_ip, category,
observed_at)` is unique, so a repeated batch cannot inflate anything.

### Drop rules

Applied in this order; each drop increments exactly one counter.

1. **Cap** — at most 500 decisions per request
   (`THREAT_MAX_DECISIONS_PER_REQUEST`). Over-cap requests are **truncated, not
   rejected** (`truncated`).
2. **`type`** must be `ban`, case-insensitive (`dropped_type`).
3. **`scope`** must be `Ip`, case-insensitive (`dropped_scope`).
4. **`origin`** must be `crowdsec` or `cscli` (`dropped_origin`). CAPI, `lists`
   and console decisions are refused: re-reporting CrowdSec's community
   blocklist would manufacture agreement between systems that never
   independently observed anything.
5. **`value`** must parse as a single IP address (`dropped_bad_ip`; a CIDR
   lands here) and must be public unicast (`dropped_private_ip`). Rejected:
   RFC1918, loopback, unspecified, CGNAT `100.64.0.0/10`, link-local including
   IMDS `169.254.169.254`, multicast, IPv6 ULA `fc00::/7`, benchmark
   `198.18.0.0/15`, and the address the server saw the report arrive from. The
   documentation ranges are *not* rejected.
6. **`scenario`** must be in the category map below (`dropped_scenario`). An
   unmapped scenario is recorded by name and surfaced in the operator UI, which
   is how the map grows.
7. **`created_at`** must parse as RFC3339 (`dropped_time`). A value more than
   24 h in the future is clamped to the server clock rather than dropped.

Only `scenario` and `duration_seconds` are retained as metadata. Nothing
free-text is stored: no usernames, no URIs, no user agents.

### Scenario → category map

The v1 category set is fixed at `port_scan`, `ssh_bruteforce`, `http_exploit`
and `sip_probe`. Unmapped scenarios are dropped rather than bucketed into a
catch-all.

| category | scenarios |
|---|---|
| `ssh_bruteforce` | `crowdsecurity/ssh-bf`, `crowdsecurity/ssh-bf_user-enum`, `crowdsecurity/ssh-slow-bf`, `crowdsecurity/ssh-slow-bf_user-enum` |
| `http_exploit` | `crowdsecurity/http-probing`, `crowdsecurity/http-bad-user-agent`, `crowdsecurity/http-path-traversal-probing`, `crowdsecurity/http-sensitive-files`, `crowdsecurity/http-sqli-probing`, `crowdsecurity/http-xss-probing`, `crowdsecurity/http-backdoors-attempts`, `crowdsecurity/http-crawl-non_statics`, `crowdsecurity/http-cve-probing` |
| `port_scan` | `crowdsecurity/port-scan`, `crowdsecurity/iptables-scan-multi_ports` |
| `sip_probe` | `crowdsecurity/asterisk-user-enum`, `crowdsecurity/asterisk-bf`, `crowdsecurity/asterisk-bf_user-enum` |

The map lives in `internal/threat/category.go`. This table is a copy of it;
the code is the authority.

## `GET /v1/blocklist`

Plain text, one address per line, two comment lines of header:

```
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
ETag: "sha256-9f2b..."
Cache-Control: max-age=900
Vary: Accept-Encoding

# nethesis threat shield v1
# generated: 2026-08-28T10:05:00Z  entries: 1843  rule: 3 systems / 1h0m0s window / 24h0m0s ttl
198.51.100.44
203.0.113.12
```

- `If-None-Match` with the current `ETag` returns `304`. At a five-minute
  regeneration cadence this is the normal answer to most polls.
- `Accept-Encoding: gzip` returns a gzip body with `Content-Encoding: gzip`.
- Order is deterministic: IPv4 before IPv6, numeric within each family.
- The list is capped at `BLOCKLIST_MAX_ENTRIES` (50 000 by default).
- `503` means no consensus pass has succeeded yet. It never means "empty".

| status | meaning |
|---|---|
| `200` | the current feed |
| `304` | unchanged since the client's `ETag` |
| `401` | invalid credential |
| `405` | method other than `GET` or `HEAD` |
| `503` | validator unreachable, or no snapshot generated yet |

### Client rules

**Never write an empty list on error.** An empty file means "no threats", which
silently disables protection. Replace the local file only on a `200` with a
well-formed body — header line present, sane size. On any failure keep the
previous file and log. The `generated:` timestamp in the header is there so a
client can decide to distrust a stale feed.

For `ns8-crowdsec`, import under a dedicated scenario name so Nethesis-sourced
bans stay distinguishable from local and CAPI decisions, and so there is a clean
escape hatch:

```
cscli decisions import -i threat-shield.txt --format values \
      --duration 24h --scenario nethesis/threat-shield
cscli decisions delete --scenario nethesis/threat-shield
```

## Promotion rule

An address is published once **≥3 distinct systems** (`BLOCKLIST_MIN_SYSTEMS`)
report it within a rolling **60 minute** window (`BLOCKLIST_WINDOW`). The entry
expires **24 h** after the last report (`BLOCKLIST_TTL`); a new report refreshes
the TTL without changing when the address was first listed.

Distinct *systems*, not distinct reports: one node reporting an address a
hundred times is one system, and one node reporting it under two categories is
still one system.

Two exclusions are applied at promotion, so adding to either one unlists an
address on the next pass rather than merely hiding it:

- the hand-maintained allowlist (`threat_allowlist`);
- the fleet egress set — every address a reporter has been seen connecting
  from, which is what stops one misconfigured appliance getting the fleet's own
  WAN address listed.

There is no cross-organization requirement, because this server has no
organization identity. Three systems in one fleet therefore count as consensus;
the two exclusions above are the compensating controls.
