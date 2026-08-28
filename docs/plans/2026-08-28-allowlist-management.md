# Allowlist management: client requests, admin API, writeable UI

## Context

Threat Shield shipped with `threat_allowlist` as a table and nothing else: rows are
added out of band because this server has no admin auth plane. That was the right
scope cut to get consensus working, but it leaves the one control that stops a
false positive being permanent unusable by anyone who isn't willing to open the
database.

Two gaps follow from it:

- **Nobody can ask.** A customer whose partner's scanner got listed has no path
  except a support ticket that ends in someone editing SQLite by hand.
- **Nobody can act.** The operator UI shows the allowlist and cannot change it, so
  the review workflow — the thing the page exists for — dead-ends.

This plan adds a client-facing request path, an authenticated admin API, and the
write half of the operator UI. It does **not** change any rule in
`docs/specs/2026-07-28-threat-shield-design.md`; the allowlist keeps being applied
at promotion, not at read.

## Decisions taken with the user

### 1. No automatic allowlisting. At all.

The original proposal had client requests auto-promote on a consensus counter, the
mirror of the blocklist rule. That is **removed entirely** — not disabled by
default, not behind a flag, not present in the code. There is no path by which a
client request becomes an allowlist entry without a human deciding.

The two consensus rules look symmetric and are not:

| | wrong blocklist entry | wrong allowlist entry |
|---|---|---|
| effect | a legitimate address is blocked | an attacker is exempted fleet-wide |
| visibility | loud — someone complains | silent — nobody reports not being blocked |
| lifetime | self-heals in `BLOCKLIST_TTL` | permanent until a human notices |
| evidence | an attack the reporter observed | an opinion; the requester proves nothing |

Blocklist consensus counts nodes reporting *what they saw*. Allowlist consensus
would count nodes reporting *what they would prefer*, with no evidence behind it
and a subscription credential as the only barrier. Three subscriptions — or one
misconfigured fleet — would buy an attacker a permanent, invisible exemption.
That is a cheaper attack than anything else in this system, so the mechanism does
not get built.

**Client requests still exist.** They are a review queue, not a decision
procedure. The distinct-system counter is kept and does real work: it ranks the
queue, so the shared resolver that forty customers are hitting floats to the top
and the single opportunistic request sinks. Ranking is all it does.

Consequence: `created_by` never takes the value `auto`. Its only values are an
admin actor name and `seed`.

### 2. Operator UI: writes authenticated, reads stay open

`GET` stays exactly as it is today — unauthenticated, fleet-wide, read-only, the
current deployment model unchanged. `POST` routes require HTTP Basic against
`ADMIN_API_KEY`. The browser prompts natively, so this costs no JavaScript, no
cookie, and no session state.

This **weakens a documented invariant** and the change has to be made
deliberately rather than absorbed quietly. Today `internal/ui` enforces "every
route answers GET, anything else is 405, enforced once, centrally" and that rule
is the reason an unauthenticated fleet-wide page is safe to run. It becomes:

> Every route answers GET. A small, explicit, enumerated set of routes also
> answers POST, and every one of those authenticates before doing anything.

The enumeration lives in one place next to the existing central check, so "which
routes can write" stays answerable by reading one function.

### 3. `X-Admin-Actor` on every write

A single shared API key has no attribution: "the allowlist changed" is useless
without "who". Every admin write therefore carries an actor, recorded with the
row and in an append-only audit table.

- **Admin API**: `X-Admin-Actor: alice`, **required** on every write. An optional
  audit field is an audit field that gets omitted, so a write without it is `400`.
- **Operator UI**: the actor is the HTTP Basic *username*. The password is
  `ADMIN_API_KEY`; the username is free text and becomes the actor. One prompt
  supplies both, which is why the UI needs no separate actor field.

This is **not a security control** and must be documented as one that isn't:
anyone holding the key can write any actor they like. It is a readable trail for
reconstructing what happened, nothing more.

## API surface

### Client-facing

Same forward-auth as every other `/v1` route.

```
POST /v1/allowlist-requests
{"cidr": "203.0.113.0/24", "reason": "our partner's vulnerability scanner"}
→ 202 {"accepted": true, "requests": 12}
```

Idempotent per `(cidr, system_id)`: one system counts once, mirroring the
blocklist's distinct-system rule. `requests` is the current distinct-system count,
returned so the caller can see its request landed — never a promise of anything.
A request for an already-allowlisted CIDR is a successful no-op.

`reason` is free text from a customer, so it is length-capped and rendered escaped
in the UI, never trusted.

### Admin

`Authorization: Bearer $ADMIN_API_KEY`, plus `X-Admin-Actor` on writes.

| method | path | |
|---|---|---|
| `GET` | `/admin/v1/allowlist` | current entries |
| `POST` | `/admin/v1/allowlist` | add or update; `200` when already present, never an error |
| `DELETE` | `/admin/v1/allowlist?cidr=…` | remove; `200` when it existed, `404` when it did not |
| `GET` | `/admin/v1/allowlist/requests` | pending requests, ranked by distinct systems |
| `POST` | `/admin/v1/allowlist/requests/approve` | `{"cidr": …}` → creates the entry |
| `POST` | `/admin/v1/allowlist/requests/reject` | `{"cidr": …}` → stops it resurfacing |
| `GET` | `/admin/v1/allowlist/audit` | the append-only write log |

The CIDR travels in the body or a query parameter, never a path segment: a `/` in
a path means every caller has to get `%2F` right, and some proxies normalise it
away.

## Admin listener

Admin routes get **their own listener**, `ADMIN_LISTEN_ADDR`, empty by default,
with the same not-loopback warning `UI_LISTEN_ADDR` already emits.

Rationale: on the public ingest socket the key would be the entire defence. On a
separate, normally loopback-bound socket it is the second layer. Unset
`ADMIN_API_KEY` or unset `ADMIN_LISTEN_ADDR` means the routes are **not
registered** — the failure mode is `404`, and there is never a default credential.

The UI's write routes are the exception: they live on the existing
`UI_LISTEN_ADDR` because that is where the forms are, and they are registered only
when `ADMIN_API_KEY` is set. With no key, the UI is exactly the read-only page it
is today.

## Schema

`threat_allowlist` is reused unchanged. Three new tables, same portability rules
as everything else (ULIDs in Go, unix-millis integers, `ON CONFLICT DO UPDATE`,
JSON as `TEXT`):

```
threat_allowlist_requests(cidr TEXT, system_id TEXT, reason TEXT, created_at INTEGER,
                          PRIMARY KEY (cidr, system_id))
threat_allowlist_reviews(cidr TEXT PRIMARY KEY, state TEXT, decided_by TEXT,
                         decided_at INTEGER, note TEXT)
threat_allowlist_audit(id TEXT PRIMARY KEY, cidr TEXT, action TEXT, actor TEXT,
                       at INTEGER, detail TEXT)
```

- Requests are append-only per system, so the counter survives a rejection and
  "who asked, and when" stays answerable.
- An absent `threat_allowlist_reviews` row means pending; `state` is `approved` or
  `rejected`. Rejected CIDRs stop surfacing in the queue without deleting the
  history of the request.
- The audit table exists because `DELETE` removes the row that would otherwise
  hold the trail. Without it, "who removed the exemption that let this through"
  is unanswerable — which is the question that gets asked.

## Validation guardrails

- **Refuse over-broad prefixes.** `0.0.0.0/0` on the allowlist silently disables
  the entire feed, and nothing anywhere would report it. Reject anything shorter
  than `/24` (v4) or `/48` (v6) unless the caller passes an explicit `force`, and
  say so in the error.
- A bare address normalises to `/32` or `/128`; everything is stored `Masked()`,
  so text equality stays identity as it does for `attacker_ip`.
- Non-public addresses are accepted with a warning rather than rejected: they can
  never be promoted, so allowlisting one is pointless but harmless, and refusing
  it would be a confusing error for a harmless request.
- `reason` and actor are length-capped and must be printable.

## Work

1. **`internal/model`** — `AllowlistRequest`, admin request/response types.
2. **`internal/threat`** — prefix validation (`ParseAllowlistEntry`) with the
   over-broad guardrail, pure and table-tested.
3. **`internal/store`** — the three tables, request upsert, ranked pending query,
   review upsert, audit append, and the reads the UI needs.
4. **`internal/admin`** — a new package for the admin plane: bearer-key
   `Authenticator`, actor extraction, the seven handlers, its own listener. Kept
   out of `internal/api` so the public ingest surface and the admin surface cannot
   accidentally share a route table.
5. **`internal/api`** — `POST /v1/allowlist-requests` alongside the existing
   Threat Shield handlers.
6. **`internal/ui`** — the write half: forms on `/blocklist` for add/delete, a new
   `/allowlist-requests` review page with approve/reject, the enumerated POST
   route set, and Basic auth on it. `GET` untouched.
7. **`cmd/insightsd`** — `ADMIN_API_KEY`, `ADMIN_LISTEN_ADDR`, wiring, the
   loopback warning, `ConfigItem` rows (the key as `set`/`unset`, never the value).
8. **Docs** — `README.md` (config, endpoints, and the UI's changed security
   story), `docs/architecture.md` (the admin plane and the weakened GET-only
   invariant), `docs/user-guide.md` (how to review a request), `AGENTS.md` (the
   invariant change and the no-auto-allowlist rule), `scripts/insights-api.sh`.

## Testing

- **Prefix validation** — table-driven: bare v4/v6, masked and unmasked prefixes,
  the `/24` and `/48` floors with and without `force`, non-public accepted,
  garbage rejected.
- **No auto-promotion** — a test asserting that a CIDR with any number of client
  requests never appears in `threat_allowlist` without an explicit approval. This
  is the executable form of decision 1 and should read as such.
- **Requests** — idempotent per `(cidr, system_id)`; the counter is distinct
  systems, not rows; a rejected CIDR leaves the queue and its requests survive.
- **Admin auth** — no key configured means the routes are absent (`404`); wrong
  key is `401`; missing `X-Admin-Actor` on a write is `400`; the actor reaches the
  audit row.
- **Admin semantics** — `POST` of an existing entry is `200` not an error;
  `DELETE` of a missing entry is `404`; approve creates the entry and records the
  actor; every write appends exactly one audit row.
- **UI** — `GET` still needs no credential on every existing page; each POST route
  is `401` without one and works with one; the Basic username lands in the audit
  as the actor; a `GET` to a write-only path is still `405`.
- **End to end** — request from a client credential, see it ranked in the queue,
  approve it as an admin, watch the address leave the blocklist on the next
  consensus pass.

## Verification

1. `go build ./... && go vet ./... && go test ./... -race -count=1`
2. Round trip locally against a stand-in validator, with
   `ADMIN_API_KEY=dev-key ADMIN_LISTEN_ADDR=127.0.0.1:9597`:
   a client posts a request, `GET /admin/v1/allowlist/requests` ranks it,
   approve it, confirm the entry exists and the audit row names the actor.
3. Confirm the address is gone from `GET /v1/blocklist` within one
   `BLOCKLIST_CONSENSUS_INTERVAL`, and that deleting the allowlist entry does
   **not** re-block it until it is reported again.
4. Confirm with `ADMIN_API_KEY` unset that the admin listener never starts and
   the UI has no write forms at all.

## Out of scope

- Any automatic promotion of a client request. See decision 1.
- Per-user admin identities, roles, or key rotation. One shared key with an actor
  header is the whole model, and its weakness is documented rather than designed
  around.
- Editing the blocklist directly. The blocklist is derived state; the supported
  way to remove an address is to allowlist it.
- Multi-instance concerns, unchanged from Threat Shield.

## Known limits to write down in the docs

- The actor is self-declared. Anyone with the key can claim any name.
- Adding an allowlist entry unlists the address on the next consensus pass
  (≤ `BLOCKLIST_CONSENSUS_INTERVAL`). **Deleting one re-blocks nothing** — the
  address has to be reported again by enough systems first.
- The request queue is customer-supplied free text and is rendered escaped. It is
  a support inbox, and should be read as one.
