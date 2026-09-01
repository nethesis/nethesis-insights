<!-- Copyright (C) 2026 Nethesis S.r.l. -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Deployed state: `rl1` dev machine, captured 2026-09-01

Snapshot of what is **actually** running on
`root@rl1.leader.default.gs.nethserver.net`, taken read-only on 2026-09-01 while
measuring the log pipeline's LLM spend. This is a scratch reference, not a source of truth —
`docs/runbooks/dev-machine-rl1.md` is the runbook. Where the two disagree, this
file records reality and the runbook records intent.

Secrets are recorded as set/unset and length only. No secret value appears here.

## Host

| | |
|---|---|
| Hostname | `rl1.leader.default.gs.nethserver.net` |
| OS | Rocky Linux 9.8 (Blue Onyx) |
| Kernel | `5.14.0-687.10.1.el9_8.0.1.x86_64` |
| Uptime at capture | 5 days, 00:20 |
| Installed NS8 modules | `crowdsec1`, `ldapproxy1`, `loki1`, `metrics1`, `traefik1` |
| Cluster `system_id` | `C32D6058-22CD-4C6E-AA2C-32FC69A4E9BF` |

`insights` runs as a bare rootful podman quadlet, **not** an NS8 module, so it
does not appear in `list-installed-modules`.

## Deltas from the runbook

These are the parts a rebuild from `docs/runbooks/dev-machine-rl1.md` would get
wrong. Everything else in the runbook still matches.

| Item | Runbook says | rl1 actually has |
|---|---|---|
| LLM provider | OpenRouter, `nvidia/nemotron-3-ultra-550b-a55b:free` | `https://api.openai.com/v1`, `gpt-4o-mini` |
| Price knobs | not mentioned | `LLM_PRICE_INPUT_PER_MTOK=0.15`, `LLM_PRICE_OUTPUT_PER_MTOK=0.60` |
| Loki `base_url` | `https://controller.gs.nethserver.net/insights` | `http://127.0.0.1:19595` — bypasses Traefik entirely |
| Traefik route `lets_encrypt` | `false` | `true` |
| `BLOCKLIST_MIN_SYSTEMS` | not mentioned | `1` (dev override; real consensus is 3) |
| `AUTH_PEPPER` | not mentioned | unset → **ephemeral, regenerated on every restart**, so the auth cache is cold after each one |
| `ADMIN_API_KEY` | not mentioned | set, 4 characters. Admin plane is still **off** because `ADMIN_LISTEN_ADDR` is empty |
| Unit `Description` | — | still says "OpenRouter/NVIDIA" — stale relative to the env file |

The runbook's documented deviation is still in force: `UI_LISTEN_ADDR=0.0.0.0:9596`,
the container publishes `9596:9596` on all interfaces, and `firewall-cmd
--list-ports` shows `9596/tcp`. The operator UI is unauthenticated and fleet-wide.
See the runbook's "Deviation in force on rl1" section for what that exposes and
how to revert it.

## Container and service

| | |
|---|---|
| Image | `ghcr.io/nethesis/nethesis-insights:latest` |
| Revision label | `4175545d516136e5d23a18f7a762810f3b6375c3` — matches `origin/main` HEAD |
| Created | 2026-09-01 14:05 UTC (restarted during the measurement session) |
| Active since | 2026-09-01 14:05 UTC |
| Ports | `9595/tcp → 127.0.0.1:19595`, `9596/tcp → 0.0.0.0:9596` |

### `/etc/containers/systemd/insights.container`

```ini
[Unit]
Description=nethesis-insights analysis server (test deployment, OpenRouter/NVIDIA)
After=network-online.target
Wants=network-online.target

[Container]
Image=ghcr.io/nethesis/nethesis-insights:latest
ContainerName=insights
PublishPort=127.0.0.1:19595:9595
PublishPort=9596:9596
Volume=insights-data:/var/lib/insights
EnvironmentFile=/etc/insights.env
AutoUpdate=registry

[Service]
Restart=always
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
```

### `/etc/insights.env`

```ini
LISTEN_ADDR=:9595
DB_PATH=/var/lib/insights/insights.db
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini
LLM_API_KEY=<set, 164 chars, sk-proj- prefix>
GATE_TOLERANCE=3.0
STALE_AFTER=24h
EWMA_ALPHA=0.3
LOG_LEVEL=debug
UI_LISTEN_ADDR=0.0.0.0:9596
BLOCKLIST_MIN_SYSTEMS=1
LLM_PRICE_INPUT_PER_MTOK=0.15
LLM_PRICE_OUTPUT_PER_MTOK=0.60
ADMIN_API_KEY=<set, 4 chars>
```

`AUTH_PEPPER` is absent, so the server generates a random one per process. The
operator UI reports it as `set (ephemeral)`.

### Effective configuration (operator UI, `GET /`)

Values not in the env file above are defaults: `LLM_TIMEOUT=2m`,
`AUTH_VALIDATE_URL=https://my.nethesis.it/auth`, `AUTH_CACHE_TTL=5m`,
`AUTH_NEG_CACHE_TTL=30s`, `AUTH_TIMEOUT=5s`, `QUEUE_SIZE=256`, `QUEUE_WORKERS=2`,
`ANALYSIS_TIMEOUT=5m`, `BLOCKLIST_CONSENSUS_INTERVAL=5m`, `BLOCKLIST_WINDOW=1h`,
`BLOCKLIST_TTL=24h`, `BLOCKLIST_MAX_ENTRIES=50000`,
`THREAT_EVENT_RETENTION=168h`, `THREAT_MAX_DECISIONS_PER_REQUEST=500`,
`ADMIN_LISTEN_ADDR` empty.

There is **no `/config` route** on the UI — effective config is rendered on `GET /`
only. (The runbook does not claim otherwise; noting it because it is an easy wrong
guess.)

## Traefik route

```json
{
  "instance": "insights", "priority": 3, "skip_cert_verify": false,
  "host": "controller.gs.nethserver.net", "path": "/insights",
  "url": "http://127.0.0.1:19595", "lets_encrypt": true, "http2https": true,
  "slash_redirect": false, "strip_prefix": true, "user_created": true
}
```

The route exists and works, but `loki1` does not use it — its collector posts
straight to `http://127.0.0.1:19595`.

## Edge (`loki1`) configuration

```json
{
  "retention_days": 365,
  "insights": {
    "status": "active",
    "base_url": "http://127.0.0.1:19595",
    "verify_tls": false,
    "subscription_configured": true,
    "last_run": "Mon 2026-08-31 06:30:59 UTC"
  },
  "cloud_log_manager": {"status": "inactive"},
  "syslog": {"status": "inactive"}
}
```

## Database

`/var/lib/insights/insights.db` inside the container; on the host at
`/var/lib/containers/storage/volumes/insights-data/_data/`. Neither the container
nor the host ships `sqlite3` — read it with the host's Python stdlib `sqlite3`
module in read-only URI mode.

| File | Size |
|---|---|
| `insights.db` | 1.5 MB |
| `insights.db-wal` | 20 KB |
| `insights.db-shm` | 32 KB |

## Measurements, 2026-09-01 14:10 UTC

The database was reset between the 2026-08-31 capture and this one, and three
real multi-module nodes joined the dev fleet. Those three are the interesting
population: `C32D6058` is the rl1 leader itself, quiet and running seven
modules, and it is not representative of a customer node.

| Metric | Value |
|---|---|
| `systems` | 5 — `C32D6058` (rl1 leader), `43BB5957`, `32B5F16E`, `811349FA`, plus a stray `test-system` |
| `system_templates` | 2225 (1056 still `crowdsec1`, now excluded at ingest and inert) |
| `module_baselines` | 587 |
| `findings` | 168, all open on the three new systems; **124 of 168 at `occurrence_count=1`** |
| `analyses` | 183 |

Last 24 h, per system:

| System | modules | windows | LLM calls | gated | avg input tok | cost/window |
|---|---|---|---|---|---|---|
| `C32D6058` | 7 | 79 | 40 | 39 (49%) | ~2,000 | ~$0.0002 |
| `43BB5957` | 15 | 3 | 3 | **0** | 7,750 | $0.0013 |
| `32B5F16E` | 28 | 3 | 3 | **0** | 11,000 | $0.0018 |
| `811349FA` | 29 | 3 | 3 | **0** | 12,140 | $0.0020 |

A real multi-module node fires the gate on **every** window. At 96 windows/day
that is ~$4.9/node/month, ~$13,200/month at 2700 nodes — the spec's ungated
upper bound (§11: ~$16,100) arriving despite the gate.

Gate reasons over the 49 reasoned windows (a window can carry several):
`deviation` 44, `security_surge` 29, `new_templates` 25, `security_new` 9,
`truncated_deviating` 7. Twelve windows fired on deviation alone.

Prompt size on the three real nodes: 32-35 KB, 160-190 templates per window,
templates ~70% of prompt bytes.

## Why it fired (the "before" numbers the fix is measured against)

- **Deviation on noise.** Median `module_baselines.ewma_rate` is 3.1 lines per
  window; 207 of 587 buckets are under 2. The buckets that fired most often are
  the smallest: `<host>/5` (baseline 2.0) 28 times, `metrics1/3` (3.0-3.7) 23,
  `loki1/6` (3.2-4.0) 4. With `GATE_TOLERANCE=3.0` a bucket that normally emits
  two lines fires at seven.
- **`security_surge` rides along**, since it requires a deviating module.
- **Novelty fired on one template.** 409 new templates in 24 h excluding
  `crowdsec1`, 245 seen exactly once, 364 of 409 at priority 3.
- **Templates are near-duplicates.** Of 710 live templates (excluding
  `crowdsec1` and rl1's own self-logs) a Drain-style clustering finds 249
  shapes (35%); 512 of the 710 sit in a multi-member cluster. `metrics1` alone
  contributed 223 templates that are 5 conditions. The server's regex
  canonicalization (`model.CanonicalTemplate`) collapses these to 526 (74%);
  the rest is structural and is edge work — see `loki-plan.md`.
- **No ceiling existed.** `internal/budget` was unbuilt.

## Configuration this deployment still needs

The env file predates the cost controls, so `rl1` runs them at their defaults.
The defaults are the intended production values, but two are worth setting
explicitly here:

```ini
LLM_DAILY_SPEND_CAP_USD=1        # off by default; cheap insurance on a dev box
LOG_LEVEL=info                   # debug mints a template per request when the
                                 # server is co-located with a collector
```

## Notes carried into the fix

- **The `ns8-loki` masker leaks more than two fields.** The CrowdSec case (GeoIP
  country code, ban duration) was only the visible one. Percentages, fractional
  parts, single-digit counters, FQDNs, request-path tails and quoted object
  names all survive masking, and each one mints a template per value. The full
  list, with line references and fixes, is in `loki-plan.md`; the server now
  collapses the measured classes on receipt rather than depending on that work
  landing first.
- **Existing `crowdsec1` rows go inert, not deleted.** Once bundles stop carrying
  the module, its 982 `system_templates` rows and its `module_baselines` rows are
  never read again. Leaving them is deliberate; removing them would be a data
  migration nobody asked for.
- **rl1 analyses its own logs, and no production node does.** `insightsd` and
  `loki1` are co-located here, so the server's own journal output is collected
  and shipped back to it. 439 of 550 host-bucket templates (79%) are `insights`
  lines, including 204 distinct `gate decision` messages. That is a closed loop:
  the server logs a gate decision, loki ships it as a novel template, the next
  window fires on `new_templates`, and the resulting analysis logs another gate
  decision. `LOG_LEVEL=debug` and unmasked `duration_ms=` values make it worse —
  every operator-UI request mints a template too.

  On the real fleet the server is central and edge nodes run only `loki1` and
  `crowdsec1`, so this loop does not exist. Treat a permanently non-zero
  `new_templates` on rl1 as this artifact until it is ruled out; it is not
  evidence that the gate is broken.

  Closed by `PIPELINE_EXCLUDE_SERVICES=insights`, which is the default. The
  digest is still not filtered by service, so `insights` log volume continues to
  count toward the host bucket's deviation baseline.

- **Findings are fingerprint `v3`** as of the canonicalization change. Each bump
  changes every finding's identity by design (spec §6.2): superseded, not
  silently re-raised, and never backfilled.

- **124 of 168 findings sit at `occurrence_count=1`.** That is a model-output
  convergence problem, not a gating one: the `ALREADY KNOWN` block is not
  stopping one-shot restatements. Worth re-measuring after the prompt selection
  change, which folds template variants and should give the model fewer ways to
  word the same condition.
