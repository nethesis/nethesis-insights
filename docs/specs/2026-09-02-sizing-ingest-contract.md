# Sizing report ingest contract

**Status:** implemented (server); reporter not yet built
**Date:** 2026-09-02
**Server:** `nethesis-insights`
**Primary client:** `ns8-core` (`cluster/bin/send-sizing-report`, leader only)

This is the wire contract between a NethServer 8 cluster and the fleet-sizing
pipeline in `nethesis-insights`. It is the authority for anything a client needs
to build a request; the reasoning behind each rule is in
`docs/plans/2026-09-02-fleet-sizing-server.md`.

Sizing is a **third independent pipeline**, beside the log-bundle pipeline and
Threat Shield. It shares the HTTP listener, `internal/auth`, the SQLite file and
`model.ModuleFamily` — and nothing else. No LLM call, no gate, no fingerprint,
no queue.

| method | path | who |
|---|---|---|
| `POST` | `/v1/sizing-reports` | the cluster leader reports one or more complete UTC days |

## Authentication

HTTP Basic, `system_id:auth_token`, the same credential and the same forward-auth
validator as `/v1/bundles` and `/v1/threat-events`. There is no separate key.

Fail-closed on authentication: `401` on a rejected credential, `503` when the
validator itself is unreachable. A `503` is retryable; a `401` is not.

Fail-open on content: a malformed node, family or metric is dropped with a
counter and the rest of the report is stored. A cluster with one broken module
must not lose the other fifteen.

## The unit is a cluster-day, and it is absolute

**One `system_id` is a cluster, not a machine.** Prometheus on the leader holds
`node_*` series for every node in the cluster, labelled `node="<numeric id>"`, so
one report carries N nodes. The storage key is `(system_id, node_id, day)`.

**A report covers whole, already-finished UTC days.** `day` is sent explicitly as
`YYYY-MM-DD` and the reporter must compute every value over the absolute range
`[day 00:00 UTC, day+1 00:00 UTC)` — never a relative `[24h]` window. This is
what makes the three-times-a-day send schedule safe: the second and third sends
of a day are byte-identical restatements of the first, the upsert **recomputes**
the row rather than accumulating into it, and a retry after a network failure
costs nothing.

`days` is an array so a node that was offline can backfill. A `day` outside
`[today − 15, today − 1]` (UTC, inclusive) is rejected and counted: the day
before today is the newest complete day, and anything older than Prometheus'
15-day retention cannot have been computed from real data.

## Request

`Content-Type: application/json`, optionally `Content-Encoding: gzip`, at most
8 MiB after decompression.

```json
{
  "schema_version": 1,
  "system_id": "<system_id>",
  "reporter_version": "1.0.0",
  "days": [
    {
      "day": "2026-09-01",
      "nodes": [
        {
          "node_id": 1,
          "metrics_present": true,
          "sample_coverage": 0.998,
          "hardware": {
            "cpu_cores": 4,
            "mem_total_bytes": 8054087680,
            "cpu_model": "AMD EPYC 7282 16-Core Processor",
            "os_id": "rocky",
            "os_version": "9.4",
            "kernel_release": "5.14.0-427.el9.x86_64",
            "virtualization": "kvm"
          },
          "resources": {
            "ram_util_p95": 0.41,
            "ram_used_bytes_p95": 3300000000,
            "cpu_util_p95": 0.12,
            "cpu_cores_used_p95": 0.48,
            "load15_per_core_p95": 0.31,
            "fs_used_frac_max": 0.62,
            "fs_days_to_full": 412.0,
            "disk_io_util_p95": 0.03
          },
          "stress": {
            "iowait_busy_frac": 0.01,
            "swapin_pps_p95": 0,
            "oom_kills": 0,
            "reboots": 0
          },
          "modules": [
            {
              "family": "nethvoice",
              "instances": 2,
              "facts_ok": 2,
              "versions": ["1.4.2"],
              "workload": { "users": 130, "trunks": 4, "queues": 6 }
            }
          ]
        }
      ],
      "cluster": {
        "user_domains": [
          { "total_users": 210, "total_groups": 18, "active_users": 190 }
        ]
      }
    }
  ]
}
```

`node_id`, `cpu_cores`, `mem_total_bytes`, `instances` and `facts_ok` are
logically integers, but the server accepts a JSON number written with a
fractional part there too (`"mem_total_bytes": 8054087680.0` as well as
`8054087680`) and truncates it toward zero. A reporter deriving these from
Prometheus, which has no integer type, can only ever emit a float literal, and
rejecting one would 400 the entire report. This tolerance applies to those
five integer fields only — a JSON string, boolean, array or object in any
field, `workload` included, is still a `400`.

`system_id` is optional — the credential already identifies the reporter — but a
mismatch when present is `403`, never something to silently override. Same rule
as `/v1/bundles` and `/v1/threat-events`.

`schema_version` must equal `1` (`model.SizingSchemaVersion`). It versions
independently of the bundle and threat envelopes.

### `resources` and `stress`

Both are **fixed-vocabulary** objects of finite, non-negative numbers. A key the
server does not know is ignored; a key whose value is negative, `NaN`, `Inf` or
not a number is dropped with a counter, and the term it feeds becomes **absent**
rather than zero.

| field | unit | meaning |
|---|---|---|
| `ram_util_p95` | fraction 0–1 | p95 of `1 - MemAvailable/MemTotal` |
| `ram_used_bytes_p95` | bytes | p95 of `MemTotal - MemAvailable` |
| `cpu_util_p95` | fraction 0–1 | p95 of non-idle CPU fraction |
| `cpu_cores_used_p95` | cores | `cpu_util_p95 × cores`, sent explicitly |
| `load15_per_core_p95` | ratio | p95 of `node_load15 / cores` |
| `fs_used_frac_max` | fraction 0–1 | worst filesystem's used fraction |
| `fs_days_to_full` | days | linear projection; omit when not shrinking |
| `disk_io_util_p95` | fraction 0–1 | stored, **not scored** (meaningless on NVMe) |
| `iowait_busy_frac` | fraction 0–1 | fraction of the day above the iowait threshold |
| `swapin_pps_p95` | pages/s | p95 of `pswpin` rate — swap **in**, not out |
| `oom_kills` | count | kernel OOM kills over the day |
| `reboots` | count | `changes(node_boot_time_seconds[1d])` |

Use **`MemAvailable`**, never `MemFree`: on any healthy Linux box `MemFree` is
near zero because the page cache holds the rest, and a report built on it says
every node in the fleet is full.

Percentiles come from `quantile_over_time(0.95, expr[1d:5m])`; durations from
`avg_over_time((expr > bool T)[1d:5m])`. **Never send a 24-hour `max`.** A max of
a 5-minute average cannot distinguish a 25-minute nightly backup (1.7 % of the
day) from a node starved for 7 hours (30 %) — a duration has a denominator and a
max does not.

`sample_coverage` is the fraction of the day for which samples actually exist
(`count_over_time(up[1d]) / expected`). Below `0.80` the server stores the row
but computes no pressure: a node that was off for 18 hours is not a
low-pressure node.

`metrics_present: false` marks a **degraded report** — Prometheus unreachable or
the metrics module removed. Send hardware, OS and the module inventory anyway:
"what is deployed on what hardware" is still worth answering, and dropping the
report instead would bias the fleet view toward metrics-healthy clusters.

### `modules[].workload` — an open map of numbers

`workload` is an open `string → number` map, and **"number" is the entire privacy
control**.

Open vocabulary for the same reason Threat Shield accepts every CrowdSec
scenario: the NS8 module set grows continuously, and a typed column per product
means every new product's metric is silently discarded until a server release.

Numbers-only because *an FQDN, an IP address, a hostname or a DMI serial cannot
be encoded in a float*. That is a stronger guarantee than any field blocklist
someone has to maintain.

Values must be:

- **finite** — no `NaN`, no `Inf`, no strings, no booleans, no nested objects;
- **non-negative**;
- **extensive** — summable across instances of a family. Counts, bytes and rates
  qualify. Versions, ratios, percentages, timestamps and identifiers do not; send
  a version in `versions` instead.

**A non-numeric value is a `400` for the whole report, not a dropped field.**
The type *is* the guarantee: a JSON string, boolean, array or object in a
workload map cannot decode into the wire type at all, so the request is refused
before the sanitizer sees it. That is deliberate and is the loud failure a
reporter bug deserves — `dropped_metric_value` counts values that *were*
numbers but were not finite and non-negative, and `dropped_metric_key` counts
keys that failed the shape check. Everything else about content is fail-open.

Shape caps, applied by truncating and counting rather than by rejecting:

| limit | value |
|---|---|
| metric key | `^[a-z][a-z0-9_]{0,39}$` |
| metrics per family | 32 |
| families per node | 64 |
| nodes per report | 16 (`SIZING_MAX_NODES_PER_REPORT`) |
| days per report | 15 |

`family` is the module **family**, not the instance: `nethvoice`, never
`nethvoice20`. The server normalizes with `model.ModuleFamily` anyway, and folds
duplicate families inside one node by summing `instances`, `facts_ok` and every
workload metric.

`facts_ok` is load-bearing and must be sent honestly. `get-facts` fails per
instance, and **a zero mailbox count from a failed call is indistinguishable from
a genuinely empty mail server**. The cohort pass treats `facts_ok > 0` with a
zero count as "idle, bucket it" and `facts_ok == 0` as "unknown, exclude it".

### `cluster`

`user_domains` is a list of per-domain objects, each an open map of numbers under
exactly the same rules as `workload`. The server sums them across domains
(extensive) and stores them per `(system_id, day)`. This is where
`total_users` / `total_groups` / `active_users` from `cluster/get-facts` land —
`openldap` has no `get-facts` of its own and needs none.

### Free text

The only free-text fields in the entire payload are `cpu_model`, `os_id`,
`os_version`, `kernel_release`, `virtualization` and `versions[]`. Each is
trimmed, stripped of control characters and length-capped on arrival.

**Never send** `node_uname_info{nodename}`, `ns8_node_info{fqdn}`,
`ns8_node_main_ip_address{address}`, a DMI `serial` or a `board_asset_tag`. They
are identifying, the server has no use for them, and the operator UI's `GET` is
unauthenticated and fleet-wide.

## Response

`202 Accepted`, always, unless the request was rejected outright — including when
every node in the report was dropped. The counters are how a reporter, and the
operator UI, sees why.

```json
{
  "accepted": true,
  "stored_days": 1,
  "stored_nodes": 3,
  "dropped": {
    "accepted_nodes": 3,
    "accepted_modules": 11,
    "accepted_metrics": 34,
    "dropped_day": 0,
    "dropped_duplicate": 0,
    "dropped_node": 0,
    "dropped_family": 1,
    "dropped_metric_key": 0,
    "dropped_metric_value": 2,
    "dropped_resource_value": 0,
    "truncated_days": 0,
    "truncated_nodes": 0,
    "truncated_families": 0,
    "truncated_metrics": 0
  }
}
```

Every counter is also persisted per `(day, system_id)` in `sizing_ingest_daily`,
where it **accumulates** across the day's sends — unlike the node rows, which
recompute. So a report posted three times shows three requests' worth of
counters and exactly one set of measurements, which is the intended behaviour and
is asserted by a test.

| status | when |
|---|---|
| `202` | accepted (see above) |
| `400` | unparseable body, bad gzip, or `schema_version` ≠ 1 |
| `401` | invalid or missing credentials |
| `403` | `system_id` present and not the authenticated system |
| `405` | method other than `POST` |
| `413` | body over 8 MiB |
| `503` | forward-auth validator unreachable, or the store failed to write |

## Client rules

1. **Leader only.** Skip on a worker node: Prometheus and the agent bus that
   answers `get-facts` both live on the leader.
2. **Send the last complete UTC day**, and backfill up to 7 earlier days that
   have not been acknowledged. Never send today.
3. **Retry on `503` and on a transport error; never on `400`, `403` or `413`.**
   Redelivery is free by construction, so a delayed report is always better than
   a lost one.
4. **Stagger.** `OnCalendar=03:00` with `RandomizedDelaySec=2h` — 2700 clusters
   posting at the same instant is the one load pattern this endpoint cannot
   absorb.
5. **Ship a partial result rather than failing.** No Prometheus → send
   `metrics_present: false`. One module's `get-facts` raising → omit that family
   or send it with `facts_ok` short of `instances`.
6. Turning insights off in the Logs UI turns sizing off too: the endpoint comes
   from the same `INSIGHTS_SERVER_URL` the log collector uses, so there is one
   on/off switch and no second place to point at a different server.
