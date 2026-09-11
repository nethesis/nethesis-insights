<!--
Copyright (C) 2026 Nethesis S.r.l.
SPDX-License-Identifier: GPL-3.0-or-later
-->
# Administrator guide

Everything needed to run a `nethesis-insights` server: what it does, how to
install and remove it, every setting, and how to read the operator
dashboards. Plain language throughout — no Go required.

For how the code is built, see `docs/architecture.md`. For the HTTP contract,
see `docs/api/openapi.yaml`.

## Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Installing the server](#installing-the-server)
  - [1. Install the container runtime](#1-install-the-container-runtime)
  - [2. Bound the journal](#2-bound-the-journal)
  - [3. Fetch the images](#3-fetch-the-images)
  - [4. Install the units](#4-install-the-units)
  - [5. Create the secrets](#5-create-the-secrets)
  - [6. Set the hostname and render the proxy configuration](#6-set-the-hostname-and-render-the-proxy-configuration)
  - [7. Start](#7-start)
  - [8. Verify](#8-verify)
- [Configuration](#configuration)
  - [Read by all four](#read-by-all-four)
  - [Read by the three pipelines](#read-by-the-three-pipelines)
  - [`authd`](#authd)
  - [`insightsd`](#insightsd)
  - [`threatd`](#threatd)
  - [`sizingd`](#sizingd)
  - [Read by no service](#read-by-no-service)
- [Authentication](#authentication)
- [Connecting nodes](#connecting-nodes)
- [Upgrading the server](#upgrading-the-server)
- [Removing the server](#removing-the-server)
- [Metrics](#metrics)
- [The operator UI](#the-operator-ui)
  - [Before exposing a dashboard](#before-exposing-a-dashboard)
  - [Signing in](#signing-in)
- [How the log pipeline works](#how-the-log-pipeline-works)
  - [1. The bundle](#1-the-bundle)
  - [2. Templates: the shape of a log line, not the line itself](#2-templates-the-shape-of-a-log-line-not-the-line-itself)
  - [3. The gate: deciding if it's worth asking the AI](#3-the-gate-deciding-if-its-worth-asking-the-ai)
  - [3a. The spending ceiling](#3a-the-spending-ceiling)
  - [4. Baselines: "what's normal" for a module](#4-baselines-whats-normal-for-a-module)
  - [5. The analysis: when the AI actually looks](#5-the-analysis-when-the-ai-actually-looks)
  - [6. Findings: the actual output](#6-findings-the-actual-output)
- [Threat Shield](#threat-shield)
  - [How it works, in four steps](#how-it-works-in-four-steps)
  - [The safety net](#the-safety-net)
  - [One thing the server refuses to do](#one-thing-the-server-refuses-to-do)
  - [The honest caveat](#the-honest-caveat)
  - [Asking for an address to be left alone](#asking-for-an-address-to-be-left-alone)
- [Fleet sizing](#fleet-sizing)
  - [What a sizing report is](#what-a-sizing-report-is)
  - [Pressure: one number for "is this node undersized?"](#pressure-one-number-for-is-this-node-undersized)
  - [The verdict: a single bad day is not a verdict](#the-verdict-a-single-bad-day-is-not-a-verdict)
  - [Cohort baselines: what the fleet says a deployment needs](#cohort-baselines-what-the-fleet-says-a-deployment-needs)
  - [And most of the thresholds are still guesses](#and-most-of-the-thresholds-are-still-guesses)
- [What this system does not do](#what-this-system-does-not-do)

## Overview

NethServer machines produce logs constantly. Somewhere in that stream are the
handful of lines that mean "something is actually wrong" — a service crash-
looping, a login being brute-forced, a disk filling up. Finding those lines
by hand across ~2700 machines is not realistic.

`nethesis-insights` is one central server that does this instead: every node
still watches its own logs and packages up what changed, but the *decision*
to spend money asking an AI about it, and the *memory* of what's already been
reported, both live here — one place, not one per machine.

## Requirements

One dedicated host. Nothing here is clustered: the four services, the reverse
proxy and the three databases all run on one machine, and exactly one instance
of each service may run against a given database.

| | |
|---|---|
| OS | RHEL-family Linux 9 or 10 — Rocky, Alma, RHEL. SELinux enforcing is supported. |
| Container runtime | rootful `podman` 5 or newer, with `container-selinux`, from the distribution repositories |
| CPU and memory | 2 vCPU and 2 GB RAM is enough for a fleet of a few thousand nodes. The databases are small and the model runs off-box. |
| Disk | 20 GB. The three SQLite files stay in the low hundreds of MB at fleet scale; the journal is capped during install. |
| Network | ports 80 and 443 free on the host **and reachable from the internet**. The certificate is issued over HTTP-01, so port 80 must be genuinely reachable, not merely unfiltered. |
| DNS | one A record pointing at the host. Everything is served from that one hostname. |
| Credentials | an OpenAI-compatible API key, if the log pipeline is to call a model. Threat Shield and fleet sizing need none. |

Give the host to this deployment alone. The install caps the journal
system-wide, which is only correct on a machine that runs nothing else.

## Installing the server

Run everything as `root`. You need the repository's `deploy/` directory on the
host — copy it there, or clone the repository.

### 1. Install the container runtime

    dnf install -y podman container-selinux httpd-tools
    install -d -m 755 /etc/containers/systemd

`httpd-tools` is only for `htpasswd` in step 5.

Check that quadlet is present, since the whole deployment is quadlet units:

    podman --version                                                 # >= 5
    ls /usr/lib/systemd/system-generators/podman-system-generator     # exists

### 2. Bound the journal

Five containers log here — the reverse proxy with access logging on, and four
services with one line per request each — so one client request can produce
five journal entries. Left unset, journald's ceiling is 10% of the filesystem
and it will use it.

    install -D -m 644 deploy/journald/insights.conf \
        /etc/systemd/journald.conf.d/insights.conf
    systemctl restart systemd-journald

This is host-wide. It is the reason the host must be dedicated.

### 3. Fetch the images

    for s in authd insightsd threatd sizingd; do
      podman pull ghcr.io/nethesis/nethesis-insights-$s:latest
    done
    podman pull docker.io/library/traefik:v3.7.13

The images are public and multi-arch (`linux/amd64`, `linux/arm64`); no
registry login is needed. The four `ghcr.io` pulls are a warm-up rather than a
prerequisite: those units carry `Pull=newer`, so the first `systemctl start`
fetches them anyway. The `traefik` pull is required — that unit is pinned to a
fixed tag and has no `Pull=` line. To build them on the host instead, use
`podman build --build-arg SERVICE=<service> -t localhost/insights-<service> .`
and change each unit's `Image=` line to match.

### 4. Install the units

    install -m 644 deploy/quadlet/*.pod       /etc/containers/systemd/
    install -m 644 deploy/quadlet/*.volume    /etc/containers/systemd/
    install -m 644 deploy/quadlet/*.container /etc/containers/systemd/

Ten units: one pod, four volumes (the three databases and the certificate
store), and five containers. All five containers share **one** pod and
therefore one network namespace. That is not a packaging convenience — it is
what makes the proxy's connection to a service a real loopback connection with
no address translation in the path, which is what the default
`TRUSTED_PROXY_CIDRS=127.0.0.0/8` depends on. See "Authentication".

The pod publishes ports 80 and 443. No container publishes a port of its own,
which is what keeps the three operator dashboards reachable only through the
proxy.

### 5. Create the secrets

Five environment files, mode 0600, none of them in the repository. Four are
written here by hand; the fifth (`metrics.env`) is generated by a script at
the end of this step.

    install -d -m 755 /etc/insights
    umask 077
    printf 'AUTH_PEPPER=%s\n'   "$(openssl rand -hex 32)" > /etc/insights/authd.env
    printf 'LLM_API_KEY=%s\n'   "<your model API key>"    > /etc/insights/insightsd.env
    printf 'ADMIN_API_KEY=%s\n' "$(openssl rand -hex 24)" > /etc/insights/threatd.env
    : > /etc/insights/sizingd.env
    chmod 600 /etc/insights/*.env

`sizingd` has no secret of its own. Create the empty file anyway: its unit
names that file unconditionally and will fail to start without it.

Then the operator password file for the proxy. Every operator gets a line, and
they all share one password — the `ADMIN_API_KEY` value. The **username** is
what gets recorded as the actor on any change made from the blocklist
dashboard, which is why each operator gets their own line:

    install -d -m 755 /etc/traefik
    ADMIN_API_KEY=$(sed -n 's/^ADMIN_API_KEY=//p' /etc/insights/threatd.env)
    htpasswd -nbB alice "$ADMIN_API_KEY" >  /etc/traefik/operators.htpasswd
    htpasswd -nbB bob   "$ADMIN_API_KEY" >> /etc/traefik/operators.htpasswd
    chmod 640 /etc/traefik/operators.htpasswd

An unrecognized username is rejected by the proxy before the request reaches a
dashboard. The actor is a readable trail, not an authorization boundary:
anyone holding the key can claim any name.

Finally the metrics scrape credential, which is scripted rather than typed
because it is generated, hashed and written to two files at once:

    bash deploy/gen-metrics-auth.sh

That writes the fifth environment file, `/etc/insights/metrics.env`
(`METRICS_AUTH_PASSWORD`, mode 0600, read by no Go binary), and hashes it into
`/etc/traefik/metrics.htpasswd` (a single `prometheus` user, mode 0640). It is
idempotent — re-running it on an upgrade reuses the existing password rather
than invalidating a scrape config somebody already deployed — and it never
prints the password.

It is a **separate** credential on purpose: not `ADMIN_API_KEY`, not a node's
`system_id:auth_token`. A monitoring system holds a password that cannot also
write to the blocklist dashboard or post bundles, so revoking it touches
nothing else. See "Metrics" below for what the endpoints it opens expose.

### 6. Set the hostname and render the proxy configuration

Two values are per-deployment and live outside the repository:

    cat > /etc/insights/deploy.env <<'END'
    INSIGHTS_HOST=insights.example.com
    ACME_EMAIL=admin@example.com
    END

Then render:

    bash deploy/render.sh

This writes `/etc/traefik/traefik.yaml` and
`/etc/traefik/dynamic/dynamic.yaml`. It fails loudly if either value is unset
rather than rendering a broken config. Re-run it after any change to either
value.

The routing half lands in a **directory** the proxy watches, rather than in a
single file, so that an optional extra set of routers can be added beside it
without editing it — see [the development monitoring
stack](../deploy/dev/README.md). Nothing else in a production deployment puts
a file there, and every file in that directory shares one namespace: a second
file must never redefine a router, service or middleware `dynamic.yaml`
already names.

### 7. Start

    systemctl daemon-reload
    systemctl start insights-pod.service
    systemctl start authd.service
    systemctl start insightsd.service threatd.service sizingd.service
    systemctl start traefik.service

Quadlet generates these units from the files installed in step 4, so
`systemctl enable` is neither needed nor available. `WantedBy=multi-user.target`
inside each unit is what starts them at boot.

### 8. Verify

    systemctl is-active insights-pod authd insightsd threatd sizingd traefik
    podman ps --format '{{.Names}}\t{{.Status}}'

The four services report `healthy`. The proxy reports only `Up` — its unit
carries no health check, so that is its correct steady state.

Confirm every container actually joined the pod, because one that did not is a
dashboard exposed on its own port:

    podman pod inspect insights --format '{{range .Containers}}{{.Name}} {{end}}'

Then confirm the host's port surface:

    ss -tlnp | grep -E ':(80|443|959[0-9]|96[0-9][0-9])\b'

**Expect 80 and 443 only.** A 95xx or 96xx port here means a container kept a
published port and is not in the pod. That is an unauthenticated fleet-wide
dashboard on a public interface — stop and fix it before going further.

Finally, the routed path:

    curl -sS -o /dev/null -w '%{http_code}\n' https://insights.example.com/blocklist/v1/feed

`401` is the correct answer: the route works, the proxy is asking for a
credential. The certificate is issued on this first request to a routed path.
A request to `/` matches no route, triggers no issuance, and is served the
proxy's own self-signed certificate — that is expected, not a fault.

If issuance fails, check in this order: does the hostname resolve to this host
from outside, is the proxy actually bound to `:80`, does the rendered
`traefik.yaml` name the right hostname. Let's Encrypt rate-limits failed
orders, so switch `caServer` to its staging directory while iterating.

## Configuration

Four services, four sets of environment variables. Each service reads its own
and nothing else. The units installed in step 4 already set everything that is
not a secret; these tables are for changing a default.

**Quadlet passes these files with `--env-file` when the container is created,
so editing one changes nothing until `systemctl restart`.**

### Read by all four

| Variable | Purpose |
|---|---|
| `LOG_LEVEL` | `debug`, `info`, `warn`, `error` (default `info`) |

`debug` adds request detail, the reason behind every 401/400/403, the gate
decision and its inputs, prompt size, provider status and timing, and queue
depth. It never logs a credential: the model API key appears only as
`llm_api_key_set=true`, and an authentication failure names the presented
`system_id` and never the secret.

### Read by the three pipelines

`insightsd`, `threatd` and `sizingd`. Not `authd`.

| Variable | Purpose |
|---|---|
| `LISTEN_ADDR` | bind address for this pipeline's client API (default `:9595`; the units give each pipeline its own port) |
| `UI_LISTEN_ADDR` | bind address for this pipeline's operator dashboard (default empty — **the dashboard is off**) |
| `UI_BASE_PATH` | path prefix the dashboard builds its own links with, e.g. `/blocklist`. Must match the prefix the proxy strips, or every link the page emits escapes the subtree |
| `DB_PATH` | this pipeline's SQLite file (defaults `/var/lib/insights/insights.db`, `/var/lib/threat/threat.db`, `/var/lib/sizing/sizing.db`) |
| `TRUSTED_PROXY_CIDRS` | CIDRs, comma-separated, whose connections this pipeline accepts as already authenticated and whose `X-Forwarded-For` it believes (default `127.0.0.0/8`). **This is the entire security boundary** — see "Authentication" |

### `authd`

| Variable | Purpose |
|---|---|
| `AUTH_LISTEN_ADDR` | bind address (default `:9590`) |
| `AUTH_VALIDATE_URL` | the external validator (default `https://my.nethesis.it/auth`) |
| `AUTH_PEPPER` | HMAC pepper for the credential cache — secret. Unset gets a random, process-lifetime one, which empties the cache on every restart |
| `AUTH_CACHE_TTL`, `AUTH_NEG_CACHE_TTL` | how long a positive/negative validator outcome is cached (default `5m`/`30s`) |
| `AUTH_CACHE_MAX_ENTRIES`, `AUTH_NEG_CACHE_MAX_ENTRIES` | cache size caps, counted separately so a flood of wrong credentials cannot evict the fleet's valid entries (default `8192`/`4096`, about 3 MB together) |
| `AUTH_TIMEOUT` | validator request timeout (default `5s`) |

### `insightsd`

| Variable | Purpose |
|---|---|
| `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY` | any OpenAI-compatible provider |
| `LLM_TIMEOUT` | request timeout (default `120s`) |
| `GATE_TOLERANCE` | deviation ratio that counts as a surge (default `3.0`) |
| `GATE_MIN_EXPECTED` | smallest normal rate a bucket needs before its ratio is trusted (default `10`) |
| `GATE_MIN_OBSERVED` | smallest line count that can be called a surge (default `20`) |
| `GATE_MIN_NEW_TEMPLATES` | novel templates required before novelty alone fires (default `3`). A new security template always fires on its own |
| `PROMPT_MAX_AMBIENT` | templates carried as background context beyond the ones the gate fired on (default `60`) |
| `LLM_MAX_CONCURRENCY` | model calls in flight at once (default `4`) |
| `LLM_MAX_CALLS_PER_SYSTEM_PER_DAY` | hard per-machine ceiling, UTC day (default `100`). A machine ships 96 windows a day, so this no longer binds normal operation — it is a backstop against a window being retried in a loop. `LLM_DAILY_SPEND_CAP_USD` is the limit that bounds a day's spend |
| `LLM_DAILY_SPEND_CAP_USD` | fleet spend ceiling for the UTC day (default `0`, off). On breach the gate narrows to security-only rather than stopping |
| `LLM_PRICE_INPUT_PER_MTOK`, `LLM_PRICE_OUTPUT_PER_MTOK` | prices for the cost ledger (default `0`). Without them the ledger records zero cost |
| `PIPELINE_EXCLUDE_MODULES` | modules dropped from every bundle before analysis (default `crowdsec`, which has its own pipeline). Matches a module **family** or an exact instance id — configure the family, since NS8 numbers instances per cluster and `crowdsec1` excludes nothing on a node running `crowdsec3` |
| `PIPELINE_EXCLUDE_SERVICES` | syslog identifiers dropped the same way, matched against the tag on each masked host line (default `insights`, so a co-located server does not analyse its own logs) |
| `STALE_AFTER` | how long without a recurrence before a finding is presumed resolved (default `24h`) |
| `EWMA_ALPHA` | baseline smoothing weight, must be in `(0, 1]` (default `0.3`). Not validated — a value outside that range silently produces a nonsensical baseline |
| `QUEUE_SIZE` | bundles buffered before ingest answers 503 (default `256`) |
| `QUEUE_WORKERS` | concurrent analyses (default `2`) |
| `ANALYSIS_TIMEOUT` | ceiling for one bundle's analysis (default `5m`) |
| `TEMPLATE_RETENTION` | how long a template survives with no fresh sighting (default `9600h`, 400 days). **The most sensitive of the three retentions** — this table is the gate's memory of what it has seen, so pruning it faster than a real recurring line recurs makes that line pay for a model call as if it were new |
| `FINDING_RETENTION` | how long a stale finding survives (default `4320h`, 180 days). An open finding is never pruned at any age. Past this window a recurrence reads as a new finding rather than a reopen — a continuity cost only |
| `ANALYSIS_RETENTION` | how long a cost-ledger row is kept (default `2160h`, 90 days). **This one destroys data permanently**: there is no rollup table, so `/cost` silently truncates its spend history at the cutoff |
| `MAINT_INTERVAL` | how often the housekeeping pass prunes those three tables (default `10m`). Each prune is internally batched, so running it often is cheap |

### `threatd`

| Variable | Purpose |
|---|---|
| `ADMIN_API_KEY` | password for the blocklist dashboard's write routes — secret. Unset means those routes answer `405`, never a default credential. Only `threatd` reads this |
| `BLOCKLIST_CONSENSUS_INTERVAL` | how often consensus runs and the feed is regenerated (default `5m`) |
| `BLOCKLIST_WINDOW` | rolling observation window for promotion (default `1h`) |
| `BLOCKLIST_MIN_SYSTEMS` | distinct machines required to publish an address (default `3`) |
| `BLOCKLIST_TTL` | how long a listing survives its last sighting (default `24h`) |
| `BLOCKLIST_MAX_ENTRIES` | hard cap on the served feed (default `50000`) |
| `THREAT_EVENT_RETENTION` | how long raw sightings are kept (default `168h`). The daily rollup is written before the prune, so the trend outlives them |
| `THREAT_MAX_DECISIONS_PER_REQUEST` | per-request cap; over-cap batches are truncated, not rejected (default `500`) |
| `THREAT_MAX_ALLOWLIST_REQUESTS_PER_SYSTEM` | distinct pending CIDRs one system may hold in the allowlist review queue (default `25`). Over-cap asks are **refused** with `429`, not truncated — a request is a permanent row only a human decision deletes. Re-asking about a CIDR the system already raised is always accepted, since it adds no row |
| `THREAT_ALLOWLIST_REQUEST_RETENTION` | how long an unreviewed client allowlist request is kept (default `2160h`, 90 days). Pruned as a step in the consensus pass; a dropped ask can simply be made again, which also re-ranks it as current evidence. The audit trail is never pruned |
| `THREAT_QUEUE_SIZE` | sanitized reports buffered before ingest answers 503 (default `256`) |
| `THREAT_QUEUE_WORKERS` | concurrent store writes (default `2`) |
| `THREAT_QUEUE_TIMEOUT` | ceiling for one report's write (default `30s`) |

### `sizingd`

| Variable | Purpose |
|---|---|
| `SIZING_RETENTION` | how long daily rows are kept (default `2400h`, 100 days). Monthly rollups are kept indefinitely |
| `SIZING_PASS_INTERVAL` | how often the cohort pass runs (default `1h`). The inputs are whole days, so faster cannot produce a different answer |
| `SIZING_WINDOW_DAYS` | trailing window for node verdicts and cohort baselines (default `28`) |
| `SIZING_MIN_DISTINCT_SYSTEMS` | distinct clusters a cohort needs before anything is published (default `20`) |
| `SIZING_MIN_NODES` | nodes a cohort needs as well (default `30`). Below either floor the cohort is deleted, not left stale |
| `SIZING_MIN_DAYS_PRESENT` | days of history a node needs before its verdict leaves `insufficient_data` (default `14`) |
| `SIZING_MAX_NODES_PER_REPORT` | per-report node cap; over-cap reports are truncated, not rejected (default `16`) |

### Read by no service

`INSIGHTS_HOST` and `ACME_EMAIL` live in `/etc/insights/deploy.env` and are
consumed only when rendering the proxy configuration (install step 6). No
binary reads either. `METRICS_AUTH_PASSWORD` (`/etc/insights/metrics.env`,
install step 5) is the same shape: it is hashed into
`/etc/traefik/metrics.htpasswd` by `deploy/gen-metrics-auth.sh` and checked
only by Traefik's `metrics-auth` middleware, never by a Go binary.

## Authentication

**Nodes.** A node authenticates with its NethServer subscription credential,
as HTTP Basic. The proxy calls `authd` before the request reaches a pipeline
at all; `authd` forwards the credential to `AUTH_VALIDATE_URL` and caches the
outcome. A `2xx` lets the request through unchanged, a `401` rejects it, and a
`503` — the validator being unreachable — is retried by the node rather than
treated as a rejected credential. That distinction matters: a node retries a
gap, but a false `401` is a customer-visible outage.

The validator only ever answers yes or no; it never returns an identity. So
each pipeline still reads the machine's identity itself, from the Basic
username of the same header, without re-checking the secret — `authd` already
did that.

**This is why `TRUSTED_PROXY_CIDRS` is the entire security boundary.** A
pipeline trusts that username only when the request arrived from an address
inside it. A request that reaches a pipeline directly, bypassing the proxy and
`authd`, is refused regardless of whether its credential is genuine — and
conversely, **a pipeline reached from inside that CIDR accepts any password**.
Two consequences:

- Never publish a pipeline's own port. The units do not, and the shared pod is
  what makes the default value correct: all five containers share one network
  namespace, so the proxy's connection really is `127.0.0.1` by construction.
- Widen it only for a client you would trust unauthenticated. Testing a
  pipeline from another machine needs it widened to that machine's address,
  which grants that machine the ability to claim any `system_id`.

The same setting gates which `X-Forwarded-For` is believed, and only its
rightmost value, because the header is client-controlled.

**Operators.** The proxy asks for a username and password before serving any
dashboard page, read-only pages included. The username must be one
provisioned in `/etc/traefik/operators.htpasswd`; the password for every
provisioned username is the `ADMIN_API_KEY` value. One login covers all three
dashboards.

The blocklist dashboard's write routes authenticate against `ADMIN_API_KEY` a
second time, inside the application, and refuse cross-site requests. That is
not redundant. The proxy's layer is still Basic auth, and a browser replays a
cached Basic credential automatically on a form POST from any other page the
operator later visits — without the in-application check, any site could
silently add an attacker's address to the fleet allowlist.

## Connecting nodes

A node authenticates with its NethServer subscription credential and calls in;
the server never initiates contact with a node. Each pipeline has its own
prefix on the one served hostname:

| Path | Who calls it |
|---|---|
| `POST /logs/v1/bundles` | `ns8-loki`'s collector ships a 15-minute bundle |
| `GET /logs/v1/findings` | a node reads its own findings, never anyone else's |
| `POST /blocklist/v1/events` | `ns8-crowdsec` reports ban decisions |
| `GET /blocklist/v1/feed` | a node fetches the consensus blocklist |
| `POST /blocklist/v1/allowlist-requests` | a node asks for an address to be left alone |
| `POST /sizing/v1/reports` | a cluster leader posts a complete UTC day |

`POST /logs/v1/bundles` answers immediately with "accepted" or "try later",
never with the analysis result — the analysis, and any model call, happen in
the background. A `503` means the queue is saturated and the node should retry
that window.

**Configuration takes the bare server root.** Every client appends its own
prefix, so one value configures both modules:

    # ns8-loki, on each node
    api-cli run module/loki1/set-insights \
      --data '{"active":true,"base_url":"https://insights.example.com","verify_tls":true}'

    # ns8-crowdsec, on each node
    INSIGHTS_SERVER_URL=https://insights.example.com

Do not bake a path prefix into either value. A root with `/logs` or
`/blocklist` already in it produces a doubled prefix and a 404.

The fleet-sizing reporter does not exist yet — see "Fleet sizing" below.

## Upgrading the server

    systemctl restart authd insightsd threatd sizingd

That is the whole upgrade. The four units carry `Pull=newer`, so each start
compares its `:latest` tag against the registry and pulls when the digest has
moved; when it has not, the check costs about half a second per container.
When the registry is unreachable the cached image is used, so a boot with no
network still comes up.

Restart them together, and expect a few seconds of proxy errors while the
containers come back: `authd` goes first, because each pipeline unit carries
`After=authd.service`, and a request arriving while it is down is answered by
a Traefik-generated `500` — never let through unauthenticated. A node treats
both that and a `503` as retryable, so nothing is lost.

`traefik` is deliberately excluded: it is pinned to `docker.io/library/traefik:v3.7.13`,
so a restart would re-check Docker Hub on every start for a tag that does not
move. Upgrading it is a deliberate two-step — `podman pull` the new tag, edit
`Image=` in `/etc/containers/systemd/traefik.container`, `systemctl daemon-reload`,
then restart it.

To confirm what is actually running:

    for s in authd insightsd threatd sizingd; do
      printf '%s ' "$s"
      podman inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$s"
    done

Nothing needs to be stopped first and no volume is touched, so no data is at
risk in an upgrade. Each pipeline re-creates its own schema on start.

## Removing the server

Quadlet units are generated from the files in `/etc/containers/systemd`, so
**removing the file is the disable**. There is no `systemctl disable` for a
generated unit.

Stop everything, then remove the units:

    systemctl stop traefik insightsd threatd sizingd authd insights-pod
    rm -f /etc/containers/systemd/{authd,insightsd,threatd,sizingd,traefik}.container
    rm -f /etc/containers/systemd/insights.pod
    rm -f /etc/containers/systemd/{insights-logs,insights-threat,insights-sizing,traefik-acme}.volume
    systemctl daemon-reload

At this point nothing runs and nothing starts at boot, but the data is still
there. To keep it — for a rebuild or an upgrade — stop here.

**The next step destroys data.** The three volumes hold every finding, the
cost ledger, the blocklist and its allowlist with its audit trail, and the
sizing history. None of it is recoverable and nothing else has a copy.

    podman pod rm -f insights                    # if the pod outlived its unit
    podman volume rm insights-logs insights-threat insights-sizing traefik-acme

Then the configuration, the secrets and the images:

    rm -rf /etc/insights /etc/traefik
    rm -f /etc/systemd/journald.conf.d/insights.conf
    systemctl restart systemd-journald
    for s in authd insightsd threatd sizingd; do
      podman rmi ghcr.io/nethesis/nethesis-insights-$s:latest
    done
    podman rmi docker.io/library/traefik:v3.7.13

Two things to know afterwards. Nodes keep calling in and get a connection
refused, which they treat as a retryable outage — they do not need
reconfiguring unless the server is gone for good, in which case set
`ns8-loki`'s `active` to `false` and unset `INSIGHTS_SERVER_URL`. And any node
that imported the blocklist keeps its last copy until its own TTL lapses;
removing the server does not unblock anything.

## Metrics

Every binary — `authd`, `insightsd`, `threatd`, `sizingd` — exposes
Prometheus exposition text at `GET /metrics` on its own `LISTEN_ADDR`, next to
`/healthz`. Traefik republishes each one, plus its own built-in exporter, at a
public path under a dedicated `/metrics/` namespace:

| Public path | Backend | Local path (unproxied) |
|---|---|---|
| `/metrics/logs` | `insightsd` | `http://localhost:9595/metrics` |
| `/metrics/threat` | `threatd` | `http://localhost:9605/metrics` |
| `/metrics/sizing` | `sizingd` | `http://localhost:9615/metrics` |
| `/metrics/authd` | `authd` | `http://localhost:9590/metrics` |
| `/metrics/traefik` | Traefik's own exporter | not reachable outside the pod — loopback-only `metrics` entryPoint, `127.0.0.1:8082` |

The local paths are unauthenticated, the same as every other endpoint's
unproxied local form — see "Before exposing a dashboard" below for the same
reasoning applied to the operator UI. The five public paths are gated by
their own credential (install step 5), never `ADMIN_API_KEY` and never a
node's `system_id:auth_token`: a monitoring system holds a password of its
own, so revoking it never touches the blocklist dashboard or the fleet.
Traefik checks that credential itself (`metrics-auth`, against
`/etc/traefik/metrics.htpasswd`); the four Go binaries never see it and never
validate it.

**Every metric is prefixed with the name of the container exporting it** —
`insightsd_`, `threatd_`, `sizingd_`, `authd_` — so one Prometheus holding
all five targets never has to disambiguate two services' request counts by
label alone. Traefik does the same for itself (`traefik_*`) out of the box.

The one deliberate exception is the standard Go runtime and process
collectors, which keep their conventional unprefixed `go_*` and `process_*`
names on all four binaries (plus `promhttp_*`): every off-the-shelf Go or
Grafana dashboard and every `go_*`-based alert rule queries those exact
names, and prefixing them would break all of it for the sake of tidiness.
Tell the two apart by the `job` label your scrape config sets.

So, per binary, in addition to `go_*`/`process_*`:

| Metric (shown with the `insightsd_` prefix) | Binary | What it means |
|---|---|---|
| `<svc>_http_requests_total{method,route,status}`, `<svc>_http_request_duration_seconds` | all four | every request, labeled by the registered route pattern — never the raw path, which would be unbounded |
| `insightsd_queue_depth{queue}`, `_queue_capacity{queue}`, `_queue_workers{queue}` | `insightsd` (`queue="bundle"`), `threatd` (`queue="threat_events"`) | the bundle/ingest queue's live state |
| `insightsd_llm_calls_total{result}`, `insightsd_llm_cost_micros_total` | `insightsd` | model calls by outcome (`success`, `transient`, `permanent`, `parse`) and running spend in micro-dollars |
| `insightsd_budget_rejections_total{reason}` | `insightsd` | windows `internal/budget` suppressed before the gate ran |
| `threatd_ingestq_full_total{queue}` | `threatd` | `POST /v1/events` batches that hit `503` because the ingest queue was saturated |
| `<svc>_pass_runs_total{pass,result}`, `<svc>_pass_duration_seconds{pass}`, `<svc>_pass_last_success_timestamp_seconds{pass}` | `insightsd` (`pass="log maintenance"`), `threatd` (`pass="blocklist consensus"`), `sizingd` (`pass="sizing cohort"`) | the periodic background pass each binary runs |
| `authd_cache_results_total{result}`, `authd_upstream_results_total{result}` | `authd` | forward-auth cache hits/misses and what the upstream validator answered |

No metric anywhere carries a `system_id` label, a raw request path, a
scenario, a template or a module name — the same cardinality and
data-protection rule this document's "How it works" sections describe for
gate reasons and findings.

**Counters start at 0, not missing.** Every counter above whose labels are a
known list — the four `insightsd_llm_calls_total` outcomes, the
`insightsd_budget_rejections_total` reason, both `authd_*` families,
`threatd_ingestq_full_total`, and both `<svc>_pass_runs_total` results — is
exported at `0` from the first scrape after a restart, before the thing it
counts has ever happened. That is what lets an alert like
`rate(insightsd_llm_calls_total{result="permanent"}[5m]) > 0` work on a
freshly restarted server: without it the series would not exist yet, the rule
would evaluate against no data, and it would stay silent until the first
failure had already occurred. Two deliberate exceptions:
`<svc>_http_requests_total` and `<svc>_http_request_duration_seconds` appear
only once a matching request has been served (the method/status combinations
are not a fixed list, so pre-creating them would invent series that never
occur), and `<svc>_pass_last_success_timestamp_seconds` appears only once
that pass has genuinely succeeded — a `0` there would mean "last succeeded in
1970" and would trip every staleness alert on every restart
(`time() - threatd_pass_last_success_timestamp_seconds > 3600`).

A sample Prometheus scrape config, one job per binary, reusing one
`basic_auth` block:

```yaml
scrape_configs:
  - job_name: nethesis-insights-logs
    scheme: https
    basic_auth:
      username: prometheus
      password: <the METRICS_AUTH_PASSWORD value>
    static_configs:
      - targets: ["insights.example.com"]
    metrics_path: /metrics/logs
  - job_name: nethesis-insights-threat
    scheme: https
    basic_auth: {username: prometheus, password: <the METRICS_AUTH_PASSWORD value>}
    static_configs: [{targets: ["insights.example.com"]}]
    metrics_path: /metrics/threat
  - job_name: nethesis-insights-sizing
    scheme: https
    basic_auth: {username: prometheus, password: <the METRICS_AUTH_PASSWORD value>}
    static_configs: [{targets: ["insights.example.com"]}]
    metrics_path: /metrics/sizing
  - job_name: nethesis-insights-authd
    scheme: https
    basic_auth: {username: prometheus, password: <the METRICS_AUTH_PASSWORD value>}
    static_configs: [{targets: ["insights.example.com"]}]
    metrics_path: /metrics/authd
  - job_name: nethesis-insights-traefik
    scheme: https
    basic_auth: {username: prometheus, password: <the METRICS_AUTH_PASSWORD value>}
    static_configs: [{targets: ["insights.example.com"]}]
    metrics_path: /metrics/traefik
```

On a development host you can skip all of this and run Prometheus and Grafana
in the pod itself, scraping the four binaries over loopback with no credential
at all — see [the development monitoring
stack](../deploy/dev/README.md). That is a dev convenience and is deliberately
absent from a production deployment, which is expected to be scraped by the
monitoring system that already exists.

The five jobs all scrape the same host on the same port, differing only in
`metrics_path`, so the `job` label is what separates them. That label is what
you need for the `go_*` and `process_*` metrics, which are identically named
on all four binaries — `go_goroutines{job="nethesis-insights-authd"}`. Every
other metric already carries its service in the name, so
`insightsd_queue_depth` is unambiguous with or without the job label.

### The job names are not cosmetic

Keep the five `job_name` values exactly as written above. They are what the
dashboard in the next section matches on: it derives each service's short
label and its fixed colour from the `nethesis-insights-` prefix, selects the
four Go binaries with
`job=~"nethesis-insights-(logs|threat|sizing|authd)"` for the runtime panels,
and picks the proxy out with `job="nethesis-insights-traefik"`. Rename a job
and those panels go blank — the metrics are still collected and every other
panel still draws, which is what makes it confusing rather than obvious.

If your Prometheus has a naming convention of its own that these have to fit,
change them in one place and one place only: the `job_name` values above and
the four `job=~`/`job=` matchers in the dashboard JSON.

### The dashboard

`deploy/dev/grafana/dashboards/nethesis-insights.json` is written to be
imported into whatever Grafana you already run — it is stored under
`deploy/dev/` because that is where the stack that provisions it
automatically lives, not because it only works there. It carries no
deployment-specific value: every panel queries through a **datasource
variable** rather than a fixed datasource id, so it resolves to your default
Prometheus on first open instead of pointing at one that does not exist.

To install it by hand:

1. Copy `deploy/dev/grafana/dashboards/nethesis-insights.json` to the machine
   running Grafana, or open it in the repository and copy its contents.
2. In Grafana, **Dashboards → New → Import**, paste the JSON, **Load**.
3. Choose a folder if you want one, then **Import**.

There is no datasource field to fill in on that screen — the variable is
resolved when the dashboard opens, not when it is imported. It appears as
**Nethesis Insights** (uid `nethesis-insights`) already pointing at your
default Prometheus, and the **Data source** picker at its top left switches
it to another one if you have more than one. Twenty-five panels in eight rows:
overview, HTTP, the log pipeline, Threat Shield, forward auth, background
passes, the proxy, and the Go runtime. Nothing in it writes anywhere or needs
a plugin.

Two things it assumes, both satisfied by the scrape config above:

- **The job names**, as the previous subsection describes.
- **Every one of the five targets.** A missing job costs you the panels that
  query it and nothing else — the dashboard does not fail as a whole.

Imported this way the dashboard is an ordinary editable dashboard: Grafana
owns it, and re-importing a later version of this file overwrites your edits.
That is the trade for editing it in the browser. The development stack takes
the opposite one, provisioning it read-only from the file so that git and the
running dashboard cannot disagree.

## The operator UI

Three separate dashboards, one per pipeline, each built into its own service:
the logs dashboard at `/logs`, the blocklist dashboard at `/blocklist`, the
sizing dashboard at `/sizing`. Each is **off unless that service's
`UI_LISTEN_ADDR` is set**. The units installed above set all three.

### Before exposing a dashboard

Unlike the node API, which is per-machine and authenticated, **a dashboard's
`GET` is unauthenticated and fleet-wide inside the application.** It shows
every machine's findings, templates, baselines and spend.

So either bind `UI_LISTEN_ADDR` to `127.0.0.1` or a trusted management
network, or put the proxy in front of it. The service will not refuse a wider
bind — that is the administrator's call — but it logs a warning at startup
whenever the dashboard is bound anywhere but a loopback address, so the choice
is never made by accident. In the deployment above, no container publishes a
dashboard port at all: the only way to reach one is through the proxy.

Everything else about a dashboard is built to match that exposure:

- **`GET` is read-only.** Every page answers `GET` with no credential.
- **Only the blocklist dashboard can write**, only when `ADMIN_API_KEY` is
  set, and only on a short enumerated list of routes that each authenticate
  first. Those routes answer `POST` and nothing else; every other method,
  `HEAD` and `DELETE` included, is `405`. With no key they answer `405` too —
  not "reachable but unauthorized".
- **Cross-site writes are refused**, because a browser replays a cached Basic
  credential automatically.
- **No secrets on any page.** The configuration table is built from an
  explicit field list, never by iterating the environment. The model and admin
  keys appear only as `set` or `unset`.
- **Nothing unmasked.** Raw log samples are never stored, so there is nothing
  unmasked to render.
- **No JavaScript, and no outside network requests.** Auto-refresh is a meta
  tag, filters are plain forms, row detail is a native disclosure element. An
  offline management network is a supported deployment.
- **No arbitrary SQL.** Every page is a fixed query with a server-side limit.

### Signing in

In the deployment above all three sit behind the same reverse proxy, which
asks for a username and password before serving *any* page of any of the
three — read-only pages included. The username must be one an administrator
has already provisioned in the proxy's own password file; an unrecognized
username is rejected before the request ever reaches the dashboard. The
password for every provisioned username is the same: the server's
`ADMIN_API_KEY` value. Whichever provisioned username is used to sign in is
what gets recorded as the actor on anything that page lets you change. So
there is one login for the whole operator surface, not three, and not a
separate one for making a change versus just looking.

Each dashboard's landing page (`/`) is its single most useful page; everything
else, including a `/status` page with queue backlog, uptime, build version and
the effective configuration, lives alongside it.

**The logs dashboard**, at `/logs`:

| Page | What you're looking at |
|---|---|
| `/logs/` | The actual reported problems, most severe and most recent first. Filter by machine, status (open/stale) or severity. Click a row to see the full summary, suggested action, evidence and fingerprint. |
| `/logs/systems` | Every machine the server has ever heard from, with a quick summary: how many templates, findings, analysis windows, and how much it's cost so far. |
| `/logs/analyses` | The cost ledger: every window processed, whether it was gated out, whether the AI was called, tokens used (including the part served from the provider's cache at half price), cost, how long it took, any error, and whether a spending limit suppressed it. This answers "what did we spend, and on what." |
| `/logs/gate` | The gate's decisions grouped by *why* — how many windows and how much money went to each distinct set of reasons. Read the summary line first: it says what share of windows was gated out, which is the only number that tells you whether the gate is working. In the table, remember that a reason set *is* the trigger, so every listed row with reasons went to the AI; the `(none)` row is the free ones. Scoped to the last 7 days by default — see the note below. |
| `/logs/cost` | Spend and token usage per day and per model — the trend line version of the ledger. |
| `/logs/templates` | What the server currently considers "already known" for a machine — i.e., what would *not* by itself trigger a new AI call. One row per condition per module *kind*, so many copies of one application share a row. |
| `/logs/baselines` | The current EWMA "normal rate" estimate per module per machine — what the gate compares actual volume against when a node doesn't supply its own expectation. |
| `/logs/status` | Is the server healthy? Queue backlog, uptime, build version, and the full effective configuration it's running with. |

**The blocklist dashboard**, at `/blocklist`:

| Page | What you're looking at |
|---|---|
| `/blocklist/` | What the fleet currently agrees is malicious. Each row expands to the evidence that got it published — how many machines, how many hits, under which rule. Below it: the allowlist, i.e. the reason an address might *never* appear here despite the fleet reporting it. |
| `/blocklist/systems` | One row per machine that has ever reported a CrowdSec decision, including a machine whose every report was a duplicate or got dropped by the sanitizer and therefore never shows up anywhere else. |
| `/blocklist/events` | The raw sightings behind the list. Filter by address to answer "who reported this, and when" — useful when somebody's customer asks why they got blocked. |
| `/blocklist/stats` | Two things: the day-by-day threat trend broken down by CrowdSec scenario, with a per-day total, and what each machine contributed — including how much of what it sent was discarded, and for which reason. |
| `/blocklist/allowlist-requests` | The review queue: which addresses customers have asked to have left alone, how many different machines asked, and the reasons they gave. Approve or reject from here — the buttons on this page and the allowlist itself are the only things on any of the three dashboards that make a change. |
| `/blocklist/audit` | The append-only trail of every allowlist change: who added, removed, approved or rejected what, and when. This exists because deleting an allowlist entry destroys the row that would otherwise say who removed the exemption that let something through. |
| `/blocklist/status` | Is the server healthy? Uptime, build version, and the full effective configuration it's running with. |

**The sizing dashboard**, at `/sizing`:

| Page | What you're looking at |
|---|---|
| `/sizing/` | One row per node, showing its most recent day: pressure, the four resource penalties behind it, the utilization percentiles beside it, and the multi-day verdict. Below it, what each node is running with its workload counts; the score's thresholds, each labelled as physically grounded, conventional or still a guess; and per-cluster ingest accounting, so "this cluster sends reports and stores nothing" comes with the rule that dropped them. |
| `/sizing/cohorts` | The published baselines: what the fleet's own hardware says a given deployment needs, in absolute bytes and cores, with the capped share alongside. On a small fleet this page correctly says "not enough data yet" — publishing a percentile computed from three nodes would be worse than publishing nothing. |
| `/sizing/status` | Is the server healthy? Uptime, build version, and the full effective configuration it's running with. |

Only the blocklist dashboard has buttons that change anything — add or remove
an allowlist entry, approve or reject a request. The logs and sizing
dashboards are read-only end to end; there is nothing on either for an
operator to approve or reject.

Nothing on any of these dashboards ever shows a raw, unmasked log line — the
server never stores those in the first place, so there's nothing to show. And
the pages make no outside network requests and need no JavaScript enabled —
they're meant to work even on an offline management network.

## How the log pipeline works

### 1. The bundle

Every 15 minutes, each node sends a **bundle**: a compact, already-masked
summary of that window's logs. It is *not* raw logs — sensitive values are
already stripped out before it ever leaves the machine. A bundle contains:

- a **digest**: for each log module, how many lines it produced this window,
  and (if the node can tell) how many it *expected*;
- a list of **templates**: the distinct *shapes* of log lines seen (see
  below), each with a count;
- bookkeeping about how much the node had to truncate to stay within its own
  budget.

### 2. Templates: the shape of a log line, not the line itself

A log line like `Failed login for user alice from 10.0.0.5` and one like
`Failed login for user bob from 10.0.0.9` are the same underlying *event*
with different specific values. A **template** is that shared shape, with the
variable parts masked out, plus a count of how many times it occurred. This
is what makes the whole system affordable: the server reasons about "this
shape happened 40 times," not about 40 individual log lines.

The server remembers, per machine, every template it has ever seen. That
memory is the basis for the single most important cost-saving trick in the
whole system: **a template the server already knows about is not
interesting**. Only a template that's genuinely new (or a known one behaving
very differently — see baselines below) is worth spending money to have an
AI look at.

### 3. The gate: deciding if it's worth asking the AI

Calling an AI model costs real money, every time. If the server called it for
every 15-minute window from every one of ~2700 machines, the bill would be
enormous (roughly $16,000/month on a cheap model, by internal estimate) for
mostly "nothing happened" windows. So before anything is sent to the AI, the
**gate** looks at the bundle and asks: is there actually anything new or
unusual here? It says yes if:

- **several templates have never been seen before** for this machine (three by
  default, not one — see "what counts as new" below);
- some module's log volume is **way higher than expected** — more than a
  configurable multiplier over its normal rate (see baselines) *and* enough
  lines for that to mean anything. A module that normally logs 2 lines per
  window and logs 7 is not surging; it is a quiet module having a quiet day.
  Both a minimum normal rate and a minimum line count must be cleared before a
  ratio counts at all;
- a template tagged **security**-related is either new for this machine, or is
  one we already know about whose module is suddenly much noisier than usual
  (the node applies the security tag, not the server). A single new
  security-tagged template is enough on its own — it never has to wait for
  company;
- a module both **dropped lines** because it hit its own budget *and* is
  behaving unusually — either one alone is not enough.

**A window is sent to the AI only if at least one of the four conditions
above is true.** If none are true, the window is "gated out": the server
still does the cheap bookkeeping (remembers the templates, updates the
baselines) and moves on — no AI call, no cost.

**What counts as "never seen before".** The node masks variable parts out of
each log line before sending it — timestamps, IP addresses, process ids — but
it cannot mask what it has no rule for, and what leaks through changes every
time the line is written. A PostgreSQL checkpoint line carries the percentage
of buffers written and the number of files recycled; those two numbers made
every checkpoint look like a brand-new kind of log line. Measured on three real
machines, 512 of 710 stored templates differed from another one only in a field
like that.

So the server collapses those fields before asking "have we seen this": one
condition is one template, however many spellings of it arrive. The same
collapse is used when a finding's identity is computed, so a leak cannot split
one problem into ten findings either. The full, unmodified line is still what
you see in the UI and on the finding — only the comparison is collapsed.

**Modules are counted by kind, not by copy.** A machine can run many copies of
one application — a measured hosting node runs 82 `nethvoice` and 71
`openldap` instances, named `nethvoice1`, `nethvoice2` and so on. Every copy
runs the same software and therefore says the same things, so the server groups
them by *kind*: `nethvoice5` and `nethvoice39` are both `nethvoice`. Without
that, one ordinary cron line occupied 82 separate templates on that machine,
each of them "never seen before" the first time its copy said it. Measured on
2026-09-02, grouping by kind and de-numbering the process names inside the line
took 678 stored templates down to 230 for the same set of real conditions.

The one place the individual copy still matters is volume: baselines and the
"unusually chatty" comparison are kept per copy, so a single misbehaving
instance is still visible on the `/baselines` page. The trade is that a finding
names the kind (`openldap`) and not which of the 71 copies emitted it.

That is also why novelty needs more than one new template. A genuinely new
condition arrives as a handful of related lines; a single new line is nearly
always one more spelling of something the machine has been saying all week.

Note the shape of the security rule: *new or surging*, not merely *present*.
Any machine reachable from the internet gets a constant trickle of failed SSH
logins, so "there is a security-tagged line in this window" is true of
essentially every window forever. Treating that as a reason to call the AI
made the gate stop gating — measured on a live node, 352 AI calls out of
352 windows, not one gated out. Steady background noise is not news; a new
kind of attack, or a sudden spike in a familiar one, is.

Some log sources are skipped before the gate even sees them, because
something else already handles them properly. CrowdSec is the built-in case:
its decisions go through Threat Shield into the shared blocklist, so sending
its log lines to the AI as well would pay twice for one signal and bury the
rest of the machine's logs in brute-force noise. That is why CrowdSec attacks
show up on the **blocklist** pages rather than as findings.

Individual services can be skipped the same way. The insights server itself is
skipped by default, because if it is installed on a machine it is also watching,
its own log lines become "new" log patterns, which look like something worth
analysing, which makes it write more log lines. Left alone that loop never
settles.

Every window, gated out or not, gets one row in the **analyses** ledger, with
a `gated` yes/no flag and the exact reasons behind that decision. This is
where gated windows live and how you find them:

- **logs dashboard, `/logs/analyses`** — every window for a machine, each row
  marked whether it was gated and whether the AI was called;
- **logs dashboard, `/logs/gate`** — the same decisions, grouped by *why*, so
  you can see which reason is driving spend across the whole fleet;
- **on disk**, the `analyses` table, `gated` column (see `docs/architecture.md`
  § Data model).

So "why did (or didn't) this window get analyzed" is always answerable after
the fact from stored data — see the `/analyses` and `/gate` pages below.

Two things to know when reading those reasons. First, **a reason is the trigger,
not a description**: the gate calls the AI if and only if at least one reason
fired, so "this window has reasons" and "this window cost money" are the same
statement. Counting them as two separate numbers tells you nothing; the useful
number is what share of windows had *no* reasons.

Second, **reasons are stored spelled the way the gate spelled them at the time**.
When a gate rule changes, old rows keep the old wording — rows written before the
security rule became *new-or-surging* say `security_category`, and older ones
still embed the counts and ratios that were later removed for making every window
its own group. That is deliberate: a formula change should be visible, not
silently rewritten. It also means an all-time grouping compares two different
gates, which is why `/gate` defaults to a recent window.

### 3a. The spending ceiling

The gate answers "is this window worth money". It cannot answer "what is the
most this can cost", because that depends on every machine at once. Three
limits do:

- **calls in flight** — how many AI requests may run at the same time. The rest
  wait in the queue; if the queue fills, machines are told to come back later;
- **calls per machine per day** — a hard ceiling, counted from midnight UTC. A
  machine whose logs are pathological cannot spend the whole fleet's budget by
  itself. A window stopped this way is recorded with a `suppressed_by` value in
  `/analyses`, costs nothing, and carries no gate reasons — nobody decided it
  was uninteresting, it simply was not affordable;
- **spend per day for the whole fleet** — off unless configured. On breach the
  gate *narrows* to security-only rather than stopping: a cost ceiling that
  blinds you to a break-in is worse than the bill it prevents.

The counts come from the stored ledger, not from memory, so restarting the
server does not hand anybody a fresh allowance.

### 4. Baselines: "what's normal" for a module

Not every node's log collector knows how many lines it expects to see for a
given module. When it doesn't say, the server keeps its own running estimate
per `(machine, module, priority)`, called a **baseline**. The gate compares
the actual count in a bundle against this baseline (or the node's own stated
expectation, if it gave one) to decide whether a module is behaving
unusually. You can see the current baseline for every module of every
machine on the `/baselines` page.

**What "EWMA" means, in simple words.** EWMA stands for Exponentially
Weighted Moving Average — a fancy name for a simple idea: "my new estimate of
normal is mostly my old estimate, nudged a little bit toward whatever just
happened." Every time a new count comes in, the server blends it with the
previous baseline:

    new baseline = (a little bit × this window's count) + (mostly × old baseline)

That "a little bit" is `EWMA_ALPHA` (default `0.3`, i.e. 30%). A higher
`EWMA_ALPHA` makes the baseline react faster to recent changes; a lower one
makes it more stable and slower to move. The very first time a module is
seen, there's no "old baseline" yet, so the baseline just starts out equal to
that first count.

One thing worth being precise about: **`EWMA_ALPHA` itself is always between
0 and 1** (it's a blending weight — "how much of the new value to mix in").
The *baseline value it produces* is **not** a 0–1 number — it's a count of
log lines, so it can be anything from 0 to several thousand, whatever is
normal for that module on that machine.

### 5. The analysis: when the AI actually looks

When the gate says yes, the server builds a prompt describing that window
(the digest, the interesting templates, what got truncated) and sends it
to an LLM, along with a reminder of what's *already* an open problem for this
machine so the AI doesn't re-report it.

The prompt does **not** carry every template in the bundle. A busy machine
ships 160-190 of them per window and only a handful are why the call happened,
so the AI is shown: everything new, everything security-tagged, everything from
a module that is behaving unusually, and then the busiest of what remains as
background context. Repeated spellings of one line are folded into a single
entry with the counts added up and a `variants=` marker, so a message the
machine logged 65 slightly different ways arrives as one thing to consider
rather than 65. Sending the rest costs money on every call and buries the
evidence the AI is supposed to weigh. The AI responds with a structured
list of findings (or none, if on reflection nothing warrants it) — never free
text, always following a strict format the server validates.

Whether or not the AI was called, the outcome of processing one window is
recorded as an **analysis**: which window, whether it was gated out or sent
to the AI, how many tokens it used, what it cost, how long it took, and any
error. This is the system's cost ledger — see the `/analyses` and `/cost`
pages.

### 6. Findings: the actual output

A **finding** is one reported problem: a title, a plain-language summary, a
suggested action, a severity (critical/high/medium/low), which log modules
it involves, and the evidence (which templates) it's based on.

The key trick here is **identity**: the server computes a fingerprint for
each finding from the machine, the modules involved, the evidence and the
category — never from anything the AI wrote in prose. That means if the same
underlying problem shows up again next window, it's recognized as *the same
finding* rather than reported as a new one — its occurrence count goes up
instead.

Getting that right takes a little more than ignoring the AI's wording. The AI
also picks *which* templates to cite as evidence, and it does not pick the same
ones every time: one window it cites the brute-force attempts from four
countries, the next window from two. Deriving identity from that raw list meant
the same recurring SSH problem arrived as a brand-new finding every window,
each stuck at an occurrence count of 1. The server now reduces the cited
evidence to one stable key before fingerprinting it, so the wobble in what the
AI cites no longer splits one problem into many.

A finding is:

- **open** — actively occurring, or has occurred recently;
- **stale** — hasn't reoccurred in a while (see `STALE_AFTER`), so it's
  presumed resolved;
- **reopened** — was stale, then happened again; a `reopened_at` timestamp
  marks when.

This is why the same misconfigured service doesn't flood you with a new
alert every 15 minutes forever — it's the *same* finding, just bumped.

## Threat Shield

Everything above is about *one machine's* logs. Threat Shield is about
something the individual machine cannot know.

Every NethServer 8 node runs CrowdSec, which bans IP addresses that misbehave
against *it*. That works, but each node starts from zero: an attacker scanning
a thousand customers gets a thousand separate first attempts, because no node
knows what the others just saw.

Threat Shield gives the fleet a shared memory. It runs on the same server, but
it is a completely separate pipeline: **no AI is involved anywhere in it**, and
none of the gating, fingerprinting or cost machinery above applies. This is
plain factual data — an address did or did not attack a node — so it is simply
collected, counted and handed back.

### How it works, in four steps

1. **A node reports its bans.** When CrowdSec bans an address, the node posts
   that decision to `POST /blocklist/v1/events` using the same subscription
   credential it uses for log bundles.

2. **The server throws most of it away.** Before anything is stored, every
   decision goes through a strict filter. Private and internal addresses
   (`10.x`, `192.168.x`, loopback, and so on) are discarded outright, so
   customer-internal addressing never reaches the database. Bans that came
   from CrowdSec's *own community blocklist* rather than the node's own
   observation are discarded too — otherwise a thousand nodes all repeating
   the same downloaded list would look like a thousand independent witnesses.
   Only the address, the CrowdSec scenario name, a timestamp and the ban
   duration survive. No usernames, no URLs, no request paths, no user agents.

3. **Consensus decides what is real.** Every few minutes the server asks: which
   addresses have been reported by at least three *different* machines in the
   last hour? Three reports from one noisy machine is not consensus — it is one
   opinion. Addresses that clear that bar are published; they drop off again
   24 hours after the last sighting, so an address that has been reassigned to
   somebody innocent does not stay blocked forever.

4. **Nodes fetch the result.** `GET /blocklist/v1/feed` returns a plain list of
   addresses, which the node imports into CrowdSec. Every subscriber gets the
   same list.

### The safety net

Consensus alone has an obvious failure mode: what if the fleet agrees on
something it shouldn't? One exclusion runs before anything is published.

- **The allowlist.** A hand-maintained list of addresses and ranges that must
  never be published, whatever the fleet says — a partner's security scanner, a
  shared resolver. It is applied when the decision to publish is made, not when
  the list is read, so adding an entry actually *removes* the address on the
  next pass rather than just hiding it — including an address the fleet had
  already got published, which is deleted rather than left to expire. "Next
  pass" is at most `BLOCKLIST_CONSENSUS_INTERVAL` away, so an exemption takes
  effect in minutes, not after the 24 h listing TTL.

  A range wider than a `/24` (IPv4) or a `/48` (IPv6) is **refused**, and there
  is no way to override it. An exemption that wide is almost never what someone
  meant, and the extreme case — `0.0.0.0/0`, "exempt everything" — would switch
  the whole feed off with nothing anywhere saying so. If you genuinely need to
  exempt a lot of address space, say it as several narrower entries; that also
  leaves a readable record of what was exempted and why. Removing an entry has
  no such limit: whatever is on the list can always be taken off it.

An earlier design also automatically excluded the address each reporting node
connects from ("fleet self-protection"), so a misconfigured appliance
reporting the fleet's own gateway could not get the fleet to block itself.
That automatic exclusion was removed as too complex and too easy to get wrong
for what it bought — the allowlist above is now the only promotion exclusion,
and it is a human decision rather than an automatic one.

### One thing the server refuses to do

If the server has not yet successfully computed a list — it has just started,
or the database is unhappy — the feed answers "unavailable" rather than
returning an empty list. This is deliberate: to a node importing the file, an
empty list does not read as "I don't know," it reads as "there are no threats,"
which would quietly switch the protection off. For the same reason, if a
computation fails the server keeps serving the *previous* list, timestamped so
a node can tell it is stale.

### The honest caveat

This server has no concept of *which customer* a machine belongs to. The
original design required agreement across at least two different
organizations, precisely so one customer's misconfiguration could not get an
address published fleet-wide. That requirement cannot be enforced here yet, so
three machines belonging to the same customer do count as consensus. The
allowlist above is what stands in for it.

### Asking for an address to be left alone

Sometimes the fleet agrees about an address that is not actually an attacker —
a partner's security scanner, a shared resolver, a customer's own gateway. Two
things exist for that.

A node can **ask**: `POST /blocklist/v1/allowlist-requests` puts the address in
a review queue, ranked by how many different machines asked for it. Forty
customers all hitting the same shared resolver floats it to the top; a single
opportunistic request sinks.

A human then **decides**. Nothing is ever exempted automatically, and this is
deliberate rather than an unfinished feature. The blocklist and the allowlist
look like mirror images and are not: if the fleet wrongly blocks an address,
somebody notices within the day and it expires anyway, whereas if the fleet
wrongly *exempts* an address, nobody notices at all — there is no complaint to
be made about not being blocked — and it stays exempt forever. Reporting an
attack is evidence; asking to be exempted is an opinion. So the counter ranks
the queue and does nothing else.

Approving or rejecting is done through the blocklist dashboard's
`/allowlist-requests` page, which asks for the operator credential and records
who did it. There is no separate admin API any more — the dashboard is the
only way in.

Once a request has been approved or rejected it **leaves the queue** — the
queue only ever shows addresses still waiting on a decision. What was asked
and how it was settled is kept in the audit trail, so a handled request is
still answerable for later; it just stops asking to be handled again.

Deciding an address is not a permanent verdict on it. If machines ask for the
same address again after a rejection, it comes back into the queue to be
looked at afresh — which is what you want, because "two machines asked once"
and "sixty machines have asked since" deserve different answers, and an old
`no` should not quietly bury the second case.

## Fleet sizing

> **Dev preview.** The server side is complete and running, but **nothing
> sends it anything yet**: the reporter that would run on an NS8 cluster
> leader is not written. Until it exists `sizingd` stores nothing, the sizing
> dashboard is empty on a fresh install, and everything described in this
> section is exercised only by tests. The thresholds are also uncalibrated —
> reasoned defaults, not values fitted to fleet data, which needs about 30
> days of real reports. Treat any number this pipeline shows as provisional.

This is a **third pipeline**, alongside the log analysis above and Threat
Shield. It shares the same server and the same subscription credential; it has
its own service and its own database file, and shares nothing else — no AI
call, no gate, no findings.

It exists to answer a question Nethesis had no fleet-wide answer to: *how much
RAM does a node running NethVoice need?* Not a guess, and not one customer's
anecdote — the answer the fleet's own machines already know.

### What a sizing report is

Once a day, each NS8 cluster's leader posts one report covering the **last
complete UTC day**. A `system_id` is a *cluster*, so one report carries one
entry per node in it, and each entry has three parts:

- **what the node is** — installed cores and memory, CPU model, OS;
- **how hard it worked** — the 95th-percentile memory, CPU, load and disk
  utilization over that day, plus how *long* it spent waiting on disk, whether
  it swapped anything back in, whether the kernel killed anything for running
  out of memory, and how many days until its fullest filesystem is full;
- **what it was running** — each module family, how many copies, and that
  family's workload counts (mailboxes, PBX users, trunks, shared folders, …).

Two design choices in that list are worth knowing about because they show up
everywhere downstream.

**A day is an absolute fact.** The report says which day it covers, and every
number in it is computed over that day's exact boundaries. That is what makes
sending it three times harmless: the second and third sends restate the first
one word for word, so the server *replaces* the row rather than adding to it,
and a retry after a network failure costs nothing. Reports older than fifteen
days are refused — the node's own metrics do not go back further, so numbers
claiming to be older cannot have come from real data.

**Workload counts can only be numbers.** The list of counts is deliberately
open — any module can invent one, and it is stored without the server needing
a release — but every value must be a number. That single rule is the whole
privacy control: a hostname, an FQDN, an IP address or a hardware serial
*cannot be written as a number*, which is a much stronger guarantee than a list
of banned field names somebody has to keep up to date. Nothing identifying is
sent, and nothing identifying could be.

### Pressure: one number for "is this node undersized?"

The server — never the node — turns each node-day into a **pressure** number
from 0 to 100. 0 means no pressure; 100 means severe. It is built from four
axes:

| Axis | Reads |
|---|---|
| memory | memory utilization, pages swapped *back in*, kernel out-of-memory kills |
| cpu | CPU utilization and run-queue length per core |
| io | the *fraction of the day* spent waiting on disk |
| disk | how full the fullest filesystem is, and how many days until it fills |

Four things about it are deliberate, and each one fixes a way of getting this
wrong:

- **Within an axis the worst term wins, not the sum.** CPU utilization and
  run-queue length are two views of one saturation; adding them would punish a
  node twice for a single cause.
- **Across axes it is the worst axis at full weight plus the rest at half.** A
  plain sum over-punishes problems that travel together; a plain maximum would
  rank a node with three simultaneous problems the same as one with a single
  problem.
- **Time is measured as a duration, never a peak.** A 24-hour *maximum* cannot
  tell a 25-minute nightly backup (1.7 % of the day) from a node starved for
  seven hours (30 %). A duration has a denominator; a maximum does not. This is
  the same mistake the log gate once made and was fixed for.
- **"Not measured" is not zero.** If a node was switched off for eighteen hours,
  or its metrics were unreachable, or it reported no cores, it gets **no
  pressure at all** rather than a flattering low one. A score computed from
  missing data is worse than no score. On the page that shows as `n/a`.

Alongside pressure, the raw utilization percentiles are shown, because they
answer a different question: pressure says *is this undersized*, the
percentiles say *how much headroom is left*.

### The verdict: a single bad day is not a verdict

Undersizing is recurrence, so the answer per node is computed over a trailing
28-day window: fewer than 14 days of data is `insufficient data`; seven or more
bad days is `undersized`; fourteen or more merely elevated days is `at risk`;
otherwise `ok`. Once a node is called `undersized` it stays that way until the
bad days largely go away, so the verdict does not flip back and forth — a
flapping verdict is one nobody acts on.

The verdict also names a **main cause**: whichever resource — RAM, CPU, disk
I/O or disk space — was the worst one on the most bad days.

**Sometimes the answer is not "buy hardware".** Because a `system_id` is a
cluster, the server can compare its nodes against each other. If one node is at
95 % memory while another sits at 20 %, the advice is **rebalance**, not buy.
This output only exists because the unit is a cluster, and it is the most useful
thing that falls out of that.

### Cohort baselines: what the fleet says a deployment needs

Once an hour the server groups nodes by what they run and publishes
percentiles of **absolute** memory and CPU demand — bytes and cores, not
percentages. Utilization is a property of hardware somebody happened to buy;
the deliverable is advice on what to buy. The recommendation is the p90 column:
the peak demand nine out of ten comparable nodes stay under.

There are two groupings, and the difference matters:

| Grouping | Answers | Safe to quote? |
|---|---|---|
| solo | "what does a node running only mail need" | **yes** |
| co-tenanted | "what does a node that runs mail, alongside whatever else, look like" | no — it is not a per-module cost |

"Only mail" means only mail out of what a customer *chose*. Every NethServer 8
cluster also runs a set of platform modules — log shipping, the identity
proxy, metrics, intrusion prevention, the ingress — and those are on every
node in the group, so their cost is inside the number. That is the honest
reading and also the useful one: nobody deploys NS8 without them. What it
means in practice is that the solo figure is what to buy for a mail node, not
what mail alone consumes.

Three honesty rules are built into this:

**Per-module cost is never *measured*.** Nothing in NS8 exports per-container
memory or CPU, so a single module's cost can only ever be *inferred* from
variation across whole nodes. The page says so; the numbers are percentiles of
whole nodes grouped by what they run, which is a different and more defensible
claim.

**Nodes whose demand cannot be observed are excluded — and counted.** An
undersized node's memory use is *capped by the memory it has*: a node that needs
12 GiB but only has 8 reports about 7.6 GiB. Averaging that in makes the answer
come out too small, which then declares more nodes adequately sized — the exact
opposite of the point. So those nodes are left out of the percentiles and
reported as **censored** instead. A group that is 40 % censored is not a
footnote: it means the hardware the fleet is actually buying for that profile is
systematically too small, which is the single most valuable thing this pass can
tell you.

**Below the evidence floor, nothing is published at all.** A group needs at
least 20 distinct clusters and 30 nodes. Distinct *clusters*, not nodes, for the
same reason the blocklist counts distinct machines: one partner's forty
identical deployments is one opinion about hardware, not forty. And a group that
drops below the floor is deleted rather than left on the page going stale.

### And most of the thresholds are still guesses

The score's knees — the point at which memory utilization starts to count as
pressure, and most of the rest — are **initial guesses**, to be calibrated once
about a month of real fleet data exists. A few are not: a filesystem at 98 % is
physically about to stop working, one runnable task per core is by definition a
saturated queue, and the disk-filling threshold is deliberately the same number
the node's own alert uses so the two never disagree.

The sizing page labels every threshold with which kind it is, because a
dashboard that renders an uncalibrated number with no label attached is
presenting a guess as advice. Because every input is stored as its own column,
recalibrating later is one pass over data the server already has — no fleet
reconfiguration, and no waiting another month.

## What this system does not do

- It does not decide *what counts as security-relevant* — that tag comes from
  the node, which has full context on its own logs. The server only reacts to
  it.
- It does not show you a *per-customer* dashboard — the three operator
  dashboards are internal, fleet-wide diagnostic tools for the people running
  the server, not a product feature for end customers.
- It does not retain raw log content anywhere — only masked templates and
  their counts.
- It does not measure any individual module's memory or CPU cost, and cannot:
  nothing in the NS8 stack reports per-container resource use. Sizing publishes
  percentiles of whole nodes grouped by what they run, and says so.
- It does not accept anything but numbers in a sizing report's workload counts,
  and it never receives a hostname, FQDN, IP address or hardware serial in one.
