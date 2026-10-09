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
  - [1. Prepare the host](#1-prepare-the-host)
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
  - [What to scrape](#what-to-scrape)
  - [How the endpoints work](#how-the-endpoints-work)
  - [The labels are not cosmetic](#the-labels-are-not-cosmetic)
  - [The dashboard](#the-dashboard)
- [The operator UI](#the-operator-ui)
  - [Before exposing a dashboard](#before-exposing-a-dashboard)
  - [Signing in](#signing-in)
- [How the log pipeline works](#how-the-log-pipeline-works)
  - [1. The bundle](#1-the-bundle)
  - [2. Templates: the shape of a log line, not the line itself](#2-templates-the-shape-of-a-log-line-not-the-line-itself)
  - [3. The gate: deciding if it's worth asking the AI](#3-the-gate-deciding-if-its-worth-asking-the-ai)
  - [3a. The spending ceiling](#3a-the-spending-ceiling)
  - [4. The analysis: when the AI actually looks](#4-the-analysis-when-the-ai-actually-looks)
  - [5. Findings: the actual output](#5-findings-the-actual-output)
  - [6. Review: deciding what customers see](#6-review-deciding-what-customers-see)
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
| Network | ports 80 and 443 free on the host **and reachable from the internet**. The certificate is issued over HTTP-01, so port 80 must be genuinely reachable, not merely unfiltered. The install turns the host firewall on and leaves only SSH, 80 and 443 open, plus 9100 (host metrics) for the metrics server alone. |
| DNS | one A record pointing at the host. Everything is served from that one hostname. |
| Credentials | an OpenAI-compatible API key, if the log pipeline is to call a model. Threat Shield and fleet sizing need none. |

Give the host to this deployment alone. The install caps the journal
system-wide, turns Cockpit off and closes every port except SSH, 80 and 443
(and 9100 for the metrics server), which is only correct on a machine that
runs nothing else.

## Installing the server

Run everything as `root`. You need the repository's `deploy/` directory on the
host — copy it there, or clone the repository.

### 1. Prepare the host

    dnf install -y podman container-selinux httpd-tools firewalld
    install -d -m 755 /etc/containers/systemd

`httpd-tools` is only for `htpasswd` in step 5.

Check that quadlet is present, since the whole deployment is quadlet units:

    podman --version                                                 # >= 5
    ls /usr/lib/systemd/system-generators/podman-system-generator     # exists

Then close the host:

    bash deploy/host-firewall.sh

This turns Cockpit off and turns the firewall on, with only SSH, HTTP and
HTTPS allowed. It also opens port 9100 — the host metrics exporter, see
"Metrics" — to the metrics server and nobody else. By default that is
`2.119.67.169`, the public address of `metrics.nethesis.it`; the name itself
is not used, because inside the Nethesis network it points to a private
address. To allow a different server, put its address in front of the
command — `METRICS_SCRAPER=203.0.113.10 bash deploy/host-firewall.sh` — and
set the same value in `deploy.env` in step 6, which the script also reads
once it exists. It must be an IP address or a CIDR range, never a name; the
script stops, changing nothing, if it is not. **If the metrics server
changes address, set the new one and run both this script and step 6's
render again**: until then it cannot scrape, and re-running also closes the
old address. Cloud images of Rocky, Alma and RHEL often ship with Cockpit —
a web login with root access — listening on port 9090 and no firewall at all.
The script allows SSH before it starts the firewall, so it cannot cut off the
session you run it from. Running it again changes nothing.

The firewall protects the host's own services. It does **not** protect a port
a container publishes: podman's own rules let that traffic through whatever
the firewall says. What keeps the dashboards private is that no container
publishes a port except the pod's 80 and 443 — step 8 checks this.

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
    podman pull quay.io/prometheus/node-exporter:v1.12.1
    podman pull ghcr.io/ggml-org/llama.cpp:server-b11429

The images are public and multi-arch (`linux/amd64`, `linux/arm64`); no
registry login is needed. The four `ghcr.io` pulls are a warm-up rather than a
prerequisite: those units carry `Pull=newer`, so the first `systemctl start`
fetches them anyway. The `traefik`, `node-exporter` and `llama.cpp` pulls are required —
those units are pinned to a fixed tag and have no `Pull=` line. To build them on the host instead, use
`podman build --build-arg SERVICE=<service> -t localhost/insights-<service> .`
and change each unit's `Image=` line to match.

### 4. Install the units

    install -m 644 deploy/quadlet/*.pod       /etc/containers/systemd/
    install -m 644 deploy/quadlet/*.volume    /etc/containers/systemd/
    install -m 644 deploy/quadlet/*.container /etc/containers/systemd/

Thirteen units: one pod, five volumes (the three databases, the certificate
store and the embedding model), and seven containers. Six of the containers share **one** pod and
therefore one network namespace. That is not a packaging convenience — it is
what makes the proxy's connection to a service a real loopback connection with
no address translation in the path, which is what the default
`TRUSTED_PROXY_CIDRS=127.0.0.0/8` depends on. See "Authentication".

The pod publishes ports 80 and 443. No container publishes a port of its own,
which is what keeps the three operator dashboards reachable only through the
proxy.

The sixth container, `embedder`, is a small local model server that lets the
review queue group look-alike finding classes (see "Review" below). It is
optional: `insightsd` works without it, and the groups simply stop growing.
It listens on loopback port 9597 inside the pod, published nowhere, and is
told where to find it by `EMBED_URL` in `insightsd`'s unit. **Its first
start needs network access to Hugging Face**: it downloads the 37 MB model
itself, into the `insights-models` volume, and every later start reads it
from there. Expect it to report `starting` for a minute on that first start.
It uses well under 100 MB of memory and needs no secret.

The seventh container, `node-exporter`, reports the host's own CPU, memory, disk
and network figures. It sits **outside** the pod, on the host's network, and
listens on port 9100. That is what lets the firewall guard it: unlike a
published pod port, it is an ordinary host service. It will not start without
the firewall, and it stops if the firewall stops, so it is never reachable by
anyone but the metrics server.

### 5. Create the secrets

Four environment files, mode 0600, none of them in the repository.

    install -d -m 755 /etc/insights
    umask 077
    printf 'AUTH_PEPPER=%s\n'   "$(openssl rand -hex 32)" > /etc/insights/authd.env
    ADMIN_API_KEY=$(openssl rand -hex 24)
    printf 'LLM_API_KEY=%s\nADMIN_API_KEY=%s\n' "<your model API key>" "$ADMIN_API_KEY" \
                                                          > /etc/insights/insightsd.env
    printf 'ADMIN_API_KEY=%s\n' "$ADMIN_API_KEY"          > /etc/insights/threatd.env
    : > /etc/insights/sizingd.env
    chmod 600 /etc/insights/*.env

`ADMIN_API_KEY` goes into two files with the same value: `threatd` checks it on
the blocklist dashboard's allowlist changes and `insightsd` on the logs
dashboard's review decisions, and one operator password covers both.

`sizingd` has no secret of its own. Create the empty file anyway: its unit
names that file unconditionally and will fail to start without it.

Then the operator password file for the proxy. Every operator gets a line, and
they all share one password — the `ADMIN_API_KEY` value. The **username** is
what gets recorded as the actor on any change made from the blocklist or logs
dashboard, which is why each operator gets their own line:

    install -d -m 755 /etc/traefik
    ADMIN_API_KEY=$(sed -n 's/^ADMIN_API_KEY=//p' /etc/insights/threatd.env)
    htpasswd -nbB alice "$ADMIN_API_KEY" >  /etc/traefik/operators.htpasswd
    htpasswd -nbB bob   "$ADMIN_API_KEY" >> /etc/traefik/operators.htpasswd
    chmod 640 /etc/traefik/operators.htpasswd

An unrecognized username is rejected by the proxy before the request reaches a
dashboard. The actor is a readable trail, not an authorization boundary:
anyone holding the key can claim any name.

### 6. Set the hostname and render the proxy configuration

Two values are per-deployment and live outside the repository, plus an
optional third:

    cat > /etc/insights/deploy.env <<'END'
    INSIGHTS_HOST=insights.example.com
    ACME_EMAIL=admin@example.com
    END

`METRICS_SCRAPER` is the optional one: the address (or CIDR range) of the
metrics server, the only client allowed to read the `/metrics/` paths — see
"Metrics". Leave it out to keep the default, `2.119.67.169`. If you set it
in step 1, add the same `METRICS_SCRAPER=<address>` line here, or the
firewall and the proxy will let in different servers.

Then render:

    bash deploy/render.sh

This writes `/etc/traefik/traefik.yaml` and
`/etc/traefik/dynamic/dynamic.yaml`. It fails loudly if either value is unset
rather than rendering a broken config, and refuses a `METRICS_SCRAPER` that
is not an address. Re-run it after any change to any of the three.

The routing half lands in a **directory** the proxy watches, rather than in a
single file, so that an extra set of routers can be dropped in beside it
without editing it — an edit would be overwritten the next time you render.
Nothing in a standard deployment puts a second file there, and every file in
that directory shares one namespace: a second file must never redefine a
router, service or middleware `dynamic.yaml` already names.

### 7. Start

    systemctl daemon-reload
    systemctl start insights-pod.service
    systemctl start authd.service
    systemctl start embedder.service
    systemctl start insightsd.service threatd.service sizingd.service
    systemctl start traefik.service
    systemctl start node-exporter.service

Quadlet generates these units from the files installed in step 4, so
`systemctl enable` is neither needed nor available. `WantedBy=multi-user.target`
inside each unit is what starts them at boot.

### 8. Verify

    systemctl is-active insights-pod authd embedder insightsd threatd sizingd traefik node-exporter
    podman ps --format '{{.Names}}\t{{.Status}}'

The four services, `embedder` and `node-exporter` report `healthy`. The proxy reports only `Up` — its unit
carries no health check, so that is its correct steady state.

Confirm every container actually joined the pod, because one that did not is a
dashboard exposed on its own port:

    podman pod inspect insights --format '{{range .Containers}}{{.Name}} {{end}}'

Then confirm the host's port surface:

    ss -tlnp | grep -E ':(80|443|959[0-9]|96[0-9][0-9])\b'

**Expect 80 and 443 only.** (Port 9100 is also open, held by
`node_exporter`; the pattern above leaves it out, and the next check covers
it.) A 95xx or 96xx port here means a container kept a
published port and is not in the pod. That is an unauthenticated fleet-wide
dashboard on a public interface — stop and fix it before going further. The
firewall does not save you here: it does not filter container ports.

Then the firewall and Cockpit:

    firewall-cmd --list-services           # ssh http https (dhcpv6-client may be listed too)
    firewall-cmd --list-rich-rules         # one 9100 rule per metrics server address, nothing else
    systemctl is-active cockpit.socket     # inactive, or no such unit

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
| `AUTH_VALIDATE_URL` | the external validator (default `https://my.nethesis.it/auth`). Entitlement checks call `<this>/service/<name>` — see "Authentication" |
| `AUTH_PEPPER` | HMAC pepper for the credential cache — secret. Unset gets a random, process-lifetime one, which empties the cache on every restart |
| `AUTH_CACHE_TTL`, `AUTH_NEG_CACHE_TTL` | how long a positive/negative validator outcome is cached (default `5m`/`30s`) |
| `AUTH_CACHE_MAX_ENTRIES`, `AUTH_NEG_CACHE_MAX_ENTRIES` | cache size caps, counted separately so a flood of wrong credentials cannot evict the fleet's valid entries (default `8192`/`4096`, about 3 MB together) |
| `AUTH_TIMEOUT` | validator request timeout (default `5s`) |

### `insightsd`

| Variable | Purpose |
|---|---|
| `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY` | any OpenAI-compatible provider |
| `LLM_SERVICE_TIER` | the provider's service tier, sent as `service_tier` (default empty: not sent). `flex` halves OpenAI's price for slower answers; when a flex request is refused for lack of capacity it is repeated once at the normal tier and price. With `flex`, raise `LLM_TIMEOUT` (for example to `10m`) and `ANALYSIS_TIMEOUT` above it |
| `LLM_TIMEOUT` | request timeout (default `120s`) |
| `GATE_MIN_NEW_TEMPLATES` | novel templates required before novelty alone fires (default `3`). A new security template always fires on its own |
| `GATE_SIMILARITY` | how alike, as a share of words, an unseen log line must be to a known one to count as known (default `0.9`; `1` turns the check off). Only identifier-like words may differ, never a real word. See "What counts as new" below |
| `GATE_SILENCE` | how long a known log line must have been absent for its return to count as new again (default `8d`, a little over a week so weekly jobs do not count; `0` turns it off) |
| `PROMPT_MAX_AMBIENT` | templates carried as background context beyond the ones the gate fired on (default `20`) |
| `LLM_MAX_CONCURRENCY` | model calls in flight at once (default `4`) |
| `LLM_MAX_CALLS_PER_SYSTEM_PER_DAY` | hard per-machine ceiling, UTC day (default `100`). A machine ships 96 windows a day, so this no longer binds normal operation — it is a backstop against a window being retried in a loop. `LLM_DAILY_SPEND_CAP_USD` is the limit that bounds a day's spend |
| `LLM_DAILY_SPEND_CAP_USD` | fleet spend ceiling for the UTC day (default `0`, off). On breach the gate narrows to security-only rather than stopping |
| `LLM_PRICE_INPUT_PER_MTOK`, `LLM_PRICE_OUTPUT_PER_MTOK` | prices for the cost ledger (default `0`). Without them the ledger records zero cost |
| `LLM_PRICE_CACHED_INPUT_PER_MTOK` | price of the input the provider served from its prompt cache (default: half of `LLM_PRICE_INPUT_PER_MTOK`, which is `gpt-4o-mini`'s discount; `gpt-6-luna`'s cached price is a tenth of its input price) |
| `PIPELINE_EXCLUDE_MODULES` | modules dropped from every bundle before analysis (default `crowdsec`, which has its own pipeline). Matches a module **family** or an exact instance id — configure the family, since NS8 numbers instances per cluster and `crowdsec1` excludes nothing on a node running `crowdsec3` |
| `PIPELINE_EXCLUDE_SERVICES` | syslog identifiers dropped the same way, matched against the `[tag]` on each masked log line (default `insights,alert-proxy`). `insights` stops a co-located server from analysing its own logs; `alert-proxy` stops the fleet re-reporting alerts your monitoring stack has already raised and already sent you. The tag is matched on every line, not only host ones — which is how `alert-proxy` is excluded without excluding the `metrics` module it runs inside. Note `PIPELINE_EXCLUDE_MODULES=alert-proxy` would match nothing: it is not a module |
| `STALE_AFTER` | how long without a recurrence before a finding is presumed resolved (default `24h`) |
| `ADMIN_API_KEY` | password for the logs dashboard's review decisions — secret, the same value `threatd` reads. Unset means the review queue is read-only and its routes answer `405` |
| `QUEUE_SIZE` | bundles buffered before ingest answers 503 (default `256`) |
| `QUEUE_WORKERS` | concurrent analyses (default `2`) |
| `ANALYSIS_TIMEOUT` | ceiling for one bundle's analysis (default `5m`) |
| `TEMPLATE_RETENTION` | how long a template survives with no fresh sighting (default `9600h`, 400 days). **The most sensitive of the three retentions** — this table is the gate's memory of what it has seen, so pruning it faster than a real recurring line recurs makes that line pay for a model call as if it were new |
| `FINDING_RETENTION` | how long a stale finding survives (default `4320h`, 180 days). An open finding is never pruned at any age. Past this window a recurrence reads as a new finding rather than a reopen — a continuity cost only |
| `ANALYSIS_RETENTION` | how long a cost-ledger row is kept (default `2160h`, 90 days). **This one destroys data permanently**: there is no rollup table, so `/cost` silently truncates its spend history at the cutoff |
| `EMBED_URL` | base URL of the embedding sidecar that groups similar finding classes on `/review` (default empty: grouping off). The deployed unit sets `http://127.0.0.1:9597`. With it set and the sidecar down, everything else keeps working and `/review` just shows no new groups |
| `REVIEW_GROUP_SIMILARITY` | how alike two classes' evidence must be, as a cosine between 0 and 1, for the newer to join the older's group (default `0.98`; above 0 and at most 1, startup refuses a number outside that range, or `NaN`, but a value that is not a number, such as `0,98`, is silently replaced by the default). Higher groups less and is safer. It is recorded on each class when it is grouped, so changing it affects only classes grouped afterwards |
| `GROUP_INTERVAL` | how often the grouping pass runs (default `1m`; must be positive when `EMBED_URL` is set, startup refuses otherwise); each run groups up to 200 ungrouped classes |
| `MAINT_INTERVAL` | how often the housekeeping pass prunes those three tables (default `10m`). Each prune is internally batched, so running it often is cheap |

### `threatd`

`threatd` checks the settings below at startup. A value that is out of the
stated range, or one that is set but does not parse at all (an integer or
duration variable's value must actually be one — `THREAT_EVENT_RETENTION=30d`
is rejected rather than silently becoming the default, since Go's duration
syntax has no `d` unit), stops it with an error naming the variable, visible
in `systemctl status threatd`.

| Variable | Purpose |
|---|---|
| `ADMIN_API_KEY` | password for the blocklist dashboard's write routes — secret. Unset means those routes answer `405`, never a default credential. `insightsd` reads the same variable for its review decisions |
| `BLOCKLIST_CONSENSUS_INTERVAL` | how often consensus runs and the feed is regenerated (default `5m`). Must be positive, and must not exceed `BLOCKLIST_WINDOW` — a longer interval leaves sightings that land and age out between two passes uncounted by either |
| `BLOCKLIST_WINDOW` | rolling observation window for promotion (default `1h`). Must be positive |
| `BLOCKLIST_MIN_SYSTEMS` | distinct machines required to publish an address (default `3`). It can be raised, never lowered: below `3` the service refuses to start |
| `BLOCKLIST_TTL` | how long a listing survives its last sighting (default `24h`). At least `BLOCKLIST_WINDOW`, or a listing would be written already expired |
| `BLOCKLIST_MAX_ENTRIES` | hard cap on the served feed (default `50000`). Must be positive. When more addresses are listed, the ones seen least recently are left out, and the blocklist dashboard says the feed is capped |
| `THREAT_EVENT_RETENTION` | how long raw sightings are kept (default `168h`). It is also how far back the dashboard's daily totals go: there is no longer-term history. At least `BLOCKLIST_WINDOW`, or sightings would be deleted before consensus counts them. A reported decision older than this is dropped at ingest and counted as `dropped_time`, the same as an unparseable `created_at`: the next prune would delete it anyway |
| `THREAT_INGEST_RETENTION` | how long per-system ingest-accounting rows are kept (default `2160h`, 90 days). This is what `/systems` is driven by, not `THREAT_EVENT_RETENTION` — deliberately much longer, so a system that has gone quiet still shows up there for a quarter after its raw sightings have aged out. Pruned as a step in the consensus pass. Must be positive |
| `THREAT_MAX_DECISIONS_PER_REQUEST` | per-request cap; over-cap batches are truncated, not rejected (default `500`). Must be positive |
| `THREAT_MAX_ALLOWLIST_REQUESTS_PER_SYSTEM` | distinct pending CIDRs one system may hold in the allowlist review queue (default `25`). Over-cap asks are **refused** with `429`, not truncated — a request is a permanent row only a human decision deletes. Re-asking about a CIDR the system already raised is always accepted, since it adds no row. Must be positive, or the cap is silently off |
| `THREAT_ALLOWLIST_REQUEST_RETENTION` | how long an unreviewed client allowlist request is kept (default `2160h`, 90 days). Pruned as a step in the consensus pass; a dropped ask can simply be made again, which also re-ranks it as current evidence. The audit trail is never pruned. Must be positive |
| `THREAT_QUEUE_SIZE` | sanitized reports buffered before ingest answers 503 (default `256`). Must be positive |
| `THREAT_QUEUE_WORKERS` | concurrent store writes (default `2`). Must be positive |
| `THREAT_QUEUE_TIMEOUT` | ceiling for one report's write (default `30s`). Must be positive, or every queued write fails immediately after the reporter has already been told `202` |

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

`INSIGHTS_HOST`, `ACME_EMAIL` and `METRICS_SCRAPER` live in
`/etc/insights/deploy.env` and are consumed only when rendering the proxy
configuration (install step 6); `METRICS_SCRAPER` is also read by
`deploy/host-firewall.sh` (install step 1). No binary reads any of them.

| Variable | Meaning |
|---|---|
| `INSIGHTS_HOST` | the public hostname every route answers on. Required |
| `ACME_EMAIL` | contact address for the Let's Encrypt account. Required |
| `METRICS_SCRAPER` | IP address or CIDR range of the metrics server, the only client allowed on the `/metrics/` paths and on port 9100 (default `2.119.67.169`, `metrics.nethesis.it`'s public address). Never a hostname |

## Authentication

**Nodes.** A node authenticates with its NethServer subscription credential,
as HTTP Basic. The proxy calls `authd` before the request reaches a pipeline
at all; `authd` forwards the credential to `AUTH_VALIDATE_URL` and caches the
outcome. A `2xx` lets the request through unchanged, a `401` rejects it, and a
`503` — the validator being unreachable — is retried by the node rather than
treated as a rejected credential. That distinction matters: a node retries a
gap, but a false `401` is a customer-visible outage.

A redirect from the validator (`AUTH_VALIDATE_URL` configured as `http://`
where upstream wants `https://`, or a trailing-slash mismatch) is also a `503`,
never followed. If every node starts getting `503` right after a
configuration change, read `authd`'s `validator unavailable` log line: it
names the upstream HTTP status, or says there was no response at all, and for
a redirect where it pointed.

**Two Threat Shield routes need more than a subscription.** Every machine with
a subscription sends data to the server; only a machine with the Threat Shield
entitlement can download the list. So `GET /blocklist/v1/feed` and
`POST /blocklist/v1/allowlist-requests` are validated against
`AUTH_VALIDATE_URL/service/ng-blacklist` rather than `AUTH_VALIDATE_URL`, while
`POST /blocklist/v1/events` and every log and sizing route use the plain check.
The node sends exactly the same credential either way — there is no second
token to distribute — and it is the proxy that picks which check runs.

A subscriber without the entitlement gets **`403`, not `401`**. The difference
is the whole point: `401` means the credential is wrong and somebody should go
looking at the node's configuration, `403` means the credential is fine and the
customer needs the entitlement. Neither is retryable, but they end in different
places. If a customer reports that the blocklist stopped updating, check for
`403` first — the node will still be reporting its own bans successfully, which
makes the credential look healthy from every other angle.

Adding a future entitlement is a Traefik change, not a release: `authd` builds
the upstream URL from the service name in its own path
(`/auth/service/<name>`), so a new route needs a new `forwardAuth` middleware
and nothing else. Names are limited to lowercase letters, digits and inner
dashes.

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
  what makes the default value correct: all six containers in the pod share one network
  namespace, so the proxy's connection really is `127.0.0.1` by construction.
  Every pod member, the `embedder` included, connects from that range and is
  therefore inside the trust boundary: a compromised embedder (a third-party
  server parsing log-derived text) could claim any `system_id` on the three
  pipelines' ingest.
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

The blocklist and logs dashboards' write routes authenticate against
`ADMIN_API_KEY` a second time, inside the application, and refuse cross-site
requests. That is not redundant. The proxy's layer is still Basic auth, and a
browser replays a cached Basic credential automatically on a form POST from any
other page the operator later visits — without the in-application check, any
site could silently add an attacker's address to the fleet allowlist, or hide a
finding from every customer.

## Connecting nodes

A node authenticates with its NethServer subscription credential and calls in;
the server never initiates contact with a node. Each pipeline has its own
prefix on the one served hostname:

| Path | Who calls it |
|---|---|
| `POST /logs/v1/bundles` | `ns8-loki`'s collector ships a 15-minute bundle |
| `GET /logs/v1/findings` | a node reads its own findings, never anyone else's |
| `POST /blocklist/v1/events` | `ns8-crowdsec` reports ban decisions |
| `GET /blocklist/v1/feed` | a node fetches the consensus blocklist — **needs the Threat Shield entitlement** |
| `POST /blocklist/v1/allowlist-requests` | a node asks for an address to be left alone — **needs the Threat Shield entitlement** |
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

That is the whole upgrade for an install that already has every unit. A
release that **adds units** needs more. This one adds the embedding sidecar, so
an existing install does, once:

    podman pull ghcr.io/ggml-org/llama.cpp:server-b11429
    install -m 644 deploy/quadlet/embedder.container deploy/quadlet/insights-models.volume \
                   deploy/quadlet/insightsd.container /etc/containers/systemd/
    systemctl daemon-reload
    systemctl start embedder.service
    systemctl restart insightsd.service

The first start of `embedder` needs outbound network to download the model (see
"Install"). After that the four pipeline units carry `Pull=newer`, so each start
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

    systemctl stop node-exporter traefik insightsd threatd sizingd embedder authd insights-pod
    rm -f /etc/containers/systemd/{authd,insightsd,threatd,sizingd,traefik,node-exporter,embedder}.container
    rm -f /etc/containers/systemd/insights.pod
    rm -f /etc/containers/systemd/{insights-logs,insights-threat,insights-sizing,insights-models,traefik-acme}.volume
    systemctl daemon-reload

At this point nothing runs and nothing starts at boot, but the data is still
there. To keep it — for a rebuild or an upgrade — stop here.

**The next step destroys data.** The three volumes hold every finding, the
cost ledger, the blocklist and its allowlist with its audit trail, and the
sizing history. None of it is recoverable and nothing else has a copy.

    podman pod rm -f insights                    # if the pod outlived its unit
    podman volume rm insights-logs insights-threat insights-sizing insights-models traefik-acme

Then the configuration, the secrets and the images:

    rm -rf /etc/insights /etc/traefik
    rm -f /etc/systemd/journald.conf.d/insights.conf
    systemctl restart systemd-journald
    for s in authd insightsd threatd sizingd; do
      podman rmi ghcr.io/nethesis/nethesis-insights-$s:latest
    done
    podman rmi docker.io/library/traefik:v3.7.13
    podman rmi quay.io/prometheus/node-exporter:v1.12.1
    podman rmi ghcr.io/ggml-org/llama.cpp:server-b11429

The firewall stays on and Cockpit stays off; both were changes to the host
rather than to this deployment. To undo them:

    firewall-cmd --permanent --remove-service=http --remove-service=https
    firewall-cmd --permanent --list-rich-rules | grep 'port="9100"' |
      while read -r r; do firewall-cmd --permanent --remove-rich-rule="$r"; done
    firewall-cmd --reload
    systemctl enable --now cockpit.socket    # only if Cockpit was in use

Two things to know afterwards. Nodes keep calling in and get a connection
refused, which they treat as a retryable outage — they do not need
reconfiguring unless the server is gone for good, in which case set
`ns8-loki`'s `active` to `false` and unset `INSIGHTS_SERVER_URL`. And any node
that imported the blocklist keeps its last copy until its own TTL lapses;
removing the server does not unblock anything.

## Metrics

### What to scrape

Six endpoints per server. Point Prometheus at every one of them; a sample
config with the labels the dashboard needs is further down.

| `service` label | URL | What it measures | Access |
|---|---|---|---|
| `logs` | `https://<host>/metrics/logs` | the log pipeline (`insightsd`): machines reporting, gate decisions, findings, queue, AI calls and spend | only from the metrics server |
| `threat` | `https://<host>/metrics/threat` | Threat Shield (`threatd`): machines reporting, events, blocklist size, ingest queue, blocklist pass | only from the metrics server |
| `sizing` | `https://<host>/metrics/sizing` | fleet sizing (`sizingd`): cohort pass | only from the metrics server |
| `authd` | `https://<host>/metrics/authd` | node login checks (`authd`): cache hits, upstream answers | only from the metrics server |
| `traefik` | `https://<host>/metrics/traefik` | the proxy: every request, by route and status | only from the metrics server |
| — | `http://<host>:9100/metrics` | the host: CPU, memory, disk, network | only from the metrics server |

None of them has a password, the same as every other host
`metrics.nethesis.it` scrapes. What protects them is the source address:
only `METRICS_SCRAPER` (default `2.119.67.169`, see install step 6) gets an
answer. The proxy checks it for the five `https` paths — everyone else gets
`403` — and the host firewall checks it for port 9100, where everyone else
gets no answer at all. The two checks are in different places because the
firewall cannot see the proxy's port 443: podman routes it past the firewall.

A server that does not run every pipeline answers `502` on the missing ones'
paths. On a server running Threat Shield alone, scrape just `threat`,
`authd`, `traefik` and `node`.

### How the endpoints work

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
reasoning applied to the operator UI. The five public paths answer only the
metrics server's address (`METRICS_SCRAPER`), with no credential of any
kind. Traefik checks the address itself (the `metrics-allow` middleware);
the four Go binaries never see the check.

**Every metric is prefixed with the name of the container exporting it** —
`insightsd_`, `threatd_`, `sizingd_`, `authd_` — so one Prometheus holding
all five targets never has to disambiguate two services' request counts by
label alone. Traefik does the same for itself (`traefik_*`) out of the box.

The one deliberate exception is the standard Go runtime and process
collectors, which keep their conventional unprefixed `go_*` and `process_*`
names on all four binaries (plus `promhttp_*`): every off-the-shelf Go or
Grafana dashboard and every `go_*`-based alert rule queries those exact
names, and prefixing them would break all of it for the sake of tidiness.
Tell the two apart by the `service` label your scrape config sets.

So, per binary, in addition to `go_*`/`process_*`:

| Metric (shown with the `insightsd_` prefix) | Binary | What it means |
|---|---|---|
| `<svc>_http_requests_total{method,route,status}`, `<svc>_http_request_duration_seconds` | all four | every request, labeled by the registered route pattern — never the raw path, which would be unbounded |
| `insightsd_queue_depth{queue}`, `_queue_capacity{queue}`, `_queue_workers{queue}` | `insightsd` (`queue="bundle"`), `threatd` (`queue="threat_events"`) | the bundle/ingest queue's live state |
| `insightsd_llm_calls_total{result}`, `insightsd_llm_cost_micros_total` | `insightsd` | model calls by outcome (`success`, `transient`, `permanent`, `parse`) and running spend in micro-dollars |
| `insightsd_budget_rejections_total{reason}` | `insightsd` | windows `internal/budget` suppressed before the gate ran |
| `insightsd_windows_total{result}` | `insightsd` | every new 15-minute window, by what the gate decided: `called` (an AI call was made — counted per attempt, so a retried window counts again), `gated_out` (nothing worth a call) or `budget` (stopped by the spending ceiling before the gate ran). A duplicate window is not counted |
| `insightsd_gate_templates_total{result}` | `insightsd` | log lines the gate's two refinements of "new" moved: `near_known` (unseen, but nearly identical to a known line, so not paid for) and `returning` (known, but back after `GATE_SILENCE`, so paid for as new) |
| `insightsd_active_systems`, `threatd_active_systems` | both | machines that reported in the last 24 hours: a log bundle for `insightsd`, a threat event for `threatd` |
| `insightsd_findings{status}` | `insightsd` | findings currently kept, by status (`open`, `stale`); dismissed classes are not counted |
| `threatd_events_total{result}` | `threatd` | decisions nodes sent, by what ingest did with each: `accepted`, one of the `dropped_*` reasons the `202` reply lists, or `truncated`. A batch refused with `503` is not counted, because the node sends it again |
| `threatd_blocklist_entries` | `threatd` | addresses in the published feed — what nodes download, after the allowlist and `BLOCKLIST_MAX_ENTRIES` |
| `threatd_ingestq_full_total{queue}` | `threatd` | `POST /v1/events` batches that hit `503` because the ingest queue was saturated |
| `<svc>_pass_runs_total{pass,result}`, `<svc>_pass_duration_seconds{pass}`, `<svc>_pass_last_success_timestamp_seconds{pass}` | `insightsd` (`pass="log maintenance"`), `insightsd` (`pass="class grouping"`, only when `EMBED_URL` is set), `threatd` (`pass="blocklist consensus"`), `sizingd` (`pass="sizing cohort"`) | the periodic background pass each binary runs. The grouping pass degrades rather than fails: a sidecar outage, or a class the sidecar rejects, still counts as a successful run, so watch the `embedder`'s health and the warning in the `insightsd` log instead |
| `authd_cache_results_total{result}`, `authd_upstream_results_total{result}` | `authd` | forward-auth cache hits/misses and what the upstream validator answered (`valid`, `invalid`, `forbidden` — a subscriber without the entitlement — or `unavailable`) |
| `authd_http_requests_total{route="/auth/service/{service}",status}` | `authd` | entitlement checks by outcome; the `403` share is how much of the fleet is asking for Threat Shield without holding it |

No metric anywhere carries a `system_id` label, a raw request path, a
scenario, a template or a module name — the same cardinality and
data-protection rule this document's "How it works" sections describe for
gate reasons and findings.

**Counters start at 0, not missing.** Every counter above whose labels are a
known list — the four `insightsd_llm_calls_total` outcomes, the
`insightsd_budget_rejections_total` reason, the three
`insightsd_windows_total` results, both `insightsd_gate_templates_total`
results, every `threatd_events_total` result, both
`authd_*` families, `threatd_ingestq_full_total`, and both
`<svc>_pass_runs_total` results — is
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

**The counts of machines, findings and blocklist entries update on the
background pass, not on every scrape.** They are read from the database,
and reading it on every scrape would compete with the pipeline's own writes.
`threatd`'s are refreshed after each consensus pass (every
`BLOCKLIST_CONSENSUS_INTERVAL`, default 5 minutes) and `insightsd`'s after
each maintenance pass (every `MAINT_INTERVAL`, default 10 minutes), so a
graph of them moves in steps of that size. Right after a restart they are
missing until the first pass finishes, and `threatd_blocklist_entries` stays
missing until a consensus pass has succeeded: "not counted yet" is not the
same as zero. If a refresh fails, the previous values stay up and the pass
is counted as failed in `<svc>_pass_runs_total`.

A sample Prometheus scrape config. It is the shape `metrics.nethesis.it`
already uses: one job for the five `/metrics/` endpoints, one for the host,
and two labels on every target.

```yaml
scrape_configs:
  - job_name: nethesis-insights
    scheme: https
    static_configs:
      - targets: ["insights.example.com:443"]
        labels: {system: insights, service: logs, __metrics_path__: /metrics/logs}
      - targets: ["insights.example.com:443"]
        labels: {system: insights, service: threat, __metrics_path__: /metrics/threat}
      - targets: ["insights.example.com:443"]
        labels: {system: insights, service: sizing, __metrics_path__: /metrics/sizing}
      - targets: ["insights.example.com:443"]
        labels: {system: insights, service: authd, __metrics_path__: /metrics/authd}
      - targets: ["insights.example.com:443"]
        labels: {system: insights, service: traefik, __metrics_path__: /metrics/traefik}
  - job_name: node
    static_configs:
      - targets: ["insights.example.com:9100"]
        labels: {system: insights}
```

The last job is the host itself: `node_exporter`'s standard `node_*` metrics,
straight from port 9100 rather than through the proxy. Like the other five it
has no password, and unlike them no TLS either; the firewall, which lets in
only the metrics server, is its only protection (install step 1).

The five `/metrics/` targets all scrape the same host on the same port,
differing only in the path, and Prometheus keeps no label for the path. So the
`service` label is what separates them. You need it for the `go_*` and
`process_*` metrics, which are identically named on all four binaries —
`go_goroutines{system="insights", service="authd"}`. Every other metric
already carries its service in the name, so `insightsd_queue_depth` is
unambiguous with or without the label.

### The labels are not cosmetic

The dashboard in the next section selects on labels, never on the job name,
so the job can be called anything your Prometheus already uses — on
`metrics.nethesis.it` the five endpoints sit in its shared `traefik` job, next
to every other Traefik it scrapes. What it needs on each of the five targets:

- **`system="insights"`**, which keeps every other host out of every panel.
- **`service`**, set to `logs`, `threat`, `sizing`, `authd` or `traefik`
  exactly. It names each service on the per-service panels and picks its
  fixed colour, and `service="traefik"` picks the proxy out of the rest.
- **`instance`**, which Prometheus sets from the target address by itself.
  It is what the dashboard's **Server** picker lists, so one dashboard shows
  one server at a time — the production and development servers never add
  up into one line. The list is read from the `authd` target, since every
  server runs `authd`.

Leave one out and the panels that need it go blank — the metrics are still
collected and every other panel still draws, which is what makes it
confusing rather than obvious.

One side effect of the `service` label: Traefik exports a `service` label of
its own, naming its backend. Prometheus keeps the target's and renames
Traefik's to `exported_service`; the dashboard's per-backend panel reads that
name.

### The dashboard

`deploy/grafana/nethesis-insights.json` is written to be imported into the
Grafana you already run. It carries no deployment-specific value: every panel
queries through a **datasource variable** rather than a fixed datasource id,
so it resolves to your default Prometheus on first open instead of pointing at
one that does not exist.

To install it:

1. Copy `deploy/grafana/nethesis-insights.json` to the machine running
   Grafana, or open it in the repository and copy its contents.
2. In Grafana, **Dashboards → New → Import**, paste the JSON, **Load**.
3. Choose a folder if you want one, then **Import**.

There is no datasource field to fill in on that screen — the variable is
resolved when the dashboard opens, not when it is imported. It appears as
**Nethesis Insights** (uid `nethesis-insights`) already pointing at your
default Prometheus, and the **Data source** picker at its top left switches
it to another one if you have more than one. The **Server** picker next to it
chooses which Nethesis Insights server the panels show. Thirty-two panels
in eight rows: overview, HTTP, the log pipeline, Threat Shield, forward auth,
background passes, the proxy, and the Go runtime. Nothing in it writes anywhere or needs
a plugin. The host's own `node_*` metrics are not on it; any standard
node_exporter dashboard shows them from the host's port-9100 target.

Two things it assumes, both satisfied by the scrape config above:

- **The labels**, as the previous subsection describes.
- **Every one of the five `/metrics/` targets.** A missing target costs you the
  panels that query it and nothing else — the dashboard does not fail as a
  whole. On a server running Threat Shield alone, the log pipeline and sizing
  panels stay empty.

Imported this way the dashboard is an ordinary editable dashboard: Grafana
owns it, and re-importing a later version of this file overwrites your edits.

## The operator UI

Three separate dashboards, one per pipeline, each built into its own service:
the logs dashboard at `/logs`, the blocklist dashboard at `/blocklist`, the
sizing dashboard at `/sizing`. Each is **off unless that service's
`UI_LISTEN_ADDR` is set**. The units installed above set all three.

### Before exposing a dashboard

Unlike the node API, which is per-machine and authenticated, **a dashboard's
`GET` is unauthenticated and fleet-wide inside the application.** It shows
every machine's findings, templates and spend.

So either bind `UI_LISTEN_ADDR` to `127.0.0.1` or a trusted management
network, or put the proxy in front of it. The service will not refuse a wider
bind — that is the administrator's call — but it logs a warning at startup
whenever the dashboard is bound anywhere but a loopback address, so the choice
is never made by accident. In the deployment above, no container publishes a
dashboard port at all: the only way to reach one is through the proxy.

Everything else about a dashboard is built to match that exposure:

- **`GET` is read-only.** Every page answers `GET` with no credential.
- **Only the blocklist and logs dashboards can write**, only when
  `ADMIN_API_KEY` is set, and only on a short enumerated list of routes that
  each authenticate first — allowlist changes on one, finding review decisions
  on the other. Those routes answer `POST` and nothing else; every other method,
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
  tag, filters are plain forms, and a row's detail opens in a native dialog
  (an HTML invoker button, not a script), which needs a browser released
  since late 2025. An
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
| `/logs/` | The actual reported problems, most severe and most recent first. Filter by machine, status (open/stale) or severity. The **Nodes** column names the cluster machines the problem was last seen on, each as its node number and full name (`1 · rl1.example.org`), or the bare number when no name has been reported yet. Click a title to open the full summary, suggested action, evidence, fingerprint, class, security tag, trigger, and whether the customer sees it; Escape, a click outside it or **Close** dismisses it. The **System** column shows the first characters of the id, and **Nodes** lists at most three machines per row (then "+N more"), each name cut short if long — hover for the whole of either; the dialog lists them in full. **The operator sees every finding here except those of a dismissed class; a customer sees one only once its class has been delivered on `/logs/review`.** The ID filter also matches a class key. |
| `/logs/review` | The review queue — see "Review" below. New finding classes wait here, ranked by how many machines raised them, each with its titles, summary and evidence and the decisions you can make on it. Switch the view to see classes already delivered, kept internal or dismissed, or all but the dismissed ones. Similar classes are grouped and may carry a suggested decision ("Review" below). Click a column name to sort by it, click it again to reverse; the arrow marks the column in use, and the order survives filtering and every decision. The **Module** column shows the module of the class's latest finding, `(host)` for host-level logs, and "+N" when it names more — the class dialog lists them all. A long class name is cut short with "…"; hover for the whole of it. |
| `/logs/review/stats` | Per prompt version: how many finding classes it raised and what operators decided about them. The number to watch when the prompt changes. |
| `/logs/review/audit` | Every review decision, who made it and when. |
| `/logs/systems` | Every cluster the server has ever heard from, with a quick summary: its **nodes** (number and reported name), how many templates, findings, analysis windows, and how much it's cost so far. |
| `/logs/analyses` | The cost ledger: every window processed, whether it was gated out, whether the AI was called, tokens used (including the part served from the provider's cache at a discount), cost, how long it took, any error, and whether a spending limit suppressed it. This answers "what did we spend, and on what." |
| `/logs/gate` | The gate's decisions grouped by *why* — how many windows and how much money went to each distinct set of reasons. Read the summary line first: it says what share of windows was gated out, which is the only number that tells you whether the gate is working. In the table, remember that a reason set *is* the trigger, so every window in a row with reasons went to the AI; the `(none)` row is the free ones, plus any a spending limit refused (**Suppressed**). Scoped to the last 7 days by default — see the note below. |
| `/logs/cost` | Spend and token usage per day and per model — the trend line version of the ledger. |
| `/logs/templates` | What the server currently considers "already known" for a machine — i.e., what would *not* by itself trigger a new AI call. One row per condition per module *kind*, so many copies of one application share a row. |
| `/logs/status` | Is the server healthy? Queue backlog, uptime, build version, and the full effective configuration it's running with. |

**The blocklist dashboard**, at `/blocklist`:

| Page | What you're looking at |
|---|---|
| `/blocklist/` | What the fleet currently agrees is malicious. Each row expands to the evidence that got it published — how many machines, how many hits, under which rule. Below it: the allowlist, i.e. the reason an address might *never* appear here despite the fleet reporting it. |
| `/blocklist/systems` | One row per machine that has ever reported a CrowdSec decision, including a machine whose every report was a duplicate or got dropped by the sanitizer and therefore never shows up anywhere else. |
| `/blocklist/events` | The raw sightings behind the list. Filter by address to answer "who reported this, and when" — useful when somebody's customer asks why they got blocked. |
| `/blocklist/stats` | Two things: the day-by-day threat totals broken down by CrowdSec scenario, with a per-day total, over the days still kept (`THREAT_EVENT_RETENTION`, a week by default); and what each machine contributed — including how much of what it sent was discarded, and for which reason. The daily totals are recomputed at most every five minutes, whatever the page traffic, and the page says when they were last computed. The oldest day and today are marked as partial/in-progress, since neither one is a complete day's total. |
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

- a **digest**: for each log module, how many lines it produced this window.
  The server no longer reads it — see "What counts as new" below for why
  volume alone is not a reason to call the AI;
- a list of **templates**: the distinct *shapes* of log lines seen (see
  below), each with a count;
- bookkeeping about how much the node had to truncate to stay within its own
  budget;
- the **node roster**: for each machine in the cluster, its node number and
  the name it reports for itself, plus — on each template — which of those
  machines produced it.

That last item is worth being precise about, because it is the one place the
server learns a customer machine's name. What a subscription identifies is an
NS8 **cluster**, not a machine, and one collector reports for the whole
cluster. Without the node numbers a finding could say what happened and when,
but not *where* — which on a multi-node cluster is the first thing you need.

The names do **not** come from your logs. Hostnames appearing inside a log
line are still masked out before the bundle leaves the machine, exactly as
before. The name is read separately from the cluster's own inventory (the
`ns8_node_info` metric every NS8 node publishes about itself), checked to be a
plausible hostname and nothing else, and stored once per machine rather than
copied into every finding — so renaming a node updates it everywhere within a
window. The AI is never shown either the names or the node numbers.

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
interesting**. Only a template that's genuinely new (or a known one that comes
back after a long silence — see the gate below) is worth spending money to
have an AI look at.

### 3. The gate: deciding if it's worth asking the AI

Calling an AI model costs real money, every time. If the server called it for
every 15-minute window from every one of ~2700 machines, the bill would be
enormous (roughly $16,000/month on a cheap model, by internal estimate) for
mostly "nothing happened" windows. So before anything is sent to the AI, the
**gate** looks at the bundle and asks: is there actually anything new or
unusual here? It says yes if:

- **several templates have never been seen before** for this machine (three by
  default, not one — see "what counts as new" below);
- a template tagged **security**-related is new for this machine (the node
  applies the security tag, not the server). A single new security-tagged
  template is enough on its own — it never has to wait for company.

**A window is sent to the AI only if at least one of the two conditions
above is true.** If neither is, the window is "gated out": the server still
does the cheap bookkeeping (remembers the templates) and moves on — no AI
call, no cost.

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

Collapsing needs a rule per kind of leak, and there are always more: a phone
system's call ids, a mail server's forwarding hashes, the usernames an
attacker tries. So the gate also treats a line as known when it is **nearly
identical** to one the machine already sent — same module kind, same number
of words, at least 90% of them the same and in the same place
(`GATE_SIMILARITY`) — **as long as every word that differs looks like an id**
(it contains digits, or mixes upper and lower case oddly) rather than a real
word. `Failed to reconnect` and `Failed to ping` differ in one real word, so
they stay different. Lines tagged security, and lines at priority critical or
above, are never matched this way. On the development fleet this check alone
avoided 28% of the AI spend.

**A line that comes back after a long silence counts as new.** If a machine
has not sent a known line for more than `GATE_SILENCE` (eight days by
default), its return is treated as new. This is how a known failure that
comes back — a backup that failed in March and fails again in May — still
gets looked at.

**Log volume alone is not a reason to call the AI.** An earlier version also
called it when a module logged far more than its running average. That
average only remembered about the last hour, so a quiet night made every
morning look like a flood: it fired in 42% of all windows and mostly found
noise. It was removed.

**Modules are counted by kind, not by copy.** A machine can run many copies of
one application — a measured hosting node runs 82 `nethvoice` and 71
`openldap` instances, named `nethvoice1`, `nethvoice2` and so on. Every copy
runs the same software and therefore says the same things, so the server groups
them by *kind*: `nethvoice5` and `nethvoice39` are both `nethvoice`. Without
that, one ordinary cron line occupied 82 separate templates on that machine,
each of them "never seen before" the first time its copy said it. Measured on
2026-09-02, grouping by kind and de-numbering the process names inside the line
took 678 stored templates down to 230 for the same set of real conditions.

The trade is that a finding names the kind (`openldap`) and not which of the
71 copies emitted it.

That is also why novelty needs more than one new template. A genuinely new
condition arrives as a handful of related lines; a single new line is nearly
always one more spelling of something the machine has been saying all week.

Note the shape of the security rule: *new*, not merely *present*.
Any machine reachable from the internet gets a constant trickle of failed SSH
logins, so "there is a security-tagged line in this window" is true of
essentially every window forever. Treating that as a reason to call the AI
made the gate stop gating — measured on a live node, 352 AI calls out of
352 windows, not one gated out. Steady background noise is not news; a new
kind of attack is.

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
statement. The useful number is what share of windows had *no* reasons.

Second, **reasons are stored spelled the way the gate spelled them at the time**.
When a gate rule changes, old rows keep the old wording — rows written before the
security rule became *new-or-surging* say `security_category`, older ones
still embed the counts and ratios that were later removed for making every window
its own group, and rows from before the volume check was removed carry
`deviation:…`, `security_surge` and `truncated_deviating`. That is deliberate:
a formula change should be visible, not silently rewritten. It also means an
all-time grouping compares different gates, which is why `/gate` defaults to a
recent window.

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

### 4. The analysis: when the AI actually looks

When the gate says yes, the server builds a prompt describing that window
(the interesting templates, what got truncated) and sends it
to an LLM, along with a reminder of what's *already* an open problem for this
machine so the AI doesn't re-report it.

The prompt does **not** carry every template in the bundle. A busy machine
ships 160-190 of them per window and only a handful are why the call happened,
so the AI is shown: everything new, everything security-tagged, and then the
busiest of what remains (20 lines by default) as background context. Repeated spellings of one line are folded into a single
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

### 5. Findings: the actual output

A **finding** is one reported problem: a title, a plain-language summary, a
suggested action, a severity (critical/high/medium/low), which log modules
it involves, the evidence (which templates) it's based on, and **which nodes
of the cluster it was seen on** — by number and, when known, by name.

Those nodes are the *most recent* occurrence's, not every node the problem has
ever touched. The column answers "where is this happening now": a condition
that moved from node 1 to node 3 reads as node 3. Accumulating instead would
mean a long-lived finding eventually listing every machine in the cluster and
telling you nothing. A node with no name yet shows as a bare number — the
number is the answer, the name is a convenience on top of it.

Deliberately, the node set is **not** part of a finding's identity (below). A
problem that spreads to a second machine is the same problem, with more
occurrences, not a new finding.

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

The same identity with the machine left out is the finding's **class**: what
an operator reviews before any customer sees the finding. That is the next
section.

### 6. Review: deciding what customers see

The AI's findings do not go straight to customers. An operator reviews them
first, on the logs dashboard's `/review` page, and **every new kind of
finding is withheld from customers until someone delivers it** — the
operator dashboard shows it straight away, the customer's findings API does
not. That includes security findings: they wait for review like everything
else.

What an operator reviews is a **finding class**: one kind of problem, across
every machine. Two machines reporting the same database timeout have two
findings (one each, with their own counts and dates) but one class, so the
decision is made once. The class is worked out by the server from the log
lines the finding is based on, the same way a finding's identity is (section
6) but leaving the machine out — never from the AI's wording. The review
queue shows the pending classes by default, the ones seen on the most
machines at the top, each with the titles and summaries the AI wrote for it,
the evidence it is based on, and the most severe severity the AI gave any of
its findings. Switching to "all" still lists whatever is still pending
first, ahead of classes already delivered or kept internal, so there is
never a decided class to scroll past to find one still waiting.

A decision applies to the whole class: every finding in it, on every machine,
now and whenever it recurs — including machines that report it for the first
time next month, which get it delivered with no new review. It never applies
to just the one finding you happened to be looking at. The decisions are:

- **Deliver** — the class's findings go to customers.
- **Keep internal** — they stay on the operator dashboard only.
- **Dismiss** — for noise nobody needs to see again. The class disappears
  from every page: the customer's findings, the operator's findings page,
  the machines page's open count and the review queue (including "all").
  Security classes can be dismissed too, and keep their security tag. It
  does not save money — the AI is still told about these findings, so it
  does not report them again as new — and it does not delete them. To undo
  it, pick the **dismissed** view on `/review` and deliver the class or keep
  it internal. Be careful with a class whose evidence lists several
  different log lines: it stands for any conclusion the AI drew from that
  module and priority together, so dismissing it also hides later, different
  problems from the same place. The form warns about these.

Deliver, keep internal and dismiss can each be replaced by another later;
none can be taken back to "pending".
- **Security on/off** — whether customers see the class tagged as a security
  problem. The node's own classification sets it the first time the class is
  seen; after that it is the operator's, and a recurrence never resets it.
- **Set severity** — what customers are shown instead of the AI's severity.
  The stored severity, and what the AI is told, do not change.
- **Set docs** — a link to remediation documentation, returned to customers
  with each finding as `doc_ref`. Only an `http`/`https` address is accepted.

**Groups and suggestions.** About half of the classes waiting in the queue
restate one already seen, worded differently by the AI or citing a slightly
different log line. When the embedding sidecar is running (`EMBED_URL`), the
server compares each new class's evidence — the log lines it is based on, never
the AI's wording — with the first class of every existing group, and a class
that is nearly identical (`REVIEW_GROUP_SIMILARITY`) joins that group. Groups
form within about a minute of a class appearing. If the sidecar refuses a class
even at the shortest cut (four sizes are tried: the full text, then 1000, 600
and 300 bytes), the server skips that class, logs a warning and retries it on
the next run; it never holds up the classes behind it. On `/review`:

- A class in a group of two or more shows **group of N**. Click it to see the
  group alone, whatever its classes' visibility (dismissed ones included).
- If exactly one decision has been made among the group's other classes —
  all delivered, or all kept internal, or all dismissed — a pending class
  shows **Suggested: …** with how many similar classes were decided that way.
  If they disagree, or none is decided, nothing is suggested.
- On a group's page, **Deliver / Keep internal / Dismiss all pending in this
  group** applies one decision to the pending classes listed on the page, each
  recorded on `/review/audit` as its own decision with the detail
  `group <anchor>`. A class that joined the group after you opened the page,
  or that is hidden by the current view, is not decided: reload to see it.
  Classes already decided are left alone.
- **Deciding several classes at once.** Every row of the queue has a checkbox
  in its first column. Tick the classes you want, then press **Deliver
  selected**, **Keep selected internal** or **Dismiss selected** above the
  table. Each ticked class gets that decision, recorded on `/review/audit` as
  its own decision with the detail `bulk`. Unlike the group buttons this also
  changes a class that was decided before, the same as the per-class buttons;
  a class already at that decision is left alone. Up to 200 classes at a time,
  and there is no select-all: tick the rows one by one.

**A suggestion is only a hint.** Nothing is ever decided without someone
pressing a button, and a group is formed by similarity, not by identity: in a
trial on 1,259 real classes, grouping at `0.98` cut the decisions needed by
about 38%, and roughly 8% of inherited suggestions were a near-miss — a
related condition in the same component, never an unrelated one (judged by
an AI proxy, not by operators' own labels). Skim a group before deciding it
as a whole. Groups are also kept apart by the model that made them: if the
model is ever replaced, classes are grouped again from scratch.

None of this changes what the AI is shown or when the server pays for a
call: that is the gate's business, and nothing an operator decides here
reaches it.

Deciding needs the operator password (`ADMIN_API_KEY` on `insightsd`), and
every decision is written to `/review/audit` with who made it. Without the
key the queue is read-only — and, since nothing can be delivered, no new
finding reaches customers. `/review/stats` shows, per prompt version, how
many classes it raised and what operators decided about them; it is the page
to watch when the prompt changes.

A class nobody has decided on is forgotten once all its findings have been
pruned (`FINDING_RETENTION`); a class with a decision is kept, so the
decision still applies if the problem comes back.

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

4. **Nodes fetch the result.** Entitled nodes, that is: this is the one step
   that needs the Threat Shield entitlement and not merely a subscription (see
   "Authentication"). `GET /blocklist/v1/feed` returns a plain list of
   addresses, which the node imports into CrowdSec. Every entitled node gets
   the same list — there is no per-customer or per-tier filtering of it.

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
