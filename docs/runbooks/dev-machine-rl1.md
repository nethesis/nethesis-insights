# Rebuilding the rl1 dev machine

The dev box `rl1.leader.default.gs.nethserver.net` is provisioned on demand and
destroyed when idle. This runbook rebuilds it to the exact state development was left
in: an NS8 cluster running the `insights` container behind a Traefik route, with
`ns8-loki` on the same node shipping real log bundles to it.

Written to be executed top to bottom by an agent. Every step ends in a check.

## What is lost on teardown

`tofu destroy` removes the VM and everything on it: the SQLite database (findings,
templates, baselines, analyses), the NS8 cluster identity, and the subscription
registration. Nothing here is a source of truth — the code is in git, the deployment is
this file — but **dev data is gone unless exported first** (step 0).

Two secrets do not live in this repository and must be supplied by the operator when
rebuilding:

| secret | where it comes from |
|---|---|
| NS8 subscription (`system_id` + `auth_token`) | registering the cluster against the subscription portal; ends up in the `cluster/subscription` Redis hash |
| `LLM_API_KEY` | the OpenRouter account. The previous key was pasted into a chat transcript, so treat it as burned and issue a new one |

## 0. Before destroying: keep the database (optional)

Run on rl1 while it is still up:

```bash
podman volume export insights-data -o /root/insights-data.tar
```

Then copy it off the machine:

```bash
scp root@rl1.leader.default.gs.nethserver.net:/root/insights-data.tar /tmp/
```

Skip this and the rebuild starts with an empty database, which is usually what you
want — the schema is created on first start by `store.Init`.

Teardown itself:

```bash
cd ~/projects/ns8/ns8-terraform-infra && tofu destroy    # confirm: yes
```

## 1. Provision the VM

```bash
cd /home/giacomo/projects/ns8/ns8-terraform-infra
tofu apply -var 'leader_node={"dn1":"rl1"}'
```

Cloud-init takes a few minutes. DNS can lag behind the new public IP; fall back to
`tofu output` for the address.

**Check:** `ssh root@rl1.leader.default.gs.nethserver.net hostname -f` answers.

`controller.gs.nethserver.net` is a second name for the same host and is what the
Traefik route in step 5 matches. Confirm both names resolve to the new IP before
continuing, otherwise the route works locally and nowhere else:

```bash
getent hosts rl1.leader.default.gs.nethserver.net controller.gs.nethserver.net
```

## 2. Install NS8 and finalize the cluster

On the node:

```bash
curl https://raw.githubusercontent.com/NethServer/ns8-core/ns8-stable/core/install.sh | bash
create-cluster $(hostname -f):55820 10.5.4.0/24 Nethesis,1234
```

Then change the admin password away from the throwaway one to `Giacomo,1234` — use the
`nethserver-admin` skill for the exact `cluster-admin` action.

**Check:** `api-cli run get-cluster-status | jq .` returns, and
`api-cli run list-installed-modules` shows `traefik1` (core installs it).

Reference state at the time of writing: `ghcr.io/nethserver/core:3.21.1`, node id 1,
Rocky 9.

## 3. Register the subscription

The insights server authenticates edges with the cluster's subscription identity, and
`ns8-loki`'s collector reads the same pair, so this must exist before either works.

Register the cluster in cluster-admin (Settings → Subscription) with a valid auth token.

**Check:**

```bash
redis-cli --raw HGET cluster/subscription system_id
redis-cli --raw HKEYS cluster/subscription     # provider support_user auth_token system_id vpn_cert_cn
```

`system_id` is a UUID and `auth_token` is the shared secret. Both are needed verbatim in
step 4 — the server's `AUTH_SYSTEM_ID`/`AUTH_SECRET` must equal them, because the
prototype's `api.StaticAuth` compares against one hardcoded pair.

## 4. Deploy the insights container

Rootful podman via a quadlet unit — deliberately *not* an NS8 module: the image carries
no `imageroot`, and `add-module` would reject it.

Environment file. Fill `AUTH_SYSTEM_ID`/`AUTH_SECRET` from step 3 and supply a fresh
OpenRouter key:

```bash
install -m 600 /dev/null /etc/insights.env
cat > /etc/insights.env <<EOF
LISTEN_ADDR=:9595
DB_PATH=/var/lib/insights/insights.db
AUTH_SYSTEM_ID=$(redis-cli --raw HGET cluster/subscription system_id)
AUTH_SECRET=$(redis-cli --raw HGET cluster/subscription auth_token)
LLM_BASE_URL=https://openrouter.ai/api/v1
LLM_MODEL=nvidia/nemotron-3-ultra-550b-a55b:free
LLM_API_KEY=<paste a fresh OpenRouter key>
GATE_TOLERANCE=3.0
STALE_AFTER=24h
EWMA_ALPHA=0.3
LOG_LEVEL=debug
EOF
```

Unit file:

```bash
mkdir -p /etc/containers/systemd
cat > /etc/containers/systemd/insights.container <<'EOF'
[Unit]
Description=nethesis-insights analysis server
After=network-online.target
Wants=network-online.target

[Container]
Image=ghcr.io/nethesis/nethesis-insights:latest
ContainerName=insights
PublishPort=127.0.0.1:19595:9595
Volume=insights-data:/var/lib/insights
EnvironmentFile=/etc/insights.env
AutoUpdate=registry

[Service]
Restart=always
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl start insights.service
```

Port `19595` is loopback-only on purpose: Traefik reaches it over `127.0.0.1`, nothing
else can, and rl1 is a shared cluster where other modules own the low ports.

To restore a database exported in step 0, before the first start:

```bash
podman volume create insights-data
podman volume import insights-data /root/insights-data.tar
```

**Check:**

```bash
systemctl is-active insights.service                       # active
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:19595/healthz   # 200
podman inspect insights --format '{{index .Config.Labels "org.opencontainers.image.revision"}}'
```

The last one should match `git rev-parse origin/main`; `:latest` is published by the
`image` workflow on every push to `main`.

## 5. Publish it through Traefik

```bash
api-cli run set-route --agent module/traefik1 --data - <<'JSON'
{
  "instance": "insights",
  "url": "http://127.0.0.1:19595",
  "host": "controller.gs.nethserver.net",
  "path": "/insights",
  "strip_prefix": true,
  "lets_encrypt": false,
  "http2https": true,
  "user_created": true
}
JSON
```

`strip_prefix` is load-bearing: the server serves `/healthz` and `/v1/*` at the root, so
without it every request arrives as `/insights/v1/...` and 404s. `lets_encrypt` is off
because the node has no certificates; clients use `curl -k`.

**Check** from a machine outside rl1:

```bash
curl -sk -o /dev/null -w '%{http_code}\n' https://controller.gs.nethserver.net/insights/healthz   # 200
curl -sk -o /dev/null -w '%{http_code}\n' https://controller.gs.nethserver.net/insights/v1/findings # 401
```

## 6. Host tooling

```bash
dnf install -y sqlite      # not present on a fresh Rocky 9; hack/insights-sql.sh needs it
```

Copy the inspection helper from a checkout of this repository:

```bash
scp hack/insights-sql.sh root@rl1.leader.default.gs.nethserver.net:/root/insights-sql.sh
```

**Check:** `bash /root/insights-sql.sh counts` prints the table row counts (all zero on a
fresh database).

`hack/insights-api.sh` runs from the workstation, not the node:

```bash
export INSIGHTS_CRED="<system_id>:<auth_token>"
./hack/insights-api.sh health
```

## 7. Point the edge at the server

`ns8-loki` on this same node is the bundle producer. Install it if the fresh cluster does
not have it, then enable its collector:

```bash
add-module ghcr.io/nethserver/loki 1        # only if list-installed-modules lacks loki1
api-cli run module/loki1/set-insights --data '{"active":true,"base_url":"https://controller.gs.nethserver.net/insights","verify_tls":false}'
```

`verify_tls: false` because of the self-signed certificate from step 5. The collector
reads `system_id`/`auth_token` from `cluster/subscription` itself, which is why step 3
has to come first.

**Check:**

```bash
api-cli run module/loki1/get-configuration | jq .insights
# {"status":"active","base_url":"https://controller.gs.nethserver.net/insights",
#  "verify_tls":false,"subscription_configured":true,"last_run":"..."}
```

Bundles arrive every 15 minutes. Watch one land:

```bash
journalctl -u insights -f
# request received … user_agent=Python-urllib/3.11 → 202 → gate decision → llm → finding outcome
```

Install `crowdsec1` too when working on the Threat Shield plan
(`docs/plans/2026-08-07-threat-shield-server.md`); it is not needed for the bundle loop:

```bash
add-module ghcr.io/nethserver/crowdsec 1
```

## 8. End-to-end verification

```bash
# 1. ingest answers immediately, analysis runs behind it
journalctl -u insights | grep 'POST /v1/bundles'          # status=202 duration_ms=0..2

# 2. the pipeline produced findings
bash /root/insights-sql.sh findings
bash /root/insights-sql.sh analyses                        # gate_reasons, tokens, duration

# 3. the read API serves them, scoped to the authenticated system
curl -sk -u "<system_id>:<auth_token>" \
     'https://controller.gs.nethserver.net/insights/v1/findings?since=0' | jq '.findings | length'
```

A gated-out window is a success, not a failure: `bundle gated out` with `llm_called=0` in
`analyses` is the cost control working.

## Updating after a push to main

```bash
podman pull ghcr.io/nethesis/nethesis-insights:latest
systemctl restart insights.service
```

Or test an unmerged branch by building on the node — it has podman and a fast link,
which is the reason this project builds there rather than locally:

```bash
# from the workstation, in the repo root
tar --exclude=.git -czf - . | ssh root@rl1... 'mkdir -p /root/nethesis-insights && tar -xzf - -C /root/nethesis-insights'
ssh root@rl1... 'cd /root/nethesis-insights && podman build -t localhost/nethesis-insights:branch -f Containerfile .'
# then point Image= at localhost/nethesis-insights:branch, daemon-reload, restart
```

Remember to put `Image=` back to the registry tag afterwards.

## Gotchas

- **rl1 is a shared live cluster.** `nethvoice2`, `crowdsec1`, `samba2`, `metrics1`,
  `traefik1` may be running for other work. Never restart another module's services; keep
  new containers on high ports.
- `podman build` warns `HEALTHCHECK is not supported for OCI image format`. Cosmetic —
  buildkit in CI keeps the directive.
- The free OpenRouter model returns response headers immediately and the body only when
  generation finishes, ~105 s later. A slow request is not a hung one; `LLM_TIMEOUT`
  defaults to 2m and `ANALYSIS_TIMEOUT` to 5m.
- Analysis is asynchronous, so a POST result says only whether the bundle was accepted.
  Outcomes live in `journalctl`, the `analyses` table and the findings API.
