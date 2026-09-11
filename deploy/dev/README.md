<!--
Copyright (C) 2026 Nethesis S.r.l.
SPDX-License-Identifier: GPL-3.0-or-later
-->
# Development monitoring stack

Prometheus and Grafana, for a **development** host only. Everything in this
directory is optional and additive: a production deployment installs nothing
from here, and the fleet already has a Prometheus of its own that scrapes the
public `/metrics/*` paths documented in
[the administrator guide](../../docs/admin-guide.md#metrics).

This exists so that, on a dev box, you can look at what the four binaries and
Traefik are actually reporting without first standing up an external
monitoring system and handing it a credential.

## What it adds

Two containers in the **same pod** as the five production ones, so they share
one network namespace:

| Container | Port (inside the pod) | Public path | What stands in front of it |
|---|---|---|---|
| `prometheus` | `127.0.0.1:9090` | `/prometheus` | Traefik BasicAuth — `operators.htpasswd`, i.e. `ADMIN_API_KEY` |
| `grafana` | `127.0.0.1:3000` | `/grafana` | Grafana's own login |

Neither publishes a port. The pod still publishes only 80 and 443, so the
only way in from outside the host is through Traefik.

Prometheus scrapes the five services over **loopback**, not over the public
`/metrics/<name>` paths: it is inside the pod with them, so it needs no TLS
and no `metricsAuth` credential, and a rotated `/etc/traefik/metrics.htpasswd`
or a certificate problem cannot break local monitoring. The job names match
the sample scrape config in the administrator guide exactly, so a dashboard
or alert written against the documented names works here unchanged.

Grafana gets the Prometheus datasource by provisioning, not by hand, so it
survives a wiped volume and cannot drift from the URL Prometheus actually
serves on.

## How it stays out of production

Traefik's file provider reads a **directory**, `/etc/traefik/dynamic/`.
`deploy/render.sh` writes `dynamic.yaml` there on every deployment;
`deploy/dev/render-dev.sh` writes `dev.yaml` beside it, and only a host that
ran that script has one. A production host therefore has no `/grafana` and
no `/prometheus` router at all — not a router that 502s towards a container
it is not running, which is what putting these into `dynamic.yaml.tmpl`
would have produced.

The two quadlet units live here rather than in `deploy/quadlet/`, so the
install steps in the administrator guide (`install -m 644 deploy/quadlet/*`)
cannot pick them up by accident.

## Installing

Run as `root`, on a host where the production deployment is already working.

### 1. Fetch the images

    podman pull docker.io/prom/prometheus:v3.13.3
    podman pull docker.io/grafana/grafana:13.0.8

Both are pinned in the unit files and carry no `Pull=` line, so this step is
required rather than a warm-up.

### 2. Install the configuration

    install -D -m 644 deploy/dev/prometheus/prometheus.yml \
        /etc/insights-dev/prometheus.yml
    install -D -m 644 deploy/dev/grafana/provisioning/datasources/prometheus.yml \
        /etc/insights-dev/grafana/provisioning/datasources/prometheus.yml

### 3. Install the units

    install -m 644 deploy/dev/quadlet/*.volume    /etc/containers/systemd/
    install -m 644 deploy/dev/quadlet/*.container /etc/containers/systemd/

### 4. Render the routers and the Grafana credential

    GRAFANA_ADMIN_PASSWORD='...' bash deploy/dev/render-dev.sh

This writes `/etc/traefik/dynamic/dev.yaml` (from `INSIGHTS_HOST` in
`/etc/insights/deploy.env`) and `/etc/insights/grafana.env` at mode 0600. The
password is stored there and **reused** on every later run, so re-rendering
after a hostname change does not need it again.

Grafana applies `GF_SECURITY_ADMIN_PASSWORD` only when it initialises its
database. Changing it later means either removing the `insights-grafana`
volume or:

    podman exec grafana grafana-cli admin reset-admin-password '...'

### 5. Start

    systemctl daemon-reload
    systemctl start prometheus.service grafana.service

Traefik picks up `dev.yaml` on its own — the provider watches the directory —
so it needs no restart.

### 6. Verify

    systemctl is-active prometheus grafana
    podman ps --format '{{.Names}}\t{{.Status}}' | grep -E 'prometheus|grafana'

Both report `healthy`. Then confirm neither container kept a port of its own:

    podman inspect prometheus grafana --format '{{.Name}} {{.NetworkSettings.SandboxKey}}'

**Both must print the same namespace path**, and the same one `traefik`
prints. A container with a namespace of its own is not in the pod, which
means it published its port — an unauthenticated Prometheus on a public
interface.

`ss -tlnp` is the wrong check here, unlike in the production install: the pod
has its own network namespace, so a container's listener never appears in the
host's table whether or not it was published, and a port these two happen to
want is one an unrelated host service may already hold — 9090 is Cockpit's
default, and 3000 is a common one. Such a listener neither collides with
these containers nor says anything about them, but it reads exactly like a
Prometheus that escaped the pod. Compare namespaces instead.

Finally, the routed paths:

    curl -sS -o /dev/null -w '%{http_code}\n' https://<host>/prometheus/graph   # 401
    curl -sS -o /dev/null -w '%{http_code}\n' https://<host>/grafana/login      # 200

`401` on Prometheus is correct: the route works and Traefik is asking for the
operator credential. Sign in to Grafana as `admin` with the password from
step 4; the `Prometheus` datasource is already there, and
`Connections → Data sources → Prometheus → Test` should pass. Every target
in `/prometheus/targets` should read `UP`.

## Removing

    systemctl stop grafana.service prometheus.service
    rm -f /etc/containers/systemd/{prometheus.container,grafana.container}
    rm -f /etc/containers/systemd/insights-{prometheus,grafana}.volume
    rm -f /etc/traefik/dynamic/dev.yaml /etc/insights/grafana.env
    rm -rf /etc/insights-dev
    systemctl daemon-reload
    podman volume rm insights-prometheus insights-grafana
    podman rmi docker.io/prom/prometheus:v3.13.3 docker.io/grafana/grafana:13.0.8

Traefik drops the routers when `dev.yaml` disappears; it needs no restart.
