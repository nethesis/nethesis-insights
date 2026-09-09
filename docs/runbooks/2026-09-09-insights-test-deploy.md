# Deploying the split pipelines to insights.gs.nethserver.net

A deployment pre-print for the five-container split described in
`docs/plans/2026-09-09-pipeline-split.md` (Task 9), written against a survey of the
target machine taken on 2026-09-09.

Nothing here has been executed. The machine was inspected read-only: no package was
installed, no unit started, no file written, no image pulled. Every "Check:" line is a
command to run when the deployment is actually performed, not a result already
observed. Where a fact could only be established by changing the machine, it is listed
in "Open questions" instead of being guessed at.

The deployment is: Traefik on host networking terminating TLS for one host, three
pipeline containers (`insightsd`, `threatd`, `sizingd`) and one forward-auth cache
(`authd`) published to loopback, three SQLite volumes, managed by podman quadlets.

---

## 1. What this machine is

Surveyed over `ssh root@insights.gs.nethserver.net`. It is a clean, single-purpose
DigitalOcean droplet — **not** an NS8 node and not a shared cluster, which is the main
way it differs from `rl1`.

| Fact | Value | Command |
|---|---|---|
| OS | Rocky Linux 10.2 (Red Quartz), `platform:el10` | `cat /etc/os-release` |
| Kernel / arch | `6.12.0-211.16.1.el10_2.0.1.x86_64`, x86-64 | `uname -a` |
| Virtualisation | KVM; DigitalOcean Droplet, serial 599050919 | `systemd-detect-virt`, `hostnamectl` |
| CPU | 2 vCPU, AMD (`DO-Premium-AMD`) | `nproc`, `lscpu` |
| Memory | **1.7 GiB total, 1.4 GiB available, no swap** | `free -h`, `swapon --show` |
| Disk | one 60 GB `vda`; `/` is 59 GB xfs, 2.0 GB used, **57 GB free** | `lsblk`, `df -hT` |
| `/var/lib` | on `/`, 20 MB used. `/var/lib/containers` **does not exist** | `findmnt -T /var/lib`, `ls /var/lib/containers` |
| systemd | 257, cgroup v2 (`cgroup2fs`), all controllers present | `systemctl --version`, `stat -fc %T /sys/fs/cgroup` |
| SELinux | **Enforcing**, `targeted` policy | `getenforce`, `sestatus` |
| podman | **not installed**; no `crun`, `netavark`, `containers-common`, `container-selinux` | `rpm -q podman …` |
| quadlet | no `/usr/share/containers/systemd`, no `/etc/containers/systemd`, no generator | `ls`, `ls /usr/lib/systemd/system-generators` |
| Go toolchain | not installed | `command -v go` |
| Available in repos | `podman 5.8.2-5.el10_2`, `container-selinux 4:2.246.0-1.el10`, `golang 1.26.7-1.el10_2` (appstream, cached metadata) | `dnf -q --cacheonly list --available …` |
| Repos enabled | `rocky`, `rocky-extras`, `digitalocean-agent`, `droplet-agent`. **`rocky-addons` and `rocky-devel` disabled** | `grep -l "enabled=1" /etc/yum.repos.d/*.repo` |
| Firewall | **none at all** — `firewalld` inactive and not-found; `firewall-cmd`, `nft`, `iptables` all absent | `systemctl is-active firewalld`, `command -v nft iptables` |
| Listening | `:22` sshd, `*:9090` cockpit (socket-activated, enabled). Nothing else | `ss -tlnp` |
| Ports 80 / 443 | **free on the host, and refused-not-filtered from the internet** (30 ms RST, vs 38 ms accept on 22) — no cloud firewall in front | `ss -tlnp`; `nc -zv 68.183.70.132 80` from the workstation |
| Loopback targets | 9590, 9595, 9596, 9605, 9606, 9615, 9616 all free | `ss -tlnp` |
| Addresses | `ens3` 68.183.70.132/20 (public) + 10.19.0.18/16; `ens4` 10.135.0.9/16 (DO private) | `ip -brief addr` |
| DNS, external | `insights.gs.nethserver.net` → **68.183.70.132**, matching `ens3`; reverse PTR agrees | `dig +short …`, `dig -x` |
| DNS, on-box | resolves to `127.0.0.1`/`::1` from `/etc/hosts` (cloud-init `manage_etc_hosts`) | `getent hosts`, `cat /etc/hosts` |
| Resolver | `10.135.255.254` over the DO private interface; `systemd-resolved` **inactive** | `cat /etc/resolv.conf` |
| `insights.nethesis.it` | **does not resolve** (no A record) | `dig +short insights.nethesis.it A` |
| TLS | no `/etc/letsencrypt`, no certbot, no nginx/httpd/caddy/traefik | `ls /etc/letsencrypt`, `rpm -q …` |
| Registries | `ghcr.io`, `quay.io`, `registry-1.docker.io` all answer `401` on `/v2/` — i.e. reachable | `curl -o /dev/null -w '%{http_code}' https://ghcr.io/v2/` |
| Time | UTC, `System clock synchronized: yes`, chrony stratum 2, offset 51 µs | `timedatectl`, `chronyc tracking` |
| Other tenants | none. No NS8 (`/etc/nethserver` absent), no `api-cli`, no cron jobs beyond `0hourly`, one non-root user `rocky` (uid 1000, cloud user) | `ls /etc/nethserver`, `crontab -l`, `getent passwd` |
| subuid/subgid | mapped for `rocky` only, **not for `root`** | `cat /etc/subuid /etc/subgid` |
| Host tooling | `curl`, `jq`, `tar`, `openssl`, `python3`, `envsubst`, `restorecon`, `semanage`, `chcon` present. `wget`, `git`, `htpasswd`, `sqlite3`, `nc`, `setfacl` **missing** | `command -v …` |

Two consequences worth stating up front, because they set the shape of everything below.

**This box is a blank slate, and it is unfirewalled.** There is no host packet filter of
any kind — not disabled, *absent*. Ports 80 and 443 are reachable from the internet the
moment something binds them, which is exactly what makes ACME HTTP-01 workable with no
extra step. It also means `PublishPort=127.0.0.1:…` is the **only** thing keeping the
three pipelines and `authd` off the public internet. A quadlet that says `PublishPort=9605:9595`
instead of `PublishPort=127.0.0.1:9605:9595` publishes an unauthenticated operator surface
to the world here, with nothing behind it to catch the mistake. Treat the loopback prefix
in every `PublishPort=` line as load-bearing, not stylistic.

**Cockpit is already exposed.** `cockpit.socket` is enabled and `*:9090` answers from the
internet (verified: TCP connect succeeds from the workstation). It is not ours and this
runbook does not touch it, but it is worth deciding whether it should be listening on a
box that is about to hold fleet-wide security findings.

---

## 2. Gaps between the machine and what the deployment needs

Every gap found, with what closes it. This is the section to read before scheduling the
work.

### 2.1 Blocking — nothing containerised can run yet

| Gap | Closes with |
|---|---|
| **podman is not installed.** No `podman`, no `crun`, no `netavark`, no `containers-common`. | `dnf install -y podman container-selinux` (appstream has `podman 5.8.2`, `container-selinux 2.246.0`). Podman 5.8 includes quadlet, so `/usr/libexec/podman/quadlet` and the `podman-system-generator` symlink arrive with it. |
| **No quadlet directories.** Neither `/etc/containers/systemd` nor `/usr/share/containers/systemd` exists. | Created by the `podman` package; `install -d -m 755 /etc/containers/systemd` if not. |
| **`container-selinux` is not installed and SELinux is Enforcing.** Without the policy module, container processes run unconfined-or-denied and every bind mount of host config into a container is denied. | Install it alongside podman (it is a hard dependency of `podman` on EL10, so a plain `dnf install podman` pulls it — verify with `rpm -q container-selinux` afterwards rather than assuming). |
| **No `/var/lib/containers`.** Image and volume storage does not exist yet. | Created on podman's first run, on `/` — 57 GB free, ample. Four Go-on-alpine images plus Traefik is well under 1 GB. |

### 2.2 Blocking — the `127.0.0.1` assumption in the plan is wrong as written

This has its own section (§4) because it is the failure the brief specifically warned
about, and because it is the one that will present as an auth bug.

### 2.3 Blocking — the hostname is baked into a committed file

Also its own section (§3).

### 2.4 Should be closed before or during the deploy

| Gap | Closes with |
|---|---|
| **1.7 GiB RAM and no swap, on 2 vCPU.** Running the stack is fine — five static Go binaries plus Traefik is on the order of 300-400 MB RSS. **Building** is not: `go build` of this module inside `golang:1.23-alpine` with 2 cores can peak north of 1 GB, and an OOM kill mid-build on a swapless box is abrupt and unhelpful. | Prefer **pulling from `ghcr.io`** over building on the node (§5.2, path A). If you must build here, add 2 GB of swap first — but note that adding swap is a state change this survey did not make, and `/swapfile` on xfs needs `fallocate` + `chattr +C`-free handling, so a `dd`-created file is the safe form. |
| **No `htpasswd`.** The operator BasicAuth file cannot be generated with the usual tool. | Either `dnf install -y httpd-tools`, or generate the bcrypt hash with `python3` (§5.6) — python3 is already present, so no new package is needed. |
| **No `wget` on the host** — irrelevant to the host, but the plan's `HealthCmd=wget -qO- …` runs *inside* the container, and the alpine runtime image has busybox `wget`. That is fine. Do not "fix" it to `curl`, which alpine does not have unless the Containerfile adds it. | Nothing. Noted so it is not mistaken for a gap. |
| **`rocky-addons` and `rocky-devel` are disabled.** Not needed for anything above, but worth knowing before an install fails on a missing dependency. | `dnf install --enablerepo=rocky-addons` if a dependency turns out to live there. |
| **`net.ipv4.ip_forward = 0`.** Podman sets this itself when it creates its first bridge network. | Nothing, but if container→internet traffic fails (the LLM call from `insightsd`, the validator call from `authd`), check this first. |
| **Rootless is not viable as root.** `/etc/subuid` and `/etc/subgid` map only `rocky`. `loginctl show-user root` shows a session but lingering is not enabled. | Deploy **rootful**: quadlets in `/etc/containers/systemd`, `systemctl daemon-reload`, `systemctl start`. Note this diverges from the plan's Task 9 Step 5, which says `systemctl --user daemon-reload` — on this machine that would put the units in the wrong place and start nothing. Use the system manager. |
| **No `git` on the node.** The `rl1` runbook's `tar | ssh | tar` shipping trick is still the way to get a working tree over, if a local build is ever needed. | `dnf install -y git`, or ship a tarball. |

### 2.5 SELinux specifics

`getenforce` returns `Enforcing`, and it should stay that way. Three concrete
consequences:

- **Host config bind-mounted into a container needs a relabel.** `/etc/traefik/` is
  mounted into the Traefik container; without `:z` (shared) or `:Z` (private) on the
  `Volume=` line, the container gets `EACCES` and Traefik exits on a config it can
  perfectly well read as root. Use `:z` on `/etc/traefik` — Traefik is the only reader,
  but `:Z` would relabel the host directory to a container-private category and make it
  awkward to re-use. `/etc/insights/*.env` is read by systemd via `EnvironmentFile=`, on
  the **host** side of the boundary, so it needs no relabel at all.
- **Named podman volumes need nothing.** `insights-logs`, `insights-threat` and
  `insights-sizing` live under `/var/lib/containers/storage/volumes/` and podman labels
  them `container_file_t` itself.
- **Host-networked Traefik is not an SELinux problem.** `NetworkMode=host` needs no
  boolean and no policy change; `container-selinux` permits it. The `httpd_can_network_*`
  booleans found `off` in the survey are for the `httpd_t` domain and are irrelevant
  here — do not flip them.

If something is denied anyway, read it, do not disable enforcement:

```bash
ausearch -m AVC -ts recent | audit2why
```

---

## 3. The served hostname is a deploy-time input

The plan's Traefik dynamic configuration hard-codes ``Host(`insights.nethesis.it`)`` in
six router rules. This machine is `insights.gs.nethserver.net`, and
`insights.nethesis.it` **has no A record at all** (`dig +short insights.nethesis.it A`
returns nothing), so on this box those rules match nothing and ACME for that name would
fail its HTTP-01 challenge.

The resolution is **not** to pick one host, add a DNS alias, or match both with
`HostRegexp`. There are two environments and they must deploy the same artifacts:

| Environment | Host |
|---|---|
| dev / test (this machine) | `insights.gs.nethserver.net` |
| production | `insights.nethesis.it` |

### 3.1 One variable

`INSIGHTS_HOST` is the single place the served hostname is set. It lives in
`/etc/insights/deploy.env`, which is **created on the machine and is not in the
repository**:

```bash
install -d -m 755 /etc/insights
install -m 644 /dev/null /etc/insights/deploy.env
cat > /etc/insights/deploy.env <<'EOF'
# Deploy-time inputs. Not in the repository; one per environment.
INSIGHTS_HOST=insights.gs.nethserver.net
ACME_EMAIL=noc@nethesis.it
EOF
```

Mode 0644 deliberately: this file holds no secret. The secrets live in the per-service
env files of §5.6, at 0600.

### 3.2 Getting it into Traefik

Traefik's file provider has **no environment interpolation** — `${INSIGHTS_HOST}` in a
`dynamic.yaml` is matched as a literal hostname, silently, and every request 404s. Three
mechanisms were considered:

| Mechanism | Verdict |
|---|---|
| One file per environment in `providers.file.directory` | Rejected. Two near-identical committed files that must be kept in step is exactly the "two definitions that will eventually disagree" failure `CLAUDE.md` warns about for `model.LessTemplate`. Adding a third environment means a third copy. |
| Traefik labels via the podman provider | Rejected. It needs the podman socket exposed to Traefik and moves routing into the quadlets, which is a much larger change than the problem justifies, and host-networked Traefik still could not resolve container names. |
| **Ship `dynamic.yaml.tmpl`, render with `envsubst` at deploy time** | **Recommended.** |

`envsubst` is already present on this machine (`/usr/bin/envsubst`), so it adds no
package. Commit the template, never the rendered file:

```
deploy/traefik/traefik.yaml.tmpl     -> /etc/traefik/traefik.yaml
deploy/traefik/dynamic.yaml.tmpl     -> /etc/traefik/dynamic.yaml
```

Render with an **explicit variable list**, so that a stray `$` anywhere in the template
(a Traefik plugin expression, a regex) is left alone rather than silently blanked:

```bash
set -a; . /etc/insights/deploy.env; set +a
envsubst '$INSIGHTS_HOST $ACME_EMAIL' \
  < /root/nethesis-insights/deploy/traefik/dynamic.yaml.tmpl \
  > /etc/traefik/dynamic.yaml
envsubst '$INSIGHTS_HOST $ACME_EMAIL' \
  < /root/nethesis-insights/deploy/traefik/traefik.yaml.tmpl \
  > /etc/traefik/traefik.yaml
```

The rendered files are reproducible from `INSIGHTS_HOST` (and `ACME_EMAIL`) alone. Add
`/etc/traefik/*.yaml` to nothing and commit nothing generated; a redeploy re-renders.
Traefik's file provider is watched (`providers.file.watch: true`), so a re-render is
picked up without a restart — which is also the fastest way to fix a wrong host without
dropping TLS.

Consider adding `deploy/render.sh` to the repository as the one command that does the
above, so the rendering is itself an artifact rather than a paragraph in a runbook.

### 3.3 Everything `INSIGHTS_HOST` must drive

- The **six** `Host(...)` matchers in `dynamic.yaml.tmpl` — `logs-api`, `logs-ui`,
  `blocklist-api`, `blocklist-ui`, `sizing-api`, `sizing-ui`. All six, not the API three:
  a missed UI rule means the operator pages 404 while the client APIs work, which reads
  as a UI bug.
- The **ACME certificate domain** in `traefik.yaml.tmpl`
  (`certificatesResolvers.le.acme` plus the `tls.domains` / `tls.certResolver` on the
  entrypoint or routers). ACME must request `${INSIGHTS_HOST}`; requesting the other name
  fails HTTP-01 because the challenge is served from this IP.
- The **ACME contact email**, kept beside it as `ACME_EMAIL` for the same reason — it is
  a deploy-time input, not a code constant.
- **Every URL in the smoke test** (§6). They are written as `https://${INSIGHTS_HOST}/…`
  throughout, sourced from the same file, so a smoke test cannot accidentally pass
  against production.

No other consumer was found. Specifically **not** consumers: `authd`'s
`AUTH_VALIDATE_URL` (an upstream at `my.nethesis.it`, unrelated to what we serve),
Traefik's `forwardAuth.address` and every `loadBalancer.servers[].url` (all
`http://127.0.0.1:<port>`, deliberately host-independent), and the `Image=` references
in the quadlets.

### 3.4 Nothing in the application is host-dependent — verified

The brief's reading is correct, and it was checked against the tree on
`plan/pipeline-split` rather than taken on trust:

- `grep -rn 'getenv("[A-Z_]*HOST\|os.Hostname' internal/ cmd/` returns **nothing**. No
  binary reads a hostname from the environment or from the kernel.
- Every link in `internal/ui/chrome/templates/layout.html` and the page templates is
  path-relative and prefixed with the base path: `href="{{.Base}}/static/pico.min.css"`,
  `action="{{$.Base}}/blocklist/allowlist"`, `href="{{.Path}}"`. `Base` comes from
  `UI_BASE_PATH` (`chrome.Config.BasePath`, normalised by `normalizeBase`) and is a
  *path* prefix, never a URL. No template emits a scheme or an authority.
- `internal/ui/chrome/chrome.go:375 sameOriginWrite` ends in `return u.Host == r.Host` —
  it compares the `Origin` header against the `Host` of the request **as it arrives**.
  It therefore follows whatever host Traefik passes through, and needs no configuration.
  This is why `passHostHeader: true` in the plan's service definitions is load-bearing:
  it is the app's only source of truth for its own name, and rewriting it makes every UI
  write a 403.

So the application deploys byte-identically to both environments. The hostname is purely
a Traefik concern.

### 3.5 What a wrong or unset `INSIGHTS_HOST` looks like

**Every request returns Traefik's own 404 page, from every path, with no backend ever
contacted** — because no router rule matches, so there is no service to fail. It looks
nothing like a backend problem: the containers are healthy, `curl` against
`127.0.0.1:9605/healthz` on the box returns 200, and the logs of all four services are
silent. If `envsubst` ran without the variable set, the rendered rule reads
``Host(``)`` — grep the rendered file first:

```bash
grep -c "Host(\`$INSIGHTS_HOST\`)" /etc/traefik/dynamic.yaml   # must be 6
```

---

## 4. The pipelines will **not** see `127.0.0.1` — and that is a 401, not an auth bug

The plan states, in a comment inside `threatd.container` and again under "Ports and
environment", that "Traefik runs with host networking, so every `RemoteAddr` this
process sees is `127.0.0.1`, which is what `TRUSTED_PROXY_CIDRS` below trusts".

Checked against this machine, the first half of that is arrangeable and the second half
does not follow.

**What is true:** Traefik with `NetworkMode=host` connects to `http://127.0.0.1:9605`
over the host's loopback, and the pipelines publish only to `127.0.0.1`. Ports 80, 443
and all seven loopback targets are free, and nothing else on the box competes. So the
*intent* is achievable here.

**What does not follow:** with rootful podman and a `PublishPort=127.0.0.1:9605:9595`
bridge-network container, the address the container sees is **the bridge gateway, not
`127.0.0.1`**. The mechanism is forced, not incidental: the host DNATs
`127.0.0.1:9605` to `<container-ip>:9595`, and if the source address were left as
`127.0.0.1` the container's reply would route to the container's *own* loopback and never
come back. Podman therefore masquerades hairpin traffic to the bridge IP. The pipeline
receives `RemoteAddr = 10.89.0.1:…` (or whatever the network's gateway is), which is not
inside `127.0.0.0/8`.

The consequence runs straight through `httpx`. `ClientIP` consults `X-Forwarded-For`
"only when `RemoteAddr` is a proxy we configured"; `SystemID` returns
`ErrUntrustedProxy` otherwise. So:

> Every `/logs/v1/*`, `/blocklist/v1/*` and `/sizing/v1/*` request returns **401**, with a
> correct credential, from a correctly configured Traefik. And `threat.Sanitize`'s
> reporter-own-address check — the reason Decision 4 exists at all — is fed the bridge
> gateway address for every report.

This is precisely the failure mode flagged in the brief: it presents as an auth bug and
is a networking one.

### 4.1 Two ways to make it true, and which to take

**Option A — pin the network subnet and trust it (recommended).**

Do not let podman pick. Declare the subnet in `deploy/quadlet/insights.network`, and put
it in `TRUSTED_PROXY_CIDRS` alongside loopback:

```ini
[Network]
NetworkName=insights
Subnet=10.89.0.0/24
Gateway=10.89.0.1
```

```
Environment=TRUSTED_PROXY_CIDRS=127.0.0.0/8,10.89.0.1/32
```

A `/32` on the gateway, not the whole `/24`: only the gateway ever appears as a
masqueraded source, and a `/24` would additionally trust any sibling container that
reached the port directly. Keeps the plan's quadlets and its network isolation intact,
and the value is deterministic because the subnet is declared rather than allocated.

**Option B — host-network the pipelines too.**

Drop `PublishPort=` and `Network=`, set `NetworkMode=host` on all four, and bind
explicitly:

```
Environment=LISTEN_ADDR=127.0.0.1:9605
Environment=UI_LISTEN_ADDR=127.0.0.1:9606
```

Now `RemoteAddr` really is `127.0.0.1` and the plan's comment becomes literally true.
Simpler, one less moving part, and on a box with no firewall the loopback bind is the
same protection the published port was providing. The cost is that the four services
share the host network namespace and each must bind a distinct port itself — a typo in
`LISTEN_ADDR` binds `0.0.0.0` on an unfirewalled public host, which is a worse failure
than the one it avoids.

**Take Option A.** It keeps the loopback publish as a structural guard rather than a
configuration value, and the extra CIDR is one line. But it is Option A *with the subnet
pinned* — leaving podman to allocate `10.88.0.0/16` or `10.89.x.0/24` by creation order
makes `TRUSTED_PROXY_CIDRS` a value someone has to look up after every rebuild.

### 4.2 Verify it on the machine, first thing

This could not be established read-only, because podman is not installed. It is the
first thing to check after the containers start, before wiring Traefik:

```bash
# from the host, straight at threatd's published port
curl -s -o /dev/null -H 'X-Forwarded-For: 198.51.100.9' http://127.0.0.1:9605/v1/feed
journalctl -u threatd -n 5
# read the logged client address. 10.89.0.1 -> Option A's CIDR is required and correct.
# 127.0.0.1 -> the plan's comment holds on this podman version; leave the default.
```

Whichever it is, record the answer here. Do not assume it, and do not assume it is the
same after a podman major upgrade.

---

## 5. Deployment

Run as `root` on `insights.gs.nethserver.net`. Rootful throughout — see §2.4 for why
`systemctl --user` is not available on this box.

### 5.1 Install the container stack

```bash
dnf install -y podman container-selinux httpd-tools
```

`httpd-tools` only for `htpasswd`; skip it and use the python3 form in §5.6 instead.

**Check:**

```bash
podman --version                                   # >= 5.8.2
rpm -q container-selinux                           # installed, not "not installed"
ls /usr/lib/systemd/system-generators/podman-system-generator   # exists
install -d -m 755 /etc/containers/systemd
getenforce                                         # still Enforcing
```

### 5.2 Get the four images

**Path A — pull from CI (recommended on this machine; see the RAM gap in §2.4).**

Task 9 Step 4 gives `image.yml` a matrix over `[authd, insightsd, threatd, sizingd]`,
pushing `ghcr.io/nethesis/nethesis-insights-<service>`. Once that has run on the branch:

```bash
for s in authd insightsd threatd sizingd; do
  podman pull ghcr.io/nethesis/nethesis-insights-$s:latest
done
podman pull docker.io/library/traefik:v3.3
```

`ghcr.io` is reachable from this box (verified: `/v2/` answers 401). A public package
needs no login; a private one needs `podman login ghcr.io -u <user>` with a PAT carrying
`read:packages`.

**Path B — build on the node.** Add swap first. Note the `Containerfile` builder is
`golang:1.23-alpine3.21` and `go.mod` says `go 1.23.6`, so the pinned builder is still
correct — check that before building, because a `go.mod` bump during the refactor would
fail the build with a version error rather than a compile error.

```bash
tar --exclude=.git -czf - . | ssh root@insights.gs.nethserver.net \
  'mkdir -p /root/nethesis-insights && tar -xzf - -C /root/nethesis-insights'
cd /root/nethesis-insights
for s in authd insightsd threatd sizingd; do
  podman build --build-arg SERVICE=$s -t localhost/insights-$s:latest -f Containerfile .
done
```

Then use `localhost/insights-<s>:latest` in the quadlets' `Image=`.

**Check:** `podman images | grep insights` lists four.

### 5.3 Network and volume units

`/etc/containers/systemd/insights.network` — with the subnet pinned per §4.1:

```ini
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#
[Network]
NetworkName=insights
Subnet=10.89.0.0/24
Gateway=10.89.0.1
```

Three volume units, `/etc/containers/systemd/insights-{logs,threat,sizing}.volume`, each:

```ini
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#
[Volume]
VolumeName=insights-logs
```

Three separate volumes, per Decision 7 — three fresh databases, nothing carried across.

### 5.4 The five container units

All in `/etc/containers/systemd/`, all following the plan's Task 9 Step 2 shape. The
per-service differences that matter on this machine:

| Unit | `Image=` | Ports | Volume | `UI_BASE_PATH` | Secret file |
|---|---|---|---|---|---|
| `authd.container` | `…-authd` | `PublishPort=127.0.0.1:9590:9590` | — | — | `/etc/insights/authd.env` (`AUTH_PEPPER`) |
| `insightsd.container` | `…-insightsd` | `127.0.0.1:9595:9595`, `127.0.0.1:9596:9596` | `insights-logs:/var/lib/insights` | `/logs` | `/etc/insights/insightsd.env` (`LLM_API_KEY`) |
| `threatd.container` | `…-threatd` | `127.0.0.1:9605:9595`, `127.0.0.1:9606:9596` | `insights-threat:/var/lib/threat` | `/blocklist` | `/etc/insights/threatd.env` (`ADMIN_API_KEY`) |
| `sizingd.container` | `…-sizingd` | `127.0.0.1:9615:9595`, `127.0.0.1:9616:9596` | `insights-sizing:/var/lib/sizing` | `/sizing` | `/etc/insights/sizingd.env` |
| `traefik.container` | `docker.io/library/traefik:v3.3` | `NetworkMode=host` | `/etc/traefik:/etc/traefik:z`, `traefik-acme:/acme` | — | — |

Each pipeline unit carries, in addition to the plan's text:

```
Network=insights.network
Environment=TRUSTED_PROXY_CIDRS=127.0.0.0/8,10.89.0.1/32
```

`authd.container` needs no volume and no `UI_BASE_PATH`; the three pipelines get
`After=authd.service`. Traefik gets `After=insightsd.service threatd.service sizingd.service`
so it does not start routing to nothing, though `forwardAuth` and the services will
recover on their own either way.

`traefik.container` is the one unit that deviates structurally, because host networking
and `PublishPort=` are mutually exclusive:

```ini
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#

[Unit]
Description=Traefik reverse proxy
After=authd.service insightsd.service threatd.service sizingd.service

[Container]
Image=docker.io/library/traefik:v3.3
ContainerName=traefik
# Host networking, deliberately: it is what puts the proxy's connections to
# the pipelines on the host's loopback, and what lets it bind 80/443 without
# a second NAT hop in front of the ACME challenge.
NetworkMode=host
Volume=/etc/traefik:/etc/traefik:z
Volume=traefik-acme.volume:/acme
Exec=--configFile=/etc/traefik/traefik.yaml

[Service]
Restart=always

[Install]
WantedBy=multi-user.target
```

The `:z` on `/etc/traefik` is the SELinux relabel from §2.5 and is not optional here.

### 5.5 Traefik configuration

Both files are committed as `.tmpl` and rendered per §3.2. `traefik.yaml.tmpl`:

```yaml
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#
entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint: {to: websecure, scheme: https, permanent: true}
  websecure:
    address: ":443"
    http:
      tls:
        certResolver: le
    # Empty, deliberately: nothing sits in front of Traefik on this host, so
    # Traefik overwrites X-Forwarded-For with the connecting address. That
    # overwrite is what makes the pipelines' rightmost-value rule correct.
    forwardedHeaders:
      trustedIPs: []

providers:
  file:
    filename: /etc/traefik/dynamic.yaml
    watch: true

certificatesResolvers:
  le:
    acme:
      email: ${ACME_EMAIL}
      storage: /acme/acme.json
      httpChallenge:
        entryPoint: web

log:
  level: INFO
accessLog: {}
```

`dynamic.yaml.tmpl` is the plan's Task 9 Step 3 file verbatim, with every
``Host(`insights.nethesis.it`)`` replaced by ``Host(`${INSIGHTS_HOST}`)`` — six
occurrences. Keep the explicit `priority: 200` / `priority: 100`, keep
`removeHeader: false` on `operator-auth`, and keep `passHostHeader: true` on all six
services; §3.4 is why the last one matters.

### 5.6 Secrets

Four files, all mode 0600, none in the repository, none in a quadlet.

```bash
install -d -m 755 /etc/insights

umask 077
printf 'AUTH_PEPPER=%s\n' "$(openssl rand -hex 32)" > /etc/insights/authd.env
printf 'LLM_API_KEY=%s\n' "$OPENROUTER_KEY"          > /etc/insights/insightsd.env
printf 'ADMIN_API_KEY=%s\n' "$(openssl rand -hex 24)" > /etc/insights/threatd.env
: > /etc/insights/sizingd.env

chmod 600 /etc/insights/*.env
```

`sizingd` has no secret of its own; the empty file exists so its
`EnvironmentFile=` does not fail the unit. Alternatively mark it
`EnvironmentFile=-/etc/insights/sizingd.env` and omit the file.

The operator htpasswd. Per Decision 5 the **password is the `ADMIN_API_KEY` value** and
the **username is the audit actor**, so one line per operator, all sharing the password:

```bash
ADMIN_API_KEY=$(sed -n 's/^ADMIN_API_KEY=//p' /etc/insights/threatd.env)

# with httpd-tools:
htpasswd -nbB giacomo "$ADMIN_API_KEY" >  /etc/traefik/operators.htpasswd
htpasswd -nbB davide  "$ADMIN_API_KEY" >> /etc/traefik/operators.htpasswd

# without it, python3 is already on the box:
python3 -c 'import crypt,sys; print(sys.argv[1]+":"+crypt.crypt(sys.argv[2], crypt.mksalt(crypt.METHOD_SHA512)))' \
  giacomo "$ADMIN_API_KEY" > /etc/traefik/operators.htpasswd

chmod 640 /etc/traefik/operators.htpasswd
```

The python3 form works on this box (3.12.13) but warns: `crypt` was removed in Python
3.13, so it is a one-release stopgap. `httpd-tools` is the durable answer.

**Check:** `grep -c : /etc/traefik/operators.htpasswd` equals the number of operators,
and no line contains the password in clear.

`AUTH_PEPPER`, `LLM_API_KEY` and `ADMIN_API_KEY` are environment-only and never written
to a database or logged — that is a Global Constraint, and these files are the whole of
their persistence.

### 5.7 Start, in order

```bash
set -a; . /etc/insights/deploy.env; set +a
bash /root/nethesis-insights/deploy/render.sh      # or the two envsubst lines from §3.2

systemctl daemon-reload
systemctl start authd.service
systemctl start insightsd.service threatd.service sizingd.service
systemctl start traefik.service
```

Quadlet-generated units are transient: `systemctl enable` is not used, and
`WantedBy=multi-user.target` in the `[Install]` section is what makes them start at boot.

**Check:**

```bash
systemctl is-active authd insightsd threatd sizingd traefik   # five x active
podman ps --format '{{.Names}}\t{{.Status}}'                  # five, all healthy
ss -tlnp | grep -E ':(80|443|9590|9595|9596|9605|9606|9615|9616)\b'
# 80 and 443 on 0.0.0.0 (traefik); every other port on 127.0.0.1 ONLY.
# Any of 9590-9616 on 0.0.0.0 is an exposed operator UI on an unfirewalled
# public host -- stop and fix the PublishPort line before going further.
```

### 5.8 TLS

Nothing to prepare. `insights.gs.nethserver.net` already resolves to this machine's
public address, port 80 is reachable from the internet (refused, not filtered — no cloud
firewall), and Traefik's HTTP-01 challenge is served from the `web` entrypoint. The
certificate is issued on the first request to `https://${INSIGHTS_HOST}/`.

**Check:**

```bash
curl -sS -o /dev/null -w '%{http_code}\n' https://${INSIGHTS_HOST}/     # not a TLS error
openssl s_client -connect ${INSIGHTS_HOST}:443 -servername ${INSIGHTS_HOST} </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
# subject CN = insights.gs.nethserver.net, issuer = Let's Encrypt
journalctl -u traefik | grep -i acme
```

If issuance fails, the order to check is: does `${INSIGHTS_HOST}` resolve to
68.183.70.132 from *outside*; is Traefik actually bound to `:80`; is the rendered
`traefik.yaml` naming the right domain. Let's Encrypt rate-limits failed orders, so use
`caServer: https://acme-staging-v02.api.letsencrypt.org/directory` while iterating.

---

## 6. Smoke test

This proves the deployment *works*, not that it started. Run from the workstation, not
the node — several of these are meaningless from inside the host. Source the host from
the same file the deploy used:

```bash
INSIGHTS_HOST=insights.gs.nethserver.net
CRED="<system_id>:<auth_token>"          # a pair AUTH_VALIDATE_URL accepts
OPCRED="giacomo:<the ADMIN_API_KEY value>"
```

**1. Routing exists at all.** Before anything else, prove the host rule matched — a
missing route 404s from Traefik itself and would make every check below fail for the
wrong reason.

```bash
curl -sS -o /dev/null -w '%{http_code}\n' https://${INSIGHTS_HOST}/blocklist/v1/feed
```

Expect **401**. A **404** means the `Host()` rule does not match `${INSIGHTS_HOST}` —
go back to §3.5, not to the containers.

**2. Unauthenticated client API is refused, on all three pipelines.**

```bash
for p in /logs/v1/findings /blocklist/v1/feed /sizing/v1/reports; do
  printf '%s ' "$p"
  curl -sS -o /dev/null -w '%{http_code}\n' https://${INSIGHTS_HOST}$p
done
```

Expect `401` three times. A `503` on all three means `authd` is down or its validator is
unreachable — that is the graded failure Decision 2 preserves, and it is a different bug.

**3. An authenticated request succeeds.**

```bash
curl -sS -u "$CRED" -o /dev/null -w '%{http_code}\n' \
  "https://${INSIGHTS_HOST}/logs/v1/findings?since=0"        # 200
```

**200 is the single most informative result in this list.** It proves, in one request:
Traefik matched the router, the `forwardAuth` middleware reached `authd` on loopback,
`authd` validated upstream, the prefix was stripped so `insightsd` saw `/v1/findings`,
**and** `insightsd` accepted `RemoteAddr` as a trusted proxy. A `401` here with a
credential you know is good is §4, not auth.

**4. The blocklist feed answers 503 before the first consensus pass — never a blank 200.**

```bash
curl -sS -u "$CRED" -o /dev/null -w '%{http_code}\n' https://${INSIGHTS_HOST}/blocklist/v1/feed
```

Expect **503** on a fresh database. A `200` with an empty body would be the
"never serve blank" invariant broken, and every client importing the feed would read it
as "no threats". After the first successful pass this becomes 200 with a snapshot and a
`generated_at`; re-run it then and confirm the transition rather than only the 503.

**5. Each operator UI is reachable and asks for credentials.**

```bash
for p in /logs/ /blocklist/ /sizing/; do
  printf '%s ' "$p"
  curl -sS -o /dev/null -w '%{http_code} ' https://${INSIGHTS_HOST}$p
  curl -sSI https://${INSIGHTS_HOST}$p | grep -i '^www-authenticate' || echo '(none)'
done
```

Expect `401` and a `WWW-Authenticate: Basic` header on each. Then with credentials:

```bash
for p in /logs/ /blocklist/ /sizing/; do
  printf '%s ' "$p"
  curl -sS -u "$OPCRED" -o /dev/null -w '%{http_code}\n' https://${INSIGHTS_HOST}$p
done
```

Expect `200` three times. Open one in a browser and confirm the CSS loads — a broken
`{{.Base}}/static/pico.min.css` is the symptom of a wrong `UI_BASE_PATH`, and it is
invisible to `curl`.

**6. Router priority is the right way round.** This is the security-relevant one from the
plan's URL map, and step 2 plus step 5 already prove it jointly: if the priorities were
inverted, `/blocklist/v1/feed` would answer `401` with a `WWW-Authenticate: Basic`
header (operator auth on the ingest path) and `/blocklist/` would accept the fleet
credential. Check the header explicitly:

```bash
curl -sSI https://${INSIGHTS_HOST}/blocklist/v1/feed | grep -i '^www-authenticate' && \
  echo 'WRONG: operator BasicAuth is on the ingest path' || echo 'ok: no basic challenge on /v1/'
```

**7. The one no unit test can prove — the reporter's real source address survives the
chain.** Post a threat report from a machine with a known public address and confirm
`threatd` recorded *that* address, not `127.0.0.1` and not the bridge gateway.

```bash
MYIP=$(curl -s https://ifconfig.me); echo "posting as $MYIP"

curl -sS -u "$CRED" -H 'Content-Type: application/json' \
  -X POST "https://${INSIGHTS_HOST}/blocklist/v1/events" -d '{
    "decisions": [{
      "value": "203.0.113.42", "scope": "Ip", "type": "ban",
      "origin": "crowdsec", "scenario": "crowdsecurity/ssh-bf",
      "created_at": "2026-09-09T12:00:00Z", "duration": "4h"
    }]
  }'
```

Then on the node:

```bash
journalctl -u threatd -n 20 | grep -i 'client\|remote\|POST /v1/events'
```

The logged client address **must equal `$MYIP`**. If it is `127.0.0.1`, Traefik is not
setting `X-Forwarded-For` (check `forwardedHeaders.trustedIPs` is empty, per §5.5). If it
is `10.89.0.1`, the pipeline is not treating the proxy as trusted and `ClientIP` fell
back to `RemoteAddr` — §4.1, `TRUSTED_PROXY_CIDRS`. If it is the *rightmost* value of a
header you did not send, someone put a second proxy in front of Traefik.

This is what makes `threat.Sanitize`'s reporter-own-address check live again, which is
the entire point of Decision 4. Verify the negative too — post a decision naming
`$MYIP` itself and confirm it is dropped, counted in `dropped_bad_ip`:

```bash
curl -sS -u "$CRED" -H 'Content-Type: application/json' \
  -X POST "https://${INSIGHTS_HOST}/blocklist/v1/events" \
  -d "{\"decisions\":[{\"value\":\"$MYIP\",\"scope\":\"Ip\",\"type\":\"ban\",\"origin\":\"crowdsec\",\"scenario\":\"crowdsecurity/ssh-bf\",\"created_at\":\"2026-09-09T12:00:00Z\",\"duration\":\"4h\"}]}"
```

The response counters should show the drop. Then confirm the accepted 203.0.113.42 is
visible on `https://${INSIGHTS_HOST}/blocklist/events` with operator credentials.

**8. Nothing but 80 and 443 is exposed.** From the workstation, not the node:

```bash
for p in 80 443 9090 9590 9595 9596 9605 9606 9615 9616; do
  printf '%s ' $p
  timeout 4 bash -c "</dev/tcp/68.183.70.132/$p" 2>/dev/null && echo OPEN || echo closed
done
```

Expect `80 OPEN`, `443 OPEN`, `9090 OPEN` (pre-existing cockpit, see §1), and **closed
for every 95xx/96xx port**. Any of those open is the unfirewalled-host failure from §2.

---

## 7. Open questions and risks

Ordered by how much they would change the deployment.

1. **The masquerade question (§4) is unresolved and cannot be resolved read-only.**
   Podman is not installed, so the source address a container actually observes on a
   loopback-published port was reasoned from the DNAT/reply-routing mechanism, not
   measured. It is the single highest-value thing to check in the first ten minutes, with
   the command in §4.2. If it turns out to be `127.0.0.1` on podman 5.8, drop the extra
   CIDR and record that here.

2. **Whether `dnf install podman` pulls `container-selinux` on EL10.** It is listed as a
   dependency and is available in appstream, but this was not verified by a dry run
   (which writes to the dnf cache). §5.1's check catches it either way. Installing
   without it under Enforcing produces confusing permission denials, not a clean error.

3. **Building on the node may OOM.** 1.7 GiB, no swap, 2 cores. Not measured — no build
   was attempted. Path A (pull from CI) sidesteps it entirely; Path B needs swap added
   first, and adding swap is a state change deliberately not made during the survey.

4. **`ADMIN_API_KEY` doubles as the shared operator password**, per Decision 5 and the
   plan's own open question 2. It is not a per-person secret: one operator leaving means
   rotating the key, the htpasswd and `threatd.env` together, and restarting `threatd`.
   Fine for a test deploy; name it as debt.

5. **`X-Admin-Actor` / the htpasswd username is not a security control**, and this
   runbook does not make it one. Everyone shares the password; the username is an audit
   label. Say so wherever the audit table is shown.

6. **Cockpit is publicly reachable on 9090** and enabled at boot. Pre-existing, not ours,
   untouched. It should probably be decided about before this box holds fleet-wide
   security findings, but that is a change and this survey made none.

7. **There is no host firewall to fall back on.** No firewalld, no nftables, no iptables
   userspace. Installing podman brings a packet-filter backend for its own NAT, but not a
   host policy. Every safety property of this deployment rests on the `127.0.0.1:` prefix
   in seven `PublishPort=` lines and on Traefik's two middlewares. Consider installing
   and configuring `firewalld` with only 22/80/443 open as a second layer — that is a
   change, so it is listed here rather than in §5.

8. **Single instance, no distributed lock.** Both the Threat Shield consensus pass and
   the fleet-sizing cohort pass are documented single-instance. One box, so fine today;
   it forecloses running a second `threatd` for availability without doing the locking
   work first.

9. **No backup of the three volumes.** `podman volume export insights-threat -o …` is the
   `rl1` runbook's pattern and works here, but nothing schedules it. Three fresh
   databases (Decision 7) means there is nothing to lose on day one, and something to
   lose on day thirty.

10. **`ACME_EMAIL` was invented by this document.** The plan does not name one. Confirm
    the address before the first issuance; Let's Encrypt sends expiry warnings there.

11. **Whether the CI matrix from Task 9 Step 4 has run on `plan/pipeline-split`.** At the
    time of writing `deploy/` does not exist in the working tree and `image.yml` still
    builds one image from one `Containerfile` with no `SERVICE` build argument. Path A in
    §5.2 depends on that task landing first; until it does, only Path B is available.

12. **Rootless was not evaluated as a real option.** `/etc/subuid` maps `rocky` only, and
    switching the deployment to run as `rocky` would need subuid/subgid for it plus
    lingering plus a way to bind 80/443 (`net.ipv4.ip_unprivileged_port_start` is 1024, so
    that needs a sysctl or a capability). Rootful is the right call for a single-purpose
    box; noted so the question is not reopened without the constraints.
