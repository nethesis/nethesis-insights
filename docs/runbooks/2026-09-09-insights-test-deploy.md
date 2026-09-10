# Deploying the split pipelines to insights.gs.nethserver.net

A deployment pre-print for the five-container split described in
`docs/plans/2026-09-09-pipeline-split.md` (Task 9), written against a survey of the
target machine taken on 2026-09-09.

Nothing here has been executed. The machine was inspected read-only: no package was
installed, no unit started, no file written, no image pulled. Every "Check:" line is a
command to run when the deployment is actually performed, not a result already
observed. Where a fact could only be established by changing the machine, it is listed
in "Open questions" instead of being guessed at.

The deployment is: five containers — Traefik, one forward-auth cache (`authd`) and three
pipelines (`insightsd`, `threatd`, `sizingd`) — **sharing a single podman pod**, three
SQLite volumes, managed by podman quadlets. The pod publishes 80 and 443 and nothing
else.

> **Revision, 2026-09-09.** This document was first written against an earlier
> arrangement in which each container published its own port to `127.0.0.1` and Traefik
> ran with host networking. The plan was then amended (`docs/plans/2026-09-09-pipeline-split.md`,
> "Ports and environment" and Task 9 Step 2) to put all five in one pod. The survey in
> §1 is unchanged — the machine did not change, only the deployment model — but §4, §5
> and §6 are rewritten, and the finding that used to sit in §4 is now dissolved rather
> than worked around. §4 keeps the reasoning anyway, because a reader who finds only the
> conclusion cannot tell whether it was thought about.

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
any kind — not disabled, *absent*. `firewalld` is inactive and not even installed;
`firewall-cmd`, `nft` and `iptables` are all missing from the filesystem. Ports 80 and
443 are reachable from the internet the moment something binds them, which is exactly
what makes ACME HTTP-01 workable with no extra step. It is also why the pod matters more
here than it would on a firewalled host.

The three operator UIs are unauthenticated and fleet-wide by design — `/logs`,
`/blocklist` and `/sizing` between them expose every `system_id` in the fleet, its
security-category findings, the LLM spend, and the whole threat blocklist. Under the
earlier published-port arrangement, the only thing keeping those off the public internet
on this machine was the `127.0.0.1:` prefix on seven `PublishPort=` lines: a single
`PublishPort=9606:9596` typo would have published a fleet-wide security dashboard to the
world, with **nothing behind it to catch the mistake** — no firewall to fail closed, no
default-deny zone, no second layer of any kind.

In a pod that failure mode does not exist. The pipeline containers have no published port
at all; only `insights.pod` publishes, and it publishes 80 and 443. There is no
`PublishPort=` line in any `.container` unit to get wrong. The single route to an operator
UI is through Traefik's `operator-auth` BasicAuth middleware. On a machine with no
firewall, "has no published port" is worth considerably more than "bound to
`127.0.0.1`", because the former survives a typo and the latter is the typo.

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

### 2.2 Not a gap — quadlet pod support is available

The deployment needs `.pod` quadlet units and the `.container` `Pod=` key. Both were
introduced in **Podman 5.0**; before that, quadlet could define networks and volumes but
not pods, and a pod had to be built by a wrapper unit calling `podman pod create`.

Rocky 10 appstream offers **`podman 5.8.2-5.el10_2`** (`dnf -q --cacheonly list --available podman`),
so the floor is met with several minor versions to spare. Record the floor rather than
the observed version: **this deployment requires podman ≥ 5.0**, and anything EL10 ships
will satisfy it.

**Check**, after §5.1's install and before writing any unit:

```bash
podman --version                                              # >= 5.0
/usr/libexec/podman/quadlet -dryrun 2>&1 | head               # runs, does not "unknown unit type"
man 5 podman-systemd.unit | grep -c '^\s*Pod='                # the key is documented
```

### 2.3 Dissolved — the `127.0.0.1` assumption

The first revision of this document flagged, as its most serious finding, that the
plan's `TRUSTED_PROXY_CIDRS=127.0.0.0/8` would be wrong under the published-port model.
The pod arrangement removes the cause rather than mitigating it. §4 has the full
reasoning and the one check that still needs running.

### 2.4 Blocking — the hostname is baked into a committed file

Also its own section (§3).

### 2.5 Should be closed before or during the deploy

| Gap | Closes with |
|---|---|
| **1.7 GiB RAM and no swap, on 2 vCPU.** Running the stack is fine — five static Go binaries plus Traefik is on the order of 300-400 MB RSS. **Building** is not: `go build` of this module inside `golang:1.23-alpine` with 2 cores can peak north of 1 GB, and an OOM kill mid-build on a swapless box is abrupt and unhelpful. | Prefer **pulling from `ghcr.io`** over building on the node (§5.2, path A). If you must build here, add 2 GB of swap first — but note that adding swap is a state change this survey did not make, and `/swapfile` on xfs needs `fallocate` + `chattr +C`-free handling, so a `dd`-created file is the safe form. |
| **No `htpasswd`.** The operator BasicAuth file cannot be generated with the usual tool. | Either `dnf install -y httpd-tools`, or generate the bcrypt hash with `python3` (§5.6) — python3 is already present, so no new package is needed. |
| **No `wget` on the host** — irrelevant to the host, but the plan's `HealthCmd=wget -qO- …` runs *inside* the container, and the alpine runtime image has busybox `wget`. That is fine. Do not "fix" it to `curl`, which alpine does not have unless the Containerfile adds it. | Nothing. Noted so it is not mistaken for a gap. |
| **`rocky-addons` and `rocky-devel` are disabled.** Not needed for anything above, but worth knowing before an install fails on a missing dependency. | `dnf install --enablerepo=rocky-addons` if a dependency turns out to live there. |
| **`net.ipv4.ip_forward = 0`.** Podman sets this itself when it creates its first bridge network. | Nothing, but if container→internet traffic fails (the LLM call from `insightsd`, the validator call from `authd`), check this first. |
| **Rootless is not viable as root.** `/etc/subuid` and `/etc/subgid` map only `rocky`. `loginctl show-user root` shows a session but lingering is not enabled. | Deploy **rootful**: quadlets in `/etc/containers/systemd`, `systemctl daemon-reload`, `systemctl start`. Note this diverges from the plan's Task 9 Step 5, which says `systemctl --user daemon-reload` — on this machine that would put the units in the wrong place and start nothing. Use the system manager. |
| **No `git` on the node.** The `rl1` runbook's `tar | ssh | tar` shipping trick is still the way to get a working tree over, if a local build is ever needed. | `dnf install -y git`, or ship a tarball. |

### 2.6 SELinux specifics

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
- **A shared pod namespace is not an SELinux problem.** Pods need no boolean and no
  policy change; `container-selinux` handles the shared namespace and the infra container
  itself. The `httpd_can_network_*` booleans found `off` in the survey are for the
  `httpd_t` domain and are irrelevant here — do not flip them.

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

`deploy/render.sh` is that one command: it sources `/etc/insights/deploy.env`, fails
loudly if `INSIGHTS_HOST` or `ACME_EMAIL` is unset, and renders both templates with the
explicit `envsubst` variable list above -- so the rendering is an artifact rather than a
paragraph an operator retypes, and cannot accidentally run `envsubst` unargumented, which
would also expand Traefik's own `${...}` syntax into a config that parses and is wrong.

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

## 4. `RemoteAddr` really is `127.0.0.1` — by construction, not by convention

`TRUSTED_PROXY_CIDRS` defaults to `127.0.0.0/8`, and everything in `httpx` hangs off it:
`ClientIP` consults `X-Forwarded-For` only when `RemoteAddr` is a configured proxy, and
`SystemID` returns `ErrUntrustedProxy` otherwise. Get it wrong and **every**
`/logs/v1/*`, `/blocklist/v1/*` and `/sizing/v1/*` request returns 401 with a perfectly
good credential, from a perfectly good Traefik — a networking failure wearing an auth
failure's clothes.

Under the pod arrangement the default is correct, and correct for a structural reason
rather than a configured one. All five containers share **one network namespace**.
Traefik's connection to `http://127.0.0.1:9605` is a genuine loopback connection inside
that namespace: it is never routed, never DNATed, never masqueraded, and never touches
the host's network stack at all. The source address `threatd` reads out of the socket is
the literal loopback address, because there is nothing in the path that could make it
anything else.

That also means `TRUSTED_PROXY_CIDRS` needs no per-machine value. It is `127.0.0.0/8` on
this box, on production, and on any future one, and it does not have to be looked up
after a rebuild.

### 4.1 Why the earlier reasoning no longer applies

The first revision of this document recommended
`TRUSTED_PROXY_CIDRS=127.0.0.0/8,10.89.0.1/32` and a pinned `Subnet=`/`Gateway=` in an
`insights.network` unit. **Both are now wrong and both should be dropped.** The reasoning
is kept because the conclusion alone would not tell a reader whether the question had
been considered — and because the same trap is waiting for anyone who later moves a
container out of the pod.

Under the published-port model, each pipeline ran in its own namespace on a bridge
network and Traefik reached it through `PublishPort=127.0.0.1:9605:9595`. That path is
DNAT: the host rewrites the destination of a packet arriving on `127.0.0.1:9605` to
`<container-ip>:9595`. If the *source* were left as `127.0.0.1`, the container's reply
would be addressed to `127.0.0.1` and would be delivered to the container's own loopback
interface, never reaching the host. Rootful podman therefore also SNATs the hairpin,
rewriting the source to the bridge gateway. The container would have observed
`RemoteAddr = 10.89.0.1:…`, outside `127.0.0.0/8`, and every `/v1/*` request would have
401'd.

Sharing a namespace removes the DNAT, which removes the reply-routing problem, which
removes the masquerade, which removes the wrong source address. Nothing is being trusted
that was not trusted before; there is simply no longer an address translation in the
path to be wrong about.

Two corollaries worth keeping:

- **If a container is ever moved out of the pod, this breaks silently and presents as
  401.** The `LISTEN_ADDR=127.0.0.1:<port>` form in each unit is deliberate for that
  reason: outside a shared namespace it fails loudly (nothing can reach it) instead of
  quietly (reachable, but every request unauthorised).
- **The pod's own published ports, 80 and 443, still go through DNAT** — but that is
  inbound from the internet, where podman preserves the source address and does not
  masquerade, so Traefik sees the real client IP and can set `X-Forwarded-For` from it.
  The exception is a request made *from the host itself* to `127.0.0.1:443`: that is a
  hairpin, so it is masqueraded and Traefik will see the gateway. On-box `curl` against
  the public port is therefore not a valid test of the address chain — run smoke test 7
  from the workstation, which is why §6 says so.

### 4.2 One port space, so every listener needs a distinct port

The other consequence of a shared namespace: the three pipelines can no longer all bind
`:9595`. Each binds its own, and a collision is a container that fails to start rather
than a request that silently reaches the wrong backend:

| Service | API | UI |
|---|---|---|
| authd | `127.0.0.1:9590` | — |
| insightsd | `127.0.0.1:9595` | `127.0.0.1:9596` |
| threatd | `127.0.0.1:9605` | `127.0.0.1:9606` |
| sizingd | `127.0.0.1:9615` | `127.0.0.1:9616` |
| traefik | `:80`, `:443` | — |

These are the same numbers the earlier revision published to the host, which is why
**Traefik's dynamic configuration needs no change at all**: its six
`loadBalancer.servers[].url` values were already `http://127.0.0.1:9595`,
`:9596`, `:9605`, `:9606`, `:9615`, `:9616`. Same numbers, different meaning — they are
now in-pod ports rather than host-published ones. It looks like nothing changed while
quite a lot did, so do not read an unchanged `dynamic.yaml.tmpl` as evidence that the
pod migration was not applied. Check the `.container` units instead: the migration is
done when no `.container` file contains a `PublishPort=` line.

`HealthCmd=` must also follow the new ports — `wget -qO- http://127.0.0.1:9605/healthz`
for threatd, not `:9595`. A healthcheck left on the old port either fails forever or, if
another pipeline happens to be listening there, reports the wrong container healthy.

### 4.3 Verify it anyway, first thing

Podman is not installed, so this was reasoned from the namespace semantics and not
measured. The reasoning is much stronger than the published-port case it replaces —
there is no translation left to be surprised by — but the cost of being wrong is a
misdiagnosed 401, so spend one command on it before wiring anything else:

```bash
podman exec traefik wget -qO- --header='X-Forwarded-For: 198.51.100.9' \
  http://127.0.0.1:9605/healthz
journalctl -u threatd -n 5
```

The logged client address must be `127.0.0.1`. Anything else means the containers are
not actually sharing a namespace — check `podman pod inspect insights` and confirm all
five are listed, and that no `.container` unit kept a `Network=` or `PublishPort=` line,
which would silently take it out of the pod.

---

## 5. Deployment

Run as `root` on `insights.gs.nethserver.net`. Rootful throughout — see §2.5 for why
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

### 5.1b Cap journald

Five containers log here: Traefik with `accessLog: {}` and four Go binaries
with one line per request each, so one client request can produce five journal
entries. Unset, journald's ceiling is 10% of the filesystem and it will spend
it; on a 1.7 GiB box with no swap, a full disk is the failure that takes
everything else down with it.

```bash
install -D -m 644 deploy/journald/insights.conf \
    /etc/systemd/journald.conf.d/insights.conf
systemctl restart systemd-journald
```

**Check:**

```bash
journalctl --disk-usage                  # bounded, and below 200M once rotated
```

This is host-wide, which is correct only because this host runs this deployment
and nothing else. Do not install it on a shared NS8 node such as `rl1`.

### 5.2 Get the four images

**Path A — pull from CI (recommended on this machine; see the RAM gap in §2.5).**

`image.yml`'s matrix over `[authd, insightsd, threatd, sizingd]` pushes
`ghcr.io/nethesis/nethesis-insights-<service>`, but its `push:` trigger fires only on
`main` or a version tag, and `type=raw,value=latest,enable={{is_default_branch}}` means
**`:latest` is produced only from `main`**. A push to a feature branch does not run the
workflow at all. So before this branch is merged there is no `:latest` to pull, and the
naive form of Path A fails with `manifest unknown`.

For a test deploy of an unmerged branch, trigger the workflow by hand and use the branch
tag it produces instead of `:latest`:

```bash
gh workflow run image.yml --ref plan/pipeline-split
gh run watch                                                       # wait for the matrix
gh run view --log | grep -m1 -o 'nethesis-insights-authd:[a-zA-Z0-9._-]*'
                                                                    # confirm the tag
```

`type=ref,event=branch` sanitizes the branch name for use as a Docker tag (`/` becomes
`-`), so read the actual tag from the run rather than assuming the exact string. Pull it
and retag it locally as `:latest`, so the quadlets' committed `Image=...:latest` need no
edit for a test deploy:

```bash
for s in authd insightsd threatd sizingd; do
  podman pull ghcr.io/nethesis/nethesis-insights-$s:<branch-tag>
  podman tag ghcr.io/nethesis/nethesis-insights-$s:<branch-tag> \
             ghcr.io/nethesis/nethesis-insights-$s:latest
done
podman pull docker.io/library/traefik:v3.3
```

After this branch merges to `main`, a push to `main` (or a version tag) republishes the
real `:latest`, and the manual-trigger-plus-retag step above is no longer needed.

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

### 5.3 The pod and volume units

`/etc/containers/systemd/insights.pod` is the **only** unit in the deployment that
publishes anything:

```ini
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#

[Unit]
Description=nethesis-insights

[Pod]
PodName=insights
# The only ports that exist outside this host. Every backend listens on
# loopback inside the shared namespace and has no published port at all, which
# is what keeps the three unauthenticated operator UIs reachable only through
# Traefik's BasicAuth -- this machine has no firewall of any kind, so "not
# published" is worth a great deal more than "bound to 127.0.0.1".
PublishPort=80:80
PublishPort=443:443

[Install]
WantedBy=multi-user.target
```

There is **no `insights.network` unit**. The earlier revision of this runbook specified
one with a pinned `Subnet=`/`Gateway=`; §4.1 explains why that is no longer needed and
should not be reintroduced. Podman gives the pod a default network of its own, and
nothing in the deployment depends on its address range.

Three volume units, `/etc/containers/systemd/insights-{logs,threat,sizing}.volume`, each:

```ini
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#
[Volume]
VolumeName=insights-logs
```

Traefik additionally needs `traefik-acme.volume` for `acme.json`. Three separate pipeline
volumes, per Decision 7 — three fresh databases, nothing carried across.

### 5.4 The five container units

All in `/etc/containers/systemd/`, all following the plan's Task 9 Step 2 shape. **No
`.container` unit carries a `PublishPort=` or a `Network=` line**; each carries
`Pod=insights.pod` instead. That absence is the single best check that the pod migration
was applied — see §4.2.

| Unit | `Image=` | `LISTEN_ADDR` / `UI_LISTEN_ADDR` | Volume | `UI_BASE_PATH` | Secret file |
|---|---|---|---|---|---|
| `authd.container` | `…-authd` | `AUTH_LISTEN_ADDR=127.0.0.1:9590` | — | — | `/etc/insights/authd.env` (`AUTH_PEPPER`) |
| `insightsd.container` | `…-insightsd` | `127.0.0.1:9595` / `127.0.0.1:9596` | `insights-logs:/var/lib/insights` | `/logs` | `/etc/insights/insightsd.env` (`LLM_API_KEY`) |
| `threatd.container` | `…-threatd` | `127.0.0.1:9605` / `127.0.0.1:9606` | `insights-threat:/var/lib/threat` | `/blocklist` | `/etc/insights/threatd.env` (`ADMIN_API_KEY`) |
| `sizingd.container` | `…-sizingd` | `127.0.0.1:9615` / `127.0.0.1:9616` | `insights-sizing:/var/lib/sizing` | `/sizing` | `/etc/insights/sizingd.env` |
| `traefik.container` | `docker.io/library/traefik:v3.3` | binds `:80`, `:443` in-pod | `/etc/traefik:/etc/traefik:z`, `traefik-acme.volume:/acme` | — | — |

Every pipeline unit carries:

```
Pod=insights.pod
Environment=TRUSTED_PROXY_CIDRS=127.0.0.0/8
```

`127.0.0.0/8` **alone** — no `10.89.0.1/32`. The gateway CIDR belonged to the
published-port model and is wrong here; §4.1 says why at length. Note that the plan's
Task 9 Step 2 example still shows the gateway appended (see §7 item 3) — the surrounding
prose in the plan is right and that one line is stale.

**`Environment=LOG_LEVEL=info` on all four `authd`/`insightsd`/`threatd`/`sizingd`
units — but raise it to `debug` while working through §4.3 and smoke test 3.** At
`info`, `httpx.SystemID`'s two rejected-request sentinels — `ErrUntrustedProxy` (the
pod's networking is wrong and every valid credential 401s) and `ErrNoCredential` (the
client simply sent nothing) — are logged only at `slog.Debug`, so neither reaches the
journal and the two failure modes are indistinguishable from outside. That distinction
is exactly what §4.3's verification step and smoke test 3 depend on being able to read,
and this is the first deployment of the pod-networking arrangement, so confirm the
pod's `RemoteAddr` behaviour at `debug` and then put it back:

```bash
sed -i 's/^Environment=LOG_LEVEL=.*/Environment=LOG_LEVEL=debug/' \
    /etc/containers/systemd/{authd,insightsd,threatd,sizingd}.container
systemctl daemon-reload && systemctl restart authd insightsd threatd sizingd
```

Leaving it at `debug` is what §5.1b's journald cap exists to survive: five containers
at one line per request each, on a box with 1.7 GiB and no swap.

`threatd.container` in full, the others by analogy:

```ini
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#

[Unit]
Description=Threat Shield pipeline
After=authd.service

[Container]
Image=ghcr.io/nethesis/nethesis-insights-threatd:latest
ContainerName=threatd
# No PublishPort: this container has no port of its own. It shares the pod's
# network namespace, so Traefik reaches it over real loopback and it sees
# RemoteAddr == 127.0.0.1 -- which is what makes the default
# TRUSTED_PROXY_CIDRS correct by construction.
#
# One namespace means one port space: 9605/9606 are threatd's alone, and a
# collision is a startup failure rather than a subtle misroute.
Pod=insights.pod
Volume=insights-threat.volume:/var/lib/threat
Environment=LISTEN_ADDR=127.0.0.1:9605
Environment=UI_LISTEN_ADDR=127.0.0.1:9606
Environment=UI_BASE_PATH=/blocklist
Environment=DB_PATH=/var/lib/threat/threat.db
Environment=TRUSTED_PROXY_CIDRS=127.0.0.0/8
EnvironmentFile=/etc/insights/threatd.env
HealthCmd=wget -qO- http://127.0.0.1:9605/healthz || exit 1
HealthInterval=30s
HealthRetries=3
HealthStartPeriod=5s

[Service]
Restart=always

[Install]
WantedBy=multi-user.target
```

The `HealthCmd` port must match that unit's own `LISTEN_ADDR` — `:9605` here, `:9595` for
insightsd, `:9615` for sizingd. In one namespace a healthcheck pointed at the wrong port
can report a *different* container's health as this one's, which is worse than failing.

`traefik.container` no longer uses host networking; it joins the pod like everything
else, and the pod's `PublishPort` lines are what put it on 80 and 443:

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
# In the pod, not on the host network: its connections to the four backends
# stay inside the shared namespace, which is what makes their RemoteAddr a
# real 127.0.0.1. Publishing is the pod's job, not this unit's.
Pod=insights.pod
Volume=/etc/traefik:/etc/traefik:z
Volume=traefik-acme.volume:/acme
Exec=--configFile=/etc/traefik/traefik.yaml

[Service]
Restart=always

[Install]
WantedBy=multi-user.target
```

The `:z` on `/etc/traefik` is the SELinux relabel from §2.6 and is not optional here.

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

**The pod migration changed nothing in this file**, and that is worth stating rather than
noticing. The `forwardAuth.address` (`http://127.0.0.1:9590/auth`) and all six
`loadBalancer.servers[].url` values were already loopback URLs on those port numbers;
they are now in-pod ports instead of host-published ones. Identical text, different
mechanism — so an unchanged `dynamic.yaml.tmpl` is not evidence the migration was
skipped. §4.2 gives the check that is.

The `web` entrypoint's `forwardedHeaders.trustedIPs: []` in `traefik.yaml.tmpl` also
stays empty: nothing sits in front of Traefik, so it overwrites `X-Forwarded-For` with
the address that connected to the published port — which, for traffic from the internet,
is the real client. That overwrite is what smoke test 7 proves end to end.

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
`EnvironmentFile=` does not fail the unit. There is no optional-file form to fall back to
instead of creating it: quadlet's `Container` `EnvironmentFile=` key takes only an
absolute-or-relative path (`man 5 podman-systemd.unit`), not systemd's leading-`-`
optional-file syntax. Verified against podman 5.8.4's quadlet generator: a value of
`-/etc/insights/sizingd.env` was resolved as a *relative* path next to the unit file
itself, producing a broken `--env-file` argument rather than an optional absolute one.
Create the empty file.

The operator htpasswd. Per Decision 5 the **password is the `ADMIN_API_KEY` value** and
the **username is the audit actor**, so one line per operator, all sharing the password:

```bash
install -d -m 755 /etc/traefik

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
systemctl start insights-pod.service
systemctl start authd.service
systemctl start insightsd.service threatd.service sizingd.service
systemctl start traefik.service
```

Quadlet names the pod's generated unit `insights-pod.service` (from `insights.pod`), and
each `.container` unit gains an implicit dependency on it, so starting a container starts
the pod anyway. Starting it explicitly first is not required, only clearer to read in the
journal when something fails.

Quadlet-generated units are transient: `systemctl enable` is not used, and
`WantedBy=multi-user.target` in the `[Install]` section is what makes them start at boot.

**Check:**

```bash
systemctl is-active insights-pod authd insightsd threatd sizingd traefik   # all active
podman pod ps                                        # one pod "insights", 6 containers
                                                     # (5 + the infra container)
podman pod inspect insights --format '{{range .Containers}}{{.Name}} {{end}}'
# authd insightsd threatd sizingd traefik (+ the -infra one). A missing name
# means that unit did not join the pod -- check it for a stray Network= line.
podman ps --format '{{.Names}}\t{{.Status}}'
# authd, insightsd, threatd and sizingd healthy; traefik merely Up -- its
# quadlet carries no HealthCmd (Traefik's own healthcheck needs the ping
# provider enabled, which this deployment does not turn on), so "Up" is its
# correct steady state, not a sign something is missing.
```

Then confirm the host's port surface, which is the security property of §1:

```bash
ss -tlnp | grep -E ':(80|443|9590|9595|9596|9605|9606|9615|9616)\b'
```

Expect **80 and 443 only**. The 95xx/96xx ports must not appear at all — they exist
inside the pod's namespace and are invisible to the host's `ss`. Seeing any of them here
means a `.container` unit kept a `PublishPort=` line and is not in the pod; that is an
unauthenticated fleet-wide dashboard on an unfirewalled public host, so stop and fix it
before continuing.

### 5.8 TLS

Nothing to prepare. `insights.gs.nethserver.net` already resolves to this machine's
public address, port 80 is reachable from the internet (refused, not filtered — no cloud
firewall), and Traefik's HTTP-01 challenge is served from the `web` entrypoint. The
certificate is issued on the first request to a **routed** path, such as
`https://${INSIGHTS_HOST}/blocklist/v1/feed` -- not to `/`, which no router in
`dynamic.yaml.tmpl` matches (every rule requires a `PathPrefix()` alongside `Host()`), so
a request to `/` triggers no router, no issuance, and gets served Traefik's own default
self-signed certificate instead.

**Check:**

```bash
curl -sS -o /dev/null -w '%{http_code}\n' https://${INSIGHTS_HOST}/blocklist/v1/feed
# 401, not a TLS error -- this is the routed path from smoke test 1 in §6
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
    "schema_version": 1,
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

The logged client address **must equal `$MYIP`**, and this must be run from the
workstation, not the node: a request made on the host to `127.0.0.1:443` is a hairpin
through the pod's published port, gets masqueraded, and would show the gateway for
reasons that have nothing to do with the header chain (§4.1).

Reading a wrong answer:

- `127.0.0.1` — Traefik is not setting `X-Forwarded-For`. Check that
  `forwardedHeaders.trustedIPs` is empty in `traefik.yaml` (§5.5); a non-empty list that
  does not contain the real client makes Traefik preserve an absent header rather than
  write one.
- The pod's gateway address, or any `10.x` — the pipeline did not treat the proxy as
  trusted and `ClientIP` fell back to `RemoteAddr`. That should be impossible in a shared
  namespace, so it means the container is **not in the pod**: check for a stray
  `PublishPort=` or `Network=` line (§4.2), not for a wrong `TRUSTED_PROXY_CIDRS`.
- The rightmost value of a header you did not send — someone put a second proxy in front
  of Traefik.

This is what makes `threat.Sanitize`'s reporter-own-address check live again, which is
the entire point of Decision 4. Verify the negative too — post a decision naming
`$MYIP` itself and confirm it is dropped, counted in `dropped_bad_ip`:

```bash
curl -sS -u "$CRED" -H 'Content-Type: application/json' \
  -X POST "https://${INSIGHTS_HOST}/blocklist/v1/events" \
  -d "{\"schema_version\":1,\"decisions\":[{\"value\":\"$MYIP\",\"scope\":\"Ip\",\"type\":\"ban\",\"origin\":\"crowdsec\",\"scenario\":\"crowdsecurity/ssh-bf\",\"created_at\":\"2026-09-09T12:00:00Z\",\"duration\":\"4h\"}]}"
```

The response counters should show the drop. Then confirm the accepted 203.0.113.42 is
visible on `https://${INSIGHTS_HOST}/blocklist/events` with operator credentials.

**8. Nothing but 80 and 443 is exposed — the negative check.** The pod is supposed to
publish exactly two ports. That is now a property worth *proving* rather than assuming,
because it is the only thing standing between three unauthenticated fleet-wide operator
dashboards and the internet on a machine with no firewall (§1).

Two probes, and both must fail to connect.

From **the host**, where the published ports live — an in-pod port must not be reachable
from outside the pod's namespace:

```bash
timeout 4 bash -c '</dev/tcp/127.0.0.1/9606' && echo 'FAIL: 9606 published to the host' \
  || echo 'ok: 9606 not reachable from the host'
timeout 4 bash -c '</dev/tcp/127.0.0.1/443' && echo 'ok: 443 published' \
  || echo 'FAIL: 443 not published'
```

From **the workstation**, against the public address:

```bash
for p in 80 443 9090 9590 9595 9596 9605 9606 9615 9616; do
  printf '%-5s ' $p
  timeout 4 bash -c "</dev/tcp/68.183.70.132/$p" 2>/dev/null && echo OPEN || echo closed
done
```

Expect exactly `80 OPEN`, `443 OPEN`, `9090 OPEN` (pre-existing cockpit, see §1), and
**closed for every 95xx/96xx port**.

If either probe reaches `9606` — on `127.0.0.1` or on the public address — the pod is
publishing more than 80 and 443. The cause is almost always a `.container` unit that kept
a `PublishPort=` line, which also takes it out of the shared namespace and will break
§4's `RemoteAddr` guarantee at the same time. Grep for it:

```bash
grep -l PublishPort /etc/containers/systemd/*.container   # must return nothing
```

Note the asymmetry between the two probes: a host-side `127.0.0.1:9606` that answers is a
**local** exposure only, and a public-address `9606` that answers is a global one. Both
are bugs; the second is an incident.

**9. Confirm the operator UI is reachable only through Traefik.** The positive form of
test 8, and the property the pod exists to give:

```bash
# through Traefik, with credentials -- works
curl -sS -u "$OPCRED" -o /dev/null -w '%{http_code}\n' https://${INSIGHTS_HOST}/blocklist/
# 200

# through Traefik, without -- refused
curl -sS -o /dev/null -w '%{http_code}\n' https://${INSIGHTS_HOST}/blocklist/
# 401

# around Traefik, from the host -- no route at all
timeout 4 bash -c '</dev/tcp/127.0.0.1/9606' || echo 'ok: no way around the proxy'
```

There is no fourth case. Under the published-port model there was: anything on the host,
including any other process and any future tenant, could reach `127.0.0.1:9606` directly
and read the whole fleet's findings with no credential. In the pod that path does not
exist.

---

## 7. Open questions and risks

Ordered by how much they would change the deployment.

1. **The pod's `RemoteAddr` guarantee is reasoned, not measured.** Podman is not
   installed, so §4 argues from namespace semantics rather than from an observation. The
   argument is strong — a loopback connection inside one namespace has no translation in
   it to be wrong about — and much stronger than the published-port case it replaces, but
   the cost of being wrong is a 401 that reads as an auth bug. Run §4.3's one command
   before wiring Traefik and record the answer here.

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
   host policy. What the pod changed is how much rests on that absence: the operator UIs
   now have no published port at all, so reaching one requires getting through Traefik's
   BasicAuth, and there is no `PublishPort=` line in a `.container` unit left to typo.
   What still rests on it is everything else — cockpit on 9090, sshd, and any future
   service. Consider installing and configuring `firewalld` with only 22/80/443 open as a
   second layer; that is a change, so it is listed here rather than in §5.

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

11. **Rootless was not evaluated as a real option.** `/etc/subuid` maps `rocky` only, and
    switching the deployment to run as `rocky` would need subuid/subgid for it plus
    lingering plus a way to bind 80/443 (`net.ipv4.ip_unprivileged_port_start` is 1024, so
    that needs a sysctl or a capability). Rootful is the right call for a single-purpose
    box; noted so the question is not reopened without the constraints.

12. **`.pod` quadlet support is recorded as a floor, not an observation.** Podman 5.0
    introduced `.pod` units and the `.container` `Pod=` key; the box's appstream offers
    5.8.2. Nothing was installed, so this was not exercised — §2.2 has the check to run
    after installing. Anything below 5.0 cannot deploy this at all and would need a
    wrapper unit calling `podman pod create`.

13. **Pod-level lifecycle coupling was not exercised.** All five containers now share one
    namespace and one infra container, so restarting the pod restarts everything, and a
    pod-level failure takes down `threatd`'s ingest along with the operator UIs. Under
    the previous model the four services failed independently. This is an accepted
    consequence of the pod, not a regression to fix, but it means "restart just threatd"
    (`systemctl restart threatd`) should be verified to work without cycling the pod
    before anyone relies on it during an incident.
