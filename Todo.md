# Todo

Where the pipeline split leaves things, 2026-09-09.

The refactor is merged (`main` at `8bc5c64`) and running on
`insights.gs.nethserver.net`. What follows is everything still open, in the
order it is worth doing.

## 1. Point rl1 at the server

Blocked on two things I could not do from here: SSH to `rl1` and to
`insights.gs.nethserver.net` is denied by the permission classifier, and no
NethServer subscription credential was available.

### Threat Shield — ready, needs a release

`ns8-crowdsec` commit `fcda90c` moves all three calls to the prefixed paths
(`/blocklist/v1/events`, `/blocklist/v1/feed`,
`/blocklist/v1/allowlist-requests`). `insights_url` stays the server root.

- [ ] Release `ns8-crowdsec` and update `crowdsec1` on rl1 — the module runs a
      released image, so the commit alone changes nothing on the node.
- [ ] Set `INSIGHTS_SERVER_URL=https://insights.gs.nethserver.net` (default is
      `https://insights.nethesis.it`, `threat_shield.py:64`).
- [ ] Confirm a real ban reaches the server: it should appear on
      `/blocklist/threat-events` in the operator UI.

### Logs — ready, needs a release

`ns8-loki` commit `9050874` moves the collector to `/logs/v1/bundles` and
leaves `base_url` as the server root, matching `ns8-crowdsec`. Both modules
read `INSIGHTS_SERVER_URL` and both now take the same value; before this they
read it to mean different things, one wanting the prefix baked in and one not.

- [ ] Release `ns8-loki` and update `loki1` on rl1.
- [ ] `api-cli run module/loki1/set-insights --data '{"active":true,"base_url":"https://insights.gs.nethserver.net"}'`
- [ ] Confirm a bundle lands: `/logs/systems` in the operator UI.

### Sizing — cannot be configured

`ns8-core` has no reporter. `cluster/bin/send-sizing-report` does not exist;
the contract (`docs/specs/2026-09-02-sizing-ingest-contract.md`) is written and
the server side is live, but nothing sends. `sizingd` will stay idle until
someone writes it.

- [ ] Write the `ns8-core` cluster reporter (leader-only, three sends a day,
      byte-identical restatements of a complete UTC day).

Both modules take the bare server root now, so one value configures both:

    INSIGHTS_SERVER_URL=https://insights.gs.nethserver.net

Note for whoever writes the sizing reporter: follow the same rule. The server
root goes in configuration, the pipeline prefix belongs to the endpoint, and
`/sizing/v1/reports` is appended by the client.

## 2. The one test never proven on hardware

Everything else in the runbook passed. The `503`-before-the-first-consensus-pass
branch was never observed live, because `threatd` had already completed a pass
by the time the feed was called — it correctly returned a non-blank document
with `entries: 0`. Covered by its unit test only.

- [ ] Catch it on a genuinely cold start, if the volume is ever rebuilt.

The credential-dependent tests were closed against a local reproduction using
the real images, the real rendered Traefik config and the real pod topology,
with the client on `203.0.113.0/24` so the reporter-own-address rule could
fire. See `.superpowers/sdd/2026-09-09-pipeline-split/deploy-run-report.md`.
Re-running them against the live host with a real credential is still worth
doing once, since that path exercises `my.nethesis.it` rather than a stub.

## 3. Follow-ups the final review triaged

Three issues, deliberately not 28. Full list with file:line in
`.superpowers/sdd/2026-09-09-pipeline-split/deferred-minors.md`.

- [ ] **Platform test coverage.** `ParseTrustedProxies`' error branch and
      bare-address promotion; `logging.go`/`health.go` untested, including the
      "the logger never touches Authorization" constraint, which now has two
      implementations and no coverage; `sqlitex`'s mutex (deleting `Lock`/`Unlock`
      leaves the suite green); authd's `default` branch, its deliberate absence
      of `WWW-Authenticate`, and the pepper fallback; `newUIServer("") == nil`
      for threatd and sizingd, which `cmd/insightsd/main_test.go` calls "a
      security property, not a convenience".
- [ ] **Doc-comment sweep.** Stale `internal/ui` / `internal/store` references at
      `analyzer.go:32`, `api/threat/api.go:28`, `api/sizing/api.go:30`,
      `store/sizing/store.go:385`, `ui/chrome/chrome_test.go:47`,
      `store/threat/ui.go:10-12`; `queue.go:54-57` claiming immutability where
      the real property is call ordering.
- [ ] **Deploy tooling.** GHA cache unscoped across the matrix (four jobs
      overwrite each other's `mode=max` export); `After=` without `Wants=` on the
      four units, so if authd fails at boot every `/v1` request 500s on a valid
      credential; `render.sh` writing straight into the directory Traefik
      watches; the duplicated `runPassLoop`/env helpers in `cmd/threatd` and
      `cmd/sizingd`.

## 4. Known operational sharp edges

- [ ] **authd down is indistinguishable from a backend fault.** Verified on the
      box: requests return a Traefik-generated `500`. `Wants=authd.service` on
      the three pipelines would make systemd say so.
- [x] **The authd negative cache is unbounded.** Fixed: `internal/platform/auth`
      now keeps two separately capped LRU tiers
      (`AUTH_CACHE_MAX_ENTRIES`/`AUTH_NEG_CACHE_MAX_ENTRIES`, default
      `8192`/`4096`). Separate rather than shared because one cap would let a
      flood of wrong credentials evict the fleet's positive entries, emptying
      the stale-entry outage fallback at a moment the attacker picks. Stale
      entries are still never dropped at expiry.
- [x] **Cap journald.** `deploy/journald/insights.conf` (`SystemMaxUse=200M`,
      `SystemMaxFileSize=20M`), installed per runbook §5.1b. Host-wide, correct
      only because that box is dedicated — never install it on `rl1`.
- [x] **Lower `LOG_LEVEL` for production.** All four units now ship `info`; the
      runbook says how and when to raise it to `debug` for §4.3 and smoke
      test 3.
- [ ] **Deploy the above.** The three fixes are in the repository, not on the
      box: the units and the journald drop-in have to be reinstalled there, and
      `authd` rebuilt from a new image.
- [ ] **Back up the volumes.** Three fresh databases means nothing to lose now
      and everything to lose later.

## 5. Not started, from the original plan

- [ ] Task 1's tooling: `Makefile`, `.golangci.yml`, `.github/workflows/ci.yml`,
      `scripts/check-license-headers.sh` — which must learn the two new comment
      forms and the vendored-file exemption under
      `internal/ui/chrome/static/`.
- [ ] `golang-migrate` in place of `CREATE TABLE IF NOT EXISTS`, now three times
      over.
- [ ] Distributed locking: both the blocklist consensus pass and the sizing
      cohort pass are single-instance only.
