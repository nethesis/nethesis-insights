# Todo

Where the pipeline split leaves things, 2026-09-09.

The refactor is merged (`main` at `8bc5c64`) and running on
`insights.gs.nethserver.net`. What follows is everything still open, in the
order it is worth doing.

## 1. Point rl1 at the server

Done 2026-09-10, and neither module needed a release: the images already
deployed on rl1 turned out to carry the two commits below, verified by diffing
the running collector and `threat_shield.py` against them before anything was
changed. rl1 is now a reporter only — its own pre-split insights server is
decommissioned (see `deploy.md`'s 2026-09-10 notice).

### Threat Shield — done, no release needed

`ns8-crowdsec` commit `fcda90c` moves all three calls to the prefixed paths
(`/blocklist/v1/events`, `/blocklist/v1/feed`,
`/blocklist/v1/allowlist-requests`). `insights_url` stays the server root.

- [x] Release `ns8-crowdsec` and update `crowdsec1` on rl1 — not needed, the
      deployed image already matched `fcda90c`.
- [x] Set `INSIGHTS_SERVER_URL=https://insights.gs.nethserver.net` (default is
      `https://insights.nethesis.it`, `threat_shield.py:64`). Set with
      `agent.set_env`; no action wires this variable. The previous value was
      `https://controller.gs.nethserver.net/insights` — a prefix baked into
      configuration, the exact shape the split clients no longer accept.
- [x] Confirm a real ban reaches the server. Two `POST /v1/events` → `202`, the
      event visible on threatd's `/events`, and the second delivery deduped
      against the first on the `(system_id, attacker_ip, scenario,
      observed_at)` index. Worth knowing for the next test: the reporter is
      CrowdSec's own `http` notification plugin with `group_wait: 30s`, alert-
      driven, **not** a timer — `cscli decisions add` alone does not push, and
      `cscli notifications reinject <alert-id>` is what forces it.

### Logs — done on rl1, no release needed

`ns8-loki` commit `9050874` moves the collector to `/logs/v1/bundles` and
leaves `base_url` as the server root, matching `ns8-crowdsec`. Both modules
read `INSIGHTS_SERVER_URL` and both now take the same value; before this they
read it to mean different things, one wanting the prefix baked in and one not.

- [x] Release `ns8-loki` and update `loki1` on rl1 — not needed, the deployed
      collector was byte-identical to `9050874`.
- [x] `api-cli run module/loki1/set-insights --data '{"active":true,"base_url":"https://insights.gs.nethserver.net","verify_tls":true}'`
- [x] Confirm a bundle lands. `202`, then gate → LLM → fingerprint in 2.9 s:
      one call, `$0.000202`, three findings inserted. The real subscription
      credential validated through `authd` → `my.nethesis.it` on the first
      try, which is the live proof the forward-auth chain works end to end.

### Sizing — cannot be configured

`ns8-core` has no reporter. `cluster/bin/send-sizing-report` does not exist;
the contract (`docs/specs/2026-09-02-sizing-ingest-contract.md`) is written and
the server side is live, but nothing sends. `sizingd` will stay idle until
someone writes it.

- [ ] Write the `ns8-core` cluster reporter (leader-only, three sends a day,
      byte-identical restatements of a complete UTC day).

Both modules take the bare server root now, so one value configures both:

    INSIGHTS_SERVER_URL=https://insights.gs.nethserver.net

- [ ] Repeat the `loki1` configuration on the manually deployed nodes. Same
      three steps as rl1, per node; the collector must already carry `9050874`
      or the new `base_url` merely 404s.

Note for whoever writes the sizing reporter: follow the same rule. The server
root goes in configuration, the pipeline prefix belongs to the endpoint, and
`/sizing/v1/reports` is appended by the client.

## 2. The one test never proven on hardware

Everything else in the runbook passed. The `503`-before-the-first-consensus-pass
branch was never observed live, because `threatd` had already completed a pass
by the time the feed was called — it correctly returned a non-blank document
with `entries: 0`. Covered by its unit test only.

- [ ] Catch it on a genuinely cold start, if the volume is ever rebuilt. Still
      open after the 2026-09-10 image redeploy: restarting the containers does
      not rebuild the volumes, so `threatd` came back to an existing database
      and completed a pass as before.

The credential-dependent tests were closed against a local reproduction using
the real images, the real rendered Traefik config and the real pod topology,
with the client on `203.0.113.0/24` so the reporter-own-address rule could
fire. See `.superpowers/sdd/2026-09-09-pipeline-split/deploy-run-report.md`.
Re-running them against the live host with a real credential is still worth
doing once, since that path exercises `my.nethesis.it` rather than a stub.

## 3. Follow-ups the final review triaged

Three issues, deliberately not 28. Full list with file:line in
`.superpowers/sdd/2026-09-09-pipeline-split/deferred-minors.md`.

- [x] **Platform test coverage.** Done 2026-09-10, 461 lines over eight files.
      Every property was verified non-vacuous by breaking it and recording the
      failure. The `Authorization` test asserts the raw value absent, the
      decoded credential absent, **and** `has_authorization=true` present, so
      it cannot pass by the logger never reading the header. `sqlitex`'s mutex
      uses the race detector as the primary signal with a bounded blocking
      check as corroboration — a fully deterministic exclusion test is not
      possible, and the test says so.
      - [ ] One gap left open deliberately: authd's `AUTH_PEPPER`-unset →
            ephemeral-pepper *decision* is inline in `main()` and unreachable
            from a test file. `randomPepper()` itself is covered. Closing it
            needs `resolvePepper(getenv) (pepper, source string)` — a
            production change, so it was not made from a test-only task.
- [x] **Doc-comment sweep.** Done 2026-09-10. Five of the seven triaged
      locations were **already correct**: `5937ce9` fixed them and the triage
      doc's line numbers had drifted, so the entry overstated the work. What
      remained: two `internal/store/threat` comments naming `threat.go`, a file
      the split renamed to `store.go`, and `queue.go`'s claim that the lockless
      `Workers()` read is safe because the field is immutable — the real
      property is call ordering, verified against both call sites.
- [ ] **Deploy tooling.** GHA cache unscoped across the matrix (four jobs
      overwrite each other's `mode=max` export); `render.sh` writing straight
      into the directory Traefik watches; the duplicated `runPassLoop`/env
      helpers in `cmd/threatd` and `cmd/sizingd`. (The `After=`-without-`Wants=`
      item from this list is done — see §4.)

## 4. Known operational sharp edges

- [x] **authd down is indistinguishable from a backend fault.** Fixed:
      `Wants=authd.service` added alongside the existing `After=` on
      `insightsd.container`, `threatd.container`, `sizingd.container` and
      `traefik.container` (`traefik.container` got the same treatment on the
      reasoning that it is the one unit that actually calls authd on every
      API request, via the `forwardAuth` middleware) -- not `Requires=`:
      propagating authd's failure would turn a recoverable auth outage into
      dead pipelines, and each unit's own health check is what's meant to
      make the difference visible instead. Still true: this only closes the
      boot-time gap where authd never got pulled in at all. A request while
      authd is down still comes back as a Traefik-generated `500`
      indistinguishable from a backend fault -- `Wants=` makes systemd say so
      in `systemctl status`/`list-dependencies`, it does not change the HTTP
      response.
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
- [x] **Deploy the above.** Done 2026-09-10: `insights.gs.nethserver.net` now
      runs the four `:latest` images built from `240412f` (all four carry
      `org.opencontainers.image.revision=240412f`), the ten quadlet units and
      `/etc/systemd/journald.conf.d/insights.conf` were reinstalled from the
      committed tree, and `systemd-analyze cat-config systemd/journald.conf`
      confirms `SystemMaxUse=200M` / `SystemMaxFileSize=20M`. All four
      containers `healthy`, Traefik `Up`, `ss -tlnp` still 80/443 only, the
      Let's Encrypt certificate untouched, and every route 401s without a
      credential. The four containers now report `LOG_LEVEL=info`.
- Backing up the volumes was considered and **dropped**: that host is a dev
  machine, its three databases hold nothing worth preserving, and
  `docs/runbooks/2026-09-09-insights-test-deploy.md` rebuilds it from scratch.
- [x] **`insightsd` has no LLM credentials on the box.** Set 2026-09-10:
      `api.openai.com/v1`, `gpt-4o-mini`, and both price knobs. Proven live by
      rl1's first bundle — one call, `$0.000202`, three findings.
- [ ] **`PIPELINE_EXCLUDE_MODULES` on the box matches nothing.** It is set to
      `crowdsec,insights`, but `model.ExcludeModules` compares `module_id`
      exactly and the id is `crowdsec1` — NS8 module ids carry an instance
      number. So the exclusion is inert: crowdsec1's log lines are gated,
      prompted and billed on the LLM path while the same signal already
      arrives on `/blocklist/v1/events`, which is the double-pay the setting
      exists to prevent. Two `crowdsec1` rows are already in
      `module_baselines`. `insights` in that list is a second mistake of the
      same kind: it is a *service*, not a module, and its own axis
      (`PIPELINE_EXCLUDE_SERVICES`) is already correct by default. Fix is
      `PIPELINE_EXCLUDE_MODULES=crowdsec1` and a restart.
- [ ] **`LLM_DAILY_SPEND_CAP_USD` is unset**, so the only ceiling is
      `LLM_MAX_CALLS_PER_SYSTEM_PER_DAY=12`. Cheap insurance on a box that now
      has live reporters.

## 5. Not started, from the original plan

- [x] Task 1's tooling: `Makefile`, `.golangci.yml`, `.github/workflows/ci.yml`,
      `scripts/check-license-headers.sh`. Done 2026-09-10. The header script
      distinguishes "missing" from "present in the wrong comment form", checks
      a Go header precedes the `package` clause, fails closed on an
      unrecognised extension, and **asserts the vendored Pico files do not
      carry our SPDX line** — the exemption is enforced in both directions, so
      nobody can "fix" them into a misattribution. The plan's draft pinned
      golangci-lint v1.62 against what is now a v2 config schema, which would
      have silently ignored the config; CI pins v2.11.3 to match.
      Landing it took a second pass to clear 38 lint findings, so CI's first
      run is green rather than red-on-arrival. One was a real defect:
      threatd's four allowlist write handlers parsed forms with no body-size
      limit and nothing upstream bounded them, now `http.MaxBytesReader` at
      16 KiB each. Exclusions are per-file and commented; `bodyclose` and
      `sqlclosecheck` were at zero findings before the pass and still are.
- [ ] `golang-migrate` in place of `CREATE TABLE IF NOT EXISTS`, now three times
      over.
- Distributed locking was considered and **dropped**, not deferred. Both the
  blocklist consensus pass and the sizing cohort pass are single-instance only,
  and that is now a documented constraint rather than a gap: run exactly one
  `threatd` and one `sizingd` against a given database. Do not reintroduce this
  as a planned item without a multi-instance deployment that actually needs it.
