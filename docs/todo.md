<!--
Copyright (C) 2026 Nethesis S.r.l.
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Todo

## Contents

- [Fleet sizing is a dev preview](#fleet-sizing-is-a-dev-preview)
- [Everything else](#everything-else)

## Fleet sizing is a dev preview

The `sizingd` server is complete: ingest, sanitizing, the `pressure` score,
the multi-day verdict, the cohort pass and three dashboard pages, all covered
by tests. **Nothing sends it a report.**

- [ ] **Write the `ns8-core` cluster reporter.** `cluster/bin/send-sizing-report`
      does not exist. The wire contract it must satisfy is
      [`docs/api/sizing-ingest.md`](api/sizing-ingest.md); the server accepts
      it today. Leader-only, three sends a day, each one a byte-identical
      restatement of a complete UTC day — the day is an absolute fact, so
      redelivery is free and measurement rows recompute rather than
      accumulate. Configuration takes the bare server root; the client appends
      `/sizing/v1/reports` itself.

Until it exists:

- `sizingd` stores nothing, and the three sizing pages are empty on any
  deployment.
- The pressure ramps and cohort floors are **uncalibrated** — reasoned
  defaults, not values fitted to fleet data. Calibrating them needs roughly 30
  days of real reports. Every number the pipeline publishes is provisional
  until then, and the dashboard labels each threshold with which kind it is.
- `webtop` and `imapsync` have no `get-facts`, so their workload metrics are
  absent rather than zero. Absent is not zero anywhere in this pipeline.

Nothing above blocks the other two pipelines. `insightsd` and `threatd` are
complete and fed by real nodes.

## Everything else

Known constraints that are decided rather than pending — single-instance-only
passes, no organization scoping, no per-system ingest rate limit — are in
[`docs/architecture.md`](architecture.md) § Known limits. They are documented
constraints, not a backlog.
