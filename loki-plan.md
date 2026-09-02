<!-- Copyright (C) 2026 Nethesis S.r.l. -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ns8-loki edge work: cut false gate triggers and template churn

## Context

The nethesis-insights server gates each 15-minute bundle and only calls an LLM when the gate fires. Measured on the rl1 dev fleet on 2026-09-01, three real multi-module nodes fired the gate on 9 of 9 windows (100%), projecting to roughly $13,200/month at 2700 nodes. The server side is being fixed in a parallel change (absolute floors under the deviation condition, a novelty quorum, a canonical template key, prompt payload trimming, and a budget package). The items below are the root causes that live in this repo and cannot be fixed server-side.

## Digest and template populations disagree

**Defect:** `insights-collector` lines 392-416, `Client.digest`, runs:

```python
query = ('sum by (module_id, priority) '
         '(count_over_time({node_id=~".+"} | json priority="PRIORITY" [{0}s]))'
         ).format(int(range_seconds))
```

It has no `| priority < 5 or category="security"` filter and no `identifier != "<self>"` exclusion, while the per-module line query at lines 418-447 applies both (lines 426-427):

```python
stages = [
    selector,
    '| json priority="PRIORITY", identifier="SYSLOG_IDENTIFIER", message="MESSAGE"',
    '| identifier != "{0}"'.format(self_identifier),
    '| priority < 5 or category="security"',
    ...
]
```

**Evidence:** The `observed` and `expected` fields in the bundle describe a population the prompt never shows. The server fires `deviation:<module>/<priority>` on lines the model cannot see.

**Fix:** Apply the same stage list to the digest query so both sides count the same lines. Add `| priority < 5 or category="security"` and `| identifier != "<self>"` to the digest aggregation query.

## `expected` has no seasonality

**Defect:** Lines 588-605: `expected = base / BASELINE_HOURS * (window_seconds / 3600.0)` with `BASELINE_HOURS = 168`, i.e. a flat 7-day hourly mean.

**Evidence:** Any bucket with a business-hours or nightly-backup shape exceeds 3x on schedule. The flat baseline fires the deviation gate on predictable, benign load patterns.

**Fix options to present:**
- A per-hour-of-week baseline that captures the day-of-week and hour-of-day patterns
- Shipping a dispersion estimate (e.g. standard deviation or a p95) so the server can threshold on something better than a bare ratio

## Masking leaks mint a new template every window

**Defect:** Masking rule 11 (lines 249-254) is `\d{2,}` (two digits minimum), so single digits, percentages and fractional parts survive:

```
checkpoint complete: wrote <NUM> buffers (1.5%); 0 WAL file(s) added, 0 removed, 1 recycled
```

This is a fresh template on every checkpoint. Also unmasked: hostnames and FQDNs (no rule at all — `scrub()` preserves them deliberately), GeoIP country codes, the `user=<name>` form (rule 10 requires whitespace, so `user=alice` is missed), and non-ISO date formats.

**Evidence:** Measured on 710 live templates from three real nodes (excluding the `crowdsec1` module and the server's own self-logs): structural leaks cause continuous novel templates.

**Fix:** Improve masking rules:
- Rule 11: catching single digits is right, but `\d+` is not the way to do it — the two-digit
  minimum exists so the priority marker `<3>` and instance names like `traefik1` survive.
  The server's form works and is worth copying: split the leading `<N>` marker off first,
  then apply `\b\d\b` (a word boundary never matches inside `traefik1`), plus separate
  rules for `\d+(\.\d+)?%` and `\d+\.\d+`. See `internal/model/canonical.go` in
  nethesis-insights
- Add explicit rules for hostnames/FQDNs, GeoIP country codes, and the `user=<name>` form where no whitespace precedes it
- Add rules for common non-ISO date formats (e.g. `dd/mm/yyyy`, `mm-dd-yy`)

Note: The server now has a narrow regex canonicalization (`model.CanonicalTemplate`) that collapses these leaks on receipt — measured 710 live templates down to 526 — but it is a workaround. The template is produced here.

Note (2026-09-02): the server also keys novelty, `system_templates` and finding identity on the module *family* (`model.ModuleFamily`: `nethvoice5` → `nethvoice`) and collapses the bracketed instance identifier `[agent@openldap55]` → `[agent@openldap]`, which took 678 live rows over 185 module instances down to 230. That closes the server's exposure, not the edge's: see `loki_optimization_plan.md` for the three edge defects behind it, the largest being that `allocate()` degrades to 2 templates per module per window at 185 instances.

## Templates are near-duplicates of each other

**Defect:** Templates within a window are often near-duplicates that differ only in variable tokens or trailing key=value pairs.

**Evidence:** Measured on 710 live templates from three real nodes: a Drain-style clustering — bucket on `(system, module, priority, token count, leading tokens)` and wildcard the token positions that vary — yields only 249 distinct shapes (35%), and 512 of the 710 sit in a multi-member cluster. `metrics1` alone contributed 223 templates that are 5 conditions. Worst offenders, verbatim:

```
 65 [metrics1] <3> [prometheus] … msg="Deleting obsolete block" component=tsdb <*>
 58 [metrics1] <3> [prometheus] time=<TS> level=INFO <*> <*> <*> <*> <*> <*> <*>
 53 [metrics1] <3> [prometheus] … msg="write block" … mint=<HEX> maxt=<HEX> <*> <*> ooo=false
 46 [<host>]   <3> [node_exporter] … source=node_exporter.go:<NUM> <*>
 17 [nethvoice5] … [INFO][AUTH] authorization success for user <USER> <*> <*>
```

**Fix:** Group templates within a window by `(module, priority, token count, leading tokens)` and wildcard the positions that vary, emitting one template with a summed count plus a count of how many raw variants were folded, so the server can see how much was collapsed.

**Critical warning:** This is a `MASKING_VERSION` bump, which makes every template on every node novel in the same window (see the insights spec section 9.3 on correlated novelty). **It must land AFTER the server's `LLM_MAX_CONCURRENCY` and daily spend cap are deployed.**

## Quiet windows ship anyway

**Defect:** `collect_and_ship` (lines 693-727) has no guard for an empty result; every node POSTs 96 bundles a day regardless.

**Evidence:** Bundles with no templates and no deviating bucket incur HTTP traffic and server ingest work unnecessarily.

**Fix:** Suppress a window with no templates and no deviating bucket. Note: this does NOT save LLM cost, because the server's gate already declines an empty bundle.

## `DENYLIST` ships empty

**Defect:** Lines 38-40, with a comment saying curating it needs real fleet data rather than a guess. There is now real fleet data.

**Evidence:** Candidates observed as pure volume with no operator value:
- Prometheus: `Head GC completed`, `WAL checkpoint complete`, `Deleting obsolete block`, `write block`
- Postgres and TimescaleDB: `checkpoint complete`
- rspamd: `finalize_item: slow ... rule`
- Alloy/promtail: `finished node evaluation`

**Fix:** Populate `DENYLIST` with these patterns.

**Tradeoff to note:** A denylist filters at the Loki query so those lines never travel, which also removes them from the digest counts. This is intentional — the query is the right place to filter, and the removed lines won't distort the digest baseline.

## Suggested order

1. Digest query filter (apply same stage list as line query)
2. Masking leak rules (single digits, hostnames, GeoIP, `user=`, date formats)
3. Denylist population
4. Quiet-window suppression
5. Seasonality (per-hour-of-week or dispersion estimate)
6. Drain-style clustering **last** because of the MASKING_VERSION bump — it cannot land until server cost controls are deployed

## Verification

The module's Robot suite is `tests/20__insights.robot` with the stub `tests/insights-stub.py`. Commit f4c31ca deleted the former `imageroot/pypkg/insights/` package and its pytest unit suite, so any new pure function (masking, clustering) needs its unit test home re-established rather than assumed.

After deploying, re-measure on rl1 by copying the server's SQLite file and counting distinct `template_key` rows per system. Expect meaningful reduction in template churn, and corresponding reduction in gate firing.
