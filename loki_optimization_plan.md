<!-- Copyright (C) 2026 Nethesis S.r.l. -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ns8-loki edge work: allocate, mask and cluster per module family

Follow-up to `loki-plan.md`. Three defects in
`imageroot/bin/insights-collector` (COLLECTOR_VERSION 2.0.0, MASKING_VERSION 3)
that all have the same root: **the collector treats every module instance as a
separate module.** On a hosting node that is 185 modules where there are 16.

The server-side change (`model.ModuleFamily`, and a bracketed-instance rule in
`model.CanonicalTemplate`) already closes the server's exposure — 678 stored
rows down to 230 — so none of this is needed to stop paying for duplicate LLM
calls. What it buys is bundle size, Loki query count, and the line budget:
today the host bucket gets **2 templates per 15-minute window** on that node.

## Context

Corpus: `template.dump` in the server repo, a dump of live `system_templates`
rows. 823 rows, 678 distinct `(module_id, priority, template)`, **185 distinct
`module_id`s across 16 families** — nethvoice=82, openldap=71, traefik=7,
ldapproxy=7, nethvoice-proxy=6, loki=2, and ten singletons including the host
bucket `module_id: ""`.

**Verify the corpus is one node before acting.** The dump carries no
`system_id` column. That 823 rows collapse to 678 distinct suggests very little
cross-system overlap, i.e. one large multi-tenant node, but confirm it:

```sql
SELECT module_id, COUNT(DISTINCT system_id) FROM system_templates GROUP BY 1;
```

Defect 1 is entirely conditional on that answer; defects 2 and 3 are not.

## Ordering

All three need a collector bump, and defect 2 needs `MASKING_VERSION` bumped.
The comment at `insights-collector:176-192` is the constraint: bumping it
changes every template's text, so **every template on every node goes novel in
the same window**. Therefore:

1. **The server change lands first** — it is one deploy, retroactive, and it
   makes the fleet's template count correct regardless of which collector
   version a node happens to run. That independence is the point of spec §8.1.2
   (`docs/specs/2026-08-05-nethesis-insights-design.md`): the server cannot
   trust that every fleet node runs a fixed collector, so it must collapse on
   its own. It is not a reason to skip fixing the source.
2. **Then confirm `LLM_MAX_CONCURRENCY` and `LLM_DAILY_SPEND_CAP_USD` are
   live** on the server, because the masking bump's novelty storm is exactly
   the event those two exist for.
3. **Then ship the edge change.** Defect 2 is then fixed on both sides. That
   redundancy is correct and intended, per §8.1.2 — not something to remove
   from either side later.

## Defect 1: `allocate()` starves the whole node

**Measurement.** `allocate()` (`:517-535`) reserves `MIN_SHARE = 20` per module
and gives up when the floors do not fit:

```python
    count = len(modules)
    if count * MIN_SHARE >= max_lines:
        # More modules than floor space. Equal shares, floor unreachable.
        share = max(1, max_lines // count)
        return {m: share for m in modules}
```

With 185 module ids and `DEFAULT_MAX_LINES = 500`, `185 * 20 = 3700 >= 500`, so
every module gets `500 // 185 = 2` templates per window — including
`module_id: ""`, the bucket whose own comment (`:558`) says it carries the
majority of security-relevant traffic. The floor that exists specifically to
stop one module starving the others is unreachable, and the effect is worse
than starvation by one module: *everything* is starved.

At 16 families, `16 * 20 = 320 < 500`, so the floor holds and each family gets
20 plus a weighted share of the 180 remaining — roughly 31, and ~51 for a
family flagged by `PRIORITY_WEIGHT`.

**Change.** Iterate families rather than module ids in the collect loop
(`:1165-1195`), which is one change with three effects:

- `allocate(families, max_lines, prioritised=deviating_families)` — the
  weighting input `deviating` (`:1162`) is a set of instances and must be
  folded to families the same way.
- **One Loki query per family instead of one per instance.** `Client.lines()`
  (`:714-718`) builds `{module_id="<id>", node_id=~".+"}`; a family needs
  `{module_id=~"<family>[0-9]+", node_id=~".+"}`. This drops 185 `query_range`
  calls to 16, which is the largest single cost in a collector run.
- **One `group_templates(page, family, share)` per family**, so `fetch_limit()`
  (`:538`) overfetches once against a share that is worth something and the
  dedup-then-cap sequence runs across the family's whole page. This is also
  defect 3, fixed by construction rather than separately.

Nothing about `MIN_SHARE`, `PRIORITY_WEIGHT`, `OVERFETCH` or `allocate()`'s own
arithmetic changes — only what it is handed.

**What must stay per-instance.** `digest[]` (`:1143-1163`) keeps
`module_id` per instance, unchanged: the server's `module_baselines` and the
gate's deviation condition are keyed on the instance on purpose, so one
instance flooding is still visible. Only `templates[]` moves to the family,
which is safe because every server-side consumer of a template's `module_id`
(novelty, `system_templates`, prompt grouping, finding identity) now families
it anyway.

**Interaction to check before shipping.** The server's
`PIPELINE_EXCLUDE_MODULES` defaults to `crowdsec1` — an instance id, matched
exactly by `model.Bundle.ExcludeModules` against `templates[]` *and*
`digest[]`. If `templates[]` starts carrying `crowdsec`, template exclusion
stops matching while digest exclusion still does, which is precisely the
split-scope failure that filter exists to prevent. Either the collector must
not emit a family whose instances are not uniformly excluded, or the server's
exclusion has to learn families. Decide this before the bundle shape changes.

**What could break.** `tests/unit/test_select.py` asserts the total never
exceeds `max_lines`; the family regex selector must not match a sibling image
(`nethvoice[0-9]+` must not match `nethvoice-proxy4` — it does not, but a
`.*`-style pattern would).

## Defect 2: masking rule 10 misses `agent@<instance>`

**Measurement.** 154 of the 678 rows are one template:

```
<4> [agent@openldap55] Signal "user <USER> signal <NUM>" caught: shutdown started.
```

one row per instance, across seven families — openldap 71, nethvoice 63,
traefik 7, ldapproxy 7, nethvoice-proxy 4, metrics 1, loki 1.

**Current code** (`:339-342`):

```python
        (
            re.compile(r'\[([A-Za-z][\w-]*?)\d+\]'),
            r'[\1]',
        ),
```

`[nethvoice84]` → `[nethvoice]` works. `[agent@openldap55]` does not: `@` is
not in the class. The identifier is the journal `SYSLOG_IDENTIFIER` of an NS8
agent, and `scrub()`'s email rule protects those names deliberately
(`:112-120`) so they reach masking intact.

**Change.** Add `@` and `.` to the class:

```python
        (
            re.compile(r'\[([A-Za-z][\w@.-]*?)\d+\]'),
            r'[\1]',
        ),
```

The digits have to be the last thing before the `]`, which is what keeps this
narrow. Verified against the whole corpus: `[php7:error]`, `[nextcloud]`,
`[sshd-session]` and `[systemd-logind]` are untouched, and the rule is
idempotent on every row. The identical rule is already in the server's
`model.CanonicalTemplate`, so the corpus evidence is the same either way.

## Defect 3: clustering never crosses instances of one family

**Measurement.** The 82 byte-identical
`<6> [CRON] pam_unix(cron:session): session closed for user <USER>` templates
all ship. Not near-duplicates — identical text.

**Cause.** `group_templates()` (`:950`) is called once per module and calls
`cluster_templates()` (`:990`) on that module's entries alone. The bucket key
is `(priority, category, len(tokens))`, with the module excluded because — as
`:849` says — the caller is already per-module:

```python
    clustered = cluster_templates(list(groups.values()))
```

So the exclusion is correct and the *caller* is the defect. Nothing in
`cluster_templates()` needs to change.

**Change.** None of its own: defect 1's family-scoped collect loop hands
`group_templates()` a whole family's page, and the existing
`(template, priority, category)` dedup at `:963` collapses the 82 identical
copies before clustering even runs, emitting one entry with `variants=82`
(`:944-945`).

If defect 1 is deferred — e.g. the 185 module ids turn out to span many nodes —
then this becomes a separate change, and the shape is a family-keyed bucket
(`(family, priority, category, len(tokens))`) rather than a global pass:
clustering across families would let `[nethvoice]` and `[openldap]` lines with
the same token count merge on a 0.5 match ratio.

**Preserve.** `CLUSTER_SIMILARITY = 0.5` (`:834`) — tuned on 710 live templates
down to 249 shapes, and the comment records what moving it in either direction
costs. `variants` must still be emitted only when greater than 1 (`:944-945`),
so an uncollapsed entry stays lean and an absent `variants` reads as 1.

## Tests

- **`tests/unit/test_masking.py`** — the rule-10 assertions at `:88-93` are the
  place for defect 2: `[agent@openldap55]` → `[agent@openldap]`, and
  `[php7:error]`, `[nextcloud]`, `[sshd-session]`, `[systemd-logind]`
  unchanged. Add an idempotency case.
- **`tests/unit/test_select.py`** — `allocate()` over 16 families / 185
  instances: total ≤ `max_lines`, the `MIN_SHARE` floor reached, the host
  bucket not starved, and the equal-share degrade path still reachable when
  families alone exceed the floor space.
- **`tests/unit/test_cluster.py`** — 82 identical entries under one family
  produce one entry with `variants=82`; two families with the same token count
  do not merge.
- **`tests/unit/test_loki.py`** — the family selector: `nethvoice[0-9]+` does
  not match `nethvoice-proxy4`, and the host bucket keeps its
  `module_id=""` form (asserted today at `:254`).
- **`tests/unit/test_bundle.py`** — `templates[]` carries families while
  `digest[]` still carries instances.
- **`tests/20__insights.robot`** — a bundle from a multi-module node still
  ships and is accepted.

## Out of scope

- `CLUSTER_SIMILARITY`, tuned on real data.
- `SCHEMA_VERSION` (`:814`) — additive-only changes, the wire shape is the
  same.
- Anything in the server repo.
