<!--
Copyright (C) 2026 Nethesis S.r.l.
SPDX-License-Identifier: GPL-3.0-or-later
-->

# What is nethesis-insights, and how does it work?

This document explains the project in plain language: what problem it solves,
what the core concepts mean (finding, analysis, template, baseline), and how
to use the operator UI. For the technical package-level design, see
`docs/architecture.md`. For the full rationale behind every rule, see
`docs/specs/2026-08-05-nethesis-insights-design.md`.

> **Keep this file in sync.** If a concept below changes meaning, or the UI
> gains/loses a page, update this document in the same change.

## The problem

NethServer machines produce logs constantly. Somewhere in that stream are the
handful of lines that mean "something is actually wrong" — a service crash-
looping, a login being brute-forced, a disk filling up. Finding those lines
by hand across ~2700 machines is not realistic.

`nethesis-insights` is one central server that does this instead: every node
still watches its own logs and packages up what changed, but the *decision*
to spend money asking an AI about it, and the *memory* of what's already been
reported, both live here — one place, not one per machine.

## The moving parts, in order

### 1. The bundle

Every 15 minutes, each node sends a **bundle**: a compact, already-masked
summary of that window's logs. It is *not* raw logs — sensitive values are
already stripped out before it ever leaves the machine. A bundle contains:

- a **digest**: for each log module, how many lines it produced this window,
  and (if the node can tell) how many it *expected*;
- a list of **templates**: the distinct *shapes* of log lines seen (see
  below), each with a count;
- bookkeeping about how much the node had to truncate to stay within its own
  budget.

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
interesting**. Only a template that's genuinely new (or a known one behaving
very differently — see baselines below) is worth spending money to have an
AI look at.

### 3. The gate: deciding if it's worth asking the AI

Calling an AI model costs real money, every time. If the server called it for
every 15-minute window from every one of ~2700 machines, the bill would be
enormous (roughly $16,000/month on a cheap model, by internal estimate) for
mostly "nothing happened" windows. So before anything is sent to the AI, the
**gate** looks at the bundle and asks: is there actually anything new or
unusual here? It says yes if:

- a template in this bundle has **never been seen before** for this machine;
- some module's log volume is **way higher than expected** (more than a
  configurable multiplier over its normal rate — see baselines);
- a template tagged **security**-related is either new for this machine, or is
  one we already know about whose module is suddenly much noisier than usual
  (the node applies the security tag, not the server);
- a module both **dropped lines** because it hit its own budget *and* is
  behaving unusually — either one alone is not enough.

**A window is sent to the AI only if at least one of the four conditions
above is true.** If none are true, the window is "gated out": the server
still does the cheap bookkeeping (remembers the templates, updates the
baselines) and moves on — no AI call, no cost.

Note the shape of the security rule: *new or surging*, not merely *present*.
Any machine reachable from the internet gets a constant trickle of failed SSH
logins, so "there is a security-tagged line in this window" is true of
essentially every window forever. Treating that as a reason to call the AI
made the gate stop gating — measured on the dev machine, 352 AI calls out of
352 windows, not one gated out. Steady background noise is not news; a new
kind of attack, or a sudden spike in a familiar one, is.

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

- **operator UI, `/analyses`** — every window for a machine, each row marked
  whether it was gated and whether the AI was called;
- **operator UI, `/gate`** — the same decisions, grouped by *why*, so you can
  see which reason is driving spend across the whole fleet;
- **on disk**, the `analyses` table, `gated` column (see `docs/architecture.md`
  § Data model).

So "why did (or didn't) this window get analyzed" is always answerable after
the fact from stored data — see the `/analyses` and `/gate` pages below.

### 4. Baselines: "what's normal" for a module

Not every node's log collector knows how many lines it expects to see for a
given module. When it doesn't say, the server keeps its own running estimate
per `(machine, module, priority)`, called a **baseline**. The gate compares
the actual count in a bundle against this baseline (or the node's own stated
expectation, if it gave one) to decide whether a module is behaving
unusually. You can see the current baseline for every module of every
machine on the `/baselines` page.

**What "EWMA" means, in simple words.** EWMA stands for Exponentially
Weighted Moving Average — a fancy name for a simple idea: "my new estimate of
normal is mostly my old estimate, nudged a little bit toward whatever just
happened." Every time a new count comes in, the server blends it with the
previous baseline:

    new baseline = (a little bit × this window's count) + (mostly × old baseline)

That "a little bit" is `EWMA_ALPHA` (default `0.3`, i.e. 30%). A higher
`EWMA_ALPHA` makes the baseline react faster to recent changes; a lower one
makes it more stable and slower to move. The very first time a module is
seen, there's no "old baseline" yet, so the baseline just starts out equal to
that first count.

One thing worth being precise about: **`EWMA_ALPHA` itself is always between
0 and 1** (it's a blending weight — "how much of the new value to mix in").
The *baseline value it produces* is **not** a 0–1 number — it's a count of
log lines, so it can be anything from 0 to several thousand, whatever is
normal for that module on that machine.

### 5. The analysis: when the AI actually looks

When the gate says yes, the server builds a prompt describing that window
(the digest, the new/interesting templates, what got truncated) and sends it
to an LLM, along with a reminder of what's *already* an open problem for this
machine so the AI doesn't re-report it. The AI responds with a structured
list of findings (or none, if on reflection nothing warrants it) — never free
text, always following a strict format the server validates.

Whether or not the AI was called, the outcome of processing one window is
recorded as an **analysis**: which window, whether it was gated out or sent
to the AI, how many tokens it used, what it cost, how long it took, and any
error. This is the system's cost ledger — see the `/analyses` and `/cost`
pages.

### 6. Findings: the actual output

A **finding** is one reported problem: a title, a plain-language summary, a
suggested action, a severity (critical/high/medium/low), which log modules
it involves, and the evidence (which templates) it's based on.

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

## How a node talks to the server

A node authenticates with a NethServer subscription credential (checked
against Nethesis's own validator, not stored or checked locally) and:

- **sends** its bundle: `POST /v1/bundles` — the server answers immediately
  with "accepted" or "try later," never with the analysis result itself,
  since the actual analysis (and any AI call) happens in the background;
- **reads** its own findings: `GET /v1/findings` — only ever for its own
  machine, never anyone else's.

## Threat Shield: the fleet as one sensor network

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
   that decision to `POST /v1/threat-events` using the same subscription
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

4. **Nodes fetch the result.** `GET /v1/blocklist` returns a plain list of
   addresses, which the node imports into CrowdSec. Every subscriber gets the
   same list.

### The two safety nets

Consensus alone has an obvious failure mode: what if the fleet agrees on
something it shouldn't? Two exclusions run before anything is published.

- **The allowlist.** A hand-maintained list of addresses and ranges that must
  never be published, whatever the fleet says — a partner's security scanner, a
  shared resolver. It is applied when the decision to publish is made, not when
  the list is read, so adding an entry actually *removes* the address on the
  next pass rather than just hiding it.

- **Fleet self-protection.** The server remembers the address each reporting
  node connects from, and never publishes any of them. This closes the worst
  case: one customer's misconfigured appliance reporting the fleet's own
  gateway, and the fleet then blocking itself.

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
allowlist and fleet self-protection above are what stands in for it.

### Asking for an address to be left alone

Sometimes the fleet agrees about an address that is not actually an attacker —
a partner's security scanner, a shared resolver, a customer's own gateway. Two
things exist for that.

A node can **ask**: `POST /v1/allowlist-requests` puts the address in a review
queue, ranked by how many different machines asked for it. Forty customers all
hitting the same shared resolver floats it to the top; a single opportunistic
request sinks.

A human then **decides**. Nothing is ever exempted automatically, and this is
deliberate rather than an unfinished feature. The blocklist and the allowlist
look like mirror images and are not: if the fleet wrongly blocks an address,
somebody notices within the day and it expires anyway, whereas if the fleet
wrongly *exempts* an address, nobody notices at all — there is no complaint to
be made about not being blocked — and it stays exempt forever. Reporting an
attack is evidence; asking to be exempted is an opinion. So the counter ranks
the queue and does nothing else.

Approving or rejecting is done either through the operator UI's
`/allowlist-requests` page or through the admin API, both of which require the
admin key and record who did it.

Once a request has been approved or rejected it **leaves the queue** — the
queue only ever shows addresses still waiting on a decision. What was asked
and how it was settled is kept in the audit trail, so a handled request is
still answerable for later; it just stops asking to be handled again.

Deciding an address is not a permanent verdict on it. If machines ask for the
same address again after a rejection, it comes back into the queue to be
looked at afresh — which is what you want, because "two machines asked once"
and "sixty machines have asked since" deserve different answers, and an old
`no` should not quietly bury the second case.

## The operator UI: looking at what the server knows

The operator UI is a separate, optional, read-only web page built into the
server binary. It is **off by default** and must be explicitly turned on
(`UI_LISTEN_ADDR=127.0.0.1:9596`) — see `README.md` for exposure guidance,
since unlike the API above, this page shows data across *every* machine at
once and isn't authenticated.

What each page shows, in plain terms:

| Page | What you're looking at |
|---|---|
| `/` (home) | Is the server healthy? Queue backlog, uptime, build version, and the full effective configuration it's running with. |
| `/systems` | Every machine the server has ever heard from, with a quick summary: how many templates, findings, analysis windows, and how much it's cost so far. |
| `/findings` | The actual reported problems, most severe and most recent first. Filter by machine, status (open/stale) or severity. Click a row to see the full summary, suggested action, evidence and fingerprint. |
| `/analyses` | The cost ledger: every window processed, whether it was gated out, whether the AI was called, tokens used, cost, how long it took, and any error. This answers "what did we spend, and on what." |
| `/gate` | The gate's decisions grouped by *why* — how many windows and how much money were spent for each distinct set of reasons. This answers "what's actually driving our AI spend." |
| `/cost` | Spend and token usage per day and per model — the trend line version of the ledger. |
| `/templates` | What the server currently considers "already known" for a machine — i.e., what would *not* by itself trigger a new AI call. |
| `/baselines` | The current EWMA "normal rate" estimate per module per machine — what the gate compares actual volume against when a node doesn't supply its own expectation. |
| `/threat-systems` | The blocklist pipeline's counterpart to `/systems`: one row per machine that has ever reported a CrowdSec decision, including a machine whose every report was a duplicate or got dropped by the sanitizer and therefore never shows up anywhere else. |
| `/blocklist` | What the fleet currently agrees is malicious. Each row expands to the evidence that got it published — how many machines, how many hits, under which rule. Below it: the allowlist and the fleet's own addresses, i.e. the two reasons an address might *never* appear here. |
| `/threat-events` | The raw sightings behind the list. Filter by address to answer "who reported this, and when" — useful when somebody's customer asks why they got blocked. |
| `/threat-stats` | Two things: the day-by-day threat trend broken down by CrowdSec scenario, with a per-day total, and what each machine contributed — including how much of what it sent was discarded, and for which reason. |
| `/allowlist-requests` | The review queue: which addresses customers have asked to have left alone, how many different machines asked, and the reasons they gave. Approve or reject from here. |

If an admin key is configured, this UI also gains a small number of **buttons**
— add or remove an allowlist entry, approve or reject a request. Those actions,
and only those, ask for a password; everything else on every page stays
readable without one. Whatever username you type at that prompt is recorded
alongside the change, so the audit trail says who did it.

Nothing on this UI ever shows a raw, unmasked log line — the server never
stores those in the first place, so there's nothing to show. And the page
itself makes no outside network requests and needs no JavaScript enabled —
it's meant to work even on an offline management network.

## What this system deliberately does *not* do

- It does not decide *what counts as security-relevant* — that tag comes from
  the node, which has full context on its own logs. The server only reacts to
  it.
- It does not show you a *per-customer* dashboard — the operator UI is an
  internal, fleet-wide diagnostic tool for the people running the server, not
  a product feature for end customers.
- It does not retain raw log content anywhere — only masked templates and
  their counts.
