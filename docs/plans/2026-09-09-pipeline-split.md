# Pipeline split implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the three pipelines that currently share one process into three
independently deployed services behind one Traefik proxy, each owning its own SQLite
file, with authentication moved to a shared caching forward-auth service.

**Architecture:** One repository, one `go.mod`, four binaries — `authd`, `insightsd`,
`threatd`, `sizingd`. Traefik terminates a deploy-configured host, strips a per-pipeline
path prefix, calls `authd` as a `forwardAuth` middleware for the client APIs, and
BasicAuths the operator UIs. Shared code lives in `internal/platform`
(`auth`, `httpx`, `sqlitex`) and `internal/ui/chrome`; everything else is grouped under
`internal/{store,api,ui}/{logs,threat,sizing}` so each binary imports exactly one of
each. The pure packages (`gate`, `fingerprint`, `prompt`, `threat`, `sizing`) keep their
current import paths.

**Tech Stack:** Go 1.23.6, `bun` + `modernc.org/sqlite`, `html/template`, Pico CSS,
Traefik v3, podman quadlets.

**Spec:** the three design documents this repository already carries —
`docs/specs/2026-08-05-nethesis-insights-design.md`,
`docs/specs/2026-07-28-threat-shield-design.md`,
`docs/plans/2026-09-02-fleet-sizing-server.md` — plus the Decisions section below, which
is the authoritative record for everything this plan changes about them.

## Global Constraints

Every task's requirements implicitly include these. They are copied from `CLAUDE.md` and
none of them is relaxed by this plan.

- License header above the `package` clause, blank line after:
  `// Copyright (C) 2026 Nethesis S.r.l.` / `// SPDX-License-Identifier: GPL-3.0-or-later`.
  `#` form for SQL, YAML, Makefile, shell; `<!-- -->` for HTML templates; `/* */` for CSS.
- **Vendored files stay exempt.** `internal/ui/static/pico.min.css` and `pico.LICENSE`
  keep their upstream notices byte-for-byte and never receive the Nethesis header.
- IDs are ULIDs generated in Go. Never `AUTOINCREMENT`/`SERIAL`.
- Timestamps are `INTEGER` unix-millis. Never native date types.
- `ON CONFLICT … DO UPDATE` only. Never `INSERT OR REPLACE`.
- JSON stored as `TEXT`, parsed in Go. No `jsonb`, no `json1`.
- SQLite: WAL, `busy_timeout=5000`, `SetMaxOpenConns(1)`, plus a mutex serializing writes.
- `gate`, `fingerprint`, `prompt`, `threat`, `sizing` stay pure: no I/O, no clock beyond
  an injected `now()`.
- Gate reasons and pressure reasons carry no computed values.
- `LLM_API_KEY` and `AUTH_PEPPER` come from the environment only, are never written to a
  database and never logged. The request logger never touches `Authorization`.
- Raw `samples` are never persisted.
- Identical bundle input produces byte-identical prompts.
- Conventional Commits. No issue reference in an individual commit message. Work on a
  branch. Stage explicit paths, never `git add .`.
- `go build ./... && go vet ./... && go test ./... -race -count=1` is green at the end of
  every task.

---

## Decisions

Locked before this plan was written. Each one closes an alternative that would otherwise
be re-litigated during execution.

1. **Monorepo, four binaries.** Separate repositories bought only separate deployment,
   and podman quadlets give that from one repository. One CI, one `openapi.yaml`, one
   `Containerfile` with a build argument.
2. **`authd` is a caching forward-auth service.** `internal/auth`'s doc comment already
   states that caching is mandatory rather than an optimization — at 2700 nodes,
   uncached validation is roughly one upstream call per bundle. Traefik's `forwardAuth`
   has no cache, so pointing it at `my.nethesis.it` directly would delete a load-bearing
   design element and collapse "validator unreachable" (503, with stale-cache fallback)
   into a plain 500. `authd` keeps both the cache and the graded failure, and one cache
   now serves all three pipelines instead of three.
3. **`system_id` still comes from the Basic username, parsed in-process.** The validator
   only ever answered yes/no; it never returned an identity. Traefik forwards the
   original `Authorization` header, so each pipeline keeps parsing it — minus the network
   call. The pipeline therefore trusts that somebody else validated that header, which is
   why every `/v1/*` request must arrive from a trusted proxy address.
4. **`X-Forwarded-For` is now trusted, from trusted proxy addresses only.** This reverses
   the previous rule. Behind Traefik, `RemoteAddr` is always the proxy, which made
   `threat.Sanitize`'s reporter-own-address check permanently dead. Traefik overwrites
   the header; the pipeline takes the rightmost value and only when `RemoteAddr` is
   inside `TRUSTED_PROXY_CIDRS`. Reaching a container directly buys nothing.
5. **Operator UIs are protected by Traefik BasicAuth using the `ADMIN_API_KEY` value**,
   with `removeHeader: false` and the htpasswd username as the audit actor. One browser
   prompt serves both the proxy gate and the app's write check. `ADMIN_API_KEY` and
   `sameOriginWrite` stay in the app: Traefik BasicAuth *is* Basic auth, so a browser
   replays it on a forged cross-site POST exactly as it would to the app, and anything on
   the host can reach the container directly.
6. **`internal/admin` is deleted.** The UI write routes cover every allowlist action and
   Traefik now fronts them. Five paths leave `openapi.yaml`; `ADMIN_LISTEN_ADDR`
   disappears; `ADMIN_API_KEY` survives as the UI write credential.
7. **Three fresh databases.** No data is carried across.
8. **Public paths are prefixed and de-stuttered.** The prefix carries the pipeline name,
   so the resource does not repeat it.
9. **Each UI's landing page is its most useful page, and the status page moves to
   `/status`.** With a base path, keeping the blocklist page at `/blocklist` under the
   `/blocklist` prefix would produce `/blocklist/blocklist`.
10. **`internal/ui` stops copying `internal/api`'s logging handler.** That duplication
    existed to keep `ui` from importing `api`; `internal/platform/httpx` removes the
    reason.

## URL map

Traefik serves one host and strips the prefix before proxying, so every handler
registers the unprefixed path.

**The host is a deploy-time input, never a committed constant.** It is set once as
`INSIGHTS_HOST` in `/etc/insights/deploy.env`, which is not in this repository:
`insights.gs.nethserver.net` on the dev machine, `insights.nethesis.it` in production.
The same artifacts deploy to both with nothing changed but that file. Nothing in the
application is host-dependent — the Go code never learns its own hostname, every link
`chrome` emits is path-relative, and the UI's cross-site check compares `Origin` against
`r.Host` as the request arrives — so `INSIGHTS_HOST` reaches Traefik only.

| Public path | Middleware | Backend | Registered route |
|---|---|---|---|
| `/logs/v1/bundles` | `forwardAuth` → authd | insightsd api | `/v1/bundles` |
| `/logs/v1/findings` | `forwardAuth` → authd | insightsd api | `/v1/findings` |
| `/blocklist/v1/events` | `forwardAuth` → authd | threatd api | `/v1/events` |
| `/blocklist/v1/feed` | `forwardAuth` → authd | threatd api | `/v1/feed` |
| `/blocklist/v1/allowlist-requests` | `forwardAuth` → authd | threatd api | `/v1/allowlist-requests` |
| `/sizing/v1/reports` | `forwardAuth` → authd | sizingd api | `/v1/reports` |
| `/logs/*` | BasicAuth | insightsd ui | `/*` |
| `/blocklist/*` | BasicAuth | threatd ui | `/*` |
| `/sizing/*` | BasicAuth | sizingd ui | `/*` |

`/healthz` is registered by every binary and routed by nobody — quadlet `HealthCmd=`
reaches it inside the container.

**Router priority is security-relevant.** `/logs/v1/` and `/logs/` share a prefix.
Traefik orders by rule length so the `/v1/` router wins, but set `priority` explicitly on
all six routers: getting it backwards puts operator BasicAuth on the ingest path, or the
fleet's system credentials on the operator UI.

### UI page paths, per binary

| insightsd (`/logs`) | threatd (`/blocklist`) | sizingd (`/sizing`) |
|---|---|---|
| `/` findings | `/` blocklist | `/` nodes |
| `/systems` | `/systems` | `/cohorts` |
| `/analyses` | `/events` | `/status` |
| `/gate` | `/stats` | |
| `/cost` | `/allowlist-requests` | |
| `/templates` | `/status` | |
| `/baselines` | | |
| `/status` | | |

Only threatd has write routes: `/blocklist/allowlist`, `/blocklist/allowlist/delete`,
`/allowlist-requests/approve`, `/allowlist-requests/reject`.

## Ports and environment

Each pipeline publishes to loopback; Traefik runs with host networking, so every
`RemoteAddr` a pipeline sees is `127.0.0.1`.

| Service | API | UI | Volume |
|---|---|---|---|
| authd | 127.0.0.1:9590 | — | — |
| insightsd | 127.0.0.1:9595 | 127.0.0.1:9596 | `insights-logs` |
| threatd | 127.0.0.1:9605 | 127.0.0.1:9606 | `insights-threat` |
| sizingd | 127.0.0.1:9615 | 127.0.0.1:9616 | `insights-sizing` |

**New variables**

- `INSIGHTS_HOST` — the served hostname, e.g. `insights.gs.nethserver.net` or
  `insights.nethesis.it`. **Read by no binary.** It lives in `/etc/insights/deploy.env` and is
  consumed only when rendering Traefik's dynamic configuration, which is what keeps the
  application host-agnostic.
- `TRUSTED_PROXY_CIDRS` — comma-separated, default `127.0.0.0/8`. All four binaries.
  **The default alone is wrong for a rootful-podman deployment**: a `PublishPort` DNAT is
  masqueraded on the reply path, so the container sees the bridge gateway rather than the
  loopback address. Pin the subnet in `insights.network` and name the gateway here
  (`127.0.0.0/8,10.89.0.1/32`). Verify against a real request before believing either value —
  see the runbook.
- `UI_BASE_PATH` — e.g. `/blocklist`, default empty. The three pipelines.
- `AUTH_LISTEN_ADDR` — default `:9590`. authd only.

**Moved to authd, removed from the pipelines**

`AUTH_VALIDATE_URL`, `AUTH_PEPPER`, `AUTH_CACHE_TTL`, `AUTH_NEG_CACHE_TTL`,
`AUTH_TIMEOUT`.

**Removed entirely**

`ADMIN_LISTEN_ADDR`.

**Partitioned by binary**

| insightsd | threatd | sizingd |
|---|---|---|
| `LLM_*`, `GATE_*`, `PROMPT_*`, `QUEUE_*`, `STALE_AFTER`, `ANALYSIS_TIMEOUT`, `PIPELINE_EXCLUDE_*`, `EWMA_ALPHA` | `BLOCKLIST_*`, `THREAT_*`, `ADMIN_API_KEY` | `SIZING_*` |

`LOG_LEVEL`, `LISTEN_ADDR`, `UI_LISTEN_ADDR`, `DB_PATH`, `TRUSTED_PROXY_CIDRS`,
`UI_BASE_PATH` are common to the three pipelines. Neither insightsd nor sizingd has a
write route, so neither reads `ADMIN_API_KEY`.

## Target file structure

```
cmd/
  authd/main.go            forward-auth cache service
  insightsd/main.go        logs pipeline
  threatd/main.go          threat shield
  sizingd/main.go          fleet sizing

internal/platform/
  auth/                    moved from internal/auth; ForwardAuth + cache + ParseBasic
  httpx/                   ClientIP, TrustedProxies, SystemID, Logging, Healthz
  sqlitex/                 Open (WAL/busy_timeout/MaxOpenConns) + a write mutex

internal/
  model/                   unchanged, imported by everything
  gate/ fingerprint/ prompt/ llm/ analyzer/ queue/ budget/    logs only
  threat/ blocklist/                                          threat only
  sizing/ baseline/                                           sizing only

  store/logs/    package logs     the 5 logs tables + the logs UI reads
  store/threat/  package threat   the 8 threat tables + the threat UI reads
  store/sizing/  package sizing   the 10 sizing tables + the sizing UI reads

  api/logs/      package logs     /v1/bundles, /v1/findings
  api/threat/    package threat   /v1/events, /v1/feed, /v1/allowlist-requests
  api/sizing/    package sizing   /v1/reports

  ui/chrome/     package chrome   layout.html, static/, view.go, Base, nav, write auth
  ui/logs/       package logs     8 pages
  ui/threat/     package threat   6 pages + 4 write routes
  ui/sizing/     package sizing   3 pages
```

### Package aliases

Grouping by pipeline means several packages share a short name — `cmd/threatd` imports
four packages called `threat`. Go handles this with an import alias, and the cost is
confined to the three `main.go` files plus each pipeline's `api` and `ui` packages. Use
exactly these aliases everywhere so a reader never has to work out which `threat` a call
belongs to:

```go
import (
	"github.com/nethesis/nethesis-insights/internal/blocklist"
	"github.com/nethesis/nethesis-insights/internal/threat"          // pure: Sanitize, CleanText

	threatapi "github.com/nethesis/nethesis-insights/internal/api/threat"
	threatstore "github.com/nethesis/nethesis-insights/internal/store/threat"
	threatui "github.com/nethesis/nethesis-insights/internal/ui/threat"
)
```

```go
import (
	"github.com/nethesis/nethesis-insights/internal/baseline"
	"github.com/nethesis/nethesis-insights/internal/sizing"          // pure: Sanitize, Pressure

	sizingapi "github.com/nethesis/nethesis-insights/internal/api/sizing"
	sizingstore "github.com/nethesis/nethesis-insights/internal/store/sizing"
	sizingui "github.com/nethesis/nethesis-insights/internal/ui/sizing"
)
```

```go
import (
	logsapi "github.com/nethesis/nethesis-insights/internal/api/logs"
	logsstore "github.com/nethesis/nethesis-insights/internal/store/logs"
	logsui "github.com/nethesis/nethesis-insights/internal/ui/logs"
)
```

**Deleted:** `internal/admin/`, `internal/auth/` (moved), `internal/api/api.go`'s
`Authenticator`/`StaticAuth`, `internal/store/store.go`'s combined `Store` interface,
`internal/ui/ui.go`'s three-pipeline server, `internal/store/ui.go`'s `Counts`
(replaced by a per-pipeline count struct).

---

### Task 1: `internal/platform/httpx`

The shared HTTP layer every binary needs: which address the client really has, which
`system_id` a request carries, the request logger, and `/healthz`. Nothing imports it
yet — this task exists on its own so its table tests can be written without dragging a
server along.

**Files:**
- Create: `internal/platform/httpx/clientip.go`
- Create: `internal/platform/httpx/clientip_test.go`
- Create: `internal/platform/httpx/identity.go`
- Create: `internal/platform/httpx/identity_test.go`
- Create: `internal/platform/httpx/logging.go`
- Create: `internal/platform/httpx/health.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type TrustedProxies []netip.Prefix`
  - `func ParseTrustedProxies(csv string) (TrustedProxies, error)`
  - `func (t TrustedProxies) Contains(remoteAddr string) bool`
  - `func ClientIP(r *http.Request, t TrustedProxies) string`
  - `func SystemID(r *http.Request, t TrustedProxies) (string, error)`
  - `var ErrUntrustedProxy, ErrNoCredential error`
  - `func Logging(next http.Handler) http.Handler`
  - `func Healthz(w http.ResponseWriter, r *http.Request)`

- [ ] **Step 1: Write the failing `ClientIP` test**

```go
// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// ClientIP is the input to threat.Sanitize's reporter-own-address check, so
// a wrong answer here is a wrong drop decision on a third party's address.
// The rule: X-Forwarded-For is consulted only when RemoteAddr is a proxy we
// configured, and then only its rightmost entry -- Traefik overwrites the
// header, but rightmost stays correct if it is ever configured to append.
func TestClientIP(t *testing.T) {
	trusted, err := ParseTrustedProxies("127.0.0.0/8,::1/128")
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}

	cases := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{"untrusted remote, no header", "203.0.113.7:4444", "", "203.0.113.7"},
		{"untrusted remote ignores a forged header", "203.0.113.7:4444", "10.0.0.1", "203.0.113.7"},
		{"trusted remote, single value", "127.0.0.1:5555", "198.51.100.9", "198.51.100.9"},
		{"trusted remote takes the rightmost value", "127.0.0.1:5555", "10.0.0.1, 198.51.100.9", "198.51.100.9"},
		{"trusted remote, no header", "127.0.0.1:5555", "", "127.0.0.1"},
		{"trusted remote, unparseable header", "127.0.0.1:5555", "not-an-address", "127.0.0.1"},
		{"trusted remote, empty header", "127.0.0.1:5555", "   ", "127.0.0.1"},
		{"trusted IPv6 loopback", "[::1]:5555", "198.51.100.9", "198.51.100.9"},
		{"remote addr without a port", "127.0.0.1", "198.51.100.9", "198.51.100.9"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/v1/events", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := ClientIP(r, trusted); got != tc.want {
				t.Errorf("ClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// An empty configuration must trust nobody rather than everybody: a missing
// TRUSTED_PROXY_CIDRS must not silently turn the header on.
func TestEmptyTrustedProxiesTrustsNoHeader(t *testing.T) {
	var none TrustedProxies
	r := httptest.NewRequest(http.MethodPost, "/v1/events", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("X-Forwarded-For", "198.51.100.9")
	if got := ClientIP(r, none); got != "127.0.0.1" {
		t.Errorf("ClientIP = %q, want the remote address", got)
	}
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `go test ./internal/platform/httpx/ -run TestClientIP -v`
Expected: build failure, `undefined: ParseTrustedProxies`.

- [ ] **Step 3: Implement `clientip.go`**

```go
// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package httpx holds the HTTP plumbing every binary in this repository
// shares: resolving the real client address behind the proxy, reading the
// system identity off a request the proxy has already authenticated, the
// request logger, and the health endpoint.
package httpx

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// TrustedProxies is the set of addresses whose X-Forwarded-For header this
// process believes. It is configuration (TRUSTED_PROXY_CIDRS), never a
// constant: the deployment's proxy address is not this package's business,
// and an empty set trusts nobody.
type TrustedProxies []netip.Prefix

// ParseTrustedProxies parses a comma-separated list of CIDR prefixes.
// A bare address is accepted and treated as a single-host prefix.
func ParseTrustedProxies(csv string) (TrustedProxies, error) {
	var out TrustedProxies
	for _, raw := range strings.Split(csv, ",") {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("httpx: %q is neither a CIDR prefix nor an address", s)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// Contains reports whether remoteAddr -- an "ip:port" or a bare ip -- falls
// inside the trusted set.
func (t TrustedProxies) Contains(remoteAddr string) bool {
	a, ok := parseHost(remoteAddr)
	if !ok {
		return false
	}
	for _, p := range t {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ClientIP returns the address the request really came from.
//
// X-Forwarded-For is consulted only when RemoteAddr is a trusted proxy,
// because the header is otherwise client-controlled and this value feeds
// threat.Sanitize's reporter-own-address check. The rightmost entry is the
// one the trusted proxy itself observed: Traefik is configured to overwrite
// the header, so there is normally exactly one, but rightmost stays correct
// if it is ever configured to append instead.
//
// Anything unparseable falls back to RemoteAddr rather than to an error --
// the caller has no useful recovery, and RemoteAddr is always a real
// observation even when it is only the proxy's.
func ClientIP(r *http.Request, t TrustedProxies) string {
	remote := hostOnly(r.RemoteAddr)
	if !t.Contains(r.RemoteAddr) {
		return remote
	}
	xff := r.Header.Get("X-Forwarded-For")
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		s := strings.TrimSpace(parts[i])
		if s == "" {
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			return a.String()
		}
		return remote
	}
	return remote
}

func parseHost(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(hostOnly(s))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

func hostOnly(s string) string {
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return strings.Trim(s, "[]")
}
```

- [ ] **Step 4: Run the tests and watch them pass**

Run: `go test ./internal/platform/httpx/ -run 'TestClientIP|TestEmptyTrusted' -v`
Expected: PASS.

- [ ] **Step 5: Write the failing `SystemID` test**

```go
// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package httpx

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The proxy has already validated the credential; this only reads the
// identity out of it. That makes the trusted-proxy check the whole security
// boundary -- reaching the container directly must not let a caller name any
// system_id it likes.
func TestSystemID(t *testing.T) {
	trusted, err := ParseTrustedProxies("127.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}

	cases := []struct {
		name       string
		remoteAddr string
		user, pass string
		setAuth    bool
		want       string
		wantErr    error
	}{
		{name: "trusted proxy, valid basic", remoteAddr: "127.0.0.1:1", user: "sys-1", pass: "t", setAuth: true, want: "sys-1"},
		{name: "direct connection is refused", remoteAddr: "203.0.113.7:1", user: "sys-1", pass: "t", setAuth: true, wantErr: ErrUntrustedProxy},
		{name: "no credential", remoteAddr: "127.0.0.1:1", setAuth: false, wantErr: ErrNoCredential},
		{name: "empty username", remoteAddr: "127.0.0.1:1", user: "", pass: "t", setAuth: true, wantErr: ErrNoCredential},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/v1/bundles", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.setAuth {
				r.SetBasicAuth(tc.user, tc.pass)
			}
			got, err := SystemID(r, trusted)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("SystemID = %q, want %q", got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 6: Run it and watch it fail**

Run: `go test ./internal/platform/httpx/ -run TestSystemID -v`
Expected: build failure, `undefined: SystemID`.

- [ ] **Step 7: Implement `identity.go`**

```go
// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package httpx

import (
	"errors"
	"net/http"
)

// ErrUntrustedProxy is returned when a request that must have come through
// the proxy did not. The credential on such a request has not been validated
// by anybody, so its username is not an identity.
var ErrUntrustedProxy = errors.New("httpx: request did not arrive from a trusted proxy")

// ErrNoCredential is returned when the request carries no usable HTTP Basic
// credential to read a system_id from.
var ErrNoCredential = errors.New("httpx: no credential")

// SystemID reads the system identity off a request the proxy has already
// authenticated via its forwardAuth middleware.
//
// The credential is NOT verified here -- authd did that, and this process
// holds no secret to verify it against. What makes the username trustworthy
// is that the request reached us from the proxy: the trusted-proxy check is
// the security boundary, not a formality. The proxy forwards the original
// Authorization header untouched, which is why the identity is still
// available without the proxy having to inject a header of its own.
func SystemID(r *http.Request, t TrustedProxies) (string, error) {
	if !t.Contains(r.RemoteAddr) {
		return "", ErrUntrustedProxy
	}
	user, _, ok := r.BasicAuth()
	if !ok || user == "" {
		return "", ErrNoCredential
	}
	return user, nil
}
```

- [ ] **Step 8: Run the tests and watch them pass**

Run: `go test ./internal/platform/httpx/ -v`
Expected: PASS.

- [ ] **Step 9: Move the request logger and health handler in**

Copy `internal/api/api.go`'s `loggingHandler`/`statusRecorder` into
`internal/platform/httpx/logging.go` as `Logging(next http.Handler) http.Handler`, and
`handleHealthz` into `internal/platform/httpx/health.go` as
`Healthz(w http.ResponseWriter, r *http.Request)`. Keep the existing behaviour exactly:
it logs method, path, status, duration, `remote_addr` and `forwarded_for`, and never
touches `Authorization`. Leave the originals in place for now — nothing imports the new
package yet, and later tasks delete them.

- [ ] **Step 10: Verify and commit**

```bash
go build ./... && go vet ./... && go test ./internal/platform/httpx/ -race -count=1
git add internal/platform/httpx
git commit -m "feat(platform): add httpx with trusted-proxy client IP and identity"
```

---

### Task 2: `internal/platform/auth` and `internal/platform/sqlitex`

Move the auth package where the new binaries can reach it, and pull the SQLite open
idiom out of `store.go` so three stores do not each re-derive it.

**Files:**
- Move: `internal/auth/` → `internal/platform/auth/`
- Modify: `internal/platform/auth/auth.go` (export `ParseBasic`)
- Create: `internal/platform/sqlitex/sqlitex.go`
- Create: `internal/platform/sqlitex/sqlitex_test.go`
- Modify: `cmd/insightsd/main.go` (import path)

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces:
  - `func auth.ParseBasic(header string) (systemID, secret string, err error)`
  - `func sqlitex.Open(path string) (*sqlitex.DB, error)`
  - `type sqlitex.DB struct{ *bun.DB }` with `func (d *DB) Lock()` / `Unlock()` and
    `func (d *DB) Close() error`

- [ ] **Step 1: Move the package**

```bash
mkdir -p internal/platform
git mv internal/auth internal/platform/auth
grep -rl 'nethesis-insights/internal/auth"' --include='*.go' . \
  | xargs sed -i 's#nethesis-insights/internal/auth"#nethesis-insights/internal/platform/auth"#'
go build ./... && go test ./internal/platform/auth/ -count=1
```

- [ ] **Step 2: Export `parseBasic`**

`internal/platform/auth/auth.go` has an unexported `parseBasic`. Rename it to `ParseBasic`
and update its callers inside the package. `cmd/authd` needs it in Task 3 for logging the
`system_id` of a rejected credential, and nothing else does — the pipelines use
`httpx.SystemID`.

- [ ] **Step 3: Run the auth tests**

Run: `go test ./internal/platform/auth/ -race -count=1`
Expected: PASS.

- [ ] **Step 4: Write the failing `sqlitex` test**

```go
// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package sqlitex

import (
	"context"
	"path/filepath"
	"testing"
)

// The three pragmas are the whole reason this package exists: WAL so a
// reader never blocks the writer, busy_timeout so a contended write waits
// instead of failing, and MaxOpenConns(1) so "single writer" is structural
// rather than a convention each store has to remember.
func TestOpenAppliesTheRequiredPragmas(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()

	var mode string
	if err := db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatalf("journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want wal", mode)
	}

	var timeout int
	if err := db.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&timeout); err != nil {
		t.Fatalf("busy_timeout: %v", err)
	}
	if timeout != 5000 {
		t.Errorf("busy_timeout = %d, want 5000", timeout)
	}

	if got := db.DB.DB.Stats().MaxOpenConnections; got != 1 {
		t.Errorf("MaxOpenConnections = %d, want 1", got)
	}
}
```

- [ ] **Step 5: Run it and watch it fail**

Run: `go test ./internal/platform/sqlitex/ -v`
Expected: build failure, `undefined: Open`.

- [ ] **Step 6: Implement `sqlitex.go`**

Lift `Open` from `internal/store/store.go:158-168` verbatim, wrap the returned `*bun.DB`
in a `DB` that also carries the write mutex the stores currently declare themselves:

```go
// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package sqlitex opens a SQLite database with the runtime settings this
// project requires everywhere: WAL, a busy timeout, a single connection, and
// a mutex that serializes writes. The spec asks for a single writer
// goroutine; a mutex gives the same guarantee with no lifecycle to leak.
package sqlitex

import (
	"database/sql"
	"fmt"
	"sync"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	_ "modernc.org/sqlite"
)

// DB is a *bun.DB plus the write mutex. Every store in this repository
// embeds one; Lock/Unlock is what makes "single writer" true across three
// processes that each own their own file.
type DB struct {
	*bun.DB
	mu sync.Mutex
}

func (d *DB) Lock()   { d.mu.Lock() }
func (d *DB) Unlock() { d.mu.Unlock() }

func (d *DB) Close() error { return d.DB.DB.Close() }

func Open(path string) (*DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", path)
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlitex: open: %w", err)
	}
	sqldb.SetMaxOpenConns(1)
	return &DB{DB: bun.NewDB(sqldb, sqlitedialect.New())}, nil
}
```

- [ ] **Step 7: Run the test and watch it pass**

Run: `go test ./internal/platform/sqlitex/ -race -count=1 -v`
Expected: PASS.

- [ ] **Step 8: Verify and commit**

```bash
go build ./... && go vet ./... && go test ./... -race -count=1
git add internal/platform cmd/insightsd/main.go
git commit -m "refactor(platform): move auth under platform and extract sqlitex"
```

---

### Task 3: `cmd/authd`

The forward-auth cache Traefik calls. It is a thin HTTP shell over the package that
already does the work, and it is what keeps the fleet from hammering
`my.nethesis.it/auth` once per request.

**Files:**
- Create: `cmd/authd/main.go`
- Create: `cmd/authd/handler.go`
- Create: `cmd/authd/handler_test.go`

**Interfaces:**
- Consumes: `auth.New`, `(*auth.ForwardAuth).Validate`, `auth.ErrInvalidCredentials`,
  `auth.ErrUnavailable`, `httpx.Logging`, `httpx.Healthz`.
- Produces: a binary listening on `AUTH_LISTEN_ADDR` with `GET /auth` and `GET /healthz`.

- [ ] **Step 1: Write the failing handler test**

```go
// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/platform/auth"
)

type fakeValidator struct {
	systemID string
	err      error
	calls    int
}

func (f *fakeValidator) Validate(ctx context.Context, authHeader string) (string, error) {
	f.calls++
	return f.systemID, f.err
}

// Traefik forwards the auth server's status when it is not 2xx, so these
// three statuses are the whole contract. 503 must stay distinct from 401:
// an ingestion gap the edge retries is recoverable, a false reject is not.
func TestAuthEndpointStatuses(t *testing.T) {
	cases := []struct {
		name string
		v    *fakeValidator
		want int
	}{
		{"valid", &fakeValidator{systemID: "sys-1"}, http.StatusOK},
		{"invalid", &fakeValidator{err: auth.ErrInvalidCredentials}, http.StatusUnauthorized},
		{"validator unavailable", &fakeValidator{err: auth.ErrUnavailable}, http.StatusServiceUnavailable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHandler(tc.v)
			r := httptest.NewRequest(http.MethodGet, "/auth", nil)
			r.SetBasicAuth("sys-1", "secret")
			w := httptest.NewRecorder()

			h.ServeHTTP(w, r)

			if w.Code != tc.want {
				t.Errorf("status = %d, want %d", w.Code, tc.want)
			}
			if tc.v.calls != 1 {
				t.Errorf("validator calls = %d, want 1", tc.v.calls)
			}
		})
	}
}

// A request with no Authorization header must be rejected without calling
// the validator: there is nothing to validate, and forwarding an empty
// header upstream would spend a request to learn that.
func TestAuthEndpointRejectsAMissingHeaderWithoutCallingTheValidator(t *testing.T) {
	v := &fakeValidator{systemID: "sys-1"}
	h := newHandler(v)
	r := httptest.NewRequest(http.MethodGet, "/auth", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if v.calls != 0 {
		t.Errorf("validator calls = %d, want 0", v.calls)
	}
}

// The response body must never echo the credential, and the header must
// never be reflected back into a response Traefik will log.
func TestAuthEndpointNeverEchoesTheCredential(t *testing.T) {
	h := newHandler(&fakeValidator{err: auth.ErrInvalidCredentials})
	r := httptest.NewRequest(http.MethodGet, "/auth", nil)
	r.SetBasicAuth("sys-1", "hunter2")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if body := w.Body.String(); contains(body, "hunter2") {
		t.Errorf("response body leaked the secret: %q", body)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		(haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `go test ./cmd/authd/ -v`
Expected: build failure, `undefined: newHandler`.

- [ ] **Step 3: Implement `handler.go`**

```go
// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/nethesis/nethesis-insights/internal/platform/auth"
	"github.com/nethesis/nethesis-insights/internal/platform/httpx"
)

// validator is the half of auth.ForwardAuth this binary uses, declared here
// so the handler tests need no network and no cache.
type validator interface {
	Validate(ctx context.Context, authHeader string) (string, error)
}

// newHandler builds authd's mux.
//
// GET /auth is Traefik's forwardAuth address. Traefik forwards the client's
// original request headers here, expects 2xx to mean "let it through", and
// passes any other status straight back to the client -- which is what keeps
// this service's 401/503 distinction visible at the edge.
func newHandler(v validator) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", httpx.Healthz)
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if header == "" {
			unauthorized(w)
			return
		}

		systemID, err := v.Validate(r.Context(), header)
		switch {
		case err == nil:
			w.WriteHeader(http.StatusOK)
		case errors.Is(err, auth.ErrInvalidCredentials):
			slog.Info("authd: rejected", "system_id", systemID, "remote_addr", r.RemoteAddr)
			unauthorized(w)
		case errors.Is(err, auth.ErrUnavailable):
			// Fail closed, but distinctly: the edge retries a 503 and gives
			// up on a 401.
			slog.Warn("authd: validator unavailable", "remote_addr", r.RemoteAddr)
			http.Error(w, "validator unavailable", http.StatusServiceUnavailable)
		default:
			slog.Error("authd: unexpected validate error", "err", err)
			http.Error(w, "validator unavailable", http.StatusServiceUnavailable)
		}
	})
	return httpx.Logging(mux)
}

// unauthorized answers without a WWW-Authenticate challenge: the client is a
// reporter with a configured credential, not a browser to prompt, and the
// challenge would only add a round trip.
func unauthorized(w http.ResponseWriter) {
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
```

- [ ] **Step 4: Run the tests and watch them pass**

Run: `go test ./cmd/authd/ -race -count=1 -v`
Expected: PASS.

- [ ] **Step 5: Write `main.go`**

```go
// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Command authd validates edge credentials on behalf of the proxy.
//
// Traefik has no cache of its own, and internal/platform/auth's doc comment
// explains why one is mandatory rather than an optimization: at fleet scale
// an uncached forwardAuth is one upstream call per bundle for credentials
// that essentially never change. Running the cache as its own service also
// means one cache serves all three pipelines instead of three.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nethesis/nethesis-insights/internal/platform/auth"
)

const defaultAuthValidateURL = "https://my.nethesis.it/auth"

func main() {
	setupLogging(getenv("LOG_LEVEL", "info"))

	listenAddr := getenv("AUTH_LISTEN_ADDR", ":9590")
	validateURL := getenv("AUTH_VALIDATE_URL", defaultAuthValidateURL)
	pepper := getenv("AUTH_PEPPER", "")
	timeout := getenvDuration("AUTH_TIMEOUT", 5*time.Second)

	fa := auth.New(validateURL, pepper, timeout, time.Now)
	fa.PositiveTTL = getenvDuration("AUTH_CACHE_TTL", 5*time.Minute)
	fa.NegativeTTL = getenvDuration("AUTH_NEG_CACHE_TTL", 30*time.Second)

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           newHandler(fa),
		ReadHeaderTimeout: 10 * time.Second,
	}

	slog.Info("authd: listening",
		"addr", listenAddr,
		"validate_url", validateURL,
		"pepper", setOrUnset(pepper),
		"positive_ttl", fa.PositiveTTL,
		"negative_ttl", fa.NegativeTTL)

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("authd: listen", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("authd: shutdown", "err", err)
	}
}
```

Copy `getenv`, `getenvDuration`, `setupLogging` and a `setOrUnset` helper from
`cmd/insightsd/main.go:43-115`. `AUTH_PEPPER` is logged as `set`/`unset`, never as
itself.

- [ ] **Step 6: Verify and commit**

```bash
go build ./... && go vet ./... && go test ./cmd/authd/ -race -count=1
git add cmd/authd
git commit -m "feat(authd): add the caching forward-auth service"
```

---

### Task 4: `internal/ui/chrome`

Everything three dashboards share: the layout, the stylesheet, the formatters, the
GET-only route discipline, the write authentication, and base-path-aware link building.
The existing `internal/ui` is rewired onto it in this same task, so the tree stays green
and the three later UI packages have a working example to copy.

**Files:**
- Create: `internal/ui/chrome/chrome.go`
- Create: `internal/ui/chrome/link_test.go`
- Move: `internal/ui/view.go` → `internal/ui/chrome/view.go`
- Move: `internal/ui/templates/layout.html` → `internal/ui/chrome/templates/layout.html`
- Move: `internal/ui/static/` → `internal/ui/chrome/static/`
- Modify: `internal/ui/ui.go`, `internal/ui/templates/*.html`
- Modify: `internal/ui/*_test.go`

**Interfaces:**
- Consumes: `httpx.Logging`.
- Produces:
  - `type Config struct { BasePath, AdminKey string; Info Info; Nav []NavGroup; Pages []string; Templates fs.FS; Funcs template.FuncMap }`
  - `type Base struct { … }`, `func New(cfg Config) (*Base, error)`
  - `func (b *Base) Link(path string) string`
  - `func (b *Base) PageData(r *http.Request, active string) PageData`
  - `func (b *Base) Render(w http.ResponseWriter, page string, data any)`
  - `func (b *Base) StoreError(w http.ResponseWriter, page string, err error)`
  - `func (b *Base) ServeStatic(w http.ResponseWriter, r *http.Request) bool`
  - `func (b *Base) AuthenticateWrite(w http.ResponseWriter, r *http.Request) (string, bool)`
  - `func (b *Base) CanWrite() bool`
  - `type NavGroup struct { Label string; Pages []NavPage }`,
    `type NavPage struct { Key, Path, Label string }`
  - `type Info struct { StartedAt int64; Build string; Config []ConfigItem }`
  - `func ClampLimit(v string, def, max int) int`, `func ParseRefresh(r *http.Request) int`
  - all the `Fmt*` helpers from today's `view.go`, unchanged

- [ ] **Step 1: Write the failing base-path test**

```go
// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package chrome

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Traefik strips the prefix before proxying, so route() never sees it and
// every emitted URL has to put it back. Every link on every page goes
// through Link, which is why it is the only place that knows the base
// exists.
func TestLink(t *testing.T) {
	cases := []struct{ base, path, want string }{
		{"", "/", "/"},
		{"", "/systems", "/systems"},
		{"/blocklist", "/", "/blocklist/"},
		{"/blocklist", "/events", "/blocklist/events"},
		{"/blocklist", "/static/style.css", "/blocklist/static/style.css"},
		{"/blocklist/", "/events", "/blocklist/events"},
		{"blocklist", "/events", "/blocklist/events"},
	}
	for _, tc := range cases {
		b := &Base{basePath: normalizeBase(tc.base)}
		if got := b.Link(tc.path); got != tc.want {
			t.Errorf("Link(%q) with base %q = %q, want %q", tc.path, tc.base, got, tc.want)
		}
	}
}

// The refresh links rebuild the current URL with one query parameter
// changed. r.URL.Path is post-strip, so the base has to be re-applied or
// every refresh link escapes the pipeline's subtree.
func TestRefreshLinksCarryTheBasePath(t *testing.T) {
	b := &Base{basePath: "/blocklist"}
	r := httptest.NewRequest(http.MethodGet, "/events?system=sys-1&refresh=10", nil)

	off, r10, r30 := b.refreshLinks(r)

	if off != "/blocklist/events?system=sys-1" {
		t.Errorf("off = %q", off)
	}
	if r10 != "/blocklist/events?refresh=10&system=sys-1" {
		t.Errorf("r10 = %q", r10)
	}
	if r30 != "/blocklist/events?refresh=30&system=sys-1" {
		t.Errorf("r30 = %q", r30)
	}
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `go test ./internal/ui/chrome/ -v`
Expected: build failure, `undefined: Base`.

- [ ] **Step 3: Move the shared assets**

```bash
mkdir -p internal/ui/chrome/templates
git mv internal/ui/view.go internal/ui/chrome/view.go
git mv internal/ui/templates/layout.html internal/ui/chrome/templates/layout.html
git mv internal/ui/static internal/ui/chrome/static
sed -i 's/^package ui$/package chrome/' internal/ui/chrome/view.go
```

`internal/ui/chrome/static/pico.min.css` and `pico.LICENSE` keep their upstream notices
untouched. `style.css` keeps its `/* … */` Nethesis header.

- [ ] **Step 4: Implement `chrome.go`**

Move these from `internal/ui/ui.go` into `chrome.go`, renaming to the exported names in
the Interfaces block above: `parseTemplates`, `render`, `storeError`, `newPageData`,
`parseRefresh`, `refreshLinks`, `cloneValues`, `clampLimit`, `sameOriginWrite`,
`authenticateWrite`, `canWrite`, the static branch of `route`, `navGroup`/`navPage`/
`navItem`/`navGroupData`/`pageData`, `ConfigItem`, `Info`, `statusRecorder`. Two changes
beyond the move:

```go
// normalizeBase turns "", "blocklist", "/blocklist" and "/blocklist/" into
// "" or "/blocklist" -- exactly one leading slash, no trailing one -- so
// Link can concatenate without thinking about it.
func normalizeBase(s string) string {
	s = strings.Trim(s, "/")
	if s == "" {
		return ""
	}
	return "/" + s
}

// Link returns an absolute URL for an internal path, with the deployment's
// base path prepended. Traefik strips the prefix before proxying, so the
// handlers route on unprefixed paths and every URL the page emits -- nav
// entries, form actions, redirects, the stylesheet, the refresh links --
// must be built here.
func (b *Base) Link(path string) string {
	if b.basePath == "" {
		return path
	}
	if path == "/" {
		return b.basePath + "/"
	}
	return b.basePath + path
}
```

`refreshLinks` becomes a method and prefixes `r.URL.Path` through `Link`. `PageData`
gains a `Base string` field, set to `b.basePath`, and builds every nav item's `Path`
through `Link`.

- [ ] **Step 5: Point `layout.html` at the base path**

```html
<link rel="stylesheet" href="{{.Base}}/static/pico.min.css">
<link rel="stylesheet" href="{{.Base}}/static/style.css">
```

The GPL header stays outside any `{{define}}` block so it is emitted into the served
page source.

- [ ] **Step 6: Run the chrome tests and watch them pass**

Run: `go test ./internal/ui/chrome/ -race -count=1 -v`
Expected: PASS.

- [ ] **Step 7: Rewire the existing `internal/ui` onto chrome**

`internal/ui/ui.go`'s `server` embeds `*chrome.Base`; delete the moved functions; replace
the four `http.Redirect` targets at `ui.go:1114,1143,1184,1217` with
`s.Link("/blocklist")` and `s.Link("/allowlist-requests")`; replace the four template form
actions with `{{$.Base}}/blocklist/allowlist` and friends; delete `internal/ui`'s copy of
the logging handler in favour of `httpx.Logging`.

- [ ] **Step 8: Run the whole suite**

Run: `go build ./... && go vet ./... && go test ./... -race -count=1`
Expected: PASS. `internal/ui`'s existing tests are the regression net for the move.

- [ ] **Step 9: Commit**

```bash
git add internal/ui cmd/insightsd
git commit -m "refactor(ui): extract chrome with base-path-aware links"
```

---

### Task 5: `threatd`

The first pipeline out of the monolith. It moves its store, its API, its UI and its
wiring into their own packages and its tables into their own file, and it deletes
`internal/admin` on the way past.

**Files:**
- Create: `internal/store/threat/{store.go,ui.go,allowlist.go,store_test.go,ui_test.go,allowlist_test.go}`
  (from `internal/store/{threat.go,threat_ui.go,allowlist.go}` and their tests)
- Create: `internal/api/threat/{api.go,threat.go,allowlist.go,*_test.go}`
  (from `internal/api/{threat.go,allowlist.go}` and their tests)
- Create: `internal/ui/threat/{ui.go,templates/*.html,*_test.go}`
- Create: `cmd/threatd/main.go`
- Delete: `internal/admin/`
- Modify: `internal/store/store.go` (drop the threat tables and methods),
  `internal/api/api.go` (drop `ThreatConfig` and the three routes),
  `internal/ui/ui.go` (drop the five threat pages and the four write routes),
  `cmd/insightsd/main.go` (drop the threat wiring)

**Interfaces:**
- Consumes: `httpx.SystemID`, `httpx.ClientIP`, `httpx.Logging`, `httpx.Healthz`,
  `sqlitex.Open`, `chrome.New`, `chrome.Base`.
- Produces:
  - `func threatstore.Open(path string) (*threatstore.Store, error)` and
    `func (*Store) Init(ctx context.Context) error`
  - `type threatstore.Store` with every method today's `store.Store` declares under the
    "Threat Shield" and "Allowlist management" comments, plus
    `func (s *Store) Counts(ctx context.Context) (Counts, error)` returning
    `{Events, BlocklistEntries, AllowlistEntries, PendingRequests int}`
  - `func threatapi.NewServer(st Store, snap *blocklist.Snapshot, trusted httpx.TrustedProxies, cfg Config) http.Handler`
  - `func threatui.NewServer(r Reader, feed Feed, w Writer, cfg chrome.Config) (http.Handler, error)`

- [ ] **Step 1: Move the store**

```bash
mkdir -p internal/store/threat
git mv internal/store/threat.go        internal/store/threat/store.go
git mv internal/store/threat_test.go   internal/store/threat/store_test.go
git mv internal/store/threat_ui.go     internal/store/threat/ui.go
git mv internal/store/allowlist.go     internal/store/threat/allowlist.go
git mv internal/store/allowlist_test.go internal/store/threat/allowlist_test.go
sed -i 's/^package store$/package threat/' internal/store/threat/*.go
```

Then, in `internal/store/threat/store.go`:
- add `Open`/`Init`, with `Init` carrying only the eight `CREATE TABLE IF NOT EXISTS`
  statements between the `--- Threat Shield ---` marker and the sizing marker in
  `internal/store/store.go`, plus their indexes;
- change the receiver from `*store.SQLiteStore` to `*Store`, where
  `type Store struct { db *sqlitex.DB }`;
- move the row types the moved methods use (`BlocklistRow`, `AllowlistRow`,
  `ThreatCandidateRow`, `ThreatEventRow`, `ThreatDailyRow`, `ThreatIngestRow`,
  `ThreatSystemRow`, `AllowlistRequestRow`, `AllowlistAuditRow`) out of
  `internal/store/store.go`;
- add `Counts`, counting `threat_events`, `threat_blocklist`, `threat_allowlist` and
  pending `threat_allowlist_requests`.

- [ ] **Step 2: Run the moved store tests**

Run: `go test ./internal/store/threat/ -race -count=1`
Expected: PASS. These are temp-file SQLite tests, not mocks — the grouping *is* the SQL,
so they are the proof the DDL came across intact.

- [ ] **Step 3: Delete the threat half of the monolith store**

Remove the threat and allowlist method declarations from `store.Store`, their
implementations, their row types, and the eight `CREATE TABLE` statements from
`store.Init`. `go build ./...` will fail until Step 6 — that is expected.

- [ ] **Step 4: Move the API**

```bash
mkdir -p internal/api/threat
git mv internal/api/threat.go        internal/api/threat/threat.go
git mv internal/api/threat_test.go   internal/api/threat/threat_test.go
git mv internal/api/allowlist.go     internal/api/threat/allowlist.go
git mv internal/api/allowlist_test.go internal/api/threat/allowlist_test.go
sed -i 's/^package api$/package threat/' internal/api/threat/*.go
```

New `internal/api/threat/api.go` holds the server struct and the mux:

```go
// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package threat serves Threat Shield's client API: CrowdSec ban decisions
// in, the fleet-consensus blocklist out, and the allowlist review queue.
//
// Authentication happens at the proxy: Traefik's forwardAuth middleware
// calls authd, and only a request it approved reaches this process. The
// Authorization header still arrives untouched, so the system identity is
// read from it here -- see httpx.SystemID, whose trusted-proxy check is what
// makes that safe.
package threat

import (
	"net/http"

	"github.com/nethesis/nethesis-insights/internal/blocklist"
	"github.com/nethesis/nethesis-insights/internal/platform/httpx"
)

type server struct {
	store   Store
	snap    *blocklist.Snapshot
	trusted httpx.TrustedProxies
	cfg     Config
}

// Config carries the ingest bounds. MaxDecisions truncates rather than
// rejects: a batch over the cap loses its tail, never the whole report.
type Config struct {
	MaxDecisions int
}

func NewServer(st Store, snap *blocklist.Snapshot, trusted httpx.TrustedProxies, cfg Config) http.Handler {
	srv := &server{store: st, snap: snap, trusted: trusted, cfg: cfg}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", httpx.Healthz)
	mux.HandleFunc("/v1/events", srv.handleEvents)
	mux.HandleFunc("/v1/feed", srv.handleFeed)
	mux.HandleFunc("/v1/allowlist-requests", srv.handleAllowlistRequest)
	return httpx.Logging(mux)
}
```

Rename `handleThreatEvents` → `handleEvents` and `handleBlocklist` → `handleFeed` to
match. Replace every `s.authenticate(w, r)` call with:

```go
systemID, err := httpx.SystemID(r, s.trusted)
if err != nil {
	writeError(w, http.StatusUnauthorized, "unauthorized")
	return
}
```

and replace the `RemoteAddr` read at today's `internal/api/threat.go:216` with
`httpx.ClientIP(r, s.trusted)`. Delete the comment block above it that says
`X-Forwarded-For` is deliberately not consulted, and replace it with the reason it now
is — decision 4 above.

- [ ] **Step 5: Fix the moved API tests**

`httptest.NewRequest` sets `RemoteAddr` to `192.0.2.1:1234`, which is not a trusted proxy,
so every moved test now gets a 401. Add to each request:

```go
r.RemoteAddr = "127.0.0.1:12345"
```

and build the server with `httpx.ParseTrustedProxies("127.0.0.0/8")`. Delete the
`api.StaticAuth` usages — there is no `Authenticator` any more. Add one new test that is
the executable form of decision 3:

```go
// The credential is not verified in this process, so the trusted-proxy check
// is the entire boundary: a direct connection must not be able to name a
// system_id.
func TestIngestRefusesARequestThatDidNotComeThroughTheProxy(t *testing.T) {
	st := newTestStore(t)
	trusted, _ := httpx.ParseTrustedProxies("127.0.0.0/8")
	h := NewServer(st, nil, trusted, Config{MaxDecisions: threat.DefaultMaxDecisions})

	r := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(`{"decisions":[]}`))
	r.RemoteAddr = "203.0.113.7:4444"
	r.SetBasicAuth("someone-elses-system", "whatever")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if n := st.insertedEvents; n != 0 {
		t.Fatalf("a direct request stored %d events", n)
	}
}
```

Run: `go test ./internal/api/threat/ -race -count=1`
Expected: PASS.

- [ ] **Step 6: Delete `internal/admin` and the threat half of `internal/api`**

```bash
git rm -r internal/admin
```

Remove `ThreatConfig`, the three `mux.HandleFunc` lines and `enabled()` from
`internal/api/api.go`. Remove the `admin` wiring, `ADMIN_LISTEN_ADDR` and the admin server
goroutine from `cmd/insightsd/main.go`.

- [ ] **Step 7: Move the UI**

```bash
mkdir -p internal/ui/threat/templates
git mv internal/ui/templates/blocklist.html          internal/ui/threat/templates/index.html
git mv internal/ui/templates/threat-systems.html     internal/ui/threat/templates/systems.html
git mv internal/ui/templates/threat-events.html      internal/ui/threat/templates/events.html
git mv internal/ui/templates/threat-stats.html       internal/ui/threat/templates/stats.html
git mv internal/ui/templates/allowlist-requests.html internal/ui/threat/templates/allowlist-requests.html
git mv internal/ui/threat_ui_test.go                 internal/ui/threat/ui_test.go
git mv internal/ui/write_test.go                     internal/ui/threat/write_test.go
```

New `internal/ui/threat/ui.go` builds a `chrome.Base` with this nav and these routes:

```go
var nav = []chrome.NavGroup{
	{Pages: []chrome.NavPage{
		{Key: "index", Path: "/", Label: "Blocklist"},
		{Key: "systems", Path: "/systems", Label: "Systems"},
		{Key: "events", Path: "/events", Label: "Events"},
		{Key: "stats", Path: "/stats", Label: "Stats"},
		{Key: "allowlist-requests", Path: "/allowlist-requests", Label: "Allowlist requests"},
		{Key: "status", Path: "/status", Label: "Status"},
	}},
}

// writableRoutes is the small, explicit, enumerated set of paths that also
// answer POST. Every one authenticates against ADMIN_API_KEY and refuses a
// cross-site request first: Traefik's BasicAuth in front of this subtree is
// still Basic auth, so a browser replays it on a forged cross-site POST
// exactly as it would here. The proxy is defence in depth, never the gate.
var writableRoutes = map[string]bool{
	"/blocklist/allowlist":        true,
	"/blocklist/allowlist/delete": true,
	"/allowlist-requests/approve": true,
	"/allowlist-requests/reject":  true,
}
```

A single nav group with no label renders as a flat row, which is right for six pages;
`navGroups`' dropdown machinery stays in chrome for nobody, and is deleted in Task 7 if
no UI ends up with more than one group.

Add a `status.html` for this pipeline: the counts from `threatstore.Counts`, the
blocklist feed state (`Ready`, `Entries`, `GeneratedAt`, `ETag`), the build string, the
uptime and the effective configuration. Copy the feed and config sections out of the
current `internal/ui/templates/status.html`; drop its queue section, which threatd has
no equivalent of.

- [ ] **Step 8: Run the moved UI tests**

Run: `go test ./internal/ui/threat/ -race -count=1`
Expected: PASS, after the page paths in the tests are updated to the new set (`/` for the
blocklist, `/events`, `/stats`, `/systems`).

- [ ] **Step 9: Write `cmd/threatd/main.go`**

Copy the shape of `cmd/insightsd/main.go`: env parsing, `sqlitex.Open`, `Init`,
`blocklist.New` + `blocklist.Snapshot`, the consensus ticker, the housekeeping order
(`RollupThreatDailyStats` **before** `PruneThreatEvents`), the API listener, the UI
listener when `UI_LISTEN_ADDR` is set, and graceful shutdown. Env: `LOG_LEVEL`,
`LISTEN_ADDR` (default `:9595`), `UI_LISTEN_ADDR`, `UI_BASE_PATH`, `DB_PATH` (default
`/var/lib/threat/threat.db`), `TRUSTED_PROXY_CIDRS`, `ADMIN_API_KEY`, `BLOCKLIST_*`,
`THREAT_*`.

A wider-than-loopback `UI_LISTEN_ADDR` warns and does not refuse, as today.

- [ ] **Step 10: Verify and commit**

```bash
go build ./... && go vet ./... && go test ./... -race -count=1
git add internal/store/threat internal/api/threat internal/ui/threat cmd/threatd \
        internal/store/store.go internal/api/api.go internal/ui cmd/insightsd
git rm -r --cached internal/admin
git commit -m "feat(threatd): split Threat Shield into its own service"
```

---

### Task 6: `sizingd`

The same shape as Task 5. Fleet sizing has no write routes and no client-facing read
endpoint, so it is the smaller of the two.

**Files:**
- Create: `internal/store/sizing/{store.go,ui.go,store_test.go,ui_test.go}`
- Create: `internal/api/sizing/{api.go,sizing.go,sizing_test.go}`
- Create: `internal/ui/sizing/{ui.go,templates/{index.html,cohorts.html,status.html},ui_test.go}`
- Create: `cmd/sizingd/main.go`
- Modify: `internal/store/store.go`, `internal/api/api.go`, `internal/ui/ui.go`,
  `cmd/insightsd/main.go`

**Interfaces:**
- Consumes: the same platform packages as Task 5.
- Produces:
  - `func sizingstore.Open(path string) (*sizingstore.Store, error)`, `Init`
  - every method today's `store.Store` declares under the "Fleet sizing" comments, plus
    the existing `SizingCounts`
  - `func sizingapi.NewServer(st Store, trusted httpx.TrustedProxies, cfg Config) http.Handler`
    serving `/v1/reports` and `/healthz`
  - `func sizingui.NewServer(r Reader, cfg chrome.Config) (http.Handler, error)`

- [ ] **Step 1: Move the store**

```bash
mkdir -p internal/store/sizing
git mv internal/store/sizing.go       internal/store/sizing/store.go
git mv internal/store/sizing_test.go  internal/store/sizing/store_test.go
git mv internal/store/sizing_ui.go    internal/store/sizing/ui.go
sed -i 's/^package store$/package sizing/' internal/store/sizing/*.go
```

Add `Open`/`Init` with the ten sizing tables from `internal/store/store.go`. Carry the
DDL comments across verbatim — they are what says which table accumulates
(`sizing_ingest_daily`) and which recomputes, and mixing them would be silent.

- [ ] **Step 2: Run the moved store tests**

Run: `go test ./internal/store/sizing/ -race -count=1`
Expected: PASS.

- [ ] **Step 3: Delete the sizing half of the monolith store**

Remove the sizing methods, row types and DDL from `internal/store/store.go`.

- [ ] **Step 4: Move the API**

```bash
mkdir -p internal/api/sizing
git mv internal/api/sizing.go      internal/api/sizing/sizing.go
git mv internal/api/sizing_test.go internal/api/sizing/sizing_test.go
sed -i 's/^package api$/package sizing/' internal/api/sizing/*.go
```

`internal/api/sizing/api.go` mirrors Task 5's, registering `/healthz` and `/v1/reports`.
Swap `s.authenticate` for `httpx.SystemID`, and set `r.RemoteAddr = "127.0.0.1:12345"` in
the moved tests. Add the same direct-connection-refused test as Task 5, Step 5.

Run: `go test ./internal/api/sizing/ -race -count=1`
Expected: PASS.

- [ ] **Step 5: Move the UI**

```bash
mkdir -p internal/ui/sizing/templates
git mv internal/ui/templates/sizing.html  internal/ui/sizing/templates/index.html
git mv internal/ui/templates/cohorts.html internal/ui/sizing/templates/cohorts.html
git mv internal/ui/sizing_ui_test.go      internal/ui/sizing/ui_test.go
```

Nav: `/` Nodes, `/cohorts` Recommendations, `/status`. The `/cohorts` caption keeps the
sentence saying a solo number includes the platform modules' cost — every node it was
measured from was running them, and an unqualified "module X costs Y" overstates the
measurement. `axisLabel`, "Capped" and "Nodes running only this module" stay: the UI
renames, the code does not.

- [ ] **Step 6: Write `cmd/sizingd/main.go`**

Env parsing, `sqlitex.Open`, `Init`, `baseline.New` + the cohort ticker, the housekeeping
order (`RollupSizingMonthly` **before** `PruneSizingDaily`), the API and UI listeners,
graceful shutdown. Env: `LOG_LEVEL`, `LISTEN_ADDR`, `UI_LISTEN_ADDR`, `UI_BASE_PATH`,
`DB_PATH` (default `/var/lib/sizing/sizing.db`), `TRUSTED_PROXY_CIDRS`, `SIZING_*`. No
`ADMIN_API_KEY`: sizingd has no write route.

Step 1 of the cohort pass recomputes stale `pressure_version` rows and must still run
before cohorts are built.

- [ ] **Step 7: Verify and commit**

```bash
go build ./... && go vet ./... && go test ./... -race -count=1
git add internal/store/sizing internal/api/sizing internal/ui/sizing cmd/sizingd \
        internal/store/store.go internal/api/api.go internal/ui cmd/insightsd
git commit -m "feat(sizingd): split fleet sizing into its own service"
```

---

### Task 7: `insightsd`

What is left of the monolith is the logs pipeline. This task moves it into the same
shape as its two siblings so no package is special, and deletes the last of the shared
scaffolding.

**Files:**
- Create: `internal/store/logs/{store.go,ui.go,store_test.go,ui_test.go}`
- Create: `internal/api/logs/{api.go,api_test.go}`
- Create: `internal/ui/logs/{ui.go,templates/*.html,ui_test.go}`
- Modify: `cmd/insightsd/main.go`
- Delete: `internal/store/store.go`'s `Store` interface, `internal/api/api.go`'s
  `Authenticator`/`StaticAuth`/`loggingHandler`/`handleHealthz`, `internal/ui/ui.go`

**Interfaces:**
- Consumes: the platform packages.
- Produces:
  - `func logsstore.Open(path string) (*logsstore.Store, error)`, `Init`
  - the remaining `store.Store` methods, plus `Counts` returning
    `{Systems, Templates, Baselines, Findings, Analyses int}`
  - `func logsapi.NewServer(q Publisher, st Store, trusted httpx.TrustedProxies, cfg Config) http.Handler`
    serving `/healthz`, `/v1/bundles`, `/v1/findings`
  - `func logsui.NewServer(r Reader, rt Runtime, cfg chrome.Config) (http.Handler, error)`

- [ ] **Step 1: Move the store**

```bash
mkdir -p internal/store/logs
git mv internal/store/store.go      internal/store/logs/store.go
git mv internal/store/store_test.go internal/store/logs/store_test.go
git mv internal/store/ui.go         internal/store/logs/ui.go
git mv internal/store/ui_test.go    internal/store/logs/ui_test.go
sed -i 's/^package store$/package logs/' internal/store/logs/*.go
```

Replace the `Store` interface with a concrete `type Store struct { db *sqlitex.DB }` and
`Open` delegating to `sqlitex.Open`. The consumers that need an interface — `analyzer`,
`budget`, `ui` — already declare their own narrow ones or gain one here; a single
88-method interface had no remaining purpose once each binary has exactly one store.

Trim `Counts` to the five logs tables.

- [ ] **Step 2: Run the moved store tests**

Run: `go test ./internal/store/logs/ -race -count=1`
Expected: PASS.

- [ ] **Step 3: Move the API**

```bash
mkdir -p internal/api/logs
git mv internal/api/api.go      internal/api/logs/api.go
git mv internal/api/api_test.go internal/api/logs/api_test.go
sed -i 's/^package api$/package logs/' internal/api/logs/*.go
rmdir internal/api 2>/dev/null || true
```

Delete `Authenticator`, `StaticAuth`, `loggingHandler`, `statusRecorder` and
`handleHealthz` — `httpx` owns all five now. Register `/healthz`, `/v1/bundles`,
`/v1/findings`. Swap `s.authenticate` for `httpx.SystemID`; set
`r.RemoteAddr = "127.0.0.1:12345"` in the moved tests; add the direct-connection-refused
test from Task 5, Step 5.

`PIPELINE_EXCLUDE_MODULES` and `PIPELINE_EXCLUDE_SERVICES` still apply in
`handleBundles` **before** `queue.Publish`, and still drop from `Templates`, `Digest` and
`Budget.TruncatedModules` together.

- [ ] **Step 4: Move the UI**

```bash
mkdir -p internal/ui/logs/templates
git mv internal/ui/templates/findings.html  internal/ui/logs/templates/index.html
git mv internal/ui/templates/systems.html   internal/ui/logs/templates/systems.html
git mv internal/ui/templates/analyses.html  internal/ui/logs/templates/analyses.html
git mv internal/ui/templates/gate.html      internal/ui/logs/templates/gate.html
git mv internal/ui/templates/cost.html      internal/ui/logs/templates/cost.html
git mv internal/ui/templates/templates.html internal/ui/logs/templates/templates.html
git mv internal/ui/templates/baselines.html internal/ui/logs/templates/baselines.html
git mv internal/ui/templates/status.html    internal/ui/logs/templates/status.html
git mv internal/ui/ui_test.go               internal/ui/logs/ui_test.go
git rm internal/ui/ui.go
```

The status page keeps the queue section (`Depth`/`Cap`/`Workers`) — insightsd is the only
binary with a queue — and drops the blocklist feed section. `/gate`'s rollup stays
time-bounded, default 7 days: reasons are stored as the formula that produced them
spelled them, so an all-time grouping mixes eras.

- [ ] **Step 5: Rewire `cmd/insightsd/main.go`**

Drop every threat and sizing variable, the `blocklist` and `baseline` wiring, the admin
server, and the auth wiring. Add `TRUSTED_PROXY_CIDRS` and `UI_BASE_PATH`. `DB_PATH`
defaults to `/var/lib/insights/insights.db`.

- [ ] **Step 6: Verify and commit**

```bash
go build ./... && go vet ./... && go test ./... -race -count=1
git add internal/store internal/api internal/ui cmd/insightsd
git commit -m "refactor(insightsd): move the logs pipeline into its own packages"
```

---

### Task 8: OpenAPI

`docs/api/openapi_test.go` fails the build on a documented path that no route serves and
on a route no path documents. It currently walks one route list; it now walks three, and
the documented paths carry the public prefix the handlers never see.

**Files:**
- Modify: `docs/api/openapi.yaml`
- Modify: `docs/api/openapi_test.go`

- [ ] **Step 1: Update the test's expected route list**

Replace the single expected-paths list with one list per service, each with its prefix:

```go
// The proxy strips the prefix before the handler sees the path, so a
// service's registered routes and its documented paths differ by exactly
// that prefix. Keeping the prefix here rather than in the handlers is what
// lets a pipeline be run without a proxy in front of it during development.
var services = []struct {
	name   string
	prefix string
	routes []string
}{
	{"insightsd", "/logs", []string{"/v1/bundles", "/v1/findings"}},
	{"threatd", "/blocklist", []string{"/v1/events", "/v1/feed", "/v1/allowlist-requests"}},
	{"sizingd", "/sizing", []string{"/v1/reports"}},
}
```

`/healthz` is registered by all three and documented by none — it is not routed by the
proxy, so it is not part of the public API. Assert that explicitly rather than letting it
fall out of the diff by accident.

- [ ] **Step 2: Run it and watch it fail**

Run: `go test ./docs/api/ -v`
Expected: FAIL, listing the six renamed paths as missing and the old unprefixed ones plus
the five `/admin/v1/*` paths as stale.

- [ ] **Step 3: Update `openapi.yaml`**

Rename the six client paths to their prefixed, de-stuttered form; delete the five
`/admin/v1/*` paths and the `/healthz` path along with any schemas that become
unreferenced. Every schema still mirrors `internal/model` field-for-field. The operator
UI stays deliberately undocumented.

- [ ] **Step 4: Run the tests and watch them pass**

Run: `go test ./docs/api/ -race -count=1 -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add docs/api
git commit -m "docs(api): document the prefixed per-service paths"
```

---

### Task 9: Container image, quadlets and Traefik

The target machine was surveyed read-only on 2026-09-09 and the findings — including two
that contradict this task as originally written — are in
`docs/runbooks/2026-09-09-insights-test-deploy.md`. Read it before starting.

**Files:**
- Modify: `Containerfile`
- Create: `deploy/quadlet/{insights.network,authd.container,insightsd.container,threatd.container,sizingd.container,traefik.container}`
- Create: `deploy/traefik/{traefik.yaml,dynamic.yaml.tmpl}`
- Modify: `.github/workflows/image.yml`
- Modify: `deploy.md`

- [ ] **Step 1: Parameterize the `Containerfile`**

```dockerfile
ARG SERVICE=insightsd
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w" -o /out/service ./cmd/${SERVICE}
```

**Build in CI, not on the node.** The target has 1.7 GiB of RAM and no swap, so a Go
build there is an OOM risk; the node pulls finished images.

The runtime stage copies `/out/service` to `/usr/local/bin/service` and drops the
`ENV LISTEN_ADDR`/`DB_PATH` defaults and the fixed `EXPOSE`/`VOLUME`/`HEALTHCHECK` — those
now belong to each quadlet, which knows its own port and path. Build with
`podman build --build-arg SERVICE=threatd -t insights-threatd .`.

- [ ] **Step 2: Write the quadlets**

`deploy/quadlet/threatd.container`, the others by analogy:

```ini
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#

[Unit]
Description=Threat Shield pipeline
After=authd.service

[Container]
Image=localhost/insights-threatd:latest
ContainerName=threatd
# Published to loopback only, so nothing off the host reaches this container
# directly -- which matters because the credential on a /v1 request is
# validated by the proxy, not here.
#
# The address this process actually SEES is not 127.0.0.1. Under rootful
# podman a PublishPort DNAT is masqueraded on the reply path, so RemoteAddr is
# the bridge gateway. TRUSTED_PROXY_CIDRS must therefore name that gateway,
# and insights.network must pin the subnet so the address is stable across
# recreation. Get this wrong and every /v1 request 401s with a valid
# credential, which reads as an auth bug rather than a networking one.
PublishPort=127.0.0.1:9605:9595
PublishPort=127.0.0.1:9606:9596
Volume=insights-threat.volume:/var/lib/threat
Environment=LISTEN_ADDR=:9595
Environment=UI_LISTEN_ADDR=:9596
Environment=UI_BASE_PATH=/blocklist
Environment=DB_PATH=/var/lib/threat/threat.db
Environment=TRUSTED_PROXY_CIDRS=127.0.0.0/8,10.89.0.1/32
EnvironmentFile=/etc/insights/threatd.env
HealthCmd=wget -qO- http://127.0.0.1:9595/healthz || exit 1
HealthInterval=30s
HealthRetries=3
HealthStartPeriod=5s

[Service]
Restart=always

[Install]
WantedBy=multi-user.target
```

`ADMIN_API_KEY` lives in `/etc/insights/threatd.env`, mode 0600, never in the unit.
Likewise `LLM_API_KEY` for insightsd and `AUTH_PEPPER` for authd.

- [ ] **Step 3: Write the Traefik dynamic configuration as a template**

The committed artifact is `dynamic.yaml.tmpl`; the rendered `dynamic.yaml` is produced at
deploy time and is reproducible from `INSIGHTS_HOST` alone:

```bash
set -a; . /etc/insights/deploy.env; set +a
envsubst '$INSIGHTS_HOST' < deploy/traefik/dynamic.yaml.tmpl > /etc/traefik/dynamic.yaml
```

Naming the variable in `envsubst`'s argument matters: unquoted, it would also expand
Traefik's own `${…}` syntax. `INSIGHTS_HOST` drives the six `Host()` matchers and the ACME
certificate domain, and nothing else — if a second consumer appears, it reads the same
variable rather than repeating the literal.

A wrong or unset `INSIGHTS_HOST` fails recognisably: Traefik matches no router and every
request 404s, which looks nothing like a misconfigured backend.

```yaml
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#
http:
  middlewares:
    system-auth:
      forwardAuth:
        address: "http://127.0.0.1:9590/auth"
    operator-auth:
      basicAuth:
        usersFile: /etc/traefik/operators.htpasswd
        # false, deliberately: the app validates ADMIN_API_KEY itself and
        # needs the header. Setting this true breaks every UI write with a
        # 401 while the proxy still lets the request through.
        removeHeader: false
    strip-logs:
      stripPrefix:
        prefixes: ["/logs"]
    strip-blocklist:
      stripPrefix:
        prefixes: ["/blocklist"]
    strip-sizing:
      stripPrefix:
        prefixes: ["/sizing"]

  routers:
    # Priority is explicit on all six: /blocklist/v1/ and /blocklist/ share a
    # prefix, and getting the order backwards would put operator BasicAuth on
    # the ingest path, or the fleet's system credentials on the operator UI.
    logs-api:
      rule: "Host(`${INSIGHTS_HOST}`) && PathPrefix(`/logs/v1/`)"
      priority: 200
      middlewares: [system-auth, strip-logs]
      service: logs-api
    logs-ui:
      rule: "Host(`${INSIGHTS_HOST}`) && PathPrefix(`/logs`)"
      priority: 100
      middlewares: [operator-auth, strip-logs]
      service: logs-ui
    blocklist-api:
      rule: "Host(`${INSIGHTS_HOST}`) && PathPrefix(`/blocklist/v1/`)"
      priority: 200
      middlewares: [system-auth, strip-blocklist]
      service: blocklist-api
    blocklist-ui:
      rule: "Host(`${INSIGHTS_HOST}`) && PathPrefix(`/blocklist`)"
      priority: 100
      middlewares: [operator-auth, strip-blocklist]
      service: blocklist-ui
    sizing-api:
      rule: "Host(`${INSIGHTS_HOST}`) && PathPrefix(`/sizing/v1/`)"
      priority: 200
      middlewares: [system-auth, strip-sizing]
      service: sizing-api
    sizing-ui:
      rule: "Host(`${INSIGHTS_HOST}`) && PathPrefix(`/sizing`)"
      priority: 100
      middlewares: [operator-auth, strip-sizing]
      service: sizing-ui

  services:
    logs-api:
      loadBalancer:
        # passHostHeader defaults to true and must stay true: the UI's
        # cross-site write check compares Origin to r.Host, and a rewritten
        # Host makes every write a 403.
        passHostHeader: true
        servers: [{url: "http://127.0.0.1:9595"}]
    logs-ui:
      loadBalancer:
        passHostHeader: true
        servers: [{url: "http://127.0.0.1:9596"}]
    blocklist-api:
      loadBalancer:
        passHostHeader: true
        servers: [{url: "http://127.0.0.1:9605"}]
    blocklist-ui:
      loadBalancer:
        passHostHeader: true
        servers: [{url: "http://127.0.0.1:9606"}]
    sizing-api:
      loadBalancer:
        passHostHeader: true
        servers: [{url: "http://127.0.0.1:9615"}]
    sizing-ui:
      loadBalancer:
        passHostHeader: true
        servers: [{url: "http://127.0.0.1:9616"}]
```

In `traefik.yaml`, set `entryPoints.websecure.forwardedHeaders.trustedIPs` to the
addresses in front of Traefik, or leave it empty so Traefik overwrites
`X-Forwarded-For` with the connecting address. That overwrite is what makes the
pipelines' rightmost-value rule correct.

- [ ] **Step 4: Build all four images in CI**

`.github/workflows/image.yml` builds one image from one `Containerfile`. Give the build
job a matrix over the four services, so each pushes its own tag:

```yaml
    strategy:
      matrix:
        service: [authd, insightsd, threatd, sizingd]
```

The metadata step's `images:` becomes
`${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}-${{ matrix.service }}`, its
`org.opencontainers.image.title` label becomes `${{ matrix.service }}`, and the build step
gains `build-args: SERVICE=${{ matrix.service }}`. Pull requests still build and never
push.

- [ ] **Step 5: Verify the deployment by hand**

```bash
# Rootful system units, not --user: rootless is not viable on the target
# (subuid/subgid map an unprivileged account only), and the quadlets live in
# /etc/containers/systemd.
systemctl daemon-reload
systemctl start authd insightsd threatd sizingd traefik

# Before anything else, confirm what address the pipelines actually see. If
# this is not inside TRUSTED_PROXY_CIDRS, every /v1 request 401s.
journalctl -u threatd -n 50 | grep remote_addr | head

curl -sS -o /dev/null -w '%{http_code}\n' https://${INSIGHTS_HOST}/blocklist/v1/feed
# 401 without a credential

curl -sS -u "$SYSTEM_ID:$TOKEN" https://${INSIGHTS_HOST}/blocklist/v1/feed | head -c 200
# 503 before the first consensus pass, a snapshot after it -- never a blank 200

curl -sS -o /dev/null -w '%{http_code}\n' https://${INSIGHTS_HOST}/blocklist/
# 401 without operator credentials
```

Then confirm in threatd's logs that an ingested decision recorded the reporter's real
address and not `127.0.0.1` — that is the end-to-end proof the `X-Forwarded-For` chain
works, and it is the one thing no unit test can show.

- [ ] **Step 6: Rewrite `deploy.md` and commit**

```bash
git add Containerfile deploy deploy.md .github/workflows/image.yml
git commit -m "feat(deploy): add quadlets and Traefik configuration for four services"
```

---

### Task 10: Documentation

The two living documents must match the system as it stands, and `CLAUDE.md` carries
several rules this plan reverses.

**Files:**
- Modify: `docs/architecture.md`, `docs/user-guide.md`, `README.md`, `CLAUDE.md`
- Modify: `docs/specs/2026-08-07-threat-events-ingest-contract.md`,
  `docs/specs/2026-09-02-sizing-ingest-contract.md`

- [ ] **Step 1: `docs/architecture.md`**

Redraw the package layering as four binaries over `internal/platform` and
`internal/{store,api,ui}/{logs,threat,sizing}`. Add the request path through Traefik, the
`forwardAuth` hop to authd, and the three databases. Keep the correctness invariants
section as is — none of them changed.

- [ ] **Step 2: `docs/user-guide.md`**

Update every URL to its prefixed form, describe the three dashboards and their landing
pages, and say that operator access is a single credential shared with `ADMIN_API_KEY`.

- [ ] **Step 3: `README.md`**

Split the environment table into four sections, one per binary, with the common rows
called out. Add `TRUSTED_PROXY_CIDRS`, `UI_BASE_PATH` and `AUTH_LISTEN_ADDR`; remove
`ADMIN_LISTEN_ADDR`; move the five `AUTH_*` rows into authd's section. Rewrite the manual
round-trip walkthrough against `/logs/v1/bundles` and note that running a pipeline
without a proxy requires setting `TRUSTED_PROXY_CIDRS` to whatever the client's address
will be.

- [ ] **Step 4: `CLAUDE.md`**

Six edits, each of which contradicts what is written there today:

1. The Threat Shield bullet beginning *"The reporter's source IP comes from `RemoteAddr`,
   never `X-Forwarded-For`"* is replaced by decision 4's rule, with the trusted-proxy
   condition stated as the load-bearing part.
2. The bullet beginning *"The admin plane is off unless both `ADMIN_LISTEN_ADDR` and
   `ADMIN_API_KEY` are set"* loses the separate admin plane; the audit table, the
   `X-Admin-Actor` requirement and the "the actor is not a security control" note move to
   the UI write routes, which are now the only writer.
3. The operator UI bullet gains the Traefik BasicAuth layer and states that it is
   additive — `ADMIN_API_KEY` and the cross-site check remain the gate.
4. The package layering diagram is replaced.
5. The "Current state" table's Auth, Backends and Operator UI rows are rewritten.
6. `scripts/insights-api.sh`'s defaults and the commands section are updated to the
   prefixed paths.

- [ ] **Step 5: The two ingest contracts**

`docs/specs/2026-08-07-threat-events-ingest-contract.md`: the endpoint is
`POST /blocklist/v1/events`, and the reporter's observed source address is now the
`X-Forwarded-For` value the proxy sets. `docs/specs/2026-09-02-sizing-ingest-contract.md`:
the endpoint is `POST /sizing/v1/reports`. Both keep every drop rule in step with
`internal/threat/sanitize.go` and `internal/sizing/sanitize.go`.

- [ ] **Step 6: `scripts/insights-api.sh`**

Update the default base URL and the five subcommands to the prefixed paths.

- [ ] **Step 7: Commit**

```bash
git add docs README.md CLAUDE.md scripts/insights-api.sh
git commit -m "docs: describe the four-service split"
```

---

### Task 11: an ingest queue in front of threatd's writes

Runs **after** Task 10 — the split must be finished first.

**What this is actually for.** The database already has exactly one writer:
`SetMaxOpenConns(1)` plus the store's write mutex, and `InsertThreatEvents`
(`internal/store/threat/store.go`) already wraps a whole report in a single
transaction with `ON CONFLICT … DO NOTHING`. So this task does not introduce
single-writer semantics; those hold today.

What it introduces is a **bound**. Today a burst of reporters produces one
blocked goroutine per in-flight request, each holding a decoded, sanitized
report, all queued on the mutex with no limit and no way to shed load: the
server degrades by growing until something dies. A bounded channel with a
fixed consumer count converts that into a queue depth an operator can see and
a fast 503 the reporter retries — the same trade `internal/queue` already
makes for bundles, for a different reason.

Dropping a queued batch on a crash is acceptable here and needs no
compensation: the `(system_id, attacker_ip, scenario, observed_at)` unique
index makes redelivery a no-op, and reporters re-send on their next cycle.

**Consequence for the wire contract:** `stored` and `duplicates` are
post-write facts and cannot survive an asynchronous ingest. The 202 keeps
`accepted` and `dropped` — `dropped` comes from `threat.Sanitize`, which runs
in the handler, before the enqueue — and loses the other two. Sanitizing
before enqueueing is what preserves it, and it also keeps the queue holding
clean events rather than raw reports.

**Where the package goes.** Not under `internal/threat`: that package is pure,
and a queue has goroutines and a clock. Not `internal/queue` either — that one
carries the `(system_id, window_start)` in-flight claim that makes bundle
redelivery idempotent, which threat neither has nor needs. A new
`internal/platform/ingestq` holds the generic half (bounded channel, `ErrFull`,
workers, `Depth`/`Cap`), and `internal/queue` is deliberately **not** refactored
onto it: its window-claim logic is load-bearing and correct, and rewriting it
for symmetry buys nothing.

**Files:**
- Create: `internal/platform/ingestq/ingestq.go`, `internal/platform/ingestq/ingestq_test.go`
- Modify: `internal/api/threat/threat.go`, `internal/api/threat/api.go`, `internal/api/threat/threat_test.go`
- Modify: `internal/ui/threat/ui.go`, `internal/ui/threat/templates/status.html`
- Modify: `cmd/threatd/main.go`
- Modify: `docs/specs/2026-08-07-threat-events-ingest-contract.md`, `docs/api/openapi.yaml`,
  `docs/api/openapi_test.go`, `docs/architecture.md`, `CLAUDE.md`, `AGENTS.md`

**Interfaces:**
- Produces:
  - `type ingestq.Queue[T any] struct{ … }`
  - `func ingestq.New[T any](size int, timeout time.Duration, h func(context.Context, T) error) *Queue[T]`
  - `func (q *Queue[T]) Publish(item T) error` returning `ingestq.ErrFull`
  - `func (q *Queue[T]) Start(workers int)`, `Stop()`, `Depth() int`, `Cap() int`
  - `Depth`/`Cap` satisfy `internal/ui/chrome`'s `Runtime` interface unchanged

- [ ] **Step 1: Write the failing queue test**

```go
// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package ingestq

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// The bound is the point: past capacity Publish must fail immediately rather
// than block, so a burst sheds load at the edge instead of growing the
// server until it dies.
func TestPublishRefusesWhenFull(t *testing.T) {
	release := make(chan struct{})
	q := New(2, time.Second, func(ctx context.Context, n int) error {
		<-release
		return nil
	})
	q.Start(1)
	defer func() { close(release); q.Stop() }()

	// One item is claimed by the worker and blocks; two more fill the buffer.
	for i := 0; i < 3; i++ {
		if err := q.Publish(i); err != nil {
			t.Fatalf("Publish(%d) = %v, want nil", i, err)
		}
	}
	waitFor(t, func() bool { return q.Depth() == 2 })

	if err := q.Publish(99); !errors.Is(err, ErrFull) {
		t.Fatalf("Publish past capacity = %v, want ErrFull", err)
	}
}

// Every accepted item must reach the handler exactly once, from any worker.
func TestEveryPublishedItemIsHandledOnce(t *testing.T) {
	const items = 200

	var mu sync.Mutex
	seen := map[int]int{}
	done := make(chan struct{})

	q := New(items, time.Second, func(ctx context.Context, n int) error {
		mu.Lock()
		seen[n]++
		if len(seen) == items {
			close(done)
		}
		mu.Unlock()
		return nil
	})
	q.Start(4)
	defer q.Stop()

	for i := 0; i < items; i++ {
		if err := q.Publish(i); err != nil {
			t.Fatalf("Publish(%d): %v", i, err)
		}
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not see every item")
	}

	mu.Lock()
	defer mu.Unlock()
	for i := 0; i < items; i++ {
		if seen[i] != 1 {
			t.Errorf("item %d handled %d times, want 1", i, seen[i])
		}
	}
}

// Stop must drain what was accepted. An item the server answered 202 for and
// then dropped at shutdown is worse than one it refused with a 503.
func TestStopDrainsAcceptedItems(t *testing.T) {
	var mu sync.Mutex
	var handled int

	q := New(16, time.Second, func(ctx context.Context, n int) error {
		time.Sleep(5 * time.Millisecond)
		mu.Lock()
		handled++
		mu.Unlock()
		return nil
	})
	q.Start(2)

	for i := 0; i < 16; i++ {
		if err := q.Publish(i); err != nil {
			t.Fatalf("Publish(%d): %v", i, err)
		}
	}
	q.Stop()

	mu.Lock()
	defer mu.Unlock()
	if handled != 16 {
		t.Errorf("handled %d items after Stop, want 16", handled)
	}
}

// A handler that fails or panics must not take the worker down with it:
// one bad report cannot stop every later report from being stored.
func TestAFailingHandlerDoesNotKillTheWorker(t *testing.T) {
	var mu sync.Mutex
	var handled int
	done := make(chan struct{})

	q := New(8, time.Second, func(ctx context.Context, n int) error {
		mu.Lock()
		handled++
		if handled == 3 {
			close(done)
		}
		mu.Unlock()
		switch n {
		case 0:
			return errors.New("boom")
		case 1:
			panic("worse")
		}
		return nil
	})
	q.Start(1)
	defer q.Stop()

	for i := 0; i < 3; i++ {
		if err := q.Publish(i); err != nil {
			t.Fatalf("Publish(%d): %v", i, err)
		}
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the worker died on a failing handler")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met within the deadline")
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `go test ./internal/platform/ingestq/ -race -v`
Expected: build failure, `undefined: New`.

- [ ] **Step 3: Implement `ingestq.go`**

Model it on `internal/queue/queue.go`, minus the window claim: a buffered
channel of `T`, `Publish` doing a non-blocking send with `default: return
ErrFull`, `Start(workers)` launching that many goroutines over the channel, a
per-item `context.WithTimeout`, a `recover()` in the worker so a panicking
handler logs and continues, and `Stop()` closing the channel and waiting on a
`sync.WaitGroup`. `Depth()` is `len(ch)`, `Cap()` is `cap(ch)`.

- [ ] **Step 4: Run the tests and watch them pass**

Run: `go test ./internal/platform/ingestq/ -race -count=1 -v`
Expected: PASS.

- [ ] **Step 5: Write the failing handler tests**

In `internal/api/threat/threat_test.go`, add three cases: an accepted report
answers 202 without the store having been written yet; a full queue answers
503 and stores nothing; a report whose every decision is dropped by
`threat.Sanitize` still answers 202 with the drop counters and never enqueues.
Assert the response body carries `accepted` and `dropped` and no longer
carries `stored` or `duplicates`.

- [ ] **Step 6: Move the write behind the queue**

`handleEvents` keeps everything up to and including `threat.Sanitize`, then
publishes `threatWork{systemID, events, counters, day}` and answers 202. The
consumer — a method on the api package's server, wired in `NewServer` — does
the `InsertThreatEvents` and `RecordIngestCounters` calls the handler used to
make, with the same error handling: an accounting failure is logged and never
fails the work item, because the evidence is already stored.

The queue is not optional: `NewServer` takes it, and `cmd/threatd` always
builds one. A nil queue would be a second, untested ingest path.

- [ ] **Step 7: Run the tests and watch them pass**

Run: `go test ./internal/api/threat/ -race -count=1 -v`
Expected: PASS.

- [ ] **Step 8: Wire the binary and the status page**

`cmd/threatd/main.go` gains `THREAT_QUEUE_SIZE` (default 256) and
`THREAT_QUEUE_WORKERS` (default 2), starts the queue before the listener and
stops it after the HTTP shutdown so accepted work drains. Pass the queue to
`threatui.NewServer` as its `Runtime`; the threat status page grows the same
depth/cap/workers row the logs status page has.

- [ ] **Step 9: Update the contract and the docs**

`docs/specs/2026-08-07-threat-events-ingest-contract.md`: the 202 body loses
`stored` and `duplicates`; add that a 503 means "retry", exactly as for
bundles. `docs/api/openapi.yaml` and its test follow. In `docs/architecture.md`,
`CLAUDE.md` and `AGENTS.md`, the Threat Shield rule currently reads "**no LLM
call, no gate, no fingerprint, no queue**" — the clause "there is no LLM here,
so no queue" was the reason, and it no longer holds. Replace it with this
task's reason: the queue bounds concurrency against a single-writer database,
it does not exist to hide latency. Keep `CLAUDE.md` and `AGENTS.md`
byte-identical.

- [ ] **Step 10: Verify and commit**

```bash
go build ./... && go vet ./... && go test ./... -race -count=1
git add internal/platform/ingestq internal/api/threat internal/ui/threat cmd/threatd \
        docs/specs/2026-08-07-threat-events-ingest-contract.md docs/api \
        docs/architecture.md CLAUDE.md AGENTS.md
git commit -m "feat(threatd): bound ingest with a queue and a consumer"
```

---

## Verification

Run at the end of Task 10:

```bash
go build ./...
go vet ./...
go test ./... -race -count=1
```

Then check the invariants no test covers:

- [ ] Every new `.go`, `.yaml`, `.ini` and `.html` file carries the license header, and
      `internal/ui/chrome/static/pico.min.css` and `pico.LICENSE` carry only their
      upstream notices.
- [ ] `grep -rn 'AUTOINCREMENT\|SERIAL\|INSERT OR REPLACE\|jsonb' internal/store/` is empty.
- [ ] Each of the three `Init` functions creates only its own pipeline's tables, and the
      three sets are disjoint.
- [ ] No package under `internal/store/logs`, `internal/api/logs` or `internal/ui/logs`
      imports `threat`, `blocklist`, `sizing` or `baseline`, and vice versa.
      `go list -deps ./cmd/threatd | grep -c internal/gate` is `0`.
- [ ] `internal/gate`, `internal/fingerprint`, `internal/prompt`, `internal/threat` and
      `internal/sizing` import no `net/http`, no `database/sql` and no `time.Now`.
- [ ] `curl` against a running stack reproduces the four checks in Task 9, Step 5.

## Open questions

None of these blocks execution; each is a decision that can be taken when its task is
reached.

1. **Does `authd` need its own `/healthz` reachable from Traefik?** The quadlet checks it
   inside the container. If Traefik should refuse traffic while authd is starting, the
   `forwardAuth` failure already produces a 503, which is the correct answer anyway — so
   this is probably nothing.
2. **Does the operator htpasswd file hold one entry or one per operator?** Decision 5
   makes the username the audit actor, which argues for one entry per person, all sharing
   the `ADMIN_API_KEY` password. That works but means the password is not really a
   per-person secret. An IdP would fix it and is out of scope here.
3. **Does `chrome` keep the nav dropdown machinery?** All three UIs now have a single
   flat group. Task 5 leaves it in place; if no UI has grown a second group by Task 7,
   delete it there.
4. **Does `internal/llm`'s stub still earn its place** now that `analyzer_test.go` is the
   only caller in a single-pipeline binary? Probably yes — it is what lets the pipeline
   run end to end with nothing running — but worth a look while `cmd/insightsd` is open.
5. **Should threatd's consumer coalesce several reports into one transaction?**
   `InsertThreatEvents` is already one transaction per report, so the queue
   alone does not reduce the commit count: at an estimated ~9-18 reports/s
   across 2700 nodes that is ~18-36 transactions/s, which WAL handles
   comfortably. Coalescing would need a new multi-system store method and is
   worth doing only against a measurement showing commit latency is the
   binding constraint. Decide with load data from the deployed stack, not now.

6. **Does sizingd need the same queue?** Its shape is identical but its load
   is not — three reports per cluster per day against Threat Shield's
   continuous stream. Left alone deliberately; revisit if the ingest ever
   blocks.

7. **Should the three UIs share one status page implementation?** They differ in exactly
   two sections (queue, feed) out of five. A shared `chrome.StatusPage` taking optional
   sections would remove the triplication; three small pages are easier to read. Task 7
   is the point where all three exist and the comparison is possible.
