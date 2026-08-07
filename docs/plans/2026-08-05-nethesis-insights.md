# Nethesis Insights Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `nethesis-insights`, a Go server that receives deduplicated log bundles from NethServer nodes, gates them against novelty and deviation before spending any LLM call, and stores fingerprinted findings that never repeat.

**Architecture:** One container running Redpanda, a static Go binary and SQLite under `s6-overlay`. HTTP ingest authenticates by forwarding Basic credentials to an external validator, then produces to a Redpanda topic. A consumer reads bundles, gates them, calls an OpenAI-compatible LLM only when warranted, and upserts findings keyed by a server-computed fingerprint. All storage goes through a `Store` interface so the SQLite backend can be swapped for Postgres.

**Tech Stack:** Go 1.23, `uptrace/bun` (SQLite + Postgres), `modernc.org/sqlite` (CGO-free), `twmb/franz-go` (Kafka client), `golang-migrate/migrate`, `oklog/ulid`, `golang.org/x/time/rate`, `stretchr/testify`, `s6-overlay`, Redpanda.

**Spec:** [2026-08-05 Nethesis Insights Design](../specs/2026-08-05-nethesis-insights-design.md)

**Repository:** `https://github.com/nethesis/nethesis-insights` — already created, public, **empty**, no license, no default branch. Task 1 makes the first commit.

**License:** GPL-3.0-or-later, matching `ns8-loki`.

## Development environment

**All work happens on the dev machine, not locally.** The operator has a local bandwidth limit, and this project pulls a Go module cache, a Redpanda image and a Postgres image.

```
host:  root@rl1.leader.default.gs.nethserver.net
os:    Rocky Linux 9.8 (Blue Onyx)
disk:  154 GB free on /
```

Verified present: `podman`. Verified **missing**: `go`, `git`, `make`, `gh`, `golangci-lint` — Task 1 installs all five.

`rl1` is a **shared live cluster** running other NS8 modules (`nethvoice2`, `crowdsec1`, `samba2`, `metrics1`, `nethvoice-proxy1`, `traefik1`). Work only inside `/root/nethesis-insights`. Never restart another module's services. The containers this project runs bind to high ports (see Task 17) specifically to avoid colliding with them.

Work checked out at `/root/nethesis-insights`. Every `Run:` step in this plan executes on that host inside that directory unless stated otherwise.

## Global Constraints

Every task's requirements implicitly include this section. Values are copied verbatim from the spec.

**License header — required on every file created by this plan.** Go files:

```go
// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later
```

SQL, YAML, Makefile and shell files use the `#` form, matching `ns8-loki`:

```
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#
```

In Go files the header goes **above** the `package` clause, separated by a blank line so it is not mistaken for a package doc comment. Code blocks in later tasks omit the header to stay readable; prepend it to every file regardless. Task 1 adds a CI step that fails the build on any missing header, so this is enforced rather than trusted.

**Commit conventions** (NethServer contribution process):
- [Conventional Commits](https://www.conventionalcommits.org/) for every commit.
- **Never put an issue reference in an individual commit message.** Issue references belong in the merge or squash commit body only — this keeps the GitHub reference graph clean.
- Work on a branch, never commit directly to `main`.

**Schema portability** (spec §3.4) — enforced by the dual-dialect migration test in Task 3:
- IDs generated in Go as ULID. Never `AUTOINCREMENT` or `SERIAL`.
- Timestamps stored as `INTEGER` unix-millis. Never native date types.
- `ON CONFLICT … DO UPDATE` only. Never `INSERT OR REPLACE`.
- JSON held as `TEXT` and parsed in Go. No `jsonb` operators, no SQLite `json1` functions.
- Migrations via `golang-migrate`, one dialect-agnostic SQL directory.

**SQLite runtime** (spec §3.4): WAL mode, `busy_timeout=5000`, all writes serialized.

**LLM** (spec §8.2): strict `response_format: json_schema` with `strict: true`. **No `temperature` field** — some models reject any non-default value. `PROMPT_VERSION` is a code constant, never configuration.

**Secrets** (spec §10): `LLM_API_KEY` and `AUTH_PEPPER` come from the environment only. Never written to the database. Never logged. The auth cache stores `HMAC(pepper, credential)`, never the credential.

**Data protection** (spec §10): raw `samples` are never written to the database. They exist only in the `bundles` topic.

**Auth** (spec §4): fail **closed**. Validator unreachable with no cache hit → `503`.

**Determinism** (spec §8.2): identical bundle input must produce byte-identical prompts. Templates sorted `(module_id, priority, template)`; digest sorted `(module_id, priority)`.

**Findings ordering** (spec §5.6): severity-descending, then `last_seen` descending. Severity rank: `critical` > `high` > `medium` > `low`.

---

## Deviations from the spec

Five deliberate refinements. Each is a decision a reviewer should be able to accept or reject on its own.

1. **`internal/prompt` is its own package.** Spec §3.3 folds prompt assembly into `internal/analyzer`, but §13 requires golden-file tests proving byte-identical output — that is a unit with its own contract. Splitting it keeps `analyzer` free of string building.

2. **Fingerprint takes `modules []string`, not `module_id`.** Spec §6.2 writes `module_id` singular while the `findings` table in §6 stores `modules` plural. Resolved toward the table: modules are sorted and joined, same as evidence. `category` is derived server-side as `"security"` if any cited template carried `category=security`, else `""` — propagating the edge's classification without the server classifying anything (§8.1).

3. **SQLite write serialization uses a mutex, not a dedicated goroutine.** Spec §3.4 says "a single writer goroutine owning all writes". A mutex gives the identical serialization guarantee with no channel lifecycle to leak and no shutdown ordering to get wrong.

4. **Two config keys added:** `LLM_PRICE_INPUT_PER_MTOK` and `LLM_PRICE_OUTPUT_PER_MTOK`. The spec's cost ledger (§6) and daily spend cap (§9.3) compute `cost_micros`, which is impossible without prices. They are configuration rather than constants because provider pricing changes independently of releases.

5. **The container's final stage is the official Fedora-based Redpanda image, not Alpine.** Project container conventions prefer Alpine but name `*-slim`/glibc images as the documented fallback on musl incompatibility. Redpanda requires glibc. Justified in Task 17.

---

## File structure

```
nethesis-insights/
├── go.mod  go.sum  Makefile  renovate.json  README.md
├── .golangci.yml
├── .github/workflows/ci.yml
├── Containerfile
├── compose.yaml                        # local dev: Redpanda + server
├── s6/                                 # s6-overlay service definitions
│   ├── redpanda/{type,run,notification-fd}
│   └── insightsd/{type,run,dependencies.d/redpanda}
├── cmd/insightsd/main.go               # wiring, config, graceful shutdown
└── internal/
    ├── model/          bundle.go  finding.go  severity.go       # shared types, no deps
    ├── store/          store.go  sqlite.go  postgres.go
    │                   migrations/*.sql  systems.go  findings.go  prune.go
    ├── fingerprint/    fingerprint.go                            # pure
    ├── gate/           gate.go                                   # pure
    ├── prompt/         prompt.go  schema.go  testdata/*.golden   # pure
    ├── llm/            llm.go  openai.go  stub.go
    ├── budget/         budget.go                                 # concurrency + spend cap
    ├── queue/          queue.go  franz.go  fake.go
    ├── auth/           auth.go  forwarder.go  cache.go
    ├── ingest/         ingest.go  validate.go  ratelimit.go
    ├── api/            api.go
    ├── analyzer/       analyzer.go
    └── maint/          maint.go
```

**Responsibility boundaries.** `model` has no dependencies and is imported by everything. `fingerprint`, `gate` and `prompt` are pure — no network, no disk, no clock beyond an injected `now` — so they carry the correctness and cost logic in the most testable form available. `store`, `queue`, `llm` and `auth` are interfaces with a real and a fake implementation each, which is what lets `analyzer` be tested end-to-end with no container running.

---

## Task 1: Provision the dev machine, scaffold the repository, CI and lint

**Files:**
- Create: `LICENSE`, `go.mod`, `Makefile`, `.golangci.yml`, `.github/workflows/ci.yml`, `renovate.json`, `README.md`, `.gitignore`
- Create: `hack/check-license-headers.sh`
- Create: `internal/version/version.go`
- Test: `internal/version/version_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `version.Version` (string var), `make test`, `make lint`, `make build`, `make license-check`. Every later task runs `make test`.

- [ ] **Step 1: Install the toolchain on the dev machine**

All five tools are missing. Versions are pinned rather than taken from `dnf`, because Rocky's `golang` package floats and this project needs a known 1.23.

Run on `root@rl1.leader.default.gs.nethserver.net`:

```bash
dnf install -y git make tar gzip

# Go 1.23 from upstream
curl -fsSL https://go.dev/dl/go1.23.6.linux-amd64.tar.gz -o /tmp/go.tgz
rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz && rm -f /tmp/go.tgz

# gh CLI
curl -fsSL https://github.com/cli/cli/releases/download/v2.63.2/gh_2.63.2_linux_amd64.tar.gz \
  -o /tmp/gh.tgz
tar -C /tmp -xzf /tmp/gh.tgz
install -m0755 /tmp/gh_2.63.2_linux_amd64/bin/gh /usr/local/bin/gh
rm -rf /tmp/gh.tgz /tmp/gh_2.63.2_linux_amd64

cat >/etc/profile.d/go.sh <<'EOF'
export PATH=$PATH:/usr/local/go/bin:/root/go/bin
EOF
. /etc/profile.d/go.sh

# golangci-lint, matching the version CI uses
curl -fsSL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
  | sh -s -- -b /root/go/bin v1.62.2
```

- [ ] **Step 2: Verify the toolchain**

Run:

```bash
. /etc/profile.d/go.sh
go version && git --version && make --version | head -1 \
  && gh --version | head -1 && golangci-lint --version && podman --version
```

Expected: `go version go1.23.6 linux/amd64`, and a version line from each of the other five. If `go version` reports anything below 1.23, stop — later tasks use `for range int` and structured `log/slog` handling that need it.

- [ ] **Step 3: Authenticate `gh` (operator step)**

`gh auth login` is interactive and cannot be scripted here. The operator runs it on the dev machine and selects HTTPS + a token with `repo` and `workflow` scopes.

Verify afterwards:

```bash
gh auth status && gh repo view nethesis/nethesis-insights --json isEmpty
```

Expected: authenticated, and `{"isEmpty":true}`.

- [ ] **Step 4: Clone the empty repository and create the working branch**

The repository already exists and is empty — clone it rather than `git init`, so the remote is correct from the first commit.

```bash
cd /root
git clone https://github.com/nethesis/nethesis-insights.git
cd nethesis-insights
git config user.name  "Giacomo Sanchietti"
git config user.email "giacomo.sanchietti@nethesis.it"
git checkout -b feat/server-scaffold
go mod init github.com/nethesis/nethesis-insights
mkdir -p cmd/insightsd internal/version hack
```

Cloning an empty repository warns `you appear to have cloned an empty repository` and leaves no branch checked out; `git checkout -b` is what establishes the first one. The default branch becomes `main` on first push (Step 12).

- [ ] **Step 5: Add the GPLv3 license and the header checker**

Fetch the canonical text rather than hand-writing it:

```bash
curl -fsSL https://www.gnu.org/licenses/gpl-3.0.txt -o LICENSE
```

Create `hack/check-license-headers.sh`:

```bash
#!/usr/bin/env bash
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Fails if any tracked source file is missing its SPDX identifier.

set -euo pipefail

missing=0
while IFS= read -r f; do
    case "$f" in
        LICENSE|*.md|*.json|*.golden|go.sum|go.mod|.gitignore) continue ;;
    esac
    if ! grep -q 'SPDX-License-Identifier: GPL-3.0-or-later' "$f"; then
        echo "missing SPDX header: $f" >&2
        missing=1
    fi
done < <(git ls-files)

if [ "$missing" -ne 0 ]; then
    echo "run: add the GPL-3.0-or-later header to the files above" >&2
    exit 1
fi
echo "license headers OK"
```

```bash
chmod +x hack/check-license-headers.sh
```

Create `.gitignore`:

```
bin/
*.db
*.db-shm
*.db-wal
coverage.out
```

- [ ] **Step 6: Write the failing test**

Create `internal/version/version_test.go` (with the Go license header from Global Constraints):

```go
package version

import "testing"

func TestVersionIsSet(t *testing.T) {
	if Version == "" {
		t.Fatal("Version must not be empty")
	}
}
```

- [ ] **Step 7: Run it to make sure it fails**

Run: `go test ./internal/version/ -v`
Expected: FAIL — `undefined: Version`

- [ ] **Step 8: Write the minimal implementation**

Create `internal/version/version.go`:

```go
// Package version records the build identity of the server.
package version

// Version is overridden at build time with -ldflags "-X .../version.Version=x.y.z".
var Version = "0.0.0-dev"
```

- [ ] **Step 9: Run the tests and make sure they pass**

Run: `go test ./internal/version/ -v`
Expected: PASS

- [ ] **Step 10: Add the Makefile**

Create `Makefile`:

```makefile
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#

BINARY := insightsd
PKG    := github.com/nethesis/nethesis-insights
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)

.PHONY: build test lint tidy license-check check

build:
	CGO_ENABLED=0 go build -trimpath \
		-ldflags "-s -w -X $(PKG)/internal/version.Version=$(VERSION)" \
		-o bin/$(BINARY) ./cmd/insightsd

test:
	go test ./... -race -count=1

lint:
	golangci-lint run

license-check:
	./hack/check-license-headers.sh

check: license-check lint test

tidy:
	go mod tidy
```

`CGO_ENABLED=0` is required: the binary must be static so it can be copied into the Redpanda base image in Task 17 without dragging a libc dependency.

- [ ] **Step 11: Add the lint configuration**

Create `.golangci.yml`:

```yaml
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#
version: "2"
linters:
  enable:
    - errcheck
    - govet
    - staticcheck
    - ineffassign
    - unused
    - bodyclose
    - sqlclosecheck
    - rowserrcheck
    - gosec
linters-settings:
  gosec:
    excludes:
      - G404 # math/rand is never used for security here
```

`bodyclose`, `sqlclosecheck` and `rowserrcheck` are the ones that matter for this codebase: it is mostly HTTP clients and database rows, and leaking either is the most likely real bug.

- [ ] **Step 12: Add CI**

Create `.github/workflows/ci.yml`:

```yaml
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#
name: ci
on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_PASSWORD: test
          POSTGRES_DB: insights_test
        ports: ["5432:5432"]
        options: >-
          --health-cmd pg_isready --health-interval 5s
          --health-timeout 5s --health-retries 10
    env:
      TEST_POSTGRES_DSN: postgres://postgres:test@localhost:5432/insights_test?sslmode=disable
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.23"
      - run: make license-check
      - run: make test
      - uses: golangci/golangci-lint-action@v6
        with:
          version: v1.62
      - run: make build
```

`make license-check` runs **first** and before the test suite, so a missing GPL header fails fast rather than after several minutes of tests.

The Postgres service exists so Task 3's dual-dialect migration test actually runs in CI. Without it, the portability rules in Global Constraints are enforced by memory rather than by the build.

- [ ] **Step 13: Add Renovate and README**

Create `renovate.json`:

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["github>NethServer/.github"]
}
```

Create `README.md`:

```markdown
# nethesis-insights

Central anomaly analysis for NethServer fleets. Receives deduplicated log
bundles from nodes, gates them against novelty and deviation, calls an LLM only
when warranted, and stores fingerprinted findings that do not repeat.

Design: `docs/superpowers/specs/2026-08-05-nethesis-insights-design.md` in the
`ns8-loki` repository.

## Development

    make check    # license headers, lint, tests
    make test     # unit + integration, race detector on
    make build    # static binary into bin/insightsd

## License

GPL-3.0-or-later. See `LICENSE`.
```

- [ ] **Step 14: Add the placeholder entrypoint and verify the whole toolchain**

`cmd/insightsd` is not wired until Task 16, but `make build` must succeed from Task 1 onward so CI is meaningful throughout.

Create `cmd/insightsd/main.go` (with the Go license header):

```go
// Command insightsd is the Nethesis Insights server. Wiring lands in Task 16.
package main

func main() {}
```

Run: `make check && make build`
Expected: `license headers OK`, lint clean, tests PASS, `bin/insightsd` produced.

- [ ] **Step 15: Commit and make the repository's first push**

This is the first commit in an empty repository, so it also establishes `main`.

```bash
git add .
git commit -m "chore: scaffold module, license, CI, lint and build"

# Establish main from this branch, then push the working branch.
git branch -M feat/server-scaffold
git push -u origin feat/server-scaffold
gh api -X PATCH repos/nethesis/nethesis-insights -f default_branch=main 2>/dev/null || true
```

`git add .` is safe here and only here: the repository was empty, `.gitignore` is already in place from Step 5, and nothing untracked exists that should not be committed. Every later task stages explicit paths.

Note the default branch cannot be set to `main` until a `main` ref exists. Create it from the scaffold once the branch is pushed:

```bash
git push origin feat/server-scaffold:refs/heads/main
gh api -X PATCH repos/nethesis/nethesis-insights -f default_branch=main
gh repo view nethesis/nethesis-insights --json defaultBranchRef
```

Expected: `{"defaultBranchRef":{"name":"main"}}`. Subsequent work continues on `feat/server-scaffold`, and Task 19 opens the draft PR against `main`.

---

## Task 2: `internal/model` — shared types

**Files:**
- Create: `internal/model/bundle.go`, `internal/model/finding.go`, `internal/model/severity.go`
- Test: `internal/model/bundle_test.go`, `internal/model/severity_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `model.Bundle`, `model.Window`, `model.DigestEntry`, `model.Template`, `model.Budget`, `model.TruncatedModule`, `model.Finding`, `model.SeverityRank(string) int`, `model.SortFindings([]Finding)`. Every later task imports this package.

- [ ] **Step 1: Write the failing test for bundle decoding**

Create `internal/model/bundle_test.go`:

```go
package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

const sampleBundle = `{
  "schema_version": 1,
  "system_id": "abc123",
  "collector_version": "2.0.0",
  "masking_version": 1,
  "window": { "start": 1754380800000, "end": 1754381700000 },
  "digest": [
    { "module_id": "traefik1", "priority": 3,
      "observed": 42, "expected": 3.2, "ratio": 13.1 }
  ],
  "templates": [
    { "template": "<3> [n1:traefik1:traefik] connection refused to <IP>:<NUM>",
      "count": 37, "module_id": "traefik1", "priority": 3,
      "category": "security",
      "first_seen": 1754380811000, "last_seen": 1754381690000,
      "samples": ["<3> raw line"] }
  ],
  "budget": {
    "max_lines": 500, "lines_seen": 4210, "lines_kept": 500,
    "truncated_modules": [ { "module_id": "traefik1", "dropped": 3200 } ]
  }
}`

func TestBundleDecodesEveryProtocolField(t *testing.T) {
	var b Bundle
	require.NoError(t, json.Unmarshal([]byte(sampleBundle), &b))

	require.Equal(t, 1, b.SchemaVersion)
	require.Equal(t, "abc123", b.SystemID)
	require.Equal(t, "2.0.0", b.CollectorVersion)
	require.Equal(t, 1, b.MaskingVersion)
	require.Equal(t, int64(1754380800000), b.Window.Start)
	require.Equal(t, int64(1754381700000), b.Window.End)

	require.Len(t, b.Digest, 1)
	require.Equal(t, "traefik1", b.Digest[0].ModuleID)
	require.Equal(t, 3, b.Digest[0].Priority)
	require.Equal(t, int64(42), b.Digest[0].Observed)
	require.NotNil(t, b.Digest[0].Expected)
	require.InDelta(t, 3.2, *b.Digest[0].Expected, 0.001)

	require.Len(t, b.Templates, 1)
	require.Equal(t, "security", b.Templates[0].Category)
	require.Equal(t, int64(37), b.Templates[0].Count)
	require.Equal(t, []string{"<3> raw line"}, b.Templates[0].Samples)

	require.Equal(t, 500, b.Budget.MaxLines)
	require.Len(t, b.Budget.TruncatedModules, 1)
	require.Equal(t, int64(3200), b.Budget.TruncatedModules[0].Dropped)
}

func TestExpectedIsNilWhenEdgeDegraded(t *testing.T) {
	// The edge omits `expected` when its Loki metric query fails.
	var b Bundle
	require.NoError(t, json.Unmarshal([]byte(
		`{"digest":[{"module_id":"m","priority":3,"observed":9}]}`), &b))
	require.Nil(t, b.Digest[0].Expected)
	require.Equal(t, int64(9), b.Digest[0].Observed)
}
```

`Expected` must be a pointer, not a `float64`. When the edge's Loki metric query fails it omits the field entirely, and a non-pointer would decode to `0.0`, which is indistinguishable from a genuine zero rate and would make the gate divide by zero.

- [ ] **Step 2: Run it to make sure it fails**

Run: `go test ./internal/model/ -run TestBundle -v`
Expected: FAIL — `undefined: Bundle`

- [ ] **Step 3: Write the minimal implementation**

Create `internal/model/bundle.go`:

```go
// Package model holds the types shared across the server. It has no
// dependencies on any other internal package.
package model

// SchemaVersion is the only bundle schema version this server accepts.
const SchemaVersion = 1

// Window is the closed time range a bundle covers, in unix milliseconds.
type Window struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}

// DigestEntry is one (module, priority) count for the window. Expected and
// Ratio are pointers because the edge omits them when its metric query fails.
type DigestEntry struct {
	ModuleID string   `json:"module_id"`
	Priority int      `json:"priority"`
	Observed int64    `json:"observed"`
	Expected *float64 `json:"expected,omitempty"`
	Ratio    *float64 `json:"ratio,omitempty"`
}

// Template is one masked log line pattern plus how often it occurred.
// Samples are representative raw lines and are never persisted (spec §10).
type Template struct {
	Template  string   `json:"template"`
	Count     int64    `json:"count"`
	ModuleID  string   `json:"module_id"`
	Priority  int      `json:"priority"`
	Category  string   `json:"category,omitempty"`
	FirstSeen int64    `json:"first_seen"`
	LastSeen  int64    `json:"last_seen"`
	Samples   []string `json:"samples,omitempty"`
}

// TruncatedModule reports lines the edge dropped for one module.
type TruncatedModule struct {
	ModuleID string `json:"module_id"`
	Dropped  int64  `json:"dropped"`
}

// Budget reports what the edge's line cap did to this window.
type Budget struct {
	MaxLines         int               `json:"max_lines"`
	LinesSeen        int64             `json:"lines_seen"`
	LinesKept        int64             `json:"lines_kept"`
	TruncatedModules []TruncatedModule `json:"truncated_modules,omitempty"`
}

// Bundle is one 15-minute analysis payload from one node.
type Bundle struct {
	SchemaVersion    int           `json:"schema_version"`
	SystemID         string        `json:"system_id"`
	CollectorVersion string        `json:"collector_version"`
	MaskingVersion   int           `json:"masking_version"`
	Window           Window        `json:"window"`
	Digest           []DigestEntry `json:"digest"`
	Templates        []Template    `json:"templates"`
	Budget           Budget        `json:"budget"`
}

// CategoryOf returns the edge-assigned category for a template text, or "".
func (b Bundle) CategoryOf(template string) string {
	for _, t := range b.Templates {
		if t.Template == template {
			return t.Category
		}
	}
	return ""
}
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `go test ./internal/model/ -run TestBundle -v && go test ./internal/model/ -run TestExpected -v`
Expected: PASS

- [ ] **Step 5: Write the failing test for findings and severity ordering**

Create `internal/model/severity_test.go`:

```go
package model

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSeverityRankIsHighestFirst(t *testing.T) {
	require.Less(t, SeverityRank("critical"), SeverityRank("high"))
	require.Less(t, SeverityRank("high"), SeverityRank("medium"))
	require.Less(t, SeverityRank("medium"), SeverityRank("low"))
}

func TestUnknownSeveritySortsLast(t *testing.T) {
	require.Greater(t, SeverityRank("banana"), SeverityRank("low"))
}

func TestSortFindingsSeverityThenLastSeen(t *testing.T) {
	in := []Finding{
		{Severity: "low", LastSeen: 100},
		{Severity: "critical", LastSeen: 50},
		{Severity: "high", LastSeen: 10},
		{Severity: "critical", LastSeen: 90},
	}
	SortFindings(in)
	require.Equal(t, []string{"critical", "critical", "high", "low"},
		[]string{in[0].Severity, in[1].Severity, in[2].Severity, in[3].Severity})
	// Within equal severity, most recent first.
	require.Equal(t, int64(90), in[0].LastSeen)
	require.Equal(t, int64(50), in[1].LastSeen)
}

func TestValidSeverity(t *testing.T) {
	require.True(t, ValidSeverity("critical"))
	require.False(t, ValidSeverity("CRITICAL"))
	require.False(t, ValidSeverity(""))
}
```

- [ ] **Step 6: Run it to make sure it fails**

Run: `go test ./internal/model/ -run TestSeverity -v`
Expected: FAIL — `undefined: SeverityRank`

- [ ] **Step 7: Write the minimal implementation**

Create `internal/model/severity.go`:

```go
package model

import "sort"

// Severities are ordered highest-first; index is the sort rank.
var Severities = []string{"critical", "high", "medium", "low"}

// Assessments are the permitted window-level verdicts.
var Assessments = []string{"nominal", "degraded", "incident"}

// Finding statuses.
const (
	StatusOpen  = "open"
	StatusStale = "stale"
)

// SeverityRank returns the sort rank of a severity, lowest number being most
// severe. Unknown severities sort after every known one.
func SeverityRank(s string) int {
	for i, known := range Severities {
		if known == s {
			return i
		}
	}
	return len(Severities)
}

// ValidSeverity reports whether s is one of the permitted severities.
func ValidSeverity(s string) bool {
	return SeverityRank(s) < len(Severities)
}

// ValidAssessment reports whether s is one of the permitted assessments.
func ValidAssessment(s string) bool {
	for _, known := range Assessments {
		if known == s {
			return true
		}
	}
	return false
}

// SortFindings orders findings severity-descending, then last_seen descending.
func SortFindings(f []Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		ri, rj := SeverityRank(f[i].Severity), SeverityRank(f[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return f[i].LastSeen > f[j].LastSeen
	})
}
```

Create `internal/model/finding.go`:

```go
package model

// Finding is one insight about one system. Fingerprint is computed server-side
// from the cited evidence and is the dedup key; the model never supplies it.
type Finding struct {
	ID              string   `json:"id"`
	SystemID        string   `json:"system_id"`
	Fingerprint     string   `json:"fingerprint"`
	Severity        string   `json:"severity"`
	Title           string   `json:"title"`
	Summary         string   `json:"summary"`
	SuggestedAction string   `json:"suggested_action"`
	Modules         []string `json:"modules"`
	Evidence        []string `json:"evidence"`
	Status          string   `json:"status"`
	OccurrenceCount int      `json:"occurrence_count"`
	FirstSeen       int64    `json:"first_seen"`
	LastSeen        int64    `json:"last_seen"`
	ReopenedAt      *int64   `json:"reopened_at,omitempty"`
	LLMModel        string   `json:"llm_model"`
	PromptVersion   string   `json:"prompt_version"`
}
```

- [ ] **Step 8: Run the whole package and make sure it passes**

Run: `go test ./internal/model/ -v`
Expected: PASS, all tests

- [ ] **Step 9: Commit**

```bash
go get github.com/stretchr/testify@latest
go mod tidy
git add internal/model go.mod go.sum
git commit -m "feat(model): bundle protocol, finding and severity ordering types"
```

---

## Task 3: `internal/store` — schema, migrations, systems, templates, baselines

**Files:**
- Create: `internal/store/store.go`, `internal/store/sqlite.go`, `internal/store/postgres.go`, `internal/store/systems.go`
- Create: `internal/store/migrations/0001_init.up.sql`, `internal/store/migrations/0001_init.down.sql`
- Test: `internal/store/store_test.go`, `internal/store/migrate_test.go`

**Interfaces:**
- Consumes: `model.Bundle`, `model.Template`, `model.DigestEntry` (Task 2).
- Produces:
  - `store.Store` interface (extended in Task 4)
  - `store.Open(driver, dsn string) (Store, error)` — driver is `"sqlite"` or `"postgres"`
  - `store.BaselineKey{ModuleID string; Priority int}`
  - `store.System{SystemID, TenantID, CollectorVersion string; FirstSeen, LastSeen int64}`
  - `Store.Migrate(ctx) error`
  - `Store.UpsertSystem(ctx, System) error`
  - `Store.KnownTemplates(ctx, systemID string) (map[string]bool, error)`
  - `Store.UpsertTemplates(ctx, systemID string, ts []model.Template, now int64) error`
  - `Store.Baselines(ctx, systemID string) (map[BaselineKey]float64, error)`
  - `Store.UpsertBaselines(ctx, systemID string, d []model.DigestEntry, alpha float64) error`
  - `Store.Close() error`

- [ ] **Step 1: Write the failing migration test**

Create `internal/store/migrate_test.go`:

```go
package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// openSQLite returns a Store backed by a throwaway file. A file, not
// :memory:, because WAL mode and busy_timeout only mean anything on a file.
func openSQLite(t *testing.T) Store {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "test.db")
	s, err := Open("sqlite", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	require.NoError(t, s.Migrate(context.Background()))
	return s
}

func TestMigrateSQLiteIsIdempotent(t *testing.T) {
	s := openSQLite(t)
	// Migrate again on an already-migrated database.
	require.NoError(t, s.Migrate(context.Background()))
}

// TestMigratePostgres enforces the portability rules in Global Constraints.
// It is the reason CI runs a Postgres service.
func TestMigratePostgres(t *testing.T) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set")
	}
	s, err := Open("postgres", dsn)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	require.NoError(t, s.Migrate(context.Background()))
	require.NoError(t, s.Migrate(context.Background()))
}
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `go test ./internal/store/ -run TestMigrate -v`
Expected: FAIL — `undefined: Open`

- [ ] **Step 3: Write the migration SQL**

Create `internal/store/migrations/0001_init.up.sql`:

```sql
CREATE TABLE IF NOT EXISTS systems (
    system_id         TEXT    PRIMARY KEY,
    tenant_id         TEXT    NOT NULL DEFAULT '',
    collector_version TEXT    NOT NULL DEFAULT '',
    first_seen        BIGINT  NOT NULL,
    last_seen         BIGINT  NOT NULL
);

CREATE TABLE IF NOT EXISTS system_templates (
    system_id   TEXT   NOT NULL,
    template    TEXT   NOT NULL,
    module_id   TEXT   NOT NULL DEFAULT '',
    priority    INT    NOT NULL DEFAULT 0,
    category    TEXT   NOT NULL DEFAULT '',
    first_seen  BIGINT NOT NULL,
    last_seen   BIGINT NOT NULL,
    total_count BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (system_id, template)
);
CREATE INDEX IF NOT EXISTS idx_templates_last_seen
    ON system_templates (last_seen);

CREATE TABLE IF NOT EXISTS module_baselines (
    system_id  TEXT   NOT NULL,
    module_id  TEXT   NOT NULL,
    priority   INT    NOT NULL,
    ewma_rate  DOUBLE PRECISION NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (system_id, module_id, priority)
);

CREATE TABLE IF NOT EXISTS findings (
    id               TEXT   PRIMARY KEY,
    system_id        TEXT   NOT NULL,
    fingerprint      TEXT   NOT NULL,
    severity         TEXT   NOT NULL,
    title            TEXT   NOT NULL,
    summary          TEXT   NOT NULL,
    suggested_action TEXT   NOT NULL DEFAULT '',
    modules          TEXT   NOT NULL DEFAULT '[]',
    evidence         TEXT   NOT NULL DEFAULT '[]',
    status           TEXT   NOT NULL,
    occurrence_count INT    NOT NULL DEFAULT 1,
    first_seen       BIGINT NOT NULL,
    last_seen        BIGINT NOT NULL,
    reopened_at      BIGINT,
    llm_model        TEXT   NOT NULL DEFAULT '',
    prompt_version   TEXT   NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_fingerprint
    ON findings (system_id, fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_lookup
    ON findings (system_id, status, last_seen);

CREATE TABLE IF NOT EXISTS analyses (
    id            TEXT   PRIMARY KEY,
    system_id     TEXT   NOT NULL,
    window_start  BIGINT NOT NULL,
    window_end    BIGINT NOT NULL,
    gated         INT    NOT NULL DEFAULT 0,
    gate_reasons  TEXT   NOT NULL DEFAULT '[]',
    llm_called    INT    NOT NULL DEFAULT 0,
    input_tokens  INT    NOT NULL DEFAULT 0,
    output_tokens INT    NOT NULL DEFAULT 0,
    cost_micros   BIGINT NOT NULL DEFAULT 0,
    model         TEXT   NOT NULL DEFAULT '',
    duration_ms   INT    NOT NULL DEFAULT 0,
    error         TEXT   NOT NULL DEFAULT '',
    created_at    BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_analyses_window
    ON analyses (system_id, window_start);
CREATE INDEX IF NOT EXISTS idx_analyses_created
    ON analyses (created_at);
```

`BIGINT`, `INT`, `DOUBLE PRECISION` and `TEXT` are the four types that mean the same thing in both dialects. Booleans are `INT` because SQLite has no boolean type — a `BOOLEAN` column would work in SQLite by aliasing but produce a genuine type mismatch when `bun` scans a Postgres `boolean` into an `int`.

Create `internal/store/migrations/0001_init.down.sql`:

```sql
DROP TABLE IF EXISTS analyses;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS module_baselines;
DROP TABLE IF EXISTS system_templates;
DROP TABLE IF EXISTS systems;
```

- [ ] **Step 4: Write the store interface and the SQLite implementation**

Create `internal/store/store.go`:

```go
// Package store owns the database schema and every query against it. No SQL
// exists outside this package.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"

	"github.com/nethesis/nethesis-insights/internal/model"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// BaselineKey identifies one rate baseline.
type BaselineKey struct {
	ModuleID string
	Priority int
}

// System is a registered node.
type System struct {
	SystemID         string
	TenantID         string
	CollectorVersion string
	FirstSeen        int64
	LastSeen         int64
}

// Store is the whole persistence surface. Implementations must be safe for
// concurrent use.
type Store interface {
	Migrate(ctx context.Context) error
	Close() error

	UpsertSystem(ctx context.Context, s System) error
	KnownTemplates(ctx context.Context, systemID string) (map[string]bool, error)
	UpsertTemplates(ctx context.Context, systemID string, ts []model.Template, now int64) error
	Baselines(ctx context.Context, systemID string) (map[BaselineKey]float64, error)
	UpsertBaselines(ctx context.Context, systemID string, d []model.DigestEntry, alpha float64) error
}

// ErrUnknownDriver is returned by Open for an unsupported driver name.
var ErrUnknownDriver = errors.New("store: unknown driver")

// Open returns a Store for driver "sqlite" or "postgres".
func Open(driver, dsn string) (Store, error) {
	switch driver {
	case "sqlite":
		return openSQLite(dsn)
	case "postgres":
		return openPostgres(dsn)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownDriver, driver)
	}
}
```

Create `internal/store/sqlite.go`:

```go
package store

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	_ "modernc.org/sqlite" // CGO-free driver
)

type sqliteStore struct {
	db *bun.DB
	// writeMu serializes writes. SQLite permits one writer at a time; taking
	// a mutex gives the same guarantee as a dedicated writer goroutine with
	// no channel lifecycle to leak (see plan Deviation 3).
	writeMu sync.Mutex
	dsn     string
}

func openSQLite(dsn string) (Store, error) {
	// WAL lets the read API run concurrently with the analyzer's writes;
	// busy_timeout absorbs the brief contention that remains.
	conn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)", dsn)
	sqldb, err := sql.Open("sqlite", conn)
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite: %w", err)
	}
	// One connection removes any chance of "database is locked" from
	// concurrent writers inside this process.
	sqldb.SetMaxOpenConns(1)
	return &sqliteStore{db: bun.NewDB(sqldb, sqlitedialect.New()), dsn: dsn}, nil
}

func (s *sqliteStore) Migrate(ctx context.Context) error {
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("store: migration source: %w", err)
	}
	drv, err := sqlite.WithInstance(s.db.DB, &sqlite.Config{})
	if err != nil {
		return fmt.Errorf("store: migration driver: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "sqlite", drv)
	if err != nil {
		return fmt.Errorf("store: migrator: %w", err)
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("store: migrate: %w", err)
	}
	return nil
}

func (s *sqliteStore) Close() error { return s.db.Close() }

func (s *sqliteStore) bun() *bun.DB      { return s.db }
func (s *sqliteStore) lock() *sync.Mutex { return &s.writeMu }
```

Create `internal/store/postgres.go`:

```go
package store

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
)

type pgStore struct {
	db *bun.DB
	// Postgres handles concurrent writers; the mutex is never contended and
	// exists only so pgStore satisfies the same internal helper interface.
	writeMu sync.Mutex
}

func openPostgres(dsn string) (Store, error) {
	sqldb, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open postgres: %w", err)
	}
	return &pgStore{db: bun.NewDB(sqldb, pgdialect.New())}, nil
}

func (s *pgStore) Migrate(ctx context.Context) error {
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("store: migration source: %w", err)
	}
	drv, err := migratepg.WithInstance(s.db.DB, &migratepg.Config{})
	if err != nil {
		return fmt.Errorf("store: migration driver: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "pgx5", drv)
	if err != nil {
		return fmt.Errorf("store: migrator: %w", err)
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("store: migrate: %w", err)
	}
	return nil
}

func (s *pgStore) Close() error { return s.db.Close() }

func (s *pgStore) bun() *bun.DB      { return s.db }
func (s *pgStore) lock() *sync.Mutex { return &s.writeMu }
```

- [ ] **Step 5: Run the migration tests**

```bash
go get github.com/uptrace/bun github.com/uptrace/bun/dialect/sqlitedialect \
       github.com/uptrace/bun/dialect/pgdialect \
       github.com/golang-migrate/migrate/v4 github.com/jackc/pgx/v5 \
       modernc.org/sqlite
go mod tidy
go test ./internal/store/ -run TestMigrate -v
```

Expected: `TestMigrateSQLiteIsIdempotent` PASS, `TestMigratePostgres` SKIP.

Then prove the Postgres path on the dev machine too, rather than only in CI. Port `55432` avoids colliding with anything the shared cluster runs:

```bash
podman run -d --name insights-pg-test \
  -e POSTGRES_PASSWORD=test -e POSTGRES_DB=insights_test \
  -p 127.0.0.1:55432:5432 postgres:16-alpine

until podman exec insights-pg-test pg_isready -q; do sleep 1; done

TEST_POSTGRES_DSN='postgres://postgres:test@127.0.0.1:55432/insights_test?sslmode=disable' \
  go test ./internal/store/ -run TestMigratePostgres -v

podman rm -f insights-pg-test
```

Expected: PASS. A failure here means one of the portability rules in Global Constraints was broken — most likely a type or an `ON CONFLICT` form that only SQLite accepts.

- [ ] **Step 6: Write the failing tests for systems, templates and baselines**

Create `internal/store/store_test.go`:

```go
package store

import (
	"context"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/stretchr/testify/require"
)

func TestUpsertSystemPreservesFirstSeen(t *testing.T) {
	ctx, s := context.Background(), openSQLite(t)
	require.NoError(t, s.UpsertSystem(ctx, System{
		SystemID: "sys1", TenantID: "t1", CollectorVersion: "2.0.0",
		FirstSeen: 100, LastSeen: 100,
	}))
	require.NoError(t, s.UpsertSystem(ctx, System{
		SystemID: "sys1", TenantID: "t1", CollectorVersion: "2.1.0",
		FirstSeen: 500, LastSeen: 500,
	}))

	// first_seen must not move on a repeat visit; last_seen and version must.
	// Scanned into a tagged local struct rather than store.System, which
	// carries no bun tags — it is a plain API type, not a table mapping.
	var got struct {
		FirstSeen        int64  `bun:"first_seen"`
		LastSeen         int64  `bun:"last_seen"`
		CollectorVersion string `bun:"collector_version"`
	}
	require.NoError(t, s.(*sqliteStore).db.NewSelect().
		Table("systems").
		Column("first_seen", "last_seen", "collector_version").
		Where("system_id = ?", "sys1").Scan(ctx, &got))
	require.Equal(t, int64(100), got.FirstSeen)
	require.Equal(t, int64(500), got.LastSeen)
	require.Equal(t, "2.1.0", got.CollectorVersion)
}

func TestKnownTemplatesIsEmptyForNewSystem(t *testing.T) {
	ctx, s := context.Background(), openSQLite(t)
	known, err := s.KnownTemplates(ctx, "sys1")
	require.NoError(t, err)
	require.Empty(t, known)
}

func TestUpsertTemplatesAccumulatesCounts(t *testing.T) {
	ctx, s := context.Background(), openSQLite(t)
	ts := []model.Template{{
		Template: "conn refused to <IP>", Count: 5, ModuleID: "m1",
		Priority: 3, Category: "security", FirstSeen: 10, LastSeen: 20,
	}}
	require.NoError(t, s.UpsertTemplates(ctx, "sys1", ts, 100))

	ts[0].Count = 7
	require.NoError(t, s.UpsertTemplates(ctx, "sys1", ts, 200))

	known, err := s.KnownTemplates(ctx, "sys1")
	require.NoError(t, err)
	require.True(t, known["conn refused to <IP>"])

	var row struct {
		TotalCount int64 `bun:"total_count"`
		FirstSeen  int64 `bun:"first_seen"`
		LastSeen   int64 `bun:"last_seen"`
	}
	require.NoError(t, s.(*sqliteStore).db.NewSelect().
		Table("system_templates").
		Column("total_count", "first_seen", "last_seen").
		Where("system_id = ?", "sys1").Scan(ctx, &row))
	require.Equal(t, int64(12), row.TotalCount)
	require.Equal(t, int64(100), row.FirstSeen) // unchanged
	require.Equal(t, int64(200), row.LastSeen)  // advanced
}

func TestTemplatesAreScopedPerSystem(t *testing.T) {
	ctx, s := context.Background(), openSQLite(t)
	ts := []model.Template{{Template: "same text", Count: 1, ModuleID: "m"}}
	require.NoError(t, s.UpsertTemplates(ctx, "sys1", ts, 100))

	// The same template text on another system must still look novel there.
	known, err := s.KnownTemplates(ctx, "sys2")
	require.NoError(t, err)
	require.False(t, known["same text"])
}

func TestUpsertTemplatesNeverStoresSamples(t *testing.T) {
	ctx, s := context.Background(), openSQLite(t)
	require.NoError(t, s.UpsertTemplates(ctx, "sys1", []model.Template{{
		Template: "masked <IP>", Count: 1, ModuleID: "m",
		Samples: []string{"SECRET raw line 10.0.0.4"},
	}}, 100))

	// Spec §10: raw samples must never reach the database. Assert no column
	// anywhere in the row contains the sample text.
	rows, err := s.(*sqliteStore).db.QueryContext(ctx,
		`SELECT * FROM system_templates`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	require.NoError(t, err)
	require.True(t, rows.Next())
	cells := make([]any, len(cols))
	for i := range cells {
		var v any
		cells[i] = &v
	}
	require.NoError(t, rows.Scan(cells...))
	require.NoError(t, rows.Err())
	for i, c := range cells {
		v := *(c.(*any))
		if str, ok := v.(string); ok {
			require.NotContains(t, str, "SECRET", "column %s leaked a sample", cols[i])
		}
	}
}

func TestBaselinesEWMA(t *testing.T) {
	ctx, s := context.Background(), openSQLite(t)
	d := []model.DigestEntry{{ModuleID: "m1", Priority: 3, Observed: 100}}

	// First observation seeds the baseline at the observed value.
	require.NoError(t, s.UpsertBaselines(ctx, "sys1", d, 0.3))
	b, err := s.Baselines(ctx, "sys1")
	require.NoError(t, err)
	require.InDelta(t, 100.0, b[BaselineKey{"m1", 3}], 0.001)

	// Second observation blends: 0.3*200 + 0.7*100 = 130
	d[0].Observed = 200
	require.NoError(t, s.UpsertBaselines(ctx, "sys1", d, 0.3))
	b, err = s.Baselines(ctx, "sys1")
	require.NoError(t, err)
	require.InDelta(t, 130.0, b[BaselineKey{"m1", 3}], 0.001)
}
```

The samples test is worth its awkwardness: it is the only automated check that the §10 data-protection boundary holds, and it fails loudly if someone later adds a `samples` column for convenience.

- [ ] **Step 7: Run them to make sure they fail**

Run: `go test ./internal/store/ -run 'TestUpsert|TestKnown|TestBaselines|TestTemplates' -v`
Expected: FAIL — `UpsertSystem` etc. not implemented

- [ ] **Step 8: Write the implementation**

Create `internal/store/systems.go`:

```go
package store

import (
	"context"
	"fmt"
	"sync"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/uptrace/bun"
)

// writer is satisfied by both sqliteStore and pgStore so the query bodies are
// written once. This is what makes the two dialects share one query codebase.
type writer interface {
	bun() *bun.DB
	lock() *sync.Mutex
}

func upsertSystem(ctx context.Context, w writer, s System) error {
	w.lock().Lock()
	defer w.lock().Unlock()
	_, err := w.bun().NewRaw(`
		INSERT INTO systems
			(system_id, tenant_id, collector_version, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (system_id) DO UPDATE SET
			tenant_id         = excluded.tenant_id,
			collector_version = excluded.collector_version,
			last_seen         = excluded.last_seen`,
		s.SystemID, s.TenantID, s.CollectorVersion, s.FirstSeen, s.LastSeen,
	).Exec(ctx)
	if err != nil {
		return fmt.Errorf("store: upsert system: %w", err)
	}
	return nil
}

func knownTemplates(ctx context.Context, w writer, systemID string) (map[string]bool, error) {
	var texts []string
	err := w.bun().NewRaw(
		`SELECT template FROM system_templates WHERE system_id = ?`, systemID,
	).Scan(ctx, &texts)
	if err != nil {
		return nil, fmt.Errorf("store: known templates: %w", err)
	}
	known := make(map[string]bool, len(texts))
	for _, t := range texts {
		known[t] = true
	}
	return known, nil
}

func upsertTemplates(ctx context.Context, w writer, systemID string,
	ts []model.Template, now int64) error {
	if len(ts) == 0 {
		return nil
	}
	w.lock().Lock()
	defer w.lock().Unlock()
	tx, err := w.bun().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, t := range ts {
		// Samples are deliberately not referenced here (spec §10).
		if _, err := tx.NewRaw(`
			INSERT INTO system_templates
				(system_id, template, module_id, priority, category,
				 first_seen, last_seen, total_count)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (system_id, template) DO UPDATE SET
				last_seen   = excluded.last_seen,
				total_count = system_templates.total_count + excluded.total_count,
				category    = excluded.category`,
			systemID, t.Template, t.ModuleID, t.Priority, t.Category,
			now, now, t.Count,
		).Exec(ctx); err != nil {
			return fmt.Errorf("store: upsert template: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit templates: %w", err)
	}
	return nil
}

func baselines(ctx context.Context, w writer, systemID string) (map[BaselineKey]float64, error) {
	var rows []struct {
		ModuleID string  `bun:"module_id"`
		Priority int     `bun:"priority"`
		Rate     float64 `bun:"ewma_rate"`
	}
	err := w.bun().NewRaw(`
		SELECT module_id, priority, ewma_rate
		FROM module_baselines WHERE system_id = ?`, systemID,
	).Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("store: baselines: %w", err)
	}
	out := make(map[BaselineKey]float64, len(rows))
	for _, r := range rows {
		out[BaselineKey{r.ModuleID, r.Priority}] = r.Rate
	}
	return out, nil
}

func upsertBaselines(ctx context.Context, w writer, systemID string,
	d []model.DigestEntry, alpha float64) error {
	if len(d) == 0 {
		return nil
	}
	w.lock().Lock()
	defer w.lock().Unlock()
	tx, err := w.bun().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, e := range d {
		// First observation seeds at the observed value; later ones blend.
		// Expressed in SQL so the read-modify-write is atomic per row.
		if _, err := tx.NewRaw(`
			INSERT INTO module_baselines
				(system_id, module_id, priority, ewma_rate, updated_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (system_id, module_id, priority) DO UPDATE SET
				ewma_rate  = (? * excluded.ewma_rate)
				             + ((1 - ?) * module_baselines.ewma_rate),
				updated_at = excluded.updated_at`,
			systemID, e.ModuleID, e.Priority, float64(e.Observed), e.Observed,
			alpha, alpha,
		).Exec(ctx); err != nil {
			return fmt.Errorf("store: upsert baseline: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit baselines: %w", err)
	}
	return nil
}
```

Now bind these to both implementations. Append to `internal/store/sqlite.go`:

```go
func (s *sqliteStore) UpsertSystem(ctx context.Context, sys System) error {
	return upsertSystem(ctx, s, sys)
}

func (s *sqliteStore) KnownTemplates(ctx context.Context, systemID string) (map[string]bool, error) {
	return knownTemplates(ctx, s, systemID)
}

func (s *sqliteStore) UpsertTemplates(ctx context.Context, systemID string,
	ts []model.Template, now int64) error {
	return upsertTemplates(ctx, s, systemID, ts, now)
}

func (s *sqliteStore) Baselines(ctx context.Context, systemID string) (map[BaselineKey]float64, error) {
	return baselines(ctx, s, systemID)
}

func (s *sqliteStore) UpsertBaselines(ctx context.Context, systemID string,
	d []model.DigestEntry, alpha float64) error {
	return upsertBaselines(ctx, s, systemID, d, alpha)
}
```

Add the identical five methods to `internal/store/postgres.go` with receiver `(s *pgStore)`, delegating to the same package-level functions. Add the required imports (`context`, `github.com/nethesis/nethesis-insights/internal/model`) to both files.

- [ ] **Step 9: Run the tests and make sure they pass**

Run: `go test ./internal/store/ -v`
Expected: PASS (Postgres test skipped locally)

- [ ] **Step 10: Commit**

```bash
git add internal/store go.mod go.sum
git commit -m "feat(store): schema, dual-dialect migrations, systems and baselines"
```

---

## Task 4: `internal/store` — findings, analyses ledger, pruning

**Files:**
- Create: `internal/store/findings.go`, `internal/store/prune.go`
- Modify: `internal/store/store.go` (extend `Store`), `internal/store/sqlite.go`, `internal/store/postgres.go` (bind methods)
- Test: `internal/store/findings_test.go`, `internal/store/analyses_test.go`, `internal/store/prune_test.go`

**Interfaces:**
- Consumes: `store.Store`, the `writer` helper interface, `openSQLite` test helper (Task 3); `model.Finding`, `model.SortFindings`, `model.StatusOpen`, `model.StatusStale` (Task 2).
- Produces, added to `Store`:
  - `BeginAnalysis(ctx, systemID string, windowStart, windowEnd, now int64) (bool, error)` — `false` means duplicate window
  - `FinalizeAnalysis(ctx, a Analysis) error`
  - `SpendSince(ctx, sinceMs int64) (int64, error)` — summed `cost_micros`
  - `OpenFindings(ctx, systemID string) ([]model.Finding, error)`
  - `UpsertFinding(ctx, f model.Finding, now int64) (Outcome, error)`
  - `MarkStale(ctx, systemID string, olderThan int64) (int, error)`
  - `ListFindings(ctx, systemID string, since int64, status string) ([]model.Finding, error)`
  - `PruneTemplates/PruneFindings/PruneAnalyses(ctx, olderThan int64) (int, error)`
  - types `store.Analysis`, `store.Outcome` with `OutcomeInserted`, `OutcomeBumped`, `OutcomeReopened`

- [ ] **Step 1: Write the failing finding-lifecycle tests**

Create `internal/store/findings_test.go`:

```go
package store

import (
	"context"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/stretchr/testify/require"
)

func finding(fp, severity string, seen int64) model.Finding {
	return model.Finding{
		SystemID: "sys1", Fingerprint: fp, Severity: severity,
		Title: "t", Summary: "s", SuggestedAction: "a",
		Modules: []string{"m1"}, Evidence: []string{"tmpl <IP>"},
		FirstSeen: seen, LastSeen: seen,
		LLMModel: "gpt-4o-mini", PromptVersion: "v1",
	}
}

func TestNewFindingIsInserted(t *testing.T) {
	ctx, s := context.Background(), openSQLite(t)
	out, err := s.UpsertFinding(ctx, finding("fp1", "high", 100), 100)
	require.NoError(t, err)
	require.Equal(t, OutcomeInserted, out)

	open, err := s.OpenFindings(ctx, "sys1")
	require.NoError(t, err)
	require.Len(t, open, 1)
	require.Equal(t, model.StatusOpen, open[0].Status)
	require.Equal(t, 1, open[0].OccurrenceCount)
	require.NotEmpty(t, open[0].ID, "ID must be a generated ULID")
	require.Equal(t, []string{"m1"}, open[0].Modules)
	require.Equal(t, []string{"tmpl <IP>"}, open[0].Evidence)
}

func TestRecurrenceBumpsInsteadOfInserting(t *testing.T) {
	ctx, s := context.Background(), openSQLite(t)
	_, err := s.UpsertFinding(ctx, finding("fp1", "high", 100), 100)
	require.NoError(t, err)

	out, err := s.UpsertFinding(ctx, finding("fp1", "high", 200), 200)
	require.NoError(t, err)
	require.Equal(t, OutcomeBumped, out)

	open, err := s.OpenFindings(ctx, "sys1")
	require.NoError(t, err)
	require.Len(t, open, 1, "recurrence must never insert a second row")
	require.Equal(t, 2, open[0].OccurrenceCount)
	require.Equal(t, int64(100), open[0].FirstSeen, "first_seen must not move")
	require.Equal(t, int64(200), open[0].LastSeen)
	require.Nil(t, open[0].ReopenedAt, "a bump is not a reopen")
}

func TestFingerprintIsScopedPerSystem(t *testing.T) {
	ctx, s := context.Background(), openSQLite(t)
	f := finding("fp1", "high", 100)
	_, err := s.UpsertFinding(ctx, f, 100)
	require.NoError(t, err)

	f.SystemID = "sys2"
	out, err := s.UpsertFinding(ctx, f, 100)
	require.NoError(t, err)
	require.Equal(t, OutcomeInserted, out,
		"the same fingerprint on another system is a different finding")
}

func TestMarkStaleThenRecurrenceReopens(t *testing.T) {
	ctx, s := context.Background(), openSQLite(t)
	_, err := s.UpsertFinding(ctx, finding("fp1", "high", 100), 100)
	require.NoError(t, err)

	n, err := s.MarkStale(ctx, "sys1", 500)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	open, err := s.OpenFindings(ctx, "sys1")
	require.NoError(t, err)
	require.Empty(t, open)

	out, err := s.UpsertFinding(ctx, finding("fp1", "high", 900), 900)
	require.NoError(t, err)
	require.Equal(t, OutcomeReopened, out)

	open, err = s.OpenFindings(ctx, "sys1")
	require.NoError(t, err)
	require.Len(t, open, 1)
	require.NotNil(t, open[0].ReopenedAt)
	require.Equal(t, int64(900), *open[0].ReopenedAt)
}

func TestMarkStaleSparesRecentFindings(t *testing.T) {
	ctx, s := context.Background(), openSQLite(t)
	_, err := s.UpsertFinding(ctx, finding("fp1", "high", 1000), 1000)
	require.NoError(t, err)
	n, err := s.MarkStale(ctx, "sys1", 500)
	require.NoError(t, err)
	require.Equal(t, 0, n, "last_seen newer than the cutoff must stay open")
}

func TestListFindingsIsSeverityDescending(t *testing.T) {
	ctx, s := context.Background(), openSQLite(t)
	for _, f := range []model.Finding{
		finding("fp-low", "low", 400),
		finding("fp-crit", "critical", 100),
		finding("fp-med", "medium", 300),
	} {
		_, err := s.UpsertFinding(ctx, f, f.LastSeen)
		require.NoError(t, err)
	}
	got, err := s.ListFindings(ctx, "sys1", 0, "")
	require.NoError(t, err)
	require.Equal(t, []string{"critical", "medium", "low"},
		[]string{got[0].Severity, got[1].Severity, got[2].Severity})
}

func TestListFindingsFiltersBySinceAndStatus(t *testing.T) {
	ctx, s := context.Background(), openSQLite(t)
	_, err := s.UpsertFinding(ctx, finding("fp1", "high", 100), 100)
	require.NoError(t, err)
	_, err = s.UpsertFinding(ctx, finding("fp2", "high", 900), 900)
	require.NoError(t, err)

	got, err := s.ListFindings(ctx, "sys1", 500, "")
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "fp2", got[0].Fingerprint)

	_, err = s.MarkStale(ctx, "sys1", 500)
	require.NoError(t, err)
	got, err = s.ListFindings(ctx, "sys1", 0, model.StatusStale)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "fp1", got[0].Fingerprint)
}

func TestSeverityEscalatesOnRecurrence(t *testing.T) {
	ctx, s := context.Background(), openSQLite(t)
	_, err := s.UpsertFinding(ctx, finding("fp1", "medium", 100), 100)
	require.NoError(t, err)
	_, err = s.UpsertFinding(ctx, finding("fp1", "critical", 200), 200)
	require.NoError(t, err)

	open, err := s.OpenFindings(ctx, "sys1")
	require.NoError(t, err)
	require.Equal(t, "critical", open[0].Severity,
		"an escalating condition must not stay pinned at its first severity")
}
```

That last test encodes a real judgement call: a recurring finding whose severity rises must escalate. Freezing severity at first sight would hide a `medium` turning into a `critical` behind a silent occurrence bump.

- [ ] **Step 2: Write the failing ledger tests**

Create `internal/store/analyses_test.go`:

```go
package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBeginAnalysisIsIdempotentPerWindow(t *testing.T) {
	ctx, s := context.Background(), openSQLite(t)
	fresh, err := s.BeginAnalysis(ctx, "sys1", 1000, 1900, 2000)
	require.NoError(t, err)
	require.True(t, fresh)

	// An edge retry of the same window must be recognised, not reprocessed.
	fresh, err = s.BeginAnalysis(ctx, "sys1", 1000, 1900, 2000)
	require.NoError(t, err)
	require.False(t, fresh)
}

func TestBeginAnalysisSeparatesSystems(t *testing.T) {
	ctx, s := context.Background(), openSQLite(t)
	_, err := s.BeginAnalysis(ctx, "sys1", 1000, 1900, 2000)
	require.NoError(t, err)
	fresh, err := s.BeginAnalysis(ctx, "sys2", 1000, 1900, 2000)
	require.NoError(t, err)
	require.True(t, fresh, "same window on another system is a new analysis")
}

func TestFinalizeAnalysisRecordsTheLedger(t *testing.T) {
	ctx, s := context.Background(), openSQLite(t)
	_, err := s.BeginAnalysis(ctx, "sys1", 1000, 1900, 2000)
	require.NoError(t, err)
	require.NoError(t, s.FinalizeAnalysis(ctx, Analysis{
		SystemID: "sys1", WindowStart: 1000,
		Gated: false, GateReasons: []string{"new_templates=2"},
		LLMCalled: true, InputTokens: 12400, OutputTokens: 300,
		CostMicros: 2040, Model: "gpt-4o-mini", DurationMs: 3100,
	}))

	spend, err := s.SpendSince(ctx, 0)
	require.NoError(t, err)
	require.Equal(t, int64(2040), spend)
}

func TestSpendSinceIgnoresOlderRows(t *testing.T) {
	ctx, s := context.Background(), openSQLite(t)
	_, err := s.BeginAnalysis(ctx, "sys1", 1000, 1900, 1000)
	require.NoError(t, err)
	require.NoError(t, s.FinalizeAnalysis(ctx, Analysis{
		SystemID: "sys1", WindowStart: 1000, CostMicros: 500}))
	_, err = s.BeginAnalysis(ctx, "sys1", 9000, 9900, 9000)
	require.NoError(t, err)
	require.NoError(t, s.FinalizeAnalysis(ctx, Analysis{
		SystemID: "sys1", WindowStart: 9000, CostMicros: 700}))

	spend, err := s.SpendSince(ctx, 5000)
	require.NoError(t, err)
	require.Equal(t, int64(700), spend, "only rows created after the cutoff count")
}

func TestSpendSinceIsZeroOnEmptyLedger(t *testing.T) {
	ctx, s := context.Background(), openSQLite(t)
	spend, err := s.SpendSince(ctx, 0)
	require.NoError(t, err)
	require.Zero(t, spend, "SUM over no rows is NULL and must scan as 0")
}

func TestGatedAnalysisCostsNothing(t *testing.T) {
	ctx, s := context.Background(), openSQLite(t)
	_, err := s.BeginAnalysis(ctx, "sys1", 1000, 1900, 2000)
	require.NoError(t, err)
	require.NoError(t, s.FinalizeAnalysis(ctx, Analysis{
		SystemID: "sys1", WindowStart: 1000,
		Gated: true, GateReasons: []string{}, LLMCalled: false}))
	spend, err := s.SpendSince(ctx, 0)
	require.NoError(t, err)
	require.Zero(t, spend)
}
```

`TestSpendSinceIsZeroOnEmptyLedger` guards a specific trap: `SUM()` over zero rows returns `NULL` in both dialects, and scanning that into a plain `int64` errors. The implementation must scan into `sql.NullInt64`. This is the first query the spend cap runs on a fresh deployment, so getting it wrong breaks the cost ceiling on day one.

- [ ] **Step 3: Run both files to make sure they fail**

Run: `go test ./internal/store/ -run 'TestNewFinding|TestBeginAnalysis' -v`
Expected: FAIL — `UpsertFinding`, `BeginAnalysis` undefined

- [ ] **Step 4: Extend the `Store` interface**

In `internal/store/store.go`, add these lines inside the `Store` interface, after `UpsertBaselines`:

```go
	BeginAnalysis(ctx context.Context, systemID string, windowStart, windowEnd, now int64) (bool, error)
	FinalizeAnalysis(ctx context.Context, a Analysis) error
	SpendSince(ctx context.Context, sinceMs int64) (int64, error)

	OpenFindings(ctx context.Context, systemID string) ([]model.Finding, error)
	UpsertFinding(ctx context.Context, f model.Finding, now int64) (Outcome, error)
	MarkStale(ctx context.Context, systemID string, olderThan int64) (int, error)
	ListFindings(ctx context.Context, systemID string, since int64, status string) ([]model.Finding, error)

	PruneTemplates(ctx context.Context, olderThan int64) (int, error)
	PruneFindings(ctx context.Context, olderThan int64) (int, error)
	PruneAnalyses(ctx context.Context, olderThan int64) (int, error)
```

Append the supporting types to the same file:

```go
// Outcome reports what UpsertFinding did, so callers can tell an alert-worthy
// event from a silent recurrence.
type Outcome string

const (
	OutcomeInserted Outcome = "inserted"
	OutcomeBumped   Outcome = "bumped"
	OutcomeReopened Outcome = "reopened"
)

// Analysis is one row of the cost and audit ledger.
type Analysis struct {
	SystemID     string
	WindowStart  int64
	Gated        bool
	GateReasons  []string
	LLMCalled    bool
	InputTokens  int
	OutputTokens int
	CostMicros   int64
	Model        string
	DurationMs   int
	Error        string
}
```

- [ ] **Step 5: Write `internal/store/findings.go`**

```go
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/oklog/ulid/v2"
)

func newID() string { return ulid.Make().String() }

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func beginAnalysis(ctx context.Context, w writer, systemID string,
	windowStart, windowEnd, now int64) (bool, error) {
	w.lock().Lock()
	defer w.lock().Unlock()
	// DO NOTHING makes a duplicate window a zero-row result rather than an
	// error, so an edge retry is ordinary data instead of an exception.
	res, err := w.bun().NewRaw(`
		INSERT INTO analyses (id, system_id, window_start, window_end, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (system_id, window_start) DO NOTHING`,
		newID(), systemID, windowStart, windowEnd, now,
	).Exec(ctx)
	if err != nil {
		return false, fmt.Errorf("store: begin analysis: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: begin analysis rows: %w", err)
	}
	return n > 0, nil
}

func finalizeAnalysis(ctx context.Context, w writer, a Analysis) error {
	reasons, err := json.Marshal(a.GateReasons)
	if err != nil {
		return fmt.Errorf("store: marshal gate reasons: %w", err)
	}
	w.lock().Lock()
	defer w.lock().Unlock()
	_, err = w.bun().NewRaw(`
		UPDATE analyses SET
			gated = ?, gate_reasons = ?, llm_called = ?,
			input_tokens = ?, output_tokens = ?, cost_micros = ?,
			model = ?, duration_ms = ?, error = ?
		WHERE system_id = ? AND window_start = ?`,
		boolToInt(a.Gated), string(reasons), boolToInt(a.LLMCalled),
		a.InputTokens, a.OutputTokens, a.CostMicros,
		a.Model, a.DurationMs, a.Error, a.SystemID, a.WindowStart,
	).Exec(ctx)
	if err != nil {
		return fmt.Errorf("store: finalize analysis: %w", err)
	}
	return nil
}

func spendSince(ctx context.Context, w writer, sinceMs int64) (int64, error) {
	// NullInt64 because SUM() over zero rows is NULL in both dialects.
	var total sql.NullInt64
	err := w.bun().NewRaw(
		`SELECT SUM(cost_micros) FROM analyses WHERE created_at >= ?`, sinceMs,
	).Scan(ctx, &total)
	if err != nil {
		return 0, fmt.Errorf("store: spend since: %w", err)
	}
	return total.Int64, nil
}

// findingRow is the on-disk shape. Modules and Evidence are JSON TEXT per the
// portability rules, so they are marshalled in Go, never by the database.
type findingRow struct {
	ID              string        `bun:"id"`
	SystemID        string        `bun:"system_id"`
	Fingerprint     string        `bun:"fingerprint"`
	Severity        string        `bun:"severity"`
	Title           string        `bun:"title"`
	Summary         string        `bun:"summary"`
	SuggestedAction string        `bun:"suggested_action"`
	Modules         string        `bun:"modules"`
	Evidence        string        `bun:"evidence"`
	Status          string        `bun:"status"`
	OccurrenceCount int           `bun:"occurrence_count"`
	FirstSeen       int64         `bun:"first_seen"`
	LastSeen        int64         `bun:"last_seen"`
	ReopenedAt      sql.NullInt64 `bun:"reopened_at"`
	LLMModel        string        `bun:"llm_model"`
	PromptVersion   string        `bun:"prompt_version"`
}

func (r findingRow) toModel() (model.Finding, error) {
	f := model.Finding{
		ID: r.ID, SystemID: r.SystemID, Fingerprint: r.Fingerprint,
		Severity: r.Severity, Title: r.Title, Summary: r.Summary,
		SuggestedAction: r.SuggestedAction, Status: r.Status,
		OccurrenceCount: r.OccurrenceCount,
		FirstSeen:       r.FirstSeen, LastSeen: r.LastSeen,
		LLMModel: r.LLMModel, PromptVersion: r.PromptVersion,
	}
	if err := json.Unmarshal([]byte(r.Modules), &f.Modules); err != nil {
		return f, fmt.Errorf("store: unmarshal modules: %w", err)
	}
	if err := json.Unmarshal([]byte(r.Evidence), &f.Evidence); err != nil {
		return f, fmt.Errorf("store: unmarshal evidence: %w", err)
	}
	if r.ReopenedAt.Valid {
		v := r.ReopenedAt.Int64
		f.ReopenedAt = &v
	}
	return f, nil
}

func upsertFinding(ctx context.Context, w writer, f model.Finding,
	now int64) (Outcome, error) {
	modules, err := json.Marshal(f.Modules)
	if err != nil {
		return "", fmt.Errorf("store: marshal modules: %w", err)
	}
	evidence, err := json.Marshal(f.Evidence)
	if err != nil {
		return "", fmt.Errorf("store: marshal evidence: %w", err)
	}

	w.lock().Lock()
	defer w.lock().Unlock()

	// Read the prior status first: it is the only thing that distinguishes a
	// bump from a reopen, and the upsert destroys it.
	var prior string
	err = w.bun().NewRaw(
		`SELECT status FROM findings WHERE system_id = ? AND fingerprint = ?`,
		f.SystemID, f.Fingerprint,
	).Scan(ctx, &prior)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		prior = ""
	case err != nil:
		return "", fmt.Errorf("store: read prior status: %w", err)
	}

	outcome := OutcomeInserted
	switch prior {
	case model.StatusOpen:
		outcome = OutcomeBumped
	case model.StatusStale:
		outcome = OutcomeReopened
	}

	// reopened_at is stamped only on the stale->open transition, keeping a
	// plain recurrence distinguishable from a genuine re-occurrence.
	var reopenedAt any
	if outcome == OutcomeReopened {
		reopenedAt = now
	}

	_, err = w.bun().NewRaw(`
		INSERT INTO findings
			(id, system_id, fingerprint, severity, title, summary,
			 suggested_action, modules, evidence, status, occurrence_count,
			 first_seen, last_seen, reopened_at, llm_model, prompt_version)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, NULL, ?, ?)
		ON CONFLICT (system_id, fingerprint) DO UPDATE SET
			severity         = excluded.severity,
			title            = excluded.title,
			summary          = excluded.summary,
			suggested_action = excluded.suggested_action,
			modules          = excluded.modules,
			evidence         = excluded.evidence,
			status           = excluded.status,
			occurrence_count = findings.occurrence_count + 1,
			last_seen        = excluded.last_seen,
			reopened_at      = ?,
			llm_model        = excluded.llm_model,
			prompt_version   = excluded.prompt_version`,
		newID(), f.SystemID, f.Fingerprint, f.Severity, f.Title, f.Summary,
		f.SuggestedAction, string(modules), string(evidence),
		model.StatusOpen, now, now, f.LLMModel, f.PromptVersion,
		reopenedAt,
	).Exec(ctx)
	if err != nil {
		return "", fmt.Errorf("store: upsert finding: %w", err)
	}
	return outcome, nil
}

func listFindings(ctx context.Context, w writer, systemID string,
	since int64, status string) ([]model.Finding, error) {
	q := w.bun().NewSelect().Table("findings").
		Where("system_id = ?", systemID).
		Where("last_seen >= ?", since)
	if status != "" {
		q = q.Where("status = ?", status)
	}
	var rows []findingRow
	if err := q.Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("store: list findings: %w", err)
	}
	out := make([]model.Finding, 0, len(rows))
	for _, r := range rows {
		f, err := r.toModel()
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	// Ordered in Go rather than SQL: severity rank is a Go concept, and a CASE
	// expression would duplicate model.Severities into the schema.
	model.SortFindings(out)
	return out, nil
}

func openFindings(ctx context.Context, w writer, systemID string) ([]model.Finding, error) {
	return listFindings(ctx, w, systemID, 0, model.StatusOpen)
}

func markStale(ctx context.Context, w writer, systemID string,
	olderThan int64) (int, error) {
	w.lock().Lock()
	defer w.lock().Unlock()
	res, err := w.bun().NewRaw(`
		UPDATE findings SET status = ?
		WHERE system_id = ? AND status = ? AND last_seen < ?`,
		model.StatusStale, systemID, model.StatusOpen, olderThan,
	).Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("store: mark stale: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: mark stale rows: %w", err)
	}
	return int(n), nil
}
```

- [ ] **Step 6: Write `internal/store/prune.go`**

```go
package store

import (
	"context"
	"fmt"

	"github.com/nethesis/nethesis-insights/internal/model"
)

func pruneTemplates(ctx context.Context, w writer, olderThan int64) (int, error) {
	return execCount(ctx, w,
		`DELETE FROM system_templates WHERE last_seen < ?`, olderThan)
}

func pruneFindings(ctx context.Context, w writer, olderThan int64) (int, error) {
	// Only stale findings are pruned. An open finding is current by
	// definition, however old its first_seen is.
	return execCount(ctx, w,
		`DELETE FROM findings WHERE status = ? AND last_seen < ?`,
		model.StatusStale, olderThan)
}

func pruneAnalyses(ctx context.Context, w writer, olderThan int64) (int, error) {
	return execCount(ctx, w,
		`DELETE FROM analyses WHERE created_at < ?`, olderThan)
}

func execCount(ctx context.Context, w writer, query string, args ...any) (int, error) {
	w.lock().Lock()
	defer w.lock().Unlock()
	res, err := w.bun().NewRaw(query, args...).Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("store: prune: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: prune rows: %w", err)
	}
	return int(n), nil
}
```

- [ ] **Step 7: Bind the ten new methods to both implementations**

Append to `internal/store/sqlite.go`:

```go
func (s *sqliteStore) BeginAnalysis(ctx context.Context, systemID string,
	windowStart, windowEnd, now int64) (bool, error) {
	return beginAnalysis(ctx, s, systemID, windowStart, windowEnd, now)
}

func (s *sqliteStore) FinalizeAnalysis(ctx context.Context, a Analysis) error {
	return finalizeAnalysis(ctx, s, a)
}

func (s *sqliteStore) SpendSince(ctx context.Context, sinceMs int64) (int64, error) {
	return spendSince(ctx, s, sinceMs)
}

func (s *sqliteStore) OpenFindings(ctx context.Context, systemID string) ([]model.Finding, error) {
	return openFindings(ctx, s, systemID)
}

func (s *sqliteStore) UpsertFinding(ctx context.Context, f model.Finding,
	now int64) (Outcome, error) {
	return upsertFinding(ctx, s, f, now)
}

func (s *sqliteStore) MarkStale(ctx context.Context, systemID string,
	olderThan int64) (int, error) {
	return markStale(ctx, s, systemID, olderThan)
}

func (s *sqliteStore) ListFindings(ctx context.Context, systemID string,
	since int64, status string) ([]model.Finding, error) {
	return listFindings(ctx, s, systemID, since, status)
}

func (s *sqliteStore) PruneTemplates(ctx context.Context, olderThan int64) (int, error) {
	return pruneTemplates(ctx, s, olderThan)
}

func (s *sqliteStore) PruneFindings(ctx context.Context, olderThan int64) (int, error) {
	return pruneFindings(ctx, s, olderThan)
}

func (s *sqliteStore) PruneAnalyses(ctx context.Context, olderThan int64) (int, error) {
	return pruneAnalyses(ctx, s, olderThan)
}
```

Add the identical ten methods to `internal/store/postgres.go` with receiver `(s *pgStore)`, delegating to the same package-level functions.

- [ ] **Step 8: Write the failing pruning tests**

Create `internal/store/prune_test.go`:

```go
package store

import (
	"context"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/stretchr/testify/require"
)

func TestPruneTemplatesByLastSeen(t *testing.T) {
	ctx, s := context.Background(), openSQLite(t)
	require.NoError(t, s.UpsertTemplates(ctx, "sys1",
		[]model.Template{{Template: "old", Count: 1}}, 100))
	require.NoError(t, s.UpsertTemplates(ctx, "sys1",
		[]model.Template{{Template: "new", Count: 1}}, 900))

	n, err := s.PruneTemplates(ctx, 500)
	require.NoError(t, err)
	require.Equal(t, 1, n)

	known, err := s.KnownTemplates(ctx, "sys1")
	require.NoError(t, err)
	require.False(t, known["old"])
	require.True(t, known["new"])
}

func TestPruneFindingsSparesOpenOnes(t *testing.T) {
	ctx, s := context.Background(), openSQLite(t)
	_, err := s.UpsertFinding(ctx, finding("fp-open", "high", 100), 100)
	require.NoError(t, err)
	_, err = s.UpsertFinding(ctx, finding("fp-stale", "high", 100), 100)
	require.NoError(t, err)

	// Stale both, then bring fp-open back so only fp-stale is prunable.
	_, err = s.MarkStale(ctx, "sys1", 200)
	require.NoError(t, err)
	_, err = s.UpsertFinding(ctx, finding("fp-open", "high", 300), 300)
	require.NoError(t, err)

	n, err := s.PruneFindings(ctx, 250)
	require.NoError(t, err)
	require.Equal(t, 1, n, "only the stale finding is deleted")

	open, err := s.OpenFindings(ctx, "sys1")
	require.NoError(t, err)
	require.Len(t, open, 1)
	require.Equal(t, "fp-open", open[0].Fingerprint)
}

func TestPruneAnalysesByCreatedAt(t *testing.T) {
	ctx, s := context.Background(), openSQLite(t)
	_, err := s.BeginAnalysis(ctx, "sys1", 1000, 1900, 100)
	require.NoError(t, err)
	_, err = s.BeginAnalysis(ctx, "sys1", 2000, 2900, 900)
	require.NoError(t, err)

	n, err := s.PruneAnalyses(ctx, 500)
	require.NoError(t, err)
	require.Equal(t, 1, n)
}
```

- [ ] **Step 9: Run the whole store package**

```bash
go get github.com/oklog/ulid/v2 && go mod tidy
go test ./internal/store/ -v
```

Expected: PASS, every test.

- [ ] **Step 10: Re-verify the Postgres dialect**

This task added `DO NOTHING`, `SUM()`, `UPDATE … WHERE` and `DELETE`. Confirm every one is portable:

```bash
podman run -d --name insights-pg-test \
  -e POSTGRES_PASSWORD=test -e POSTGRES_DB=insights_test \
  -p 127.0.0.1:55432:5432 postgres:16-alpine
until podman exec insights-pg-test pg_isready -q; do sleep 1; done
TEST_POSTGRES_DSN='postgres://postgres:test@127.0.0.1:55432/insights_test?sslmode=disable' \
  go test ./internal/store/ -run TestMigratePostgres -v
podman rm -f insights-pg-test
```

Expected: PASS

- [ ] **Step 11: Commit**

```bash
git add internal/store go.mod go.sum
git commit -m "feat(store): finding lifecycle, analysis ledger and pruning"
```

---

## Task 5: `internal/fingerprint` — server-owned finding identity

**Files:**
- Create: `internal/fingerprint/fingerprint.go`
- Test: `internal/fingerprint/fingerprint_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `fingerprint.Version` — const `"v1"`
  - `fingerprint.Compute(systemID string, modules, evidence []string, category string) string` — returns 64-char lowercase hex

- [ ] **Step 1: Write the failing test**

Create `internal/fingerprint/fingerprint_test.go`:

```go
package fingerprint

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStableAcrossEvidenceOrder(t *testing.T) {
	a := Compute("sys1", []string{"m1"}, []string{"tmpl A", "tmpl B"}, "")
	b := Compute("sys1", []string{"m1"}, []string{"tmpl B", "tmpl A"}, "")
	require.Equal(t, a, b,
		"the model may cite evidence in any order; identity must not depend on it")
}

func TestStableAcrossModuleOrder(t *testing.T) {
	require.Equal(t,
		Compute("sys1", []string{"m1", "m2"}, []string{"t"}, ""),
		Compute("sys1", []string{"m2", "m1"}, []string{"t"}, ""))
}

func TestDistinctPerSystem(t *testing.T) {
	require.NotEqual(t,
		Compute("sys1", []string{"m1"}, []string{"t"}, ""),
		Compute("sys2", []string{"m1"}, []string{"t"}, ""),
		"one customer's finding must never dedup against another's")
}

func TestDistinctPerModuleSet(t *testing.T) {
	require.NotEqual(t,
		Compute("s", []string{"m1"}, []string{"t"}, ""),
		Compute("s", []string{"m2"}, []string{"t"}, ""))
}

func TestDistinctPerCategory(t *testing.T) {
	require.NotEqual(t,
		Compute("s", []string{"m"}, []string{"t"}, "security"),
		Compute("s", []string{"m"}, []string{"t"}, ""))
}

func TestDistinctPerEvidence(t *testing.T) {
	require.NotEqual(t,
		Compute("s", []string{"m"}, []string{"t1"}, ""),
		Compute("s", []string{"m"}, []string{"t1", "t2"}, ""))
}

func TestDuplicateEvidenceIsCollapsed(t *testing.T) {
	require.Equal(t,
		Compute("s", []string{"m"}, []string{"t1"}, ""),
		Compute("s", []string{"m"}, []string{"t1", "t1"}, ""),
		"a model repeating one template must not mint a second identity")
}

func TestFieldBoundariesCannotBeForged(t *testing.T) {
	// Two evidence items must not collide with one item containing whatever
	// separator the implementation uses. A plain strings.Join would collide.
	require.NotEqual(t,
		Compute("s", []string{"m"}, []string{"x", "y"}, ""),
		Compute("s", []string{"m"}, []string{"x\x1fy"}, ""))
	// The same hazard across adjacent fields.
	require.NotEqual(t,
		Compute("ab", []string{"m"}, []string{"t"}, "c"),
		Compute("a", []string{"m"}, []string{"t"}, "bc"))
}

func TestEmptyInputsAreHandled(t *testing.T) {
	got := Compute("s", nil, nil, "")
	require.Regexp(t, "^[0-9a-f]{64}$", got)
}

func TestIsHexSHA256(t *testing.T) {
	got := Compute("s", []string{"m"}, []string{"t"}, "")
	require.Len(t, got, 64)
	require.Regexp(t, "^[0-9a-f]{64}$", got)
}

func TestGoldenValueIsPinned(t *testing.T) {
	// Pinned in Step 5 so an accidental formula change fails loudly here
	// rather than silently re-raising every open finding on the fleet.
	got := Compute("sys1", []string{"traefik1"},
		[]string{"<3> [n1:traefik1:traefik] connection refused to <IP>:<NUM>"},
		"security")
	t.Logf("pin this value in Step 5: %s", got)
	require.Len(t, got, 64)
}
```

`TestFieldBoundariesCannotBeForged` is the test that earns its keep. Without length-prefixed fields, a template containing the separator byte collapses two distinct findings into one identity — a silent dedup bug that would be nearly impossible to diagnose from production symptoms.

- [ ] **Step 2: Run it to make sure it fails**

Run: `go test ./internal/fingerprint/ -v`
Expected: FAIL — `undefined: Compute`

- [ ] **Step 3: Write the implementation**

Create `internal/fingerprint/fingerprint.go`:

```go
// Package fingerprint computes the stable identity of a finding. It is pure:
// no I/O, no clock, no randomness.
package fingerprint

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"sort"
)

// Version prefixes every fingerprint. Changing it changes the identity of
// every finding in existence, so it moves only as a deliberate migration.
const Version = "v1"

// Compute returns the identity of a finding: its system, category, module set
// and the set of evidence templates it cites.
//
// Lists are sorted and de-duplicated so the model's presentation order never
// affects identity, and every field is length-prefixed so no input value can
// imitate a field boundary.
func Compute(systemID string, modules, evidence []string, category string) string {
	h := sha256.New()
	writeField(h, Version)
	writeField(h, systemID)
	writeField(h, category)
	writeList(h, modules)
	writeList(h, evidence)
	return hex.EncodeToString(h.Sum(nil))
}

// writeField length-prefixes a value so "ab"+"c" cannot collide with "a"+"bc".
func writeField(h hash.Hash, s string) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(s)))
	_, _ = h.Write(n[:])
	_, _ = h.Write([]byte(s))
}

// writeList length-prefixes the element count, then each element.
func writeList(h hash.Hash, items []string) {
	uniq := dedupeSorted(items)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(uniq)))
	_, _ = h.Write(n[:])
	for _, it := range uniq {
		writeField(h, it)
	}
}

func dedupeSorted(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	cp := append([]string(nil), items...)
	sort.Strings(cp)
	out := cp[:1]
	for _, it := range cp[1:] {
		if it != out[len(out)-1] {
			out = append(out, it)
		}
	}
	return out
}
```

`sha256.New()` returns a `hash.Hash` whose `Write` never returns an error, which is why the returns are discarded — `errcheck` accepts the explicit `_ =` form.

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `go test ./internal/fingerprint/ -v`
Expected: PASS. Record the value logged by `TestGoldenValueIsPinned`.

- [ ] **Step 5: Pin the golden value**

Replace `TestGoldenValueIsPinned` with the observed hash substituted for the placeholder:

```go
func TestGoldenValueIsPinned(t *testing.T) {
	got := Compute("sys1", []string{"traefik1"},
		[]string{"<3> [n1:traefik1:traefik] connection refused to <IP>:<NUM>"},
		"security")
	require.Equal(t, "PASTE_THE_64_HEX_VALUE_FROM_STEP_4", got,
		"the fingerprint formula changed; that is a fleet-wide identity "+
			"migration, not a refactor")
}
```

Run: `go test ./internal/fingerprint/ -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/fingerprint
git commit -m "feat(fingerprint): stable server-computed finding identity"
```

---

## Task 6: `internal/gate` — the cost control

**Files:**
- Create: `internal/gate/gate.go`
- Test: `internal/gate/gate_test.go`

**Interfaces:**
- Consumes: `model.Bundle`, `model.DigestEntry`, `model.Template` (Task 2); `store.BaselineKey` (Task 3).
- Produces:
  - `gate.SystemState{KnownTemplates map[string]bool; Baselines map[store.BaselineKey]float64; SecurityOnly bool}`
  - `gate.Decision{Call bool; Reasons []string}`
  - `gate.Evaluate(b model.Bundle, s SystemState, tolerance float64) Decision`
  - reason constants `gate.ReasonNewTemplates`, `ReasonDeviation`, `ReasonSecurity`, `ReasonTruncatedDeviating`

- [ ] **Step 1: Write the failing test**

Create `internal/gate/gate_test.go`:

```go
package gate

import (
	"strings"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/store"
	"github.com/stretchr/testify/require"
)

func f64(v float64) *float64 { return &v }

// steady is a bundle a healthy, unchanged system produces: every template
// already known, every rate at baseline, nothing security-flagged.
func steady() model.Bundle {
	return model.Bundle{
		SystemID: "sys1",
		Digest: []model.DigestEntry{
			{ModuleID: "m1", Priority: 4, Observed: 10, Expected: f64(10)},
		},
		Templates: []model.Template{
			{Template: "known line <IP>", Count: 10, ModuleID: "m1", Priority: 4},
		},
	}
}

func steadyState() SystemState {
	return SystemState{
		KnownTemplates: map[string]bool{"known line <IP>": true},
		Baselines:      map[store.BaselineKey]float64{{ModuleID: "m1", Priority: 4}: 10},
	}
}

func TestSteadyStateCostsNothing(t *testing.T) {
	d := Evaluate(steady(), steadyState(), 3.0)
	require.False(t, d.Call, "an unchanged system must not spend an LLM call")
	require.Empty(t, d.Reasons)
}

func TestNewTemplateTriggers(t *testing.T) {
	b := steady()
	b.Templates = append(b.Templates, model.Template{
		Template: "never seen before <NUM>", Count: 1, ModuleID: "m1", Priority: 4,
	})
	d := Evaluate(b, steadyState(), 3.0)
	require.True(t, d.Call)
	require.Contains(t, strings.Join(d.Reasons, ","), ReasonNewTemplates)
}

func TestDeviationUsesEdgeExpected(t *testing.T) {
	b := steady()
	b.Digest[0].Observed = 40 // 40/10 = 4.0 > 3.0
	d := Evaluate(b, steadyState(), 3.0)
	require.True(t, d.Call)
	require.Contains(t, strings.Join(d.Reasons, ","), ReasonDeviation)
}

func TestDeviationJustUnderToleranceDoesNotTrigger(t *testing.T) {
	b := steady()
	b.Digest[0].Observed = 29 // 2.9 < 3.0
	require.False(t, Evaluate(b, steadyState(), 3.0).Call)
}

func TestDeviationFallsBackToServerEWMAWhenEdgeDegraded(t *testing.T) {
	// The edge's Loki metric query failed, so Expected is absent. The server
	// baseline must keep the deviation gate working.
	b := steady()
	b.Digest[0].Expected = nil
	b.Digest[0].Observed = 40
	d := Evaluate(b, steadyState(), 3.0)
	require.True(t, d.Call, "server EWMA must cover for a degraded edge")
	require.Contains(t, strings.Join(d.Reasons, ","), ReasonDeviation)
}

func TestNoExpectedAndNoBaselineDoesNotTrigger(t *testing.T) {
	// Nothing to compare against. Novelty already covers a first observation,
	// so inventing a deviation here would double-charge for the same signal.
	b := steady()
	b.Digest[0].Expected = nil
	b.Digest[0].Observed = 9999
	s := steadyState()
	s.Baselines = map[store.BaselineKey]float64{}
	require.False(t, Evaluate(b, s, 3.0).Call)
}

func TestZeroExpectedNeverDividesByZero(t *testing.T) {
	b := steady()
	b.Digest[0].Expected = f64(0)
	b.Digest[0].Observed = 500
	s := steadyState()
	s.Baselines = map[store.BaselineKey]float64{}
	require.NotPanics(t, func() { Evaluate(b, s, 3.0) })
	require.False(t, Evaluate(b, s, 3.0).Call)
}

func TestSecurityCategoryAlwaysTriggers(t *testing.T) {
	b := steady()
	b.Templates[0].Category = "security"
	d := Evaluate(b, steadyState(), 3.0)
	require.True(t, d.Call, "a security line is never gated out")
	require.Contains(t, strings.Join(d.Reasons, ","), ReasonSecurity)
}

func TestTruncationAloneDoesNotTrigger(t *testing.T) {
	b := steady()
	b.Budget.TruncatedModules = []model.TruncatedModule{
		{ModuleID: "m1", Dropped: 3000},
	}
	require.False(t, Evaluate(b, steadyState(), 3.0).Call,
		"a chatty module at its normal rate is noise, not signal")
}

func TestTruncationPlusDeviationTriggers(t *testing.T) {
	b := steady()
	b.Digest[0].Observed = 40
	b.Budget.TruncatedModules = []model.TruncatedModule{
		{ModuleID: "m1", Dropped: 3000},
	}
	d := Evaluate(b, steadyState(), 3.0)
	require.True(t, d.Call)
	joined := strings.Join(d.Reasons, ",")
	require.Contains(t, joined, ReasonTruncatedDeviating)
}

func TestTruncationOfANonDeviatingModuleDoesNotTrigger(t *testing.T) {
	b := steady()
	b.Digest = append(b.Digest, model.DigestEntry{
		ModuleID: "m2", Priority: 4, Observed: 40, Expected: f64(10),
	})
	b.Budget.TruncatedModules = []model.TruncatedModule{
		{ModuleID: "m1", Dropped: 3000}, // m1 is fine; m2 is the one deviating
	}
	d := Evaluate(b, steadyState(), 3.0)
	require.True(t, d.Call, "m2 deviates, so the call happens")
	require.NotContains(t, strings.Join(d.Reasons, ","), ReasonTruncatedDeviating,
		"truncation of a healthy module is not itself a reason")
}

func TestSecurityOnlyModeSuppressesEverythingElse(t *testing.T) {
	// Spend cap breached: only security may still spend.
	s := steadyState()
	s.SecurityOnly = true

	b := steady()
	b.Templates = append(b.Templates, model.Template{
		Template: "brand new <NUM>", Count: 1, ModuleID: "m1", Priority: 4})
	b.Digest[0].Observed = 999
	require.False(t, Evaluate(b, s, 3.0).Call,
		"novelty and deviation must be suppressed under the spend cap")

	b.Templates[0].Category = "security"
	d := Evaluate(b, s, 3.0)
	require.True(t, d.Call, "security must still get through")
	require.Contains(t, strings.Join(d.Reasons, ","), ReasonSecurity)
}

func TestReasonsAreDeterministic(t *testing.T) {
	b := steady()
	b.Digest[0].Observed = 40
	b.Templates = append(b.Templates, model.Template{
		Template: "new <NUM>", Count: 1, ModuleID: "m1", Priority: 4})

	first := Evaluate(b, steadyState(), 3.0).Reasons
	for range 20 {
		require.Equal(t, first, Evaluate(b, steadyState(), 3.0).Reasons,
			"reasons are persisted and compared; map iteration must not leak in")
	}
}
```

`TestReasonsAreDeterministic` guards against the most likely bug in this package: iterating `KnownTemplates` or `Baselines` directly and letting Go's randomized map order into the persisted `gate_reasons`.

- [ ] **Step 2: Run it to make sure it fails**

Run: `go test ./internal/gate/ -v`
Expected: FAIL — `undefined: Evaluate`

- [ ] **Step 3: Write the implementation**

Create `internal/gate/gate.go`:

```go
// Package gate decides whether a bundle is worth an LLM call. It is pure: no
// I/O, no clock. This is the primary cost control for the whole system.
package gate

import (
	"fmt"
	"sort"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/store"
)

// Reason codes recorded in the analyses ledger.
const (
	ReasonNewTemplates       = "new_templates"
	ReasonDeviation          = "deviation"
	ReasonSecurity           = "security_category"
	ReasonTruncatedDeviating = "truncated_deviating"
)

// SystemState is everything the gate needs to know about a system's history.
type SystemState struct {
	KnownTemplates map[string]bool
	Baselines      map[store.BaselineKey]float64
	// SecurityOnly narrows the gate to security lines only. Set when the
	// daily spend cap has been breached.
	SecurityOnly bool
}

// Decision is the gate's verdict plus the reasons behind it, which are
// persisted so both "why did this cost money" and "why was this missed" are
// answerable from stored data.
type Decision struct {
	Call    bool
	Reasons []string
}

// Evaluate returns the decision for one bundle.
func Evaluate(b model.Bundle, s SystemState, tolerance float64) Decision {
	var reasons []string

	// Security is evaluated first because it is the only condition that
	// survives SecurityOnly mode.
	if securityPresent(b) {
		reasons = append(reasons, ReasonSecurity)
	}

	if !s.SecurityOnly {
		if n := countNovel(b, s); n > 0 {
			reasons = append(reasons, fmt.Sprintf("%s=%d", ReasonNewTemplates, n))
		}
		deviating := deviatingModules(b, s, tolerance)
		for _, key := range sortedKeys(deviating) {
			reasons = append(reasons, fmt.Sprintf("%s:%s/%d=%.2f",
				ReasonDeviation, key.ModuleID, key.Priority, deviating[key]))
		}
		// Truncation is only a reason when the truncated module is also
		// deviating: under-sampling a module that is behaving normally tells
		// us nothing.
		for _, id := range truncatedAndDeviating(b, deviating) {
			reasons = append(reasons, fmt.Sprintf("%s:%s", ReasonTruncatedDeviating, id))
		}
	}

	return Decision{Call: len(reasons) > 0, Reasons: reasons}
}

func securityPresent(b model.Bundle) bool {
	for _, t := range b.Templates {
		if t.Category == "security" {
			return true
		}
	}
	return false
}

func countNovel(b model.Bundle, s SystemState) int {
	n := 0
	for _, t := range b.Templates {
		if !s.KnownTemplates[t.Template] {
			n++
		}
	}
	return n
}

// deviatingModules returns the observed/expected ratio for every entry above
// tolerance. Edge-supplied Expected wins; the server EWMA is the fallback for
// a degraded edge; with neither, there is nothing to compare and the entry is
// skipped — a first observation is already covered by novelty.
func deviatingModules(b model.Bundle, s SystemState,
	tolerance float64) map[store.BaselineKey]float64 {
	out := map[store.BaselineKey]float64{}
	for _, e := range b.Digest {
		key := store.BaselineKey{ModuleID: e.ModuleID, Priority: e.Priority}
		expected := 0.0
		if e.Expected != nil {
			expected = *e.Expected
		}
		if expected <= 0 {
			expected = s.Baselines[key]
		}
		if expected <= 0 {
			continue
		}
		if ratio := float64(e.Observed) / expected; ratio > tolerance {
			out[key] = ratio
		}
	}
	return out
}

func truncatedAndDeviating(b model.Bundle,
	deviating map[store.BaselineKey]float64) []string {
	deviatingModuleIDs := map[string]bool{}
	for key := range deviating {
		deviatingModuleIDs[key.ModuleID] = true
	}
	var out []string
	for _, tm := range b.Budget.TruncatedModules {
		if deviatingModuleIDs[tm.ModuleID] {
			out = append(out, tm.ModuleID)
		}
	}
	sort.Strings(out)
	return out
}

// sortedKeys gives map iteration a stable order so persisted reasons are
// deterministic.
func sortedKeys(m map[store.BaselineKey]float64) []store.BaselineKey {
	keys := make([]store.BaselineKey, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].ModuleID != keys[j].ModuleID {
			return keys[i].ModuleID < keys[j].ModuleID
		}
		return keys[i].Priority < keys[j].Priority
	})
	return keys
}
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `go test ./internal/gate/ -v`
Expected: PASS, all fourteen tests

- [ ] **Step 5: Commit**

```bash
git add internal/gate
git commit -m "feat(gate): novelty and deviation gating before any LLM spend"
```

---

## Task 7: `internal/prompt` — the LLM wire contract

This package owns both directions of the LLM contract: what is sent (system prompt, user prompt, JSON schema) and what is accepted back (parse and validate). Keeping both in one package means the schema and the parser cannot drift apart.

**Files:**
- Create: `internal/prompt/prompt.go`, `internal/prompt/schema.go`
- Test: `internal/prompt/prompt_test.go`, `internal/prompt/parse_test.go`, `internal/prompt/testdata/render.golden`

**Interfaces:**
- Consumes: `model.Bundle`, `model.Finding`, `model.ValidSeverity`, `model.ValidAssessment` (Task 2).
- Produces:
  - `prompt.Version` — const `"v1"`, the value stamped on findings
  - `prompt.System` — const, the system prompt
  - `prompt.Schema` — `map[string]any`, the strict JSON schema
  - `prompt.Render(b model.Bundle, open []model.Finding) string`
  - `prompt.Parse(body string) (findings []ParsedFinding, assessment string, err error)`
  - `prompt.ParsedFinding{Severity, Title, Summary, SuggestedAction string; Modules, Evidence []string}`

- [ ] **Step 1: Write the failing determinism test**

Create `internal/prompt/prompt_test.go`:

```go
package prompt

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/stretchr/testify/require"
)

func f64(v float64) *float64 { return &v }

func fixture() model.Bundle {
	return model.Bundle{
		SchemaVersion: 1, SystemID: "sys1", CollectorVersion: "2.0.0",
		MaskingVersion: 1,
		Window:         model.Window{Start: 1754380800000, End: 1754381700000},
		Digest: []model.DigestEntry{
			{ModuleID: "traefik1", Priority: 3, Observed: 42, Expected: f64(3.2)},
			{ModuleID: "samba2", Priority: 4, Observed: 5, Expected: f64(4.0)},
		},
		Templates: []model.Template{
			{Template: "<4> [n1:samba2:smbd] slow oplock break <NUM>ms",
				Count: 5, ModuleID: "samba2", Priority: 4},
			{Template: "<3> [n1:traefik1:traefik] connection refused to <IP>:<NUM>",
				Count: 37, ModuleID: "traefik1", Priority: 3, Category: "security"},
		},
		Budget: model.Budget{
			MaxLines: 500, LinesSeen: 4210, LinesKept: 500,
			TruncatedModules: []model.TruncatedModule{
				{ModuleID: "traefik1", Dropped: 3200}},
		},
	}
}

func TestRenderIsByteIdenticalAcrossInputOrder(t *testing.T) {
	a := Render(fixture(), nil)

	// Same content, reversed input order. Identical prompts are what make
	// LLM output reproducible and what let a caching layer ever work.
	shuffled := fixture()
	shuffled.Digest[0], shuffled.Digest[1] = shuffled.Digest[1], shuffled.Digest[0]
	shuffled.Templates[0], shuffled.Templates[1] =
		shuffled.Templates[1], shuffled.Templates[0]
	b := Render(shuffled, nil)

	require.Equal(t, a, b)
}

func TestRenderIsStableAcrossCalls(t *testing.T) {
	first := Render(fixture(), nil)
	for range 20 {
		require.Equal(t, first, Render(fixture(), nil))
	}
}

func TestRenderNeverIncludesSamples(t *testing.T) {
	b := fixture()
	b.Templates[0].Samples = []string{"RAW 10.0.0.4 secret"}
	require.NotContains(t, Render(b, nil), "RAW 10.0.0.4 secret",
		"the prompt carries templates and counts, not raw lines")
}

func TestRenderIncludesTruncationDetail(t *testing.T) {
	out := Render(fixture(), nil)
	require.Contains(t, out, "traefik1")
	require.Contains(t, out, "3200",
		"the model must see which module was under-sampled and by how much")
}

func TestRenderIncludesOpenFindingsAndTheInstruction(t *testing.T) {
	out := Render(fixture(), []model.Finding{{
		Severity: "high", Title: "Traefik backend unreachable",
		Fingerprint: "abc", LastSeen: 1754380000000,
	}})
	require.Contains(t, out, "Traefik backend unreachable")
	require.Contains(t, out, "ALREADY KNOWN")
}

func TestRenderMatchesGolden(t *testing.T) {
	got := Render(fixture(), nil)
	path := filepath.Join("testdata", "render.golden")

	if os.Getenv("UPDATE_GOLDEN") != "" {
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(path, []byte(got), 0o644))
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err, "run with UPDATE_GOLDEN=1 to create the golden file")
	require.Equal(t, string(want), got,
		"the prompt changed; bump prompt.Version deliberately")
}
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `go test ./internal/prompt/ -run TestRender -v`
Expected: FAIL — `undefined: Render`

- [ ] **Step 3: Write the renderer**

Create `internal/prompt/prompt.go`:

```go
// Package prompt owns the LLM wire contract in both directions: the system
// prompt, the user prompt and the response schema that is sent, and the parser
// that validates what comes back. It is pure: no I/O, no clock.
package prompt

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nethesis/nethesis-insights/internal/model"
)

// Version is stamped on every finding. It must change whenever System, Render
// or Schema changes, so a finding always records how it was produced.
const Version = "v1"

// System is the system prompt. It is a constant, not a template: any
// per-request variation belongs in the user prompt.
const System = "You are a log analysis assistant for NethServer systems. " +
	"You are given a digest of log volumes and a set of masked log line " +
	"templates with occurrence counts for one 15-minute window.\n\n" +
	"Report only conditions that indicate a real problem. Report only NEW or " +
	"CHANGED conditions: if a condition is listed as ALREADY KNOWN, do not " +
	"report it again unless its character has materially changed.\n\n" +
	"Cite evidence by copying template strings verbatim from the TEMPLATES " +
	"block. Never invent a template. Never include raw hostnames, IP " +
	"addresses or user names beyond what the templates already contain.\n\n" +
	"If nothing warrants reporting, return an empty findings array with " +
	"window_assessment \"nominal\"."

// Render builds the user prompt. Every list is sorted, so the same bundle
// always produces byte-identical output regardless of input order.
func Render(b model.Bundle, open []model.Finding) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "WINDOW\nstart_ms=%d end_ms=%d collector=%s masking=%d\n\n",
		b.Window.Start, b.Window.End, b.CollectorVersion, b.MaskingVersion)

	sb.WriteString("DIGEST (module priority observed expected ratio)\n")
	for _, e := range sortedDigest(b.Digest) {
		if e.Expected != nil && *e.Expected > 0 {
			fmt.Fprintf(&sb, "%s %d %d %.2f %.2f\n", e.ModuleID, e.Priority,
				e.Observed, *e.Expected, float64(e.Observed)/*e.Expected)
		} else {
			fmt.Fprintf(&sb, "%s %d %d - -\n", e.ModuleID, e.Priority, e.Observed)
		}
	}

	sb.WriteString("\nTEMPLATES (count module priority category | template)\n")
	for _, t := range sortedTemplates(b.Templates) {
		category := t.Category
		if category == "" {
			category = "-"
		}
		fmt.Fprintf(&sb, "%d %s %d %s | %s\n",
			t.Count, t.ModuleID, t.Priority, category, t.Template)
	}

	fmt.Fprintf(&sb, "\nSAMPLING\nlines_seen=%d lines_kept=%d max_lines=%d\n",
		b.Budget.LinesSeen, b.Budget.LinesKept, b.Budget.MaxLines)
	if len(b.Budget.TruncatedModules) > 0 {
		sb.WriteString("under_sampled (module dropped)\n")
		for _, tm := range sortedTruncated(b.Budget.TruncatedModules) {
			fmt.Fprintf(&sb, "%s %d\n", tm.ModuleID, tm.Dropped)
		}
		sb.WriteString("Lines were dropped for the modules above. Treat their " +
			"counts as lower bounds.\n")
	}

	sb.WriteString("\nALREADY KNOWN (do not report these again)\n")
	if len(open) == 0 {
		sb.WriteString("none\n")
	} else {
		cp := append([]model.Finding(nil), open...)
		model.SortFindings(cp)
		for _, f := range cp {
			fmt.Fprintf(&sb, "[%s] %s\n", f.Severity, f.Title)
		}
	}

	return sb.String()
}

func sortedDigest(in []model.DigestEntry) []model.DigestEntry {
	out := append([]model.DigestEntry(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].ModuleID != out[j].ModuleID {
			return out[i].ModuleID < out[j].ModuleID
		}
		return out[i].Priority < out[j].Priority
	})
	return out
}

func sortedTemplates(in []model.Template) []model.Template {
	out := append([]model.Template(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].ModuleID != out[j].ModuleID {
			return out[i].ModuleID < out[j].ModuleID
		}
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].Template < out[j].Template
	})
	return out
}

func sortedTruncated(in []model.TruncatedModule) []model.TruncatedModule {
	out := append([]model.TruncatedModule(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].ModuleID < out[j].ModuleID })
	return out
}
```

- [ ] **Step 4: Create the golden file and confirm the tests pass**

```bash
UPDATE_GOLDEN=1 go test ./internal/prompt/ -run TestRenderMatchesGolden
go test ./internal/prompt/ -run TestRender -v
cat internal/prompt/testdata/render.golden
```

Expected: PASS, and the golden file reads as a sorted digest, sorted templates, a sampling block naming `traefik1 3200`, and `ALREADY KNOWN\nnone`.

The golden file needs no license header — `.golden` is excluded by `hack/check-license-headers.sh`.

- [ ] **Step 5: Write the failing parser tests**

Create `internal/prompt/parse_test.go`:

```go
package prompt

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const validResponse = `{
  "window_assessment": "incident",
  "findings": [
    {"severity": "high", "title": "T", "summary": "S",
     "suggested_action": "A", "modules": ["m1"], "evidence": ["tmpl <IP>"]}
  ]
}`

func TestParseValidResponse(t *testing.T) {
	fs, assessment, err := Parse(validResponse)
	require.NoError(t, err)
	require.Equal(t, "incident", assessment)
	require.Len(t, fs, 1)
	require.Equal(t, "high", fs[0].Severity)
	require.Equal(t, []string{"tmpl <IP>"}, fs[0].Evidence)
}

func TestParseAcceptsFencedJSON(t *testing.T) {
	// Some models wrap JSON in a markdown fence despite strict schema mode.
	fenced := "```json\n" + validResponse + "\n```"
	_, _, err := Parse(fenced)
	require.NoError(t, err)
}

func TestParseAcceptsEmptyFindings(t *testing.T) {
	fs, assessment, err := Parse(`{"window_assessment":"nominal","findings":[]}`)
	require.NoError(t, err)
	require.Equal(t, "nominal", assessment)
	require.Empty(t, fs)
}

func TestParseRejectsUnknownSeverity(t *testing.T) {
	_, _, err := Parse(strings.Replace(validResponse, `"high"`, `"catastrophic"`, 1))
	require.Error(t, err)
	require.Contains(t, err.Error(), "severity")
}

func TestParseRejectsUnknownAssessment(t *testing.T) {
	_, _, err := Parse(strings.Replace(validResponse, `"incident"`, `"vibes"`, 1))
	require.Error(t, err)
	require.Contains(t, err.Error(), "assessment")
}

func TestParseRejectsMissingTitle(t *testing.T) {
	_, _, err := Parse(strings.Replace(validResponse, `"title": "T"`, `"title": ""`, 1))
	require.Error(t, err)
	require.Contains(t, err.Error(), "title")
}

func TestParseRejectsEmptyEvidence(t *testing.T) {
	// Evidence is what the fingerprint is computed from. A finding with none
	// has no stable identity and would dedup against every other such finding.
	_, _, err := Parse(strings.Replace(validResponse,
		`"evidence": ["tmpl <IP>"]`, `"evidence": []`, 1))
	require.Error(t, err)
	require.Contains(t, err.Error(), "evidence")
}

func TestParseRejectsMalformedJSON(t *testing.T) {
	_, _, err := Parse(`not json at all`)
	require.Error(t, err)
}

func TestParseAllowsEmptySuggestedAction(t *testing.T) {
	_, _, err := Parse(strings.Replace(validResponse,
		`"suggested_action": "A"`, `"suggested_action": ""`, 1))
	require.NoError(t, err, "an action is useful but not always available")
}
```

`TestParseRejectsEmptyEvidence` protects the fingerprint: identity is computed from evidence, so a finding citing nothing would collapse onto every other evidence-free finding for that system.

- [ ] **Step 6: Run them to make sure they fail**

Run: `go test ./internal/prompt/ -run TestParse -v`
Expected: FAIL — `undefined: Parse`

- [ ] **Step 7: Write the schema and the parser**

Create `internal/prompt/schema.go`:

```go
package prompt

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/nethesis/nethesis-insights/internal/model"
)

// Schema is the strict JSON schema sent as response_format. additionalProperties
// is false and every property is required, which is what OpenAI's strict mode
// demands.
var Schema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"window_assessment": map[string]any{
			"type": "string", "enum": model.Assessments,
		},
		"findings": map[string]any{
			"type": "array",
			"items": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"severity": map[string]any{
						"type": "string", "enum": model.Severities,
					},
					"title":            map[string]any{"type": "string"},
					"summary":          map[string]any{"type": "string"},
					"suggested_action": map[string]any{"type": "string"},
					"modules": map[string]any{
						"type":  "array",
						"items": map[string]any{"type": "string"},
					},
					"evidence": map[string]any{
						"type":  "array",
						"items": map[string]any{"type": "string"},
					},
				},
				"required": []string{"severity", "title", "summary",
					"suggested_action", "modules", "evidence"},
				"additionalProperties": false,
			},
		},
	},
	"required":             []string{"window_assessment", "findings"},
	"additionalProperties": false,
}

// ParsedFinding is one finding as the model returned it. It has no fingerprint
// and no ID: identity is the server's to compute, never the model's.
type ParsedFinding struct {
	Severity        string   `json:"severity"`
	Title           string   `json:"title"`
	Summary         string   `json:"summary"`
	SuggestedAction string   `json:"suggested_action"`
	Modules         []string `json:"modules"`
	Evidence        []string `json:"evidence"`
}

type response struct {
	WindowAssessment string          `json:"window_assessment"`
	Findings         []ParsedFinding `json:"findings"`
}

var fenceRE = regexp.MustCompile("(?s)^\\s*```(?:json)?\\s*\n(.*?)\n?\\s*```\\s*$")

// Parse validates a model response. Schema mode is enforced server-side by the
// provider, but this validation is not redundant: providers vary, and a
// malformed finding that reaches the store corrupts identity permanently.
func Parse(body string) ([]ParsedFinding, string, error) {
	if m := fenceRE.FindStringSubmatch(body); m != nil {
		body = m[1]
	}
	var r response
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &r); err != nil {
		return nil, "", fmt.Errorf("prompt: decode response: %w", err)
	}
	if !model.ValidAssessment(r.WindowAssessment) {
		return nil, "", fmt.Errorf("prompt: invalid window_assessment %q",
			r.WindowAssessment)
	}
	for i, f := range r.Findings {
		if !model.ValidSeverity(f.Severity) {
			return nil, "", fmt.Errorf("prompt: finding %d: invalid severity %q",
				i, f.Severity)
		}
		if strings.TrimSpace(f.Title) == "" {
			return nil, "", fmt.Errorf("prompt: finding %d: empty title", i)
		}
		if strings.TrimSpace(f.Summary) == "" {
			return nil, "", fmt.Errorf("prompt: finding %d: empty summary", i)
		}
		if len(f.Evidence) == 0 {
			return nil, "", fmt.Errorf(
				"prompt: finding %d: empty evidence, cannot compute identity", i)
		}
	}
	return r.Findings, r.WindowAssessment, nil
}
```

- [ ] **Step 8: Run the whole package**

Run: `go test ./internal/prompt/ -v`
Expected: PASS, all tests

- [ ] **Step 9: Commit**

```bash
git add internal/prompt
git commit -m "feat(prompt): deterministic prompt rendering, strict schema and parser"
```

---

## Task 8: `internal/llm` — OpenAI-compatible client

**Files:**
- Create: `internal/llm/llm.go`, `internal/llm/openai.go`, `internal/llm/stub.go`
- Test: `internal/llm/openai_test.go`

**Interfaces:**
- Consumes: `prompt.System`, `prompt.Schema` (Task 7).
- Produces:
  - `llm.Client` interface — `Complete(ctx, Request) (Response, error)`
  - `llm.Request{Model, UserPrompt string}`
  - `llm.Response{Content, Model string; InputTokens, OutputTokens int}`
  - `llm.HTTPError{StatusCode int; Body string}` with method `Permanent() bool`
  - `llm.NewOpenAI(baseURL, apiKey string, timeout time.Duration) *OpenAI`
  - `llm.Stub` — a `Client` for tests, with fields `Content string`, `Err error`, `Calls int`, `LastRequest Request`

- [ ] **Step 1: Write the failing test**

Create `internal/llm/openai_test.go`:

```go
package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRequestBodyOmitsTemperature(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			require.NoError(t, json.Unmarshal(body, &captured))
			_, _ = w.Write([]byte(`{"model":"m","choices":[{"message":
				{"content":"{}"}}],"usage":{"prompt_tokens":10,
				"completion_tokens":2}}`))
		}))
	defer srv.Close()

	c := NewOpenAI(srv.URL, "test-key", 5*time.Second)
	_, err := c.Complete(context.Background(),
		Request{Model: "gpt-4o-mini", UserPrompt: "hello"})
	require.NoError(t, err)

	// Some models reject any non-default temperature outright. The field must
	// be absent, not zero.
	_, present := captured["temperature"]
	require.False(t, present, "temperature must never be sent")

	rf, ok := captured["response_format"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "json_schema", rf["type"])
	js, ok := rf["json_schema"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, true, js["strict"])
}

func TestCompleteReturnsContentAndUsage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"model":"gpt-4o-mini","choices":[{"message":
				{"content":"{\"window_assessment\":\"nominal\",\"findings\":[]}"}}],
				"usage":{"prompt_tokens":12400,"completion_tokens":300}}`))
		}))
	defer srv.Close()

	resp, err := NewOpenAI(srv.URL, "k", 5*time.Second).
		Complete(context.Background(), Request{Model: "gpt-4o-mini"})
	require.NoError(t, err)
	require.Contains(t, resp.Content, "nominal")
	require.Equal(t, 12400, resp.InputTokens)
	require.Equal(t, 300, resp.OutputTokens)
	require.Equal(t, "gpt-4o-mini", resp.Model)
}

func TestSendsBearerToken(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			auth = r.Header.Get("Authorization")
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{}"}}]}`))
		}))
	defer srv.Close()

	_, err := NewOpenAI(srv.URL, "sk-secret", 5*time.Second).
		Complete(context.Background(), Request{Model: "m"})
	require.NoError(t, err)
	require.Equal(t, "Bearer sk-secret", auth)
}

func TestClientErrorIsPermanent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"bad schema"}}`))
		}))
	defer srv.Close()

	_, err := NewOpenAI(srv.URL, "k", 5*time.Second).
		Complete(context.Background(), Request{Model: "m"})
	require.Error(t, err)

	var he *HTTPError
	require.ErrorAs(t, err, &he)
	require.Equal(t, 400, he.StatusCode)
	require.Contains(t, he.Body, "bad schema")
	require.True(t, he.Permanent(), "a 400 will fail identically on retry")
}

func TestRateLimitIsNotPermanent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}))
	defer srv.Close()

	_, err := NewOpenAI(srv.URL, "k", 5*time.Second).
		Complete(context.Background(), Request{Model: "m"})
	var he *HTTPError
	require.ErrorAs(t, err, &he)
	require.False(t, he.Permanent(), "429 is the canonical retryable case")
}

func TestServerErrorIsNotPermanent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}))
	defer srv.Close()

	_, err := NewOpenAI(srv.URL, "k", 5*time.Second).
		Complete(context.Background(), Request{Model: "m"})
	var he *HTTPError
	require.ErrorAs(t, err, &he)
	require.False(t, he.Permanent())
}

func TestErrorNeverLeaksTheAPIKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"message":"bad key"}}`))
		}))
	defer srv.Close()

	_, err := NewOpenAI(srv.URL, "sk-super-secret", 5*time.Second).
		Complete(context.Background(), Request{Model: "m"})
	require.Error(t, err)
	require.NotContains(t, err.Error(), "sk-super-secret",
		"errors are logged; the key must never appear in one")
}

func TestEmptyChoicesIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"choices":[]}`))
		}))
	defer srv.Close()

	_, err := NewOpenAI(srv.URL, "k", 5*time.Second).
		Complete(context.Background(), Request{Model: "m"})
	require.Error(t, err)
}
```

`TestErrorNeverLeaksTheAPIKey` matters because error strings end up in the `analyses.error` column and in logs. A client that formats its request into an error message would write the key to disk.

- [ ] **Step 2: Run it to make sure it fails**

Run: `go test ./internal/llm/ -v`
Expected: FAIL — `undefined: NewOpenAI`

- [ ] **Step 3: Write the implementation**

Create `internal/llm/llm.go`:

```go
// Package llm talks to an OpenAI-compatible chat completions endpoint.
package llm

import (
	"context"
	"fmt"
	"net/http"
)

// Request is one completion request. The system prompt and response schema are
// supplied by the llm package itself, so callers cannot vary them per call and
// accidentally break output consistency.
type Request struct {
	Model      string
	UserPrompt string
}

// Response is what the provider returned, plus token usage for the ledger.
type Response struct {
	Content      string
	Model        string
	InputTokens  int
	OutputTokens int
}

// Client is the provider abstraction. The analyzer depends on this, never on
// the concrete implementation, which is what makes it testable offline.
type Client interface {
	Complete(ctx context.Context, req Request) (Response, error)
}

// HTTPError is a non-2xx response. Body is the provider's message and never
// contains request data.
type HTTPError struct {
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("llm: provider returned %d: %s", e.StatusCode, e.Body)
}

// Permanent reports whether retrying is pointless. A 4xx other than 429 means
// the request itself is wrong and will fail identically forever, so the caller
// should dead-letter rather than retry.
func (e *HTTPError) Permanent() bool {
	return e.StatusCode >= 400 && e.StatusCode < 500 &&
		e.StatusCode != http.StatusTooManyRequests
}
```

Create `internal/llm/openai.go`:

```go
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/nethesis/nethesis-insights/internal/prompt"
)

// maxErrorBody caps how much of a provider error is read, so a misbehaving
// endpoint cannot fill the analyses.error column or the logs.
const maxErrorBody = 4096

// OpenAI implements Client against any OpenAI-compatible /chat/completions
// endpoint, including OpenRouter.
type OpenAI struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewOpenAI returns a client. apiKey is held in memory only and never appears
// in an error or log message.
func NewOpenAI(baseURL, apiKey string, timeout time.Duration) *OpenAI {
	return &OpenAI{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		apiKey:  apiKey,
		client:  &http.Client{Timeout: timeout},
	}
}

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	// No Temperature field at all. Some models reject any non-default value,
	// and omitempty on a zero float would still send 0 when set explicitly.
	ResponseFormat responseFormat `json:"response_format"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type responseFormat struct {
	Type       string     `json:"type"`
	JSONSchema jsonSchema `json:"json_schema"`
}

type jsonSchema struct {
	Name   string         `json:"name"`
	Strict bool           `json:"strict"`
	Schema map[string]any `json:"schema"`
}

type chatResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

// Complete sends one request. It does not retry: retry policy is the
// analyzer's, because only the analyzer knows whether the work is still owned.
func (c *OpenAI) Complete(ctx context.Context, req Request) (Response, error) {
	body, err := json.Marshal(chatRequest{
		Model: req.Model,
		Messages: []chatMessage{
			{Role: "system", Content: prompt.System},
			{Role: "user", Content: req.UserPrompt},
		},
		ResponseFormat: responseFormat{
			Type: "json_schema",
			JSONSchema: jsonSchema{
				Name: "anomaly_report", Strict: true, Schema: prompt.Schema,
			},
		},
	})
	if err != nil {
		return Response{}, fmt.Errorf("llm: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Response{}, fmt.Errorf("llm: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.client.Do(httpReq)
	if err != nil {
		// %w on the transport error only; the request is never formatted in,
		// so the key cannot leak into a log line.
		return Response{}, fmt.Errorf("llm: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		return Response{}, &HTTPError{
			StatusCode: resp.StatusCode, Body: string(msg),
		}
	}

	var parsed chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return Response{}, fmt.Errorf("llm: decode response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return Response{}, fmt.Errorf("llm: response contained no choices")
	}
	return Response{
		Content:      parsed.Choices[0].Message.Content,
		Model:        parsed.Model,
		InputTokens:  parsed.Usage.PromptTokens,
		OutputTokens: parsed.Usage.CompletionTokens,
	}, nil
}
```

Create `internal/llm/stub.go`:

```go
package llm

import "context"

// Stub is a Client for tests. It lives in the production package rather than a
// _test.go file so other packages' tests can use it.
type Stub struct {
	Content      string
	Model        string
	InputTokens  int
	OutputTokens int
	Err          error

	Calls       int
	LastRequest Request
}

// Complete records the call and returns the configured result.
func (s *Stub) Complete(_ context.Context, req Request) (Response, error) {
	s.Calls++
	s.LastRequest = req
	if s.Err != nil {
		return Response{}, s.Err
	}
	return Response{
		Content: s.Content, Model: s.Model,
		InputTokens: s.InputTokens, OutputTokens: s.OutputTokens,
	}, nil
}
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `go test ./internal/llm/ -v`
Expected: PASS, all eight tests

- [ ] **Step 5: Commit**

```bash
git add internal/llm
git commit -m "feat(llm): OpenAI-compatible client with strict schema and no temperature"
```

---

## Task 9: `internal/budget` — concurrency cap and daily spend ceiling

These are the thundering-herd defences from spec §9.3. A fleet-wide collector upgrade makes every template novel at once, so without these the gate opens for all 2700 systems in the same window.

**Files:**
- Create: `internal/budget/budget.go`
- Test: `internal/budget/budget_test.go`

**Interfaces:**
- Consumes: `store.Store` (for `SpendSince`) — Task 4.
- Produces:
  - `budget.NewLimiter(n int) *Limiter` with `Acquire(ctx) error` and `Release()`
  - `budget.Pricing{InputPerMTok, OutputPerMTok float64}` with `CostMicros(inputTokens, outputTokens int) int64`
  - `budget.NewGuard(s SpendReader, capMicros int64, ttl time.Duration, now func() int64) *Guard` with `SecurityOnly(ctx) bool`
  - `budget.SpendReader` interface — `SpendSince(ctx, sinceMs int64) (int64, error)`

- [ ] **Step 1: Write the failing test**

Create `internal/budget/budget_test.go`:

```go
package budget

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLimiterCapsConcurrency(t *testing.T) {
	l := NewLimiter(2)
	ctx := context.Background()
	require.NoError(t, l.Acquire(ctx))
	require.NoError(t, l.Acquire(ctx))

	// The third acquire must block until a slot frees.
	done := make(chan struct{})
	go func() {
		_ = l.Acquire(ctx)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("third acquire should have blocked")
	case <-time.After(50 * time.Millisecond):
	}
	l.Release()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("release did not free a slot")
	}
}

func TestLimiterRespectsContextCancellation(t *testing.T) {
	l := NewLimiter(1)
	require.NoError(t, l.Acquire(context.Background()))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Error(t, l.Acquire(ctx),
		"a shutting-down analyzer must not block forever on a full limiter")
}

func TestLimiterIsSafeUnderConcurrentUse(t *testing.T) {
	l := NewLimiter(4)
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			require.NoError(t, l.Acquire(context.Background()))
			l.Release()
		}()
	}
	wg.Wait()
}

func TestCostMicros(t *testing.T) {
	// gpt-4o-mini: $0.15 per 1M input, $0.60 per 1M output.
	p := Pricing{InputPerMTok: 0.15, OutputPerMTok: 0.60}
	// 12400 input -> $0.00186; 300 output -> $0.00018; total $0.00204
	require.Equal(t, int64(2040), p.CostMicros(12400, 300))
}

func TestCostMicrosIsZeroForFreeModels(t *testing.T) {
	p := Pricing{}
	require.Zero(t, p.CostMicros(999999, 999999),
		"a free OpenRouter model must not accrue phantom spend")
}

type fakeSpend struct {
	micros int64
	err    error
	calls  int
}

func (f *fakeSpend) SpendSince(_ context.Context, _ int64) (int64, error) {
	f.calls++
	return f.micros, f.err
}

func TestGuardOpensBelowTheCap(t *testing.T) {
	s := &fakeSpend{micros: 1000}
	g := NewGuard(s, 5000, time.Minute, func() int64 { return 0 })
	require.False(t, g.SecurityOnly(context.Background()))
}

func TestGuardClosesAtTheCap(t *testing.T) {
	s := &fakeSpend{micros: 5000}
	g := NewGuard(s, 5000, time.Minute, func() int64 { return 0 })
	require.True(t, g.SecurityOnly(context.Background()),
		"reaching the cap must narrow the gate, not stop the service")
}

func TestGuardCachesWithinTTL(t *testing.T) {
	s := &fakeSpend{micros: 0}
	now := int64(0)
	g := NewGuard(s, 5000, time.Minute, func() int64 { return now })

	require.False(t, g.SecurityOnly(context.Background()))
	require.False(t, g.SecurityOnly(context.Background()))
	require.Equal(t, 1, s.calls, "the ledger must not be summed on every bundle")

	now = 61_000 // past the TTL
	require.False(t, g.SecurityOnly(context.Background()))
	require.Equal(t, 2, s.calls)
}

func TestGuardIsDisabledWhenCapIsZero(t *testing.T) {
	s := &fakeSpend{micros: 999_999_999}
	g := NewGuard(s, 0, time.Minute, func() int64 { return 0 })
	require.False(t, g.SecurityOnly(context.Background()))
	require.Zero(t, s.calls, "an unset cap must not even query the ledger")
}

func TestGuardFailsOpenOnLedgerError(t *testing.T) {
	// A database hiccup must not silently narrow the gate to security-only
	// and hide real incidents. Losing money is recoverable; losing detection
	// without any signal is not.
	s := &fakeSpend{err: errors.New("db down")}
	g := NewGuard(s, 5000, time.Minute, func() int64 { return 0 })
	require.False(t, g.SecurityOnly(context.Background()))
}
```

`TestGuardFailsOpenOnLedgerError` is the opposite choice from the auth path, deliberately. Auth fails closed because failing open there is a security hole. The spend guard fails open because failing closed there silently suppresses detection with no operator signal, and an over-run bill is visible and recoverable.

- [ ] **Step 2: Run it to make sure it fails**

Run: `go test ./internal/budget/ -v`
Expected: FAIL — `undefined: NewLimiter`

- [ ] **Step 3: Write the implementation**

Create `internal/budget/budget.go`:

```go
// Package budget bounds what the analyzer may spend: how many LLM calls run
// at once, and how much money may be spent per day.
package budget

import (
	"context"
	"log/slog"
	"math"
	"sync"
	"time"
)

// Limiter caps concurrent LLM calls. Excess work waits in the Redpanda topic,
// which is what the topic is for.
type Limiter struct {
	sem chan struct{}
}

// NewLimiter returns a limiter allowing n concurrent holders. n < 1 is treated
// as 1 so a misconfiguration cannot deadlock the analyzer.
func NewLimiter(n int) *Limiter {
	if n < 1 {
		n = 1
	}
	return &Limiter{sem: make(chan struct{}, n)}
}

// Acquire takes a slot, blocking until one is free or ctx is done.
func (l *Limiter) Acquire(ctx context.Context) error {
	select {
	case l.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release returns a slot.
func (l *Limiter) Release() {
	select {
	case <-l.sem:
	default:
	}
}

// Pricing converts token usage into money. Values are US dollars per million
// tokens, matching how providers publish them.
type Pricing struct {
	InputPerMTok  float64
	OutputPerMTok float64
}

// CostMicros returns the cost in micro-dollars, rounded to nearest.
func (p Pricing) CostMicros(inputTokens, outputTokens int) int64 {
	dollars := (float64(inputTokens)/1e6)*p.InputPerMTok +
		(float64(outputTokens)/1e6)*p.OutputPerMTok
	return int64(math.Round(dollars * 1e6))
}

// SpendReader is the slice of the store the guard needs.
type SpendReader interface {
	SpendSince(ctx context.Context, sinceMs int64) (int64, error)
}

// Guard answers whether the daily spend cap has been reached. The answer is
// cached: summing the ledger on every bundle would add a query per message for
// a value that changes slowly.
type Guard struct {
	reader    SpendReader
	capMicros int64
	ttl       time.Duration
	now       func() int64

	mu        sync.Mutex
	cached    bool
	cachedAt  int64
	lastValue bool
}

// NewGuard returns a guard. capMicros <= 0 disables the cap entirely.
func NewGuard(r SpendReader, capMicros int64, ttl time.Duration,
	now func() int64) *Guard {
	return &Guard{reader: r, capMicros: capMicros, ttl: ttl, now: now}
}

// SecurityOnly reports whether the gate should narrow to security lines only.
//
// It fails open. A ledger read error must not silently suppress detection: an
// over-run bill is visible and recoverable, whereas a gate quietly narrowed by
// a database hiccup hides real incidents with no operator signal.
func (g *Guard) SecurityOnly(ctx context.Context) bool {
	if g.capMicros <= 0 {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()
	if g.cached && now-g.cachedAt < g.ttl.Milliseconds() {
		return g.lastValue
	}

	dayStart := now - (24 * time.Hour).Milliseconds()
	spent, err := g.reader.SpendSince(ctx, dayStart)
	if err != nil {
		slog.Error("budget: reading spend ledger failed, leaving the gate open",
			"error", err)
		return false
	}

	breached := spent >= g.capMicros
	if breached {
		slog.Warn("budget: daily spend cap reached, narrowing gate to security only",
			"spent_micros", spent, "cap_micros", g.capMicros)
	}
	g.cached, g.cachedAt, g.lastValue = true, now, breached
	return breached
}
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `go test ./internal/budget/ -race -v`
Expected: PASS, all eleven tests, no race reports

- [ ] **Step 5: Commit**

```bash
git add internal/budget
git commit -m "feat(budget): LLM concurrency cap and daily spend ceiling"
```

---

## Task 10: `internal/analyzer` — the pipeline

**Files:**
- Create: `internal/analyzer/analyzer.go`
- Test: `internal/analyzer/analyzer_test.go`

**Interfaces:**
- Consumes: everything from Tasks 2–9.
- Produces:
  - `analyzer.Config{Tolerance float64; StaleAfter time.Duration; EWMAAlpha float64; Model string; Pricing budget.Pricing}`
  - `analyzer.New(s store.Store, c llm.Client, lim *budget.Limiter, g *budget.Guard, cfg Config, now func() int64) *Analyzer`
  - `analyzer.Analyzer.Process(ctx, b model.Bundle) error` — returns `nil` on success or a gated-out bundle; a non-nil error means the caller must not commit the offset
  - `analyzer.ErrPermanent` — sentinel wrapping a failure that must be dead-lettered rather than retried

- [ ] **Step 1: Write the failing tests**

Create `internal/analyzer/analyzer_test.go`:

```go
package analyzer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nethesis/nethesis-insights/internal/budget"
	"github.com/nethesis/nethesis-insights/internal/llm"
	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/store"
	"github.com/stretchr/testify/require"
)

func f64(v float64) *float64 { return &v }

const nominalReply = `{"window_assessment":"nominal","findings":[]}`

const incidentReply = `{"window_assessment":"incident","findings":[
  {"severity":"high","title":"Traefik backend unreachable",
   "summary":"Repeated connection refusals",
   "suggested_action":"Check the backend service",
   "modules":["traefik1"],
   "evidence":["<3> [n1:traefik1:traefik] connection refused to <IP>:<NUM>"]}]}`

func openStore(t *testing.T) store.Store {
	t.Helper()
	s, err := store.Open("sqlite", t.TempDir()+"/a.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	require.NoError(t, s.Migrate(context.Background()))
	return s
}

func newAnalyzer(t *testing.T, s store.Store, c llm.Client, now int64) *Analyzer {
	t.Helper()
	return New(s, c, budget.NewLimiter(2),
		budget.NewGuard(s, 0, time.Minute, func() int64 { return now }),
		Config{
			Tolerance: 3.0, StaleAfter: 24 * time.Hour, EWMAAlpha: 0.3,
			Model:   "gpt-4o-mini",
			Pricing: budget.Pricing{InputPerMTok: 0.15, OutputPerMTok: 0.60},
		},
		func() int64 { return now })
}

// novelBundle has a template no system has seen, so the gate opens.
func novelBundle() model.Bundle {
	return model.Bundle{
		SchemaVersion: 1, SystemID: "sys1", CollectorVersion: "2.0.0",
		Window: model.Window{Start: 1000, End: 1900},
		Digest: []model.DigestEntry{
			{ModuleID: "traefik1", Priority: 3, Observed: 37, Expected: f64(30)},
		},
		Templates: []model.Template{{
			Template: "<3> [n1:traefik1:traefik] connection refused to <IP>:<NUM>",
			Count:    37, ModuleID: "traefik1", Priority: 3,
		}},
	}
}

func TestGatedBundleNeverCallsTheLLM(t *testing.T) {
	ctx, s := context.Background(), openStore(t)
	stub := &llm.Stub{Content: nominalReply}
	a := newAnalyzer(t, s, stub, 2000)

	// First pass opens the gate on novelty and records the template.
	require.NoError(t, a.Process(ctx, novelBundle()))
	require.Equal(t, 1, stub.Calls)

	// Second pass: same templates, same rates, nothing new.
	b := novelBundle()
	b.Window = model.Window{Start: 2000, End: 2900}
	require.NoError(t, a.Process(ctx, b))
	require.Equal(t, 1, stub.Calls, "a steady-state bundle must cost nothing")
}

func TestDuplicateWindowIsSkipped(t *testing.T) {
	ctx, s := context.Background(), openStore(t)
	stub := &llm.Stub{Content: nominalReply}
	a := newAnalyzer(t, s, stub, 2000)

	require.NoError(t, a.Process(ctx, novelBundle()))
	require.NoError(t, a.Process(ctx, novelBundle()))
	require.Equal(t, 1, stub.Calls, "an edge retry must not be reprocessed")
}

func TestFindingIsStoredWithServerComputedIdentity(t *testing.T) {
	ctx, s := context.Background(), openStore(t)
	a := newAnalyzer(t, s, &llm.Stub{Content: incidentReply,
		Model: "gpt-4o-mini", InputTokens: 12400, OutputTokens: 300}, 2000)
	require.NoError(t, a.Process(ctx, novelBundle()))

	open, err := s.OpenFindings(ctx, "sys1")
	require.NoError(t, err)
	require.Len(t, open, 1)
	require.Equal(t, "high", open[0].Severity)
	require.Len(t, open[0].Fingerprint, 64)
	require.Equal(t, "gpt-4o-mini", open[0].LLMModel)
	require.NotEmpty(t, open[0].PromptVersion)
}

func TestRepeatedIncidentBumpsRatherThanDuplicates(t *testing.T) {
	ctx, s := context.Background(), openStore(t)
	stub := &llm.Stub{Content: incidentReply, Model: "gpt-4o-mini"}

	// Two windows, both producing the same finding. The second only reaches
	// the LLM because a fresh novel template is added.
	require.NoError(t, newAnalyzer(t, s, stub, 2000).Process(ctx, novelBundle()))

	b := novelBundle()
	b.Window = model.Window{Start: 2000, End: 2900}
	b.Templates = append(b.Templates, model.Template{
		Template: "<4> [n1:samba2:smbd] new thing <NUM>", Count: 1,
		ModuleID: "samba2", Priority: 4})
	require.NoError(t, newAnalyzer(t, s, stub, 3000).Process(ctx, b))
	require.Equal(t, 2, stub.Calls)

	open, err := s.OpenFindings(ctx, "sys1")
	require.NoError(t, err)
	require.Len(t, open, 1, "the same insight must not be raised twice")
	require.Equal(t, 2, open[0].OccurrenceCount)
}

// This is the §7 correctness constraint, asserted directly.
func TestLLMFailureLeavesTemplatesUnrecorded(t *testing.T) {
	ctx, s := context.Background(), openStore(t)
	failing := &llm.Stub{Err: &llm.HTTPError{StatusCode: 503, Body: "down"}}
	a := newAnalyzer(t, s, failing, 2000)

	err := a.Process(ctx, novelBundle())
	require.Error(t, err, "a retryable LLM failure must not be swallowed")

	known, err2 := s.KnownTemplates(ctx, "sys1")
	require.NoError(t, err2)
	require.Empty(t, known,
		"recording templates before a successful analysis would make the "+
			"retry see them as known and lose the anomaly permanently")
}

func TestPermanentLLMFailureIsNotRetryable(t *testing.T) {
	ctx, s := context.Background(), openStore(t)
	a := newAnalyzer(t, s,
		&llm.Stub{Err: &llm.HTTPError{StatusCode: 400, Body: "bad schema"}}, 2000)

	err := a.Process(ctx, novelBundle())
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPermanent,
		"a 400 must be dead-lettered, not retried forever")
}

func TestUnparseableResponseIsPermanent(t *testing.T) {
	ctx, s := context.Background(), openStore(t)
	a := newAnalyzer(t, s, &llm.Stub{Content: "not json"}, 2000)
	err := a.Process(ctx, novelBundle())
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPermanent)
}

func TestLedgerRecordsGatedAndCalledRuns(t *testing.T) {
	ctx, s := context.Background(), openStore(t)
	stub := &llm.Stub{Content: nominalReply, InputTokens: 12400, OutputTokens: 300}
	require.NoError(t, newAnalyzer(t, s, stub, 2000).Process(ctx, novelBundle()))

	spend, err := s.SpendSince(ctx, 0)
	require.NoError(t, err)
	require.Equal(t, int64(2040), spend,
		"12400 input + 300 output at gpt-4o-mini prices is 2040 micro-dollars")
}

func TestGatedRunSpendsNothing(t *testing.T) {
	ctx, s := context.Background(), openStore(t)
	stub := &llm.Stub{Content: nominalReply, InputTokens: 12400, OutputTokens: 300}
	a := newAnalyzer(t, s, stub, 2000)
	require.NoError(t, a.Process(ctx, novelBundle()))

	b := novelBundle()
	b.Window = model.Window{Start: 2000, End: 2900}
	require.NoError(t, a.Process(ctx, b))

	spend, err := s.SpendSince(ctx, 0)
	require.NoError(t, err)
	require.Equal(t, int64(2040), spend, "the gated second run added nothing")
}

func TestStaleFindingsAreMarkedAfterTheThreshold(t *testing.T) {
	ctx, s := context.Background(), openStore(t)
	stub := &llm.Stub{Content: incidentReply}
	require.NoError(t, newAnalyzer(t, s, stub, 2000).Process(ctx, novelBundle()))

	// A later window, well past StaleAfter, in which the LLM reports nothing.
	dayLater := int64(2000) + (25 * time.Hour).Milliseconds()
	b := novelBundle()
	b.Window = model.Window{Start: 500_000, End: 501_000}
	b.Templates = append(b.Templates, model.Template{
		Template: "another new one <NUM>", Count: 1, ModuleID: "m9", Priority: 4})
	require.NoError(t, newAnalyzer(t, s,
		&llm.Stub{Content: nominalReply}, dayLater).Process(ctx, b))

	open, err := s.OpenFindings(ctx, "sys1")
	require.NoError(t, err)
	require.Empty(t, open, "a finding absent for over StaleAfter goes stale")

	stale, err := s.ListFindings(ctx, "sys1", 0, model.StatusStale)
	require.NoError(t, err)
	require.Len(t, stale, 1)
}

func TestSystemIsRegisteredOnFirstBundle(t *testing.T) {
	ctx, s := context.Background(), openStore(t)
	a := newAnalyzer(t, s, &llm.Stub{Content: nominalReply}, 2000)
	require.NoError(t, a.Process(ctx, novelBundle()))
	// Registration is what lets an operator see a node exists before it has
	// ever produced a finding.
	known, err := s.KnownTemplates(ctx, "sys1")
	require.NoError(t, err)
	require.NotEmpty(t, known)
}

func TestStoreErrorIsRetryable(t *testing.T) {
	ctx := context.Background()
	s := openStore(t)
	require.NoError(t, s.Close()) // force every query to fail
	a := newAnalyzer(t, s, &llm.Stub{Content: nominalReply}, 2000)

	err := a.Process(ctx, novelBundle())
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrPermanent,
		"a closed database is transient; the message must be redelivered")
}

func TestConcurrentProcessingIsSafe(t *testing.T) {
	ctx, s := context.Background(), openStore(t)
	a := newAnalyzer(t, s, &llm.Stub{Content: nominalReply}, 2000)

	errs := make(chan error, 8)
	for i := range 8 {
		go func(i int) {
			b := novelBundle()
			b.Window = model.Window{Start: int64(i) * 1000, End: int64(i)*1000 + 900}
			errs <- a.Process(ctx, b)
		}(i)
	}
	for range 8 {
		require.NoError(t, <-errs)
	}
}

var _ = errors.New // keep the import if unused after edits
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `go test ./internal/analyzer/ -v`
Expected: FAIL — `undefined: New`

- [ ] **Step 3: Write the implementation**

Create `internal/analyzer/analyzer.go`:

```go
// Package analyzer runs the bundle pipeline: gate, infer, fingerprint, store.
package analyzer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nethesis/nethesis-insights/internal/budget"
	"github.com/nethesis/nethesis-insights/internal/fingerprint"
	"github.com/nethesis/nethesis-insights/internal/gate"
	"github.com/nethesis/nethesis-insights/internal/llm"
	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/prompt"
	"github.com/nethesis/nethesis-insights/internal/store"
)

// ErrPermanent marks a failure that will recur identically on retry. The
// consumer dead-letters these instead of redelivering forever.
var ErrPermanent = errors.New("permanent failure")

// Config holds the analyzer's tunables.
type Config struct {
	Tolerance  float64
	StaleAfter time.Duration
	EWMAAlpha  float64
	Model      string
	Pricing    budget.Pricing
}

// Analyzer processes one bundle at a time and is safe for concurrent use.
type Analyzer struct {
	store store.Store
	llm   llm.Client
	lim   *budget.Limiter
	guard *budget.Guard
	cfg   Config
	now   func() int64
}

// New wires an analyzer. now is injected so tests control time.
func New(s store.Store, c llm.Client, lim *budget.Limiter, g *budget.Guard,
	cfg Config, now func() int64) *Analyzer {
	return &Analyzer{store: s, llm: c, lim: lim, guard: g, cfg: cfg, now: now}
}

// Process runs the pipeline for one bundle.
//
// A nil return means the offset may be committed — including for a bundle that
// was gated out or was a duplicate window. A non-nil return means it may not.
// Wrapping ErrPermanent additionally means retrying is pointless.
func (a *Analyzer) Process(ctx context.Context, b model.Bundle) error {
	now := a.now()
	started := time.Now()

	// 1. Idempotency. A duplicate window is success, not an error: the edge
	//    retried and the work is already done.
	fresh, err := a.store.BeginAnalysis(ctx, b.SystemID,
		b.Window.Start, b.Window.End, now)
	if err != nil {
		return fmt.Errorf("analyzer: begin analysis: %w", err)
	}
	if !fresh {
		slog.Debug("analyzer: duplicate window ignored",
			"system_id", b.SystemID, "window_start", b.Window.Start)
		return nil
	}

	if err := a.store.UpsertSystem(ctx, store.System{
		SystemID: b.SystemID, CollectorVersion: b.CollectorVersion,
		FirstSeen: now, LastSeen: now,
	}); err != nil {
		return fmt.Errorf("analyzer: upsert system: %w", err)
	}

	// 2. Read state BEFORE recording anything, or every template looks known.
	known, err := a.store.KnownTemplates(ctx, b.SystemID)
	if err != nil {
		return fmt.Errorf("analyzer: known templates: %w", err)
	}
	baselines, err := a.store.Baselines(ctx, b.SystemID)
	if err != nil {
		return fmt.Errorf("analyzer: baselines: %w", err)
	}

	// 3. Gate.
	decision := gate.Evaluate(b, gate.SystemState{
		KnownTemplates: known,
		Baselines:      baselines,
		SecurityOnly:   a.guard.SecurityOnly(ctx),
	}, a.cfg.Tolerance)

	// 4. Gated out: record the decision and stop. No LLM cost.
	if !decision.Call {
		if err := a.record(ctx, b, store.Analysis{
			SystemID: b.SystemID, WindowStart: b.Window.Start,
			Gated: true, GateReasons: decision.Reasons,
			DurationMs: int(time.Since(started).Milliseconds()),
		}, now); err != nil {
			return err
		}
		return nil
	}

	// 5-6. Render and infer, under the concurrency cap.
	open, err := a.store.OpenFindings(ctx, b.SystemID)
	if err != nil {
		return fmt.Errorf("analyzer: open findings: %w", err)
	}
	userPrompt := prompt.Render(b, open)

	if err := a.lim.Acquire(ctx); err != nil {
		return fmt.Errorf("analyzer: acquire llm slot: %w", err)
	}
	resp, llmErr := a.llm.Complete(ctx, llm.Request{
		Model: a.cfg.Model, UserPrompt: userPrompt,
	})
	a.lim.Release()

	if llmErr != nil {
		// Record the failure in the ledger before returning, so a repeatedly
		// failing system is visible rather than merely absent.
		_ = a.store.FinalizeAnalysis(ctx, store.Analysis{
			SystemID: b.SystemID, WindowStart: b.Window.Start,
			Gated: false, GateReasons: decision.Reasons, LLMCalled: true,
			Error:      truncate(llmErr.Error(), 500),
			DurationMs: int(time.Since(started).Milliseconds()),
		})
		var he *llm.HTTPError
		if errors.As(llmErr, &he) && he.Permanent() {
			return fmt.Errorf("analyzer: %w: %w", ErrPermanent, llmErr)
		}
		return fmt.Errorf("analyzer: llm: %w", llmErr)
	}

	// 7. Parse. A malformed response will parse identically on retry.
	parsed, assessment, err := prompt.Parse(resp.Content)
	if err != nil {
		_ = a.store.FinalizeAnalysis(ctx, store.Analysis{
			SystemID: b.SystemID, WindowStart: b.Window.Start,
			GateReasons: decision.Reasons, LLMCalled: true,
			InputTokens: resp.InputTokens, OutputTokens: resp.OutputTokens,
			CostMicros: a.cfg.Pricing.CostMicros(resp.InputTokens, resp.OutputTokens),
			Model:      resp.Model,
			Error:      truncate(err.Error(), 500),
			DurationMs: int(time.Since(started).Milliseconds()),
		})
		return fmt.Errorf("analyzer: %w: %w", ErrPermanent, err)
	}

	// 8. Store findings under server-computed identity.
	for _, pf := range parsed {
		category := categoryFor(b, pf.Evidence)
		fp := fingerprint.Compute(b.SystemID, pf.Modules, pf.Evidence, category)
		outcome, err := a.store.UpsertFinding(ctx, model.Finding{
			SystemID: b.SystemID, Fingerprint: fp,
			Severity: pf.Severity, Title: pf.Title, Summary: pf.Summary,
			SuggestedAction: pf.SuggestedAction,
			Modules:         pf.Modules, Evidence: pf.Evidence,
			LLMModel: resp.Model, PromptVersion: prompt.Version,
		}, now)
		if err != nil {
			return fmt.Errorf("analyzer: upsert finding: %w", err)
		}
		if outcome != store.OutcomeBumped {
			slog.Info("analyzer: finding raised",
				"system_id", b.SystemID, "outcome", string(outcome),
				"severity", pf.Severity, "title", pf.Title)
		}
	}

	// 9. Only now is it safe to record templates and baselines. Doing this
	//    earlier would make a retry after an LLM failure see them as known.
	if err := a.record(ctx, b, store.Analysis{
		SystemID: b.SystemID, WindowStart: b.Window.Start,
		Gated: false, GateReasons: decision.Reasons, LLMCalled: true,
		InputTokens: resp.InputTokens, OutputTokens: resp.OutputTokens,
		CostMicros: a.cfg.Pricing.CostMicros(resp.InputTokens, resp.OutputTokens),
		Model:      resp.Model,
		DurationMs: int(time.Since(started).Milliseconds()),
	}, now); err != nil {
		return err
	}

	slog.Debug("analyzer: window analysed", "system_id", b.SystemID,
		"assessment", assessment, "findings", len(parsed))
	return nil
}

// record commits the state a successful (or gated) pass produces: templates,
// baselines, staleness, and the ledger row.
func (a *Analyzer) record(ctx context.Context, b model.Bundle,
	entry store.Analysis, now int64) error {
	if err := a.store.UpsertTemplates(ctx, b.SystemID, b.Templates, now); err != nil {
		return fmt.Errorf("analyzer: upsert templates: %w", err)
	}
	if err := a.store.UpsertBaselines(ctx, b.SystemID, b.Digest,
		a.cfg.EWMAAlpha); err != nil {
		return fmt.Errorf("analyzer: upsert baselines: %w", err)
	}
	if _, err := a.store.MarkStale(ctx, b.SystemID,
		now-a.cfg.StaleAfter.Milliseconds()); err != nil {
		return fmt.Errorf("analyzer: mark stale: %w", err)
	}
	if err := a.store.FinalizeAnalysis(ctx, entry); err != nil {
		return fmt.Errorf("analyzer: finalize analysis: %w", err)
	}
	return nil
}

// categoryFor propagates the edge's classification: security if any cited
// template was flagged security. The server never classifies anything itself.
func categoryFor(b model.Bundle, evidence []string) string {
	for _, e := range evidence {
		if b.CategoryOf(e) == "security" {
			return "security"
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `go test ./internal/analyzer/ -race -v`
Expected: PASS, all fourteen tests. Remove the `var _ = errors.New` line from the test file if `errors` is genuinely used by then.

- [ ] **Step 5: Run the whole suite and the linter**

Run: `make check`
Expected: `license headers OK`, lint clean, every package PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/analyzer
git commit -m "feat(analyzer): gate, infer, fingerprint and store pipeline"
```

---

## Plan 1 complete

At this point the entire analysis pipeline works and is tested offline: a `model.Bundle` in, findings in SQLite out, with gating, deduplication and a cost ledger. Nothing is reachable over the network yet.

**Plan 2** ([2026-08-05-nethesis-insights-transport.md](2026-08-05-nethesis-insights-transport.md)) adds the transport and delivery layer: `internal/queue`, `internal/auth`, `internal/ingest`, `internal/api`, `internal/maint`, `cmd/insightsd` wiring, the container, the load smoke test, and the draft PR.
