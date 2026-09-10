#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#

PKG      := github.com/nethesis/nethesis-insights
BINARIES := authd insightsd threatd sizingd
BIN_DIR  := bin

.PHONY: build test lint tidy license-check check clean $(BINARIES)

# One binary per pipeline (plus authd, the shared forward-auth cache) -- see
# CLAUDE.md's "Package layering". CGO_ENABLED=0 keeps every binary static so
# it can be copied into the Containerfile's minimal Alpine runtime stage
# without dragging a libc dependency; that build already cross-compiles each
# service independently (ARG SERVICE), this target is for local dev/CI only.
build: $(BINARIES)

$(BINARIES):
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o $(BIN_DIR)/$@ ./cmd/$@

test:
	go test ./... -race -count=1

lint:
	golangci-lint run

license-check:
	./scripts/check-license-headers.sh

# license-check first: a missing header fails in well under a second, so
# nobody waits out `go test ./... -race` to learn about it.
check: license-check lint test

tidy:
	go mod tidy

clean:
	rm -rf $(BIN_DIR)
