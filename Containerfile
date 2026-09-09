#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#

# One Containerfile builds all four binaries, selected by SERVICE. CI's
# matrix (.github/workflows/image.yml) invokes this once per service and
# pushes each result under its own tag; a node never builds this itself --
# see the ARG's build-arg wiring below and deploy/quadlet, which pull
# finished images.
ARG SERVICE=insightsd

# Stage 1: build a static, CGO-free binary.
# --platform=$BUILDPLATFORM keeps multi-arch builds native: the Go toolchain
# cross-compiles for $TARGETARCH instead of running the whole stage under QEMU.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.23-alpine3.21 AS builder

ARG SERVICE

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w" -o /out/service ./cmd/${SERVICE}

# Stage 2: runtime. No ENV, EXPOSE, VOLUME or HEALTHCHECK here -- each of the
# four services binds its own port and path, so those belong to its quadlet
# (deploy/quadlet/*.container), not to a single image shared by all of them.
FROM docker.io/library/alpine:3.21

RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -u 1001 -h /var/lib/app app

COPY --from=builder /out/service /usr/local/bin/service

USER 1001
WORKDIR /var/lib/app

ENTRYPOINT ["/usr/local/bin/service"]
