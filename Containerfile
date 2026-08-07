#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#

# Stage 1: build a static, CGO-free binary.
# --platform=$BUILDPLATFORM keeps multi-arch builds native: the Go toolchain
# cross-compiles for $TARGETARCH instead of running the whole stage under QEMU.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.23-alpine3.21 AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w" -o /out/insightsd ./cmd/insightsd

# Stage 2: runtime.
FROM docker.io/library/alpine:3.21

RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -u 1001 -h /var/lib/insights insights

COPY --from=builder /out/insightsd /usr/local/bin/insightsd

ENV LISTEN_ADDR=:9595 \
    DB_PATH=/var/lib/insights/insights.db

USER 1001
WORKDIR /var/lib/insights
VOLUME /var/lib/insights
EXPOSE 9595

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:9595/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/insightsd"]
