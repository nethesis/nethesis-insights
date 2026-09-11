#!/bin/bash
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#

# Generates the Prometheus scrape credential and writes
# /etc/traefik/metrics.htpasswd (or DEST_DIR, if given as $1) from it.
#
# This is a sibling to render.sh, not folded into it: render.sh's whole job
# is templating dynamic.yaml/traefik.yaml from deploy.env, and mixing secret
# generation into that would make one script respond to two very different
# kinds of change. This belongs with the other secrets instead -- it is the
# last thing install step 5 runs, after the four hand-written *.env files and
# the operator htpasswd, and before step 6 renders the proxy config.
#
# The credential is deliberately separate from operator BasicAuth
# (/etc/traefik/operators.htpasswd, keyed on ADMIN_API_KEY): the point of a
# distinct metricsAuth scheme (see docs/api/openapi.yaml) is a password a
# monitoring system holds on its own, never one shared with an operator's
# dashboard login or the fleet's ADMIN_API_KEY. It lives in
# /etc/insights/metrics.env, alongside the other four *.env secret files
# install step 5 creates.
#
# Idempotent: an existing METRICS_AUTH_PASSWORD in metrics.env is reused
# rather than replaced, so re-running this (an upgrade, a re-render, a
# second host) never invalidates a scrape config a monitoring system
# already holds. The password is never echoed -- htpasswd -nbB folds it
# straight into a bcrypt hash and nothing here prints the plaintext.
set -euo pipefail

dest_dir=${1:-/etc/traefik}
secrets_dir=/etc/insights
metrics_env="$secrets_dir/metrics.env"

command -v htpasswd >/dev/null 2>&1 || {
    echo "gen-metrics-auth: htpasswd not found -- install httpd-tools (see admin-guide.md step 1)" >&2
    exit 1
}
command -v openssl >/dev/null 2>&1 || {
    echo "gen-metrics-auth: openssl not found" >&2
    exit 1
}

install -d -m 755 "$secrets_dir"
install -d -m 755 "$dest_dir"

if [ -f "$metrics_env" ] && grep -q '^METRICS_AUTH_PASSWORD=' "$metrics_env"; then
    # shellcheck disable=SC1090
    . "$metrics_env"
else
    METRICS_AUTH_PASSWORD=$(openssl rand -hex 32)
    umask 077
    printf 'METRICS_AUTH_PASSWORD=%s\n' "$METRICS_AUTH_PASSWORD" > "$metrics_env"
    chmod 600 "$metrics_env"
fi

: "${METRICS_AUTH_PASSWORD:?METRICS_AUTH_PASSWORD is empty in $metrics_env}"

# Same atomic-render discipline as render.sh: Traefik's file provider
# watches this directory, so write into a temp file in the SAME directory
# first and rename over the target -- Traefik then only ever sees the old
# file or the fully-written new one, never a half-written one.
tmp_htpasswd=$(mktemp "$dest_dir/.metrics.htpasswd.XXXXXX")
trap 'rm -f "$tmp_htpasswd"' EXIT

htpasswd -nbB prometheus "$METRICS_AUTH_PASSWORD" > "$tmp_htpasswd"

if [ -e "$dest_dir/metrics.htpasswd" ]; then
    chmod --reference="$dest_dir/metrics.htpasswd" "$tmp_htpasswd"
else
    chmod 640 "$tmp_htpasswd"
fi

mv -f "$tmp_htpasswd" "$dest_dir/metrics.htpasswd"

echo "wrote $dest_dir/metrics.htpasswd (credential in $metrics_env, never printed)" >&2
