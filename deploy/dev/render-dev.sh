#!/bin/bash
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#

# Renders the DEVELOPMENT monitoring stack's two per-deployment files -- see
# deploy/dev/README.md:
#
#   /etc/traefik/dynamic/dev.yaml   the Grafana and Prometheus routers
#   /etc/insights/grafana.env       Grafana's root URL and admin credential
#
# It is a sibling to deploy/render.sh, never folded into it: render.sh runs
# on every deployment, this runs only on a host that wants the dev stack, and
# that separation IS the mechanism keeping Grafana and Prometheus out of
# production. A production host simply never runs this, so /etc/traefik/
# dynamic/dev.yaml does not exist and the routers do not exist either.
#
# Unlike production -- where render.sh does templating and gen-metrics-auth.sh
# does secrets -- one script does both here, because grafana.env is a single
# file that is BOTH templated (the root URL is built from INSIGHTS_HOST) and
# secret (it holds the admin password). Splitting one file's generation across
# two scripts would be worse than one script covering two concerns.
#
# INSIGHTS_HOST comes from /etc/insights/deploy.env, the same
# not-in-this-repository file render.sh reads. ACME_EMAIL is not needed here.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
dest_dir=${1:-/etc/traefik}
dynamic_dir="$dest_dir/dynamic"

secrets_dir=/etc/insights
deploy_env="$secrets_dir/deploy.env"
grafana_env="$secrets_dir/grafana.env"

if [ -f "$deploy_env" ]; then
    set -a
    # shellcheck source=/dev/null
    . "$deploy_env"
    set +a
fi

: "${INSIGHTS_HOST:?INSIGHTS_HOST is not set -- define it in $deploy_env}"

install -d -m 755 "$secrets_dir"
install -d -m 755 "$dynamic_dir"

# --- the admin credential -------------------------------------------------
#
# Idempotent, the same rule gen-metrics-auth.sh follows: an existing password
# is reused rather than replaced, so re-running this (a re-render after a
# hostname change, an upgrade) never locks anybody out of a Grafana they are
# already signed in to. Read with sed rather than by sourcing the file --
# this value is a password, and sourcing it would run whatever it happens to
# contain.
existing=""
if [ -f "$grafana_env" ]; then
    existing=$(sed -n 's/^GF_SECURITY_ADMIN_PASSWORD=//p' "$grafana_env" | head -1)
fi

password=${GRAFANA_ADMIN_PASSWORD:-$existing}
if [ -z "$password" ]; then
    echo "render-dev: no password -- run with GRAFANA_ADMIN_PASSWORD=... (it is stored in $grafana_env and reused on later runs)" >&2
    exit 1
fi

# systemd's EnvironmentFile parser strips quotes and backslash escapes from a
# value, so a password containing either arrives at Grafana as something else
# and the login fails in a way that looks like a wrong password rather than a
# quoting bug. Refuse it here instead.
case $password in
    *\"*|*\'*|*\\*|*$'\n'*)
        echo "render-dev: GRAFANA_ADMIN_PASSWORD must not contain quotes, backslashes or newlines -- systemd's EnvironmentFile parser rewrites them" >&2
        exit 1
        ;;
esac

umask 077
tmp_env=$(mktemp "$secrets_dir/.grafana.env.XXXXXX")
trap 'rm -f "$tmp_env"' EXIT

# GF_SERVER_ROOT_URL carries the public path, and SERVE_FROM_SUB_PATH is what
# makes Grafana actually mount itself there rather than merely generate links
# that point there. Both, or the UI loads and every asset 404s.
#
# GF_SECURITY_ADMIN_PASSWORD is only applied when Grafana initialises its
# database -- on a volume that already holds an admin user it is ignored, so
# changing the password later means either wiping insights-grafana.volume or
# running `podman exec grafana grafana-cli admin reset-admin-password ...`.
{
    printf '#\n# Written by deploy/dev/render-dev.sh. Not in the repository.\n#\n'
    printf 'GF_SERVER_ROOT_URL=https://%s/grafana/\n' "$INSIGHTS_HOST"
    printf 'GF_SERVER_SERVE_FROM_SUB_PATH=true\n'
    printf 'GF_SECURITY_ADMIN_USER=admin\n'
    printf 'GF_SECURITY_ADMIN_PASSWORD=%s\n' "$password"
} > "$tmp_env"
chmod 600 "$tmp_env"
mv -f "$tmp_env" "$grafana_env"

# --- the Traefik routers --------------------------------------------------
#
# Same atomic-render discipline as render.sh, and it matters more here:
# $dynamic_dir is read by Traefik's file provider as a DIRECTORY, so a
# half-written config in it is a half-loaded router set rather than one
# half-read file. The temp file's random suffix is not one of the extensions
# that provider loads (.yaml/.yml/.toml/.json), so Traefik ignores it even
# mid-render; the rename is what publishes it.
tmp_dev=$(mktemp "$dynamic_dir/.dev.yaml.XXXXXX")
trap 'rm -f "$tmp_env" "$tmp_dev"' EXIT

# The explicit variable list matters: unquoted and unargumented, envsubst
# also expands Traefik's own ${...} syntax, producing a config that parses
# cleanly and is silently wrong.
envsubst '$INSIGHTS_HOST' \
    < "$script_dir/traefik/dev.yaml.tmpl" \
    > "$tmp_dev"

# rename(2) carries the temp file's own permissions onto the destination, so
# without this every render would inherit mktemp's 0600 instead of the
# readable mode a plain "> file" would have created.
if [ -e "$dynamic_dir/dev.yaml" ]; then
    chmod --reference="$dynamic_dir/dev.yaml" "$tmp_dev"
else
    chmod 644 "$tmp_dev"
fi

mv -f "$tmp_dev" "$dynamic_dir/dev.yaml"

echo "rendered $dynamic_dir/dev.yaml and $grafana_env for INSIGHTS_HOST=$INSIGHTS_HOST (password never printed)" >&2
