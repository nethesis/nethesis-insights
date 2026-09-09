#!/bin/bash
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#

# Renders deploy/traefik/*.tmpl to /etc/traefik/*.yaml (or DEST_DIR, if
# given as $1). Both Traefik files are committed as templates deliberately
# -- templating one and leaving the other static is a trap, since the
# static one looks editable in place and either the edit is silently
# overwritten on the next render or it is not and the two quietly disagree
# -- so this script is the one place either gets rendered, rather than a
# paragraph of envsubst invocations an operator retypes by hand.
#
# INSIGHTS_HOST and ACME_EMAIL come from /etc/insights/deploy.env, which is
# NOT in this repository -- one per environment (dev vs. production). Both
# are required and this script fails loudly if either is unset rather than
# rendering a broken config: an unset INSIGHTS_HOST fails recognisably
# (Traefik matches no router and every request 404s), but an unset
# ACME_EMAIL would silently render "email: " and fail ACME registration in a
# way that looks like a network problem.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
dest_dir=${1:-/etc/traefik}

deploy_env=/etc/insights/deploy.env
if [ -f "$deploy_env" ]; then
    set -a
    # shellcheck source=/dev/null
    . "$deploy_env"
    set +a
fi

: "${INSIGHTS_HOST:?INSIGHTS_HOST is not set -- define it in $deploy_env}"
: "${ACME_EMAIL:?ACME_EMAIL is not set -- define it in $deploy_env}"

mkdir -p "$dest_dir"

# The explicit variable list matters: unquoted and unargumented, envsubst
# also expands Traefik's own ${...} syntax, producing a config that parses
# cleanly and is silently wrong.
envsubst '$INSIGHTS_HOST $ACME_EMAIL' \
    < "$script_dir/traefik/dynamic.yaml.tmpl" \
    > "$dest_dir/dynamic.yaml"
envsubst '$INSIGHTS_HOST $ACME_EMAIL' \
    < "$script_dir/traefik/traefik.yaml.tmpl" \
    > "$dest_dir/traefik.yaml"

echo "rendered $dest_dir/dynamic.yaml and $dest_dir/traefik.yaml for INSIGHTS_HOST=$INSIGHTS_HOST" >&2
