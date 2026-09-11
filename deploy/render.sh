#!/bin/bash
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#

# Renders deploy/traefik/*.tmpl to /etc/traefik/traefik.yaml and
# /etc/traefik/dynamic/dynamic.yaml (or under DEST_DIR, if given as $1).
# The dynamic half lands in a subdirectory because traefik.yaml.tmpl points
# the file provider at a DIRECTORY -- see its comment: that is what lets the
# optional development stack (deploy/dev/) add routers as a second file
# rather than an edit to this one.
# Both Traefik files are committed as templates deliberately
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
dynamic_dir="$dest_dir/dynamic"

deploy_env=/etc/insights/deploy.env
if [ -f "$deploy_env" ]; then
    set -a
    # shellcheck source=/dev/null
    . "$deploy_env"
    set +a
fi

: "${INSIGHTS_HOST:?INSIGHTS_HOST is not set -- define it in $deploy_env}"
: "${ACME_EMAIL:?ACME_EMAIL is not set -- define it in $deploy_env}"

mkdir -p "$dest_dir" "$dynamic_dir"

# traefik.yaml.tmpl configures the file provider with watch: true, so
# $dynamic_dir is a directory Traefik is actively reading from while this
# script runs. Rendering straight into dynamic.yaml/traefik.yaml would give
# Traefik a window to read a half-written file mid-render -- a routing
# outage that lands at exactly the moment someone is changing routing, and
# looks like a bad config rather than the race it actually is. So render
# into a temp file in the SAME directory first -- mv is only atomic within a
# filesystem, so a temp file anywhere else would turn the final step back
# into a non-atomic copy -- and rename over the target: Traefik then only
# ever sees the old file or the fully-rendered new one, never a partial one.
# The temp name's random suffix is not one of the extensions the directory
# provider loads (.yaml/.yml/.toml/.json), so Traefik ignores it even while
# it is being written.
tmp_dynamic=$(mktemp "$dynamic_dir/.dynamic.yaml.XXXXXX")
tmp_traefik=$(mktemp "$dest_dir/.traefik.yaml.XXXXXX")
# set -euo pipefail means a failed envsubst below exits the script
# immediately, and without this trap the temp file it was writing would be
# left behind in a directory Traefik watches -- harmless to Traefik (it
# never matches *.tmp), but clutter next to config an operator is
# debugging. Runs on success too, where both mv's below have already
# renamed the temp files away, so rm -f is a no-op.
trap 'rm -f "$tmp_dynamic" "$tmp_traefik"' EXIT

# The explicit variable list matters: unquoted and unargumented, envsubst
# also expands Traefik's own ${...} syntax, producing a config that parses
# cleanly and is silently wrong.
envsubst '$INSIGHTS_HOST $ACME_EMAIL' \
    < "$script_dir/traefik/dynamic.yaml.tmpl" \
    > "$tmp_dynamic"
envsubst '$INSIGHTS_HOST $ACME_EMAIL' \
    < "$script_dir/traefik/traefik.yaml.tmpl" \
    > "$tmp_traefik"

# rename(2) carries the temp file's own permissions onto the destination, not
# the destination's -- so without this, the first render after an operator
# hand-edited a mode on either file would silently discard it, and every
# render would otherwise inherit mktemp's 0600 instead of the readable mode
# a plain "> file" would have created. Match what's already there; on the
# very first render there is nothing to match, so fall back to the same 0644
# a fresh "> file" gets under a standard umask.
if [ -e "$dynamic_dir/dynamic.yaml" ]; then
    chmod --reference="$dynamic_dir/dynamic.yaml" "$tmp_dynamic"
else
    chmod 644 "$tmp_dynamic"
fi
if [ -e "$dest_dir/traefik.yaml" ]; then
    chmod --reference="$dest_dir/traefik.yaml" "$tmp_traefik"
else
    chmod 644 "$tmp_traefik"
fi

mv -f "$tmp_dynamic" "$dynamic_dir/dynamic.yaml"
mv -f "$tmp_traefik" "$dest_dir/traefik.yaml"

echo "rendered $dynamic_dir/dynamic.yaml and $dest_dir/traefik.yaml for INSIGHTS_HOST=$INSIGHTS_HOST" >&2
