#!/bin/bash
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Query a running insightsd over HTTP.
#
#   INSIGHTS_URL   base URL          (default https://controller.gs.nethserver.net/insights)
#   INSIGHTS_CRED  system_id:secret  (required for everything except `health`)
#   INSIGHTS_CURL  extra curl flags  (default -k, the route serves a self-signed cert)

set -euo pipefail

URL=${INSIGHTS_URL:-https://controller.gs.nethserver.net/insights}
CRED=${INSIGHTS_CRED:-}
CURL_OPTS=${INSIGHTS_CURL:--k}

pretty() {
    if command -v jq >/dev/null; then jq .; else python3 -m json.tool; fi
}

need_cred() {
    if [ -z "$CRED" ]; then
        echo "set INSIGHTS_CRED=system_id:secret" >&2
        exit 2
    fi
}

cmd=${1:-findings}
shift || true

case "$cmd" in
health)
    # shellcheck disable=SC2086
    curl -s $CURL_OPTS -o /dev/null -w '%{http_code}\n' "$URL/healthz"
    ;;

findings)
    # findings [since_millis]   — every finding changed after `since`, newest first
    need_cred
    since=${1:-0}
    # shellcheck disable=SC2086
    curl -s $CURL_OPTS -u "$CRED" "$URL/v1/findings?since=$since" | pretty
    ;;

open)
    # open   — one line per open finding: severity, title, modules
    need_cred
    # shellcheck disable=SC2086
    curl -s $CURL_OPTS -u "$CRED" "$URL/v1/findings?since=0" \
        | jq -r '.findings[]? | select(.status=="open")
                 | [.severity, .title, (.modules|join(",")), .occurrence_count] | @tsv' \
        | column -t -s "$(printf '\t')"
    ;;

post)
    # post <bundle.json>   — ingest a bundle, print the HTTP status and timing
    need_cred
    file=${1:?usage: post <bundle.json>}
    # shellcheck disable=SC2086
    curl -s $CURL_OPTS -u "$CRED" -X POST -H 'Content-Type: application/json' \
        --data @"$file" -w '\nHTTP %{http_code} in %{time_total}s\n' "$URL/v1/bundles"
    ;;

raw)
    # raw <path> [curl args...]   — anything else, e.g. raw '/v1/findings?since=0'
    need_cred
    path=${1:?usage: raw <path>}
    shift
    # shellcheck disable=SC2086
    curl -s $CURL_OPTS -u "$CRED" "$@" "$URL$path"
    ;;

*)
    sed -n '7,12p' "$0"
    echo
    echo "commands: health | findings [since] | open | post <bundle.json> | raw <path>"
    exit 2
    ;;
esac
