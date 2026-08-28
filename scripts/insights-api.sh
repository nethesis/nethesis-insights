#!/bin/bash
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Query a running insightsd over HTTP.
#
#   INSIGHTS_URL   base URL          (default http://localhost:9595)
#   INSIGHTS_CRED  system_id:secret  (required for everything except `health`)
#   INSIGHTS_CURL  extra curl flags  (default none; pass -k for a self-signed
#                  route like the one in docs/runbooks/dev-machine-rl1.md)

set -euo pipefail

URL=${INSIGHTS_URL:-http://localhost:9595}
CRED=${INSIGHTS_CRED:-}
CURL_OPTS=${INSIGHTS_CURL:-}

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

threat-events)
    # threat-events <decisions.json>   — report CrowdSec ban decisions
    need_cred
    file=${1:?usage: threat-events <decisions.json>}
    # shellcheck disable=SC2086
    curl -s $CURL_OPTS -u "$CRED" -X POST -H 'Content-Type: application/json' \
        --data @"$file" -w '\nHTTP %{http_code} in %{time_total}s\n' "$URL/v1/threat-events"
    ;;

blocklist)
    # blocklist [etag]   — fetch the consensus feed; with an etag, expect 304
    need_cred
    etag=${1:-}
    if [ -n "$etag" ]; then
        # shellcheck disable=SC2086
        curl -s $CURL_OPTS -u "$CRED" -H "If-None-Match: $etag" \
            -o /dev/null -w 'HTTP %{http_code}\n' "$URL/v1/blocklist"
    else
        # -D- so the ETag, which the next poll needs, is visible.
        # shellcheck disable=SC2086
        curl -s $CURL_OPTS -u "$CRED" -D- "$URL/v1/blocklist"
    fi
    ;;

allowlist-request)
    # allowlist-request <cidr> [reason]   — ask for an address to be exempted.
    # This only queues a request: nothing is ever allowlisted automatically.
    need_cred
    cidr=${1:?usage: allowlist-request <cidr> [reason]}
    reason=${2:-}
    # shellcheck disable=SC2086
    curl -s $CURL_OPTS -u "$CRED" -X POST -H 'Content-Type: application/json' \
        -d "{\"cidr\":\"$cidr\",\"reason\":\"$reason\"}" \
        -w '\nHTTP %{http_code}\n' "$URL/v1/allowlist-requests"
    ;;

admin)
    # admin <method> <path> [json]   — the allowlist admin API.
    #   INSIGHTS_ADMIN_URL    base URL          (default http://127.0.0.1:9597)
    #   INSIGHTS_ADMIN_KEY    ADMIN_API_KEY     (required)
    #   INSIGHTS_ADMIN_ACTOR  X-Admin-Actor     (default $USER; required on writes)
    #
    # e.g. admin GET  /admin/v1/allowlist/requests
    #      admin POST /admin/v1/allowlist '{"cidr":"203.0.113.0/24","reason":"partner"}'
    admin_url=${INSIGHTS_ADMIN_URL:-http://127.0.0.1:9597}
    admin_key=${INSIGHTS_ADMIN_KEY:-}
    actor=${INSIGHTS_ADMIN_ACTOR:-${USER:-unknown}}
    if [ -z "$admin_key" ]; then
        echo "set INSIGHTS_ADMIN_KEY to the server's ADMIN_API_KEY" >&2
        exit 2
    fi
    method=${1:?usage: admin <method> <path> [json]}
    path=${2:?usage: admin <method> <path> [json]}
    body=${3:-}
    if [ -n "$body" ]; then
        # shellcheck disable=SC2086
        curl -s $CURL_OPTS -X "$method" \
            -H "Authorization: Bearer $admin_key" -H "X-Admin-Actor: $actor" \
            -H 'Content-Type: application/json' -d "$body" "$admin_url$path" | pretty
    else
        # shellcheck disable=SC2086
        curl -s $CURL_OPTS -X "$method" \
            -H "Authorization: Bearer $admin_key" -H "X-Admin-Actor: $actor" \
            "$admin_url$path" | pretty
    fi
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
    sed -n '7,13p' "$0"
    echo
    echo "commands: health | findings [since] | open | post <bundle.json>"
    echo "          threat-events <decisions.json> | blocklist [etag]"
    echo "          allowlist-request <cidr> [reason] | admin <method> <path> [json] | raw <path>"
    exit 2
    ;;
esac
