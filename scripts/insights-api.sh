#!/bin/bash
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Query the split pipelines (insightsd, threatd, sizingd) through the
# Traefik front door, using the prefixed public paths (/logs, /blocklist,
# /sizing) each command targets.
#
#   INSIGHTS_URL   base URL          (default http://localhost -- Traefik's
#                  entrypoint; each command supplies its own /logs, /blocklist
#                  or /sizing prefix)
#   INSIGHTS_CRED  system_id:secret  (required for everything except `health`)
#   INSIGHTS_CURL  extra curl flags  (default none; pass -k for a route
#                  serving a self-signed certificate)
#
# Talking to one binary directly instead (no Traefik in front), e.g. during
# development -- see README.md's manual round trip -- set INSIGHTS_URL to
# that binary's own LISTEN_ADDR (default http://localhost:9595) and drop the
# /logs, /blocklist or /sizing prefix from the path yourself; the handlers
# register unprefixed routes so a pipeline can run standalone.

set -euo pipefail

URL=${INSIGHTS_URL:-http://localhost}
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
    # health   — NOTE: /healthz is registered by every binary but routed by
    # no Traefik rule (only the quadlet HealthCmd= reaches it, inside the
    # container), so this only works when INSIGHTS_URL points directly at
    # one binary's own LISTEN_ADDR, not at the Traefik-fronted host.
    # shellcheck disable=SC2086
    curl -s $CURL_OPTS -o /dev/null -w '%{http_code}\n' "$URL/healthz"
    ;;

findings)
    # findings [since_millis]   — every finding changed after `since`, newest first
    need_cred
    since=${1:-0}
    # shellcheck disable=SC2086
    curl -s $CURL_OPTS -u "$CRED" "$URL/logs/v1/findings?since=$since" | pretty
    ;;

open)
    # open   — one line per open finding: severity, title, modules
    need_cred
    # shellcheck disable=SC2086
    curl -s $CURL_OPTS -u "$CRED" "$URL/logs/v1/findings?since=0" \
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
        --data @"$file" -w '\nHTTP %{http_code} in %{time_total}s\n' "$URL/logs/v1/bundles"
    ;;

events)
    # events <decisions.json>   — report CrowdSec ban decisions
    need_cred
    file=${1:?usage: events <decisions.json>}
    # shellcheck disable=SC2086
    curl -s $CURL_OPTS -u "$CRED" -X POST -H 'Content-Type: application/json' \
        --data @"$file" -w '\nHTTP %{http_code} in %{time_total}s\n' "$URL/blocklist/v1/events"
    ;;

feed)
    # feed [etag]   — fetch the consensus feed; with an etag, expect 304
    need_cred
    etag=${1:-}
    if [ -n "$etag" ]; then
        # shellcheck disable=SC2086
        curl -s $CURL_OPTS -u "$CRED" -H "If-None-Match: $etag" \
            -o /dev/null -w 'HTTP %{http_code}\n' "$URL/blocklist/v1/feed"
    else
        # -D- so the ETag, which the next poll needs, is visible.
        # shellcheck disable=SC2086
        curl -s $CURL_OPTS -u "$CRED" -D- "$URL/blocklist/v1/feed"
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
        -w '\nHTTP %{http_code}\n' "$URL/blocklist/v1/allowlist-requests"
    ;;

raw)
    # raw <path> [curl args...]   — anything else, e.g. raw '/logs/v1/findings?since=0'
    need_cred
    path=${1:?usage: raw <path>}
    shift
    # shellcheck disable=SC2086
    curl -s $CURL_OPTS -u "$CRED" "$@" "$URL$path"
    ;;

*)
    sed -n '6,21p' "$0"
    echo
    echo "commands: health | findings [since] | open | post <bundle.json>"
    echo "          events <decisions.json> | feed [etag]"
    echo "          allowlist-request <cidr> [reason] | raw <path>"
    echo
    echo "There is no admin API any more -- allowlist writes go through the"
    echo "blocklist dashboard's own write routes (see docs/admin-guide.md)."
    exit 2
    ;;
esac
