#!/bin/bash
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Who was refused a blocklist feed: reads authd's "authd: denied" lines
# from the journal and prints one row per (outcome, system_id, client
# address, path) with how many times and when last, most frequent first.
#
#   scripts/feed-denials.sh [--since 24h] [host]
#   scripts/feed-denials.sh --input saved.log
#
#   host           run journalctl over `ssh host` instead of locally
#   --since WHEN   journal window (default 24h). A bare "<n><unit>" such as
#                  24h or 7d means that long ago; anything else is passed to
#                  journalctl --since verbatim ("2026-11-09", "yesterday").
#   --input FILE   read log lines from FILE ("-" for stdin) instead of the
#                  journal, e.g. a saved `journalctl -u authd -o cat`.
#
# Outcomes: invalid_credentials is a 401 -- the system_id is whatever the
# caller typed (authd logs it as claimed_system_id), so the client address
# is the better clue. not_entitled is a 403 -- a genuine subscriber without
# the add-on the full feed needs (/blocklist/v1/feed: ng-blacklist,
# /blocklist/crowdsec/v1/feed: crowdsec-advanced-threat-shield).
#
# Values are printed as authd logged them: slog has already quoted and
# escaped anything a caller could have put in a username, and this script
# does not unescape it.

set -euo pipefail

since=24h
input=
host=

usage() {
    sed -n '6,28p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case $1 in
        --since) since=${2:?--since needs a value}; shift 2 ;;
        --since=*) since=${1#--since=}; shift ;;
        --input) input=${2:?--input needs a file}; shift 2 ;;
        --input=*) input=${1#--input=}; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
        *)
            if [ -n "$host" ]; then
                echo "only one host" >&2
                exit 2
            fi
            host=$1; shift ;;
    esac
done

# journalctl reads "-24h" as 24 hours before now.
if [[ $since =~ ^[0-9]+[a-z]+$ ]]; then
    since=-$since
fi

read_log() {
    if [ -n "$input" ]; then
        cat -- "$input"
        return
    fi
    local cmd=(journalctl -u authd --since "$since" -o cat --no-pager)
    if [ -n "$host" ]; then
        # ssh joins its arguments into one remote shell command, so each
        # one is quoted for that shell.
        ssh -- "$host" "$(printf '%q ' "${cmd[@]}")"
    else
        "${cmd[@]}"
    fi
}

# Parse each line as logfmt (slog's text format): key=value, value either
# bare or double-quoted with backslash escapes. The first occurrence of a
# key wins.
summarize() {
    awk '
    function parse(line,    i, n, c, key, val) {
        split("", f)
        n = length(line); i = 1
        while (i <= n) {
            while (i <= n && substr(line, i, 1) == " ") i++
            key = ""
            while (i <= n && (c = substr(line, i, 1)) != "=" && c != " ") { key = key c; i++ }
            if (i > n || substr(line, i, 1) != "=") continue
            i++
            val = ""
            if (substr(line, i, 1) == "\"") {
                i++
                while (i <= n) {
                    c = substr(line, i, 1)
                    if (c == "\\") { val = val c substr(line, i + 1, 1); i += 2; continue }
                    if (c == "\"") { i++; break }
                    val = val c; i++
                }
            } else {
                while (i <= n && (c = substr(line, i, 1)) != " ") { val = val c; i++ }
            }
            if (!(key in f)) f[key] = val
        }
    }
    BEGIN {
        feeds["/blocklist/v1/feed"]
        feeds["/blocklist/v1/basic-feed"]
        feeds["/blocklist/crowdsec/v1/feed"]
        feeds["/blocklist/crowdsec/v1/basic-feed"]
        OFS = "\t"
    }
    {
        parse($0)
        if (f["msg"] != "authd: denied" || !(f["path"] in feeds)) next
        id = ("system_id" in f) ? f["system_id"] : f["claimed_system_id"]
        if (id == "") id = "-"
        k = f["outcome"] OFS id OFS f["client_addr"] OFS f["path"]
        count[k]++
        if (f["time"] > last[k]) last[k] = f["time"]
    }
    END {
        for (k in count) print count[k], k, last[k]
    }'
}

# grep finding nothing is not an error; journalctl or ssh failing is.
rows=$(read_log | { grep -F 'msg="authd: denied"' || true; } | summarize |
    sort -t "$(printf '\t')" -k1,1nr -k2,2 -k3,3)

if [ -z "$rows" ]; then
    if [ -n "$input" ]; then
        echo "no feed denials in $input"
    else
        echo "no feed denials since $since${host:+ on $host}"
    fi
    exit 0
fi

{
    printf 'COUNT\tOUTCOME\tSYSTEM_ID\tCLIENT_ADDR\tPATH\tLAST\n'
    printf '%s\n' "$rows"
} | if command -v column >/dev/null; then column -t -s "$(printf '\t')"; else cat; fi
