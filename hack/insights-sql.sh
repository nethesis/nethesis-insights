#!/bin/bash
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Read-only SQLite views over an insightsd database. Run it on the node that
# hosts the container, as root.
#
#   INSIGHTS_DB   path to insights.db
#                 (default: the rootful podman volume insights-data)

set -euo pipefail

DB=${INSIGHTS_DB:-/var/lib/containers/storage/volumes/insights-data/_data/insights.db}

if ! command -v sqlite3 >/dev/null; then
    echo "sqlite3 not installed. On Rocky: dnf install -y sqlite" >&2
    exit 2
fi
if [ ! -f "$DB" ]; then
    echo "no database at $DB (set INSIGHTS_DB)" >&2
    exit 2
fi

# -readonly keeps this script from ever competing with the writer for the lock.
q() { sqlite3 -readonly -header -column "$DB" "$1"; }

# Timestamps are unix-millis by design (portable to Postgres), so every query
# that shows one divides by 1000.
cmd=${1:-findings}
shift || true

case "$cmd" in
findings)
    # Severity-ranked exactly as the API returns them.
    q "SELECT substr(id,1,8) AS id, system_id, severity, status, occurrence_count AS n,
              substr(title,1,48) AS title,
              datetime(last_seen/1000,'unixepoch') AS last_seen
       FROM findings
       ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                              WHEN 'medium' THEN 2 ELSE 3 END, last_seen DESC;"
    ;;

finding)
    # finding <fingerprint-prefix|id-prefix>   — the full row, evidence included
    key=${1:?usage: finding <fingerprint or id prefix>}
    q "SELECT * FROM findings
       WHERE fingerprint LIKE '${key}%' OR id LIKE '${key}%';" | sed 's/  */\n  /'
    ;;

analyses)
    # The cost ledger: why each window did or did not spend money.
    q "SELECT substr(id,1,8) AS id, system_id,
              datetime(window_start/1000,'unixepoch') AS window_start,
              gated, llm_called AS llm, completed,
              input_tokens AS in_tok, output_tokens AS out_tok,
              cost_micros AS cost_u, duration_ms AS ms,
              substr(gate_reasons,1,40) AS gate_reasons,
              substr(coalesce(error,''),1,30) AS error
       FROM analyses ORDER BY window_start DESC LIMIT 50;"
    ;;

gate)
    # How often each gate reason fired — the answer to 'why are we paying'.
    q "SELECT gate_reasons, count(*) AS windows, sum(llm_called) AS llm_calls,
              sum(cost_micros) AS cost_micros
       FROM analyses GROUP BY gate_reasons ORDER BY windows DESC;"
    ;;

cost)
    # Spend and token totals per model and per day.
    q "SELECT date(created_at/1000,'unixepoch') AS day, model,
              count(*) AS windows, sum(llm_called) AS llm_calls,
              sum(input_tokens) AS in_tok, sum(output_tokens) AS out_tok,
              sum(cost_micros)/1000000.0 AS cost_usd
       FROM analyses WHERE llm_called=1 GROUP BY day, model ORDER BY day DESC;"
    ;;

templates)
    # What the server considers already-known for a system. A template listed
    # here will not trigger the novelty gate again.
    q "SELECT system_id, module_id, priority AS pri, category, total_count AS n,
              substr(template,1,60) AS template,
              datetime(last_seen/1000,'unixepoch') AS last_seen
       FROM system_templates ORDER BY last_seen DESC LIMIT 50;"
    ;;

baselines)
    # EWMA rates, the fallback the gate uses when a bundle carries no `expected`.
    q "SELECT system_id, module_id, priority AS pri, round(ewma_rate,2) AS ewma,
              datetime(updated_at/1000,'unixepoch') AS updated_at
       FROM module_baselines ORDER BY system_id, module_id, priority;"
    ;;

systems)
    q "SELECT system_id, tenant_id, collector_version,
              datetime(first_seen/1000,'unixepoch') AS first_seen,
              datetime(last_seen/1000,'unixepoch') AS last_seen
       FROM systems ORDER BY last_seen DESC;"
    ;;

counts)
    q "SELECT 'systems' AS t, count(*) AS n FROM systems
       UNION ALL SELECT 'system_templates', count(*) FROM system_templates
       UNION ALL SELECT 'module_baselines', count(*) FROM module_baselines
       UNION ALL SELECT 'findings', count(*) FROM findings
       UNION ALL SELECT 'analyses', count(*) FROM analyses;"
    ;;

schema)
    q "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL;"
    ;;

sql)
    # sql "<query>"   — anything else
    q "${1:?usage: sql \"SELECT ...\"}"
    ;;

*)
    echo "commands: findings | finding <fp> | analyses | gate | cost | templates |"
    echo "          baselines | systems | counts | schema | sql \"SELECT ...\""
    exit 2
    ;;
esac
