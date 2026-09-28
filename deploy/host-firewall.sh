#!/bin/bash
#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-3.0-or-later
#

# Closes the host down to SSH plus the proxy's two ports: turns Cockpit off
# and turns firewalld on with ssh, http and https allowed in the default
# zone. Also opens node_exporter's 9100 (node-exporter.container), but only
# to the metrics server -- METRICS_SCRAPER, an address or a name, default
# 2.119.67.169 (metrics.nethesis.it's public address). Idempotent, so it is safe to re-run on a
# server already running.
#
# Cockpit goes because a stock RHEL-family cloud image ships cockpit.socket
# enabled on *:9090 -- a root-capable web login on a public interface, on a
# host whose whole port surface is otherwise 80 and 443.
#
# The firewall covers the HOST's own listeners (sshd, anything a package
# enables later), and only those. It does NOT guard a port a container
# publishes: netavark's DNAT rules route published traffic around firewalld's
# service filter -- verified on the deployed host, where a container
# published on a port firewalld does not list answered from the internet. So
# "no container has a PublishPort except the pod's 80/443" stays the control
# for the three unauthenticated dashboards, and admin-guide.md step 8's `ss`
# check stays the way to verify it; this script is not a substitute.
#
# ssh is added before firewalld is ever started, through
# firewall-offline-cmd, so starting it cannot lock the operator out of the
# session running this script, even on a zone someone stripped of ssh.
#
# The default is an address, not metrics.nethesis.it, because that name
# resolves to a private address inside Nethesis's network, while scrapes
# arrive from its public one. firewalld matches addresses, not names, so a
# name given in METRICS_SCRAPER is resolved once, here. If the metrics server
# moves to a new address, scraping stops until this is re-run with it;
# re-running also closes the old address, since every 9100 rule is replaced
# rather than added to.
set -euo pipefail

scraper=${METRICS_SCRAPER:-2.119.67.169}
node_exporter_port=9100

command -v firewall-cmd >/dev/null 2>&1 || {
    echo "host-firewall: firewalld not found -- install it (see admin-guide.md step 1)" >&2
    exit 1
}

# Resolved before anything changes: a name that does not resolve stops the
# script with the host untouched, rather than leaving 9100 open to nobody
# (or, worse, to a guess).
mapfile -t scraper_addrs < <(getent ahosts "$scraper" | awk '{print $1}' | sort -u)
if [ "${#scraper_addrs[@]}" -eq 0 ]; then
    echo "host-firewall: $scraper does not resolve -- set METRICS_SCRAPER or fix DNS" >&2
    exit 1
fi

if systemctl list-unit-files cockpit.socket >/dev/null 2>&1; then
    systemctl disable --now cockpit.socket cockpit.service >/dev/null 2>&1 || true
fi

# The offline tool reads the same permanent configuration the daemon will
# load, so both branches agree on the zone. --get-default-zone is a
# stand-alone option and refuses --permanent, hence its own call; and the
# offline tool reads a bare --remove-service as a legacy lokkit option that
# refuses --zone, so it spells the zone form --remove-service-from-zone.
if systemctl is-active --quiet firewalld; then
    running=1
    fw() { firewall-cmd --permanent "$@"; }
    zone=$(firewall-cmd --get-default-zone)
    remove_service=--remove-service
else
    running=0
    fw() { firewall-offline-cmd "$@"; }
    zone=$(firewall-offline-cmd --get-default-zone)
    remove_service=--remove-service-from-zone
fi

for svc in ssh http https; do
    fw --zone="$zone" --query-service="$svc" >/dev/null 2>&1 ||
        fw --zone="$zone" --add-service="$svc" >/dev/null
done
if fw --zone="$zone" --query-service=cockpit >/dev/null 2>&1; then
    fw --zone="$zone" "$remove_service=cockpit" >/dev/null
fi

if [ "$running" -eq 0 ]; then
    systemctl enable --now firewalld
fi

# Rich rules exist only in the daemon's tool (firewall-offline-cmd has no
# rich-rule options), so this half always runs against a running firewalld.
# Every rule for the port is removed and the current addresses added back:
# all of it --permanent, so nothing changes on the wire until the reload.
while IFS= read -r rule; do
    case $rule in
    *"port port=\"$node_exporter_port\" protocol=\"tcp\""*)
        firewall-cmd --permanent --zone="$zone" --remove-rich-rule="$rule" >/dev/null
        ;;
    esac
done < <(firewall-cmd --permanent --zone="$zone" --list-rich-rules)
for addr in "${scraper_addrs[@]}"; do
    family=ipv4
    case $addr in *:*) family=ipv6 ;; esac
    firewall-cmd --permanent --zone="$zone" \
        --add-rich-rule="rule family=\"$family\" source address=\"$addr\" port port=\"$node_exporter_port\" protocol=\"tcp\" accept" >/dev/null
done
firewall-cmd --reload >/dev/null

echo "firewalld on, zone $zone allows: $(firewall-cmd --zone="$zone" --list-services); $node_exporter_port/tcp from $scraper (${scraper_addrs[*]}) only; cockpit off" >&2
