// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package httpx holds the HTTP plumbing every binary in this repository
// shares: resolving the real client address behind the proxy, reading the
// system identity off a request the proxy has already authenticated, the
// request logger, and the health endpoint.
package httpx

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// TrustedProxies is the set of addresses whose X-Forwarded-For header this
// process believes. It is configuration (TRUSTED_PROXY_CIDRS), never a
// constant: the deployment's proxy address is not this package's business,
// and an empty set trusts nobody.
type TrustedProxies []netip.Prefix

// ParseTrustedProxies parses a comma-separated list of CIDR prefixes.
// A bare address is accepted and treated as a single-host prefix.
func ParseTrustedProxies(csv string) (TrustedProxies, error) {
	var out TrustedProxies
	for _, raw := range strings.Split(csv, ",") {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("httpx: %q is neither a CIDR prefix nor an address", s)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// Contains reports whether remoteAddr -- an "ip:port" or a bare ip -- falls
// inside the trusted set.
func (t TrustedProxies) Contains(remoteAddr string) bool {
	a, ok := parseHost(remoteAddr)
	if !ok {
		return false
	}
	for _, p := range t {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ClientIP returns the address the request really came from.
//
// X-Forwarded-For is consulted only when RemoteAddr is a trusted proxy,
// because the header is otherwise client-controlled and this value feeds
// threat.Sanitize's reporter-own-address check. The rightmost entry is the
// one the trusted proxy itself observed: Traefik is configured to overwrite
// the header, so there is normally exactly one, but rightmost stays correct
// if it is ever configured to append instead.
//
// Anything unparseable falls back to RemoteAddr rather than to an error --
// the caller has no useful recovery, and RemoteAddr is always a real
// observation even when it is only the proxy's.
func ClientIP(r *http.Request, t TrustedProxies) string {
	remote := hostOnly(r.RemoteAddr)
	if !t.Contains(r.RemoteAddr) {
		return remote
	}
	xff := r.Header.Get("X-Forwarded-For")
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		s := strings.TrimSpace(parts[i])
		if s == "" {
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			return a.String()
		}
		return remote
	}
	return remote
}

func parseHost(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(hostOnly(s))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

func hostOnly(s string) string {
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return strings.Trim(s, "[]")
}
