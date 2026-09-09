// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package threat

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	threatstore "github.com/nethesis/nethesis-insights/internal/store/threat"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/platform/httpx"
	"github.com/nethesis/nethesis-insights/internal/threat"
)

// maxThreatReportSize matches the bundle limit. A report is a list of ban
// decisions, so it is far smaller in practice; the cap exists to bound a
// malicious or broken reporter, not the honest one.
const maxThreatReportSize = 8 << 20 // 8 MiB

// blocklistCacheSeconds is advertised to clients. Consensus regenerates every
// BLOCKLIST_CONSENSUS_INTERVAL, so most polls are answered by a 304.
const blocklistCacheSeconds = 900

// handleEvents ingests a batch of CrowdSec ban decisions.
//
// Fail-closed on authentication, fail-open on content: a malformed decision
// is dropped with a counter and the rest of the batch is stored, because a
// probe under active attack is exactly the reporter whose batch must not be
// thrown away whole. Synchronous -- there is no LLM here, so no queue.
func (s *server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	authenticatedSystemID, err := httpx.SystemID(r, s.trusted)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var reader io.Reader = io.LimitReader(r.Body, maxThreatReportSize)
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(reader)
		if err != nil {
			reject(w, r, http.StatusBadRequest, "invalid gzip body", "error", err.Error())
			return
		}
		defer gz.Close()
		reader = gz
	}

	var report model.ThreatReport
	if err := json.NewDecoder(reader).Decode(&report); err != nil {
		reject(w, r, http.StatusBadRequest, "invalid json body",
			"error", err.Error(), "content_length", r.ContentLength)
		return
	}

	if report.SchemaVersion != model.ThreatSchemaVersion {
		reject(w, r, http.StatusBadRequest, "unsupported schema_version",
			"got", report.SchemaVersion, "want", model.ThreatSchemaVersion)
		return
	}
	// system_id is optional -- the credential already identifies the reporter
	// -- but a mismatch is a broken reporter, not something to silently
	// override. Same rule as insightsd's bundle ingest.
	if report.SystemID != "" && report.SystemID != authenticatedSystemID {
		reject(w, r, http.StatusForbidden, "system_id does not match authenticated system",
			"report_system_id", report.SystemID, "authenticated_system_id", authenticatedSystemID)
		return
	}

	now := s.cfg.Now()
	sourceIP := sourceAddr(r, s.trusted)

	res := threat.Sanitize(report, threat.Options{
		SourceIP:     sourceIP,
		MaxDecisions: s.cfg.MaxDecisions,
	}, now)

	inserted, duplicates, err := s.store.InsertThreatEvents(r.Context(), authenticatedSystemID, res.Events)
	if err != nil {
		slog.Error("insert threat events failed", "system_id", authenticatedSystemID, "error", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily unavailable")
		return
	}

	// Accounting failures must never cost the reporter its 202: the evidence
	// is already stored, and the counters are an operator convenience.
	day := threatstore.DayString(now)
	if err := s.store.RecordIngestCounters(r.Context(), day, authenticatedSystemID, res.Counters, duplicates); err != nil {
		slog.Error("record ingest counters failed", "system_id", authenticatedSystemID, "error", err)
	}

	slog.Debug("threat report accepted",
		"system_id", authenticatedSystemID,
		"decisions", len(report.Decisions),
		"stored", inserted,
		"duplicates", duplicates,
		"counters", res.Counters,
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(threatIngestResponse{
		Accepted:   true,
		Stored:     inserted,
		Duplicates: duplicates,
		Dropped:    res.Counters,
	})
}

type threatIngestResponse struct {
	Accepted   bool                 `json:"accepted"`
	Stored     int                  `json:"stored"`
	Duplicates int                  `json:"duplicates"`
	Dropped    model.ThreatCounters `json:"dropped"`
}

// handleFeed serves the consensus feed as plain text.
//
// Plain text serves every consumer with no per-client format branch: banip
// reads it as a file, `cscli decisions import --format values` reads it as a
// list.
func (s *server) handleFeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if _, err := httpx.SystemID(r, s.trusted); err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if s.snap == nil || !s.snap.Ready() {
		// No successful consensus pass yet. An empty body would mean "no
		// threats" to every client that imports it, which silently disables
		// protection -- so refuse instead.
		reject(w, r, http.StatusServiceUnavailable, "blocklist not generated yet")
		return
	}

	etag := s.snap.ETag()
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(blocklistCacheSeconds))
	w.Header().Set("Vary", "Accept-Encoding")

	// At a five-minute regeneration cadence, 304 is the normal answer to most
	// polls.
	if matchesETag(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	body := s.snap.Body()
	if acceptsGzip(r) {
		w.Header().Set("Content-Encoding", "gzip")
		body = s.snap.Gzip()
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

// sourceAddr extracts the reporter's real address as httpx.ClientIP resolved
// it.
//
// Behind Traefik, RemoteAddr is always the proxy's own address, which used to
// make the reporter-own-address check below permanently dead (every decision
// looked like it came from someone other than the proxy, so nothing ever
// matched). Traefik is configured to overwrite X-Forwarded-For with the
// connection it actually accepted, and httpx.ClientIP only believes that
// header when RemoteAddr is inside the configured trusted-proxy set -- so a
// direct connection (never trusted) still cannot spoof its way past this with
// a forged header.
func sourceAddr(r *http.Request, trusted httpx.TrustedProxies) netip.Addr {
	host := httpx.ClientIP(r, trusted)
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap().WithZone("")
}

// matchesETag implements the If-None-Match comparison for the one entity tag
// this endpoint serves, including the "*" and comma-separated list forms.
func matchesETag(header, etag string) bool {
	header = strings.TrimSpace(header)
	if header == "" {
		return false
	}
	if header == "*" {
		return true
	}
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		// A cache may weaken the tag; the body is byte-identical either way.
		candidate = strings.TrimPrefix(candidate, "W/")
		if candidate == etag {
			return true
		}
	}
	return false
}

func acceptsGzip(r *http.Request) bool {
	for _, enc := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		name, _, _ := strings.Cut(strings.TrimSpace(enc), ";")
		if strings.EqualFold(name, "gzip") {
			return true
		}
	}
	return false
}
