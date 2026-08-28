// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/store"
	"github.com/nethesis/nethesis-insights/internal/threat"
)

// ThreatStore is the slice of the store the ingest handler needs. Declared
// here, narrow, so the handler is testable with a small fake instead of a
// thirty-method stub. *store.SQLiteStore satisfies it.
type ThreatStore interface {
	InsertThreatEvents(ctx context.Context, systemID string, ev []model.ThreatEvent) (int, int, error)
	RecordSystemEgress(ctx context.Context, systemID, sourceIP string, now int64) error
	RecordIngestCounters(ctx context.Context, day, systemID string, c model.ThreatCounters, duplicates int) error
}

// Feed is the rendered blocklist snapshot. *blocklist.Snapshot satisfies it.
// Serving never touches the database: feed cost is flat regardless of how
// many subscribers poll.
type Feed interface {
	Ready() bool
	Body() []byte
	Gzip() []byte
	ETag() string
	GeneratedAt() int64
}

// ThreatConfig wires the Threat Shield endpoints. The zero value leaves them
// unregistered, which is what api's own tests use.
type ThreatConfig struct {
	Store        ThreatStore
	Feed         Feed
	MaxDecisions int
	Now          func() int64
}

func (c ThreatConfig) enabled() bool { return c.Store != nil && c.Feed != nil }

// maxThreatReportSize matches the bundle limit. A report is a list of ban
// decisions, so it is far smaller in practice; the cap exists to bound a
// malicious or broken reporter, not the honest one.
const maxThreatReportSize = 8 << 20 // 8 MiB

// blocklistCacheSeconds is advertised to clients. Consensus regenerates every
// BLOCKLIST_CONSENSUS_INTERVAL, so most polls are answered by a 304.
const blocklistCacheSeconds = 900

// handleThreatEvents ingests a batch of CrowdSec ban decisions.
//
// Fail-closed on authentication, fail-open on content: a malformed decision
// is dropped with a counter and the rest of the batch is stored, because a
// probe under active attack is exactly the reporter whose batch must not be
// thrown away whole. Synchronous -- there is no LLM here, so no queue.
func (s *server) handleThreatEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	authenticatedSystemID, ok := s.authenticate(w, r)
	if !ok {
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
	// override. Same rule as handleBundles.
	if report.SystemID != "" && report.SystemID != authenticatedSystemID {
		reject(w, r, http.StatusForbidden, "system_id does not match authenticated system",
			"report_system_id", report.SystemID, "authenticated_system_id", authenticatedSystemID)
		return
	}

	now := s.threat.Now()
	sourceIP := remoteAddr(r)

	res := threat.Sanitize(report, threat.Options{
		SourceIP:     sourceIP,
		MaxDecisions: s.threat.MaxDecisions,
	}, now)

	// Recorded before the events: the egress set is what stops one
	// misconfigured appliance getting the fleet's own WAN address listed, and
	// it must be known even for a batch that contributes nothing.
	if sourceIP.IsValid() {
		if err := s.threat.Store.RecordSystemEgress(r.Context(), authenticatedSystemID, sourceIP.String(), now); err != nil {
			slog.Error("record system egress failed", "system_id", authenticatedSystemID, "error", err)
		}
	}

	inserted, duplicates, err := s.threat.Store.InsertThreatEvents(r.Context(), authenticatedSystemID, res.Events)
	if err != nil {
		slog.Error("insert threat events failed", "system_id", authenticatedSystemID, "error", err)
		writeJSONError(w, http.StatusServiceUnavailable, "temporarily unavailable")
		return
	}

	// Accounting failures must never cost the reporter its 202: the evidence
	// is already stored, and the counters are an operator convenience.
	day := store.DayString(now)
	if err := s.threat.Store.RecordIngestCounters(r.Context(), day, authenticatedSystemID, res.Counters, duplicates); err != nil {
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

// handleBlocklist serves the consensus feed as plain text.
//
// Plain text serves every consumer with no per-client format branch: banip
// reads it as a file, `cscli decisions import --format values` reads it as a
// list.
func (s *server) handleBlocklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if _, ok := s.authenticate(w, r); !ok {
		return
	}

	feed := s.threat.Feed
	if !feed.Ready() {
		// No successful consensus pass yet. An empty body would mean "no
		// threats" to every client that imports it, which silently disables
		// protection -- so refuse instead.
		reject(w, r, http.StatusServiceUnavailable, "blocklist not generated yet")
		return
	}

	etag := feed.ETag()
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
	body := feed.Body()
	if acceptsGzip(r) {
		w.Header().Set("Content-Encoding", "gzip")
		body = feed.Gzip()
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

// remoteAddr extracts the peer address the server actually observed.
//
// X-Forwarded-For is deliberately NOT consulted. The value feeds the fleet
// self-protection exclusion set, and the header is client-controlled: an
// authenticated edge could otherwise inject any address it liked and keep it
// off the blocklist permanently. Behind a reverse proxy this records the
// proxy's address, which makes the exclusion useless but never wrong.
func remoteAddr(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
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
