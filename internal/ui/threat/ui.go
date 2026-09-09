// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package threat serves threatd's operator dashboard: the blocklist and its
// allowlist, per-system ingest accounting, the raw event stream, the daily
// rollup and the client-facing allowlist review queue. It sits on chrome the
// same way insightsd's internal/ui/logs does -- see that package's doc comment
// for the shared shape (zero JavaScript, every list bounded, secrets never
// rendered) and this file for what is specific to Threat Shield.
package threat

import (
	"context"
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/platform/httpx"
	threatstore "github.com/nethesis/nethesis-insights/internal/store/threat"
	"github.com/nethesis/nethesis-insights/internal/threat"
	"github.com/nethesis/nethesis-insights/internal/ui/chrome"
)

// pageAssets embeds this dashboard's own content templates -- layout.html
// and static/ live in chrome's embed.FS instead.
//
//go:embed templates
var pageAssets embed.FS

// Reader is the read-only slice of threatstore.Store the UI needs.
// *threatstore.Store satisfies it.
type Reader interface {
	Counts(ctx context.Context) (threatstore.Counts, error)
	ListBlocklistEntries(ctx context.Context, limit int) ([]threatstore.BlocklistRow, error)
	ListThreatEvents(ctx context.Context, systemID, attackerIP string, limit int) ([]threatstore.ThreatEventRow, error)
	ThreatDailyStats(ctx context.Context, limit int) ([]threatstore.ThreatDailyRow, error)
	ThreatIngestStats(ctx context.Context, limit int) ([]threatstore.ThreatIngestRow, error)
	ListThreatSystems(ctx context.Context) ([]threatstore.ThreatSystemRow, error)
	ListThreatAllowlist(ctx context.Context) ([]threatstore.AllowlistRow, error)

	// PendingAllowlistRequests backs the /allowlist-requests review queue.
	// This is a read: the queue is visible to anyone who can reach this
	// listener, exactly like every other page here, and it carries no more
	// than a ranked list of CIDRs someone asked about. Only acting on an
	// entry (approve/reject) requires the admin key.
	PendingAllowlistRequests(ctx context.Context, limit int) ([]threatstore.AllowlistRequestRow, error)

	// ListAllowlistAudit backs the /audit page -- the only reader of the
	// append-only trail the four write routes below populate. Without a page
	// reading it, the table would be write-only: CLAUDE.md keeps this trail
	// specifically because DELETE on threat_allowlist destroys the row that
	// would otherwise hold "who removed the exemption that let this through".
	ListAllowlistAudit(ctx context.Context, limit int) ([]threatstore.AllowlistAuditRow, error)
}

// Writer is the slice of threatstore.Store the UI's write routes need:
// adding or removing a threat_allowlist entry, and turning a request into an
// approval or a rejection. It is wired in, and its routes are registered,
// only when ADMIN_API_KEY is set -- see NewServer and writableRoutes.
//
// *threatstore.Store satisfies it, exactly like Reader.
type Writer interface {
	UpsertThreatAllowlistEntry(ctx context.Context, e threatstore.AllowlistRow) error
	DeleteThreatAllowlistEntry(ctx context.Context, cidr string) (bool, error)
	UpsertAllowlistReview(ctx context.Context, cidr, state, decidedBy, note string, now int64) error
	DeleteAllowlistRequests(ctx context.Context, cidr string) (int, error)
	AppendAllowlistAudit(ctx context.Context, cidr, action, actor, detail string, now int64) error
}

// Feed reports the state of the rendered blocklist snapshot.
// *blocklist.Snapshot satisfies it. It may be nil -- tests, and a
// misconfigured deployment -- in which case the pages render "n/a" rather
// than panicking. Only the snapshot's *state* crosses this boundary, never
// its body: the UI does not serve the feed.
type Feed interface {
	Ready() bool
	Entries() int
	GeneratedAt() int64
	ETag() string
}

// Bounds on unbounded-by-default queries. This is a fleet-wide,
// unauthenticated surface and no list here is allowed to be unbounded.
const (
	blocklistLimit     = 500
	threatEventsDefLim = 50
	threatEventsMaxLim = 500
	threatStatsLimit   = 200
	allowlistReqLimit  = 200
	auditLimit         = 500
)

// nav is this dashboard's nav bar structure. A single group with no label
// renders as a flat row, which is right for seven pages.
var nav = []chrome.NavGroup{
	{Pages: []chrome.NavPage{
		{Key: "index", Path: "/", Label: "Blocklist"},
		{Key: "systems", Path: "/systems", Label: "Systems"},
		{Key: "events", Path: "/events", Label: "Events"},
		{Key: "stats", Path: "/stats", Label: "Stats"},
		{Key: "allowlist-requests", Path: "/allowlist-requests", Label: "Allowlist requests"},
		{Key: "audit", Path: "/audit", Label: "Audit"},
		{Key: "status", Path: "/status", Label: "Status"},
	}},
}

// pages lists the content templates, each combined with chrome's layout into
// its own *template.Template -- see chrome.ParseTemplates.
var pages = []string{
	"index.html", "systems.html", "events.html", "stats.html",
	"allowlist-requests.html", "audit.html", "status.html",
}

// writableRoutes is the small, explicit, enumerated set of paths that also
// answer POST. Every one authenticates against ADMIN_API_KEY and refuses a
// cross-site request first: Traefik's BasicAuth in front of this subtree is
// still Basic auth, so a browser replays it on a forged cross-site POST
// exactly as it would here. The proxy is defence in depth, never the gate.
//
// The CIDR itself never travels in these paths: it is always a form field.
var writableRoutes = map[string]bool{
	"/blocklist/allowlist":        true, // add or update an entry
	"/blocklist/allowlist/delete": true, // remove an entry
	"/allowlist-requests/approve": true,
	"/allowlist-requests/reject":  true,
}

type server struct {
	chrome *chrome.Base
	reader Reader
	feed   Feed
	writer Writer
	config []chrome.ConfigItem
}

// NewServer builds threatd's operator UI handler. feed and w may be nil: a
// nil feed renders "n/a" on the status and blocklist pages, and a nil writer
// (equivalently, cfg.AdminKey == "") leaves every write route unreachable --
// an operator who has not set ADMIN_API_KEY gets the plain read-only
// dashboard, with no write form reachable at all.
func NewServer(r Reader, feed Feed, w Writer, cfg chrome.Config) (http.Handler, error) {
	pageTemplates, err := fs.Sub(pageAssets, "templates")
	if err != nil {
		// Only reachable if the embed directive above stops matching the
		// templates/ directory -- a build-time programming error, not a
		// runtime condition.
		return nil, err
	}

	cfg.Name = "threatd"
	cfg.Nav = nav
	cfg.Pages = pages
	cfg.Templates = pageTemplates

	base, err := chrome.New(cfg)
	if err != nil {
		return nil, err
	}

	srv := &server{
		chrome: base,
		reader: r,
		feed:   feed,
		writer: w,
		config: cfg.Info.Config,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.route)

	return httpx.Logging(mux), nil
}

// canWrite reports whether the write forms should render, and whether a
// write route is reachable at all. It is false whenever ADMIN_API_KEY was
// not configured -- an operator who has not set it gets "no write forms at
// all", not forms that render and then always 401.
func (s *server) canWrite() bool {
	return s.writer != nil && s.chrome.CanWrite()
}

func (s *server) route(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		if !s.canWrite() || !writableRoutes[r.URL.Path] {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		actor, ok := s.chrome.AuthenticateWrite(w, r)
		if !ok {
			return
		}
		switch r.URL.Path {
		case "/blocklist/allowlist":
			s.handleAddAllowlist(w, r, actor)
		case "/blocklist/allowlist/delete":
			s.handleDeleteAllowlist(w, r, actor)
		case "/allowlist-requests/approve":
			s.handleApproveRequest(w, r, actor)
		case "/allowlist-requests/reject":
			s.handleRejectRequest(w, r, actor)
		}
		return
	}

	if s.chrome.ServeStatic(w, r) {
		return
	}

	switch r.URL.Path {
	case "/":
		s.handleIndex(w, r)
	case "/systems":
		s.handleSystems(w, r)
	case "/events":
		s.handleEvents(w, r)
	case "/stats":
		s.handleStats(w, r)
	case "/allowlist-requests":
		s.handleAllowlistRequests(w, r)
	case "/audit":
		s.handleAudit(w, r)
	case "/status":
		s.handleStatus(w, r)
	default:
		http.NotFound(w, r)
	}
}

// --- handlers ---

// feedState is the snapshot half of the status and index pages. It is a
// value rather than the Feed itself so a nil feed renders as "off" instead
// of panicking in the template.
type feedState struct {
	Present     bool
	Ready       bool
	Entries     int
	GeneratedAt int64
	ETag        string
}

func (s *server) feedState() feedState {
	if s.feed == nil {
		return feedState{}
	}
	return feedState{
		Present:     true,
		Ready:       s.feed.Ready(),
		Entries:     s.feed.Entries(),
		GeneratedAt: s.feed.GeneratedAt(),
		ETag:        s.feed.ETag(),
	}
}

type statusPageData struct {
	chrome.PageData
	Counts threatstore.Counts
	Feed   feedState
	Config []chrome.ConfigItem
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	counts, err := s.reader.Counts(r.Context())
	if err != nil {
		s.chrome.StoreError(w, "status", err)
		return
	}
	s.chrome.Render(w, "status.html", statusPageData{
		PageData: s.chrome.PageData(r, "status"),
		Counts:   counts,
		Feed:     s.feedState(),
		Config:   s.config,
	})
}

type indexPageData struct {
	chrome.PageData
	Feed      feedState
	Entries   []threatstore.BlocklistRow
	Allowlist []threatstore.AllowlistRow
	Now       int64
	CanWrite  bool
}

// handleIndex shows what the fleet currently agrees on, plus the allowlist
// exclusion. "Why is this IP listed" and "why is this IP never listed" are
// both operator questions, and both are answered on one page.
func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	entries, err := s.reader.ListBlocklistEntries(r.Context(), blocklistLimit)
	if err != nil {
		s.chrome.StoreError(w, "index", err)
		return
	}
	allowlist, err := s.reader.ListThreatAllowlist(r.Context())
	if err != nil {
		s.chrome.StoreError(w, "index", err)
		return
	}
	s.chrome.Render(w, "index.html", indexPageData{
		PageData:  s.chrome.PageData(r, "index"),
		Feed:      s.feedState(),
		Entries:   entries,
		Allowlist: allowlist,
		Now:       time.Now().UnixMilli(),
		CanWrite:  s.canWrite(),
	})
}

type systemsPageData struct {
	chrome.PageData
	Systems []threatstore.ThreatSystemRow
}

// handleSystems is one row per system that has ever reported threat events,
// including a system whose every report was dropped or duplicate.
func (s *server) handleSystems(w http.ResponseWriter, r *http.Request) {
	systems, err := s.reader.ListThreatSystems(r.Context())
	if err != nil {
		s.chrome.StoreError(w, "systems", err)
		return
	}
	s.chrome.Render(w, "systems.html", systemsPageData{
		PageData: s.chrome.PageData(r, "systems"),
		Systems:  systems,
	})
}

type eventsPageData struct {
	chrome.PageData
	Events []threatstore.ThreatEventRow
	System string
	IP     string
	Limit  int
}

func (s *server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	systemID := q.Get("system")
	// Not validated as an address on purpose: an unmatched filter returning
	// nothing is a clearer answer than silently ignoring what was typed. It is
	// a bind parameter either way.
	ip := q.Get("ip")
	limit := chrome.ClampLimit(q.Get("limit"), threatEventsDefLim, threatEventsMaxLim)

	events, err := s.reader.ListThreatEvents(r.Context(), systemID, ip, limit)
	if err != nil {
		s.chrome.StoreError(w, "events", err)
		return
	}
	s.chrome.Render(w, "events.html", eventsPageData{
		PageData: s.chrome.PageData(r, "events"),
		Events:   events,
		System:   systemID,
		IP:       ip,
		Limit:    limit,
	})
}

type statsPageData struct {
	chrome.PageData
	Daily  []dayGroup
	Ingest []threatstore.ThreatIngestRow
}

// dayGroup folds ThreatDailyStats' per-day-per-scenario rows into one group
// per day, plus that day's total hits across every scenario. TotalHits is
// additive so it sums cleanly; DistinctIPs is deliberately not summed here,
// since the same address can appear under more than one scenario and a
// naive sum would overcount it.
type dayGroup struct {
	Day       string
	Rows      []threatstore.ThreatDailyRow
	TotalHits int64
}

func (s *server) handleStats(w http.ResponseWriter, r *http.Request) {
	dailyRows, err := s.reader.ThreatDailyStats(r.Context(), threatStatsLimit)
	if err != nil {
		s.chrome.StoreError(w, "stats", err)
		return
	}
	var daily []dayGroup
	for _, row := range dailyRows {
		if len(daily) == 0 || daily[len(daily)-1].Day != row.Day {
			daily = append(daily, dayGroup{Day: row.Day})
		}
		g := &daily[len(daily)-1]
		g.Rows = append(g.Rows, row)
		g.TotalHits += row.TotalHits
	}
	ingest, err := s.reader.ThreatIngestStats(r.Context(), threatStatsLimit)
	if err != nil {
		s.chrome.StoreError(w, "stats", err)
		return
	}
	s.chrome.Render(w, "stats.html", statsPageData{
		PageData: s.chrome.PageData(r, "stats"),
		Daily:    daily,
		Ingest:   ingest,
	})
}

// --- Allowlist requests: the review queue, and its write half ---

type allowlistRequestsPageData struct {
	chrome.PageData
	Requests []threatstore.AllowlistRequestRow
	CanWrite bool
}

// handleAllowlistRequests shows the pending review queue. It is a GET, and
// therefore unauthenticated like every other page: the queue is a ranked
// list of CIDRs someone asked about, and only acting on one (approve/reject)
// requires the admin key.
func (s *server) handleAllowlistRequests(w http.ResponseWriter, r *http.Request) {
	requests, err := s.reader.PendingAllowlistRequests(r.Context(), allowlistReqLimit)
	if err != nil {
		s.chrome.StoreError(w, "allowlist-requests", err)
		return
	}
	s.chrome.Render(w, "allowlist-requests.html", allowlistRequestsPageData{
		PageData: s.chrome.PageData(r, "allowlist-requests"),
		Requests: requests,
		CanWrite: s.canWrite(),
	})
}

type auditPageData struct {
	chrome.PageData
	Entries []threatstore.AllowlistAuditRow
}

// handleAudit shows the append-only trail every allowlist write appends to
// (add, delete, approve, reject) -- the only page in this pipeline that
// reads it. It is a plain GET, same as the review queue: this table records
// who did what, not a decision to be made, so there is nothing to
// authenticate here.
func (s *server) handleAudit(w http.ResponseWriter, r *http.Request) {
	entries, err := s.reader.ListAllowlistAudit(r.Context(), auditLimit)
	if err != nil {
		s.chrome.StoreError(w, "audit", err)
		return
	}
	s.chrome.Render(w, "audit.html", auditPageData{
		PageData: s.chrome.PageData(r, "audit"),
		Entries:  entries,
	})
}

// handleAddAllowlist and handleDeleteAllowlist are POST form handlers
// (writableRoutes), reached only after HTTP Basic authentication. Both
// redirect back to / rather than answering JSON: this is a human submitting
// a form, and the useful response is the updated page, not a status code.

func (s *server) handleAddAllowlist(w http.ResponseWriter, r *http.Request, actor string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	force := r.FormValue("force") != ""
	cidr, _, err := threat.ParseAllowlistEntry(r.FormValue("cidr"), force)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	reason := threat.CleanText(r.FormValue("reason"), model.MaxAllowlistReasonLen)
	now := time.Now().UnixMilli()

	if err := s.writer.UpsertThreatAllowlistEntry(r.Context(), threatstore.AllowlistRow{
		CIDR: cidr, Reason: reason, CreatedBy: actor, CreatedAt: now,
	}); err != nil {
		s.chrome.StoreError(w, "index", err)
		return
	}
	if err := s.writer.AppendAllowlistAudit(r.Context(), cidr, "allowlist.upsert", actor, reason, now); err != nil {
		slog.Error("ui: append allowlist audit failed", "cidr", cidr, "error", err)
	}
	http.Redirect(w, r, s.chrome.Link("/"), http.StatusSeeOther)
}

func (s *server) handleDeleteAllowlist(w http.ResponseWriter, r *http.Request, actor string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	// force=true: breadth guards adding an exemption, not removing one --
	// the caller must be able to remove whatever is actually stored.
	cidr, _, err := threat.ParseAllowlistEntry(r.FormValue("cidr"), true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	existed, err := s.writer.DeleteThreatAllowlistEntry(r.Context(), cidr)
	if err != nil {
		s.chrome.StoreError(w, "index", err)
		return
	}
	if !existed {
		http.Error(w, "no such allowlist entry", http.StatusNotFound)
		return
	}
	now := time.Now().UnixMilli()
	if err := s.writer.AppendAllowlistAudit(r.Context(), cidr, "allowlist.delete", actor, "", now); err != nil {
		slog.Error("ui: append allowlist audit failed", "cidr", cidr, "error", err)
	}
	http.Redirect(w, r, s.chrome.Link("/"), http.StatusSeeOther)
}

// handleApproveRequest is the only path this package offers from a client
// request to a live allowlist entry, and it only ever runs because an
// authenticated human submitted this form -- see the "no automatic
// promotion" rule in CLAUDE.md.
func (s *server) handleApproveRequest(w http.ResponseWriter, r *http.Request, actor string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	cidr, _, err := threat.ParseAllowlistEntry(r.FormValue("cidr"), false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	note := threat.CleanText(r.FormValue("note"), model.MaxAllowlistReasonLen)
	reason := note
	if reason == "" {
		reason = "approved via operator UI"
	}
	now := time.Now().UnixMilli()

	if err := s.writer.UpsertThreatAllowlistEntry(r.Context(), threatstore.AllowlistRow{
		CIDR: cidr, Reason: reason, CreatedBy: actor, CreatedAt: now,
	}); err != nil {
		s.chrome.StoreError(w, "allowlist-requests", err)
		return
	}
	if err := s.writer.UpsertAllowlistReview(r.Context(), cidr, threatstore.AllowlistReviewApproved, actor, note, now); err != nil {
		slog.Error("ui: record allowlist review failed", "cidr", cidr, "error", err)
	}
	if err := s.writer.AppendAllowlistAudit(r.Context(), cidr, "request.approve", actor, note, now); err != nil {
		slog.Error("ui: append allowlist audit failed", "cidr", cidr, "error", err)
	}
	// Retire the handled request, last: see threatstore.DeleteAllowlistRequests
	// for why the queue is emptied only after the decision is durable.
	if _, err := s.writer.DeleteAllowlistRequests(r.Context(), cidr); err != nil {
		slog.Error("ui: delete handled allowlist requests failed", "cidr", cidr, "error", err)
	}
	http.Redirect(w, r, s.chrome.Link("/allowlist-requests"), http.StatusSeeOther)
}

// handleRejectRequest creates no allowlist entry -- there is nothing here
// that could auto-promote anything.
func (s *server) handleRejectRequest(w http.ResponseWriter, r *http.Request, actor string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	raw := strings.TrimSpace(r.FormValue("cidr"))
	if raw == "" {
		http.Error(w, "cidr is required", http.StatusBadRequest)
		return
	}
	cidr, _, err := threat.ParseAllowlistEntry(raw, true) // no entry is created; breadth is irrelevant
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	note := threat.CleanText(r.FormValue("note"), model.MaxAllowlistReasonLen)
	now := time.Now().UnixMilli()

	if err := s.writer.UpsertAllowlistReview(r.Context(), cidr, threatstore.AllowlistReviewRejected, actor, note, now); err != nil {
		s.chrome.StoreError(w, "allowlist-requests", err)
		return
	}
	if err := s.writer.AppendAllowlistAudit(r.Context(), cidr, "request.reject", actor, note, now); err != nil {
		slog.Error("ui: append allowlist audit failed", "cidr", cidr, "error", err)
	}
	if _, err := s.writer.DeleteAllowlistRequests(r.Context(), cidr); err != nil {
		slog.Error("ui: delete handled allowlist requests failed", "cidr", cidr, "error", err)
	}
	http.Redirect(w, r, s.chrome.Link("/allowlist-requests"), http.StatusSeeOther)
}
