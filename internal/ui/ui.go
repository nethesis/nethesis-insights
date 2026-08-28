// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package ui serves an optional, off-by-default, unauthenticated read-only
// operator dashboard for insightsd. It replaces the shell helper that used to
// need sqlite3, root on the node and the podman volume path, and adds the live
// process state a query over the database could never see: queue depth,
// uptime, and the effective configuration.
//
// This surface is unauthenticated and fleet-wide -- it shows every system's
// findings, templates, baselines and spend, across tenants. That is why the
// constraints here are not optional:
//
//   - Zero JavaScript. Interactions are <meta refresh>, <form method="get">
//     and <details>, never a <script> tag.
//   - Every handler is GET-only; anything else is 405, enforced once,
//     centrally.
//   - Every list is bounded server-side.
//   - Secrets never render: Info.Config arrives already redacted by the
//     caller, and this package never reads the environment.
package ui

import (
	"bytes"
	"context"
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/store"
)

//go:embed templates static
var assets embed.FS

// Reader is the read-only slice of store.Store the UI needs. *store.SQLiteStore
// satisfies it.
type Reader interface {
	Counts(ctx context.Context) (store.Counts, error)
	ListSystems(ctx context.Context) ([]store.SystemRow, error)
	ListAnalyses(ctx context.Context, systemID string, limit int) ([]store.AnalysisRow, error)
	GateRollup(ctx context.Context) ([]store.GateRow, error)
	CostRollup(ctx context.Context) ([]store.CostRow, error)
	ListAllFindings(ctx context.Context, systemID, status, severity string, limit int) ([]model.Finding, error)
	ListTemplates(ctx context.Context, systemID string, limit int) ([]store.TemplateRow, error)
	ListBaselines(ctx context.Context, systemID string) ([]store.BaselineRow, error)

	// Threat Shield.
	ListBlocklistEntries(ctx context.Context, limit int) ([]store.BlocklistRow, error)
	ListThreatEvents(ctx context.Context, systemID, attackerIP string, limit int) ([]store.ThreatEventRow, error)
	ThreatDailyStats(ctx context.Context, limit int) ([]store.ThreatDailyRow, error)
	ThreatIngestStats(ctx context.Context, limit int) ([]store.ThreatIngestRow, error)
	ListThreatAllowlist(ctx context.Context) ([]store.AllowlistRow, error)
	ListSystemEgress(ctx context.Context) ([]store.EgressRow, error)
}

// Runtime reports live process state. *queue.Queue satisfies it. rt may be
// nil -- tests, and a future caller without a queue -- in which case the
// queue section of the status page renders "n/a" rather than panicking.
type Runtime interface {
	Depth() int
	Cap() int
}

// Feed reports the state of the rendered blocklist snapshot.
// *blocklist.Snapshot satisfies it. Like Runtime it may be nil -- tests, and
// a deployment with the threat pipeline off -- in which case the pages render
// "n/a" rather than panicking. Only the snapshot's *state* crosses this
// boundary, never its body: the UI does not serve the feed.
type Feed interface {
	Ready() bool
	Entries() int
	GeneratedAt() int64
	ETag() string
}

// ConfigItem is one row of the status page's configuration table. The
// caller (cmd/insightsd) builds these explicitly, field by field, from its
// own env config -- this package never reads os.Environ() and never sees a
// raw secret. LLM_API_KEY / AUTH_PEPPER arrive as "set" / "unset" already.
type ConfigItem struct {
	Name  string
	Value string
}

// Info is the static half of the status page, built once by the caller.
type Info struct {
	StartedAt int64 // unix millis
	Workers   int
	Build     string       // from runtime/debug.ReadBuildInfo; "unknown" if absent
	Config    []ConfigItem // explicit list; secrets ALREADY reduced to set/unset by the caller
}

// Bounds on unbounded-by-default queries. /analyses is the only page that
// exposes its limit to the caller (?limit=, clamped to analysesMaxLimit);
// the rest use a fixed internal bound -- this is a fleet-wide, unauthenticated
// surface and no list here is allowed to be unbounded.
const (
	findingsLimit      = 200
	templatesLimit     = 200
	analysesDefaultLim = 50
	analysesMaxLimit   = 500
	blocklistLimit     = 500
	threatEventsDefLim = 50
	threatEventsMaxLim = 500
	threatStatsLimit   = 200
)

type navPage struct {
	Key, Path, Label string
}

var navPages = []navPage{
	{"status", "/", "Status"},
	{"systems", "/systems", "Systems"},
	{"findings", "/findings", "Findings"},
	{"analyses", "/analyses", "Analyses"},
	{"gate", "/gate", "Gate"},
	{"cost", "/cost", "Cost"},
	{"templates", "/templates", "Templates"},
	{"baselines", "/baselines", "Baselines"},
	{"blocklist", "/blocklist", "Blocklist"},
	{"threat-events", "/threat-events", "Threat events"},
	{"threat-stats", "/threat-stats", "Threat stats"},
}

type navItem struct {
	Path, Label string
	Active      bool
}

// pageData is embedded (anonymously) in every page's template data, so
// layout.html's nav/refresh/footer chrome renders the same way regardless
// of which page is on screen.
type pageData struct {
	Nav        []navItem
	Refresh    int
	RefreshOff string
	Refresh10  string
	Refresh30  string
	Build      string
	Uptime     string
}

type server struct {
	reader Reader
	rt     Runtime
	feed   Feed
	info   Info
	tmpl   map[string]*template.Template
	static http.Handler
}

// NewServer builds the operator UI handler. rt and feed may be nil.
func NewServer(r Reader, rt Runtime, feed Feed, info Info) http.Handler {
	staticFS, err := fs.Sub(assets, "static")
	if err != nil {
		// Only reachable if the embed directive above stops matching the
		// static/ directory -- a build-time programming error, not a
		// runtime condition.
		panic("ui: static assets: " + err.Error())
	}

	srv := &server{
		reader: r,
		rt:     rt,
		feed:   feed,
		info:   info,
		tmpl:   parseTemplates(),
		static: http.FileServer(http.FS(staticFS)),
	}

	mux := http.NewServeMux()
	// Every path, including unknown ones, is dispatched centrally through
	// route() so the GET-only rule and the 404 fallback are enforced in
	// exactly one place, per the plan's "enforce it centrally, once".
	mux.HandleFunc("/", srv.route)

	return &loggingHandler{next: mux}
}

// pages lists the content templates, each combined with layout.html into
// its own *template.Template so that every page's {{define "content"}}
// block lives in an isolated namespace -- html/template errors on a
// duplicate block name within one parsed set, and every page legitimately
// defines a block named "content".
var pages = []string{
	"status.html", "systems.html", "findings.html", "analyses.html",
	"gate.html", "cost.html", "templates.html", "baselines.html",
	"blocklist.html", "threat-events.html", "threat-stats.html",
}

func parseTemplates() map[string]*template.Template {
	out := make(map[string]*template.Template, len(pages))
	for _, p := range pages {
		out[p] = template.Must(
			template.New("layout.html").Funcs(funcMap).ParseFS(assets, "templates/layout.html", "templates/"+p),
		)
	}
	return out
}

func (s *server) route(w http.ResponseWriter, r *http.Request) {
	// This is a read-only surface: every route, including /static/, answers
	// only GET. Enforced once, here, rather than per-handler.
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/static/") {
		http.StripPrefix("/static/", s.static).ServeHTTP(w, r)
		return
	}

	switch r.URL.Path {
	case "/":
		s.handleStatus(w, r)
	case "/systems":
		s.handleSystems(w, r)
	case "/findings":
		s.handleFindings(w, r)
	case "/analyses":
		s.handleAnalyses(w, r)
	case "/gate":
		s.handleGate(w, r)
	case "/cost":
		s.handleCost(w, r)
	case "/templates":
		s.handleTemplates(w, r)
	case "/baselines":
		s.handleBaselines(w, r)
	case "/blocklist":
		s.handleBlocklist(w, r)
	case "/threat-events":
		s.handleThreatEvents(w, r)
	case "/threat-stats":
		s.handleThreatStats(w, r)
	default:
		// net/http's ServeMux treats "/" as a subtree covering every
		// unmatched path; because we only ever register "/" itself here and
		// dispatch by hand, an unrecognised path correctly falls through to
		// this 404 rather than silently rendering the status page.
		http.NotFound(w, r)
	}
}

func (s *server) render(w http.ResponseWriter, page string, data any) {
	var buf bytes.Buffer
	if err := s.tmpl[page].ExecuteTemplate(&buf, "layout.html", data); err != nil {
		slog.Error("ui: render failed", "page", page, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

func (s *server) storeError(w http.ResponseWriter, page string, err error) {
	slog.Error("ui: store query failed", "page", page, "error", err)
	http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
}

// newPageData builds the chrome shared by every page: nav with the active
// entry underlined, the meta-refresh value, and the three refresh links
// (off/10s/30s) that preserve the rest of the current query string.
func (s *server) newPageData(r *http.Request, active string) pageData {
	nav := make([]navItem, len(navPages))
	for i, p := range navPages {
		nav[i] = navItem{Path: p.Path, Label: p.Label, Active: p.Key == active}
	}
	off, r10, r30 := refreshLinks(r)
	return pageData{
		Nav:        nav,
		Refresh:    parseRefresh(r),
		RefreshOff: off,
		Refresh10:  r10,
		Refresh30:  r30,
		Build:      s.info.Build,
		Uptime:     FmtAgo(s.info.StartedAt),
	}
}

// parseRefresh returns the positive integer from ?refresh=N, or 0 for a
// missing, zero, negative or non-numeric value. The raw string is never
// returned or rendered -- only this validated int reaches the template,
// which is what keeps an invalid value from ever being reflected into the
// page.
func parseRefresh(r *http.Request) int {
	v := r.URL.Query().Get("refresh")
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// refreshLinks builds the three nav "auto-refresh" links against the
// current path and query string, with only the refresh parameter changed --
// every other filter (system, status, severity, limit, ...) survives.
func refreshLinks(r *http.Request) (off, r10, r30 string) {
	base := r.URL.Path
	q := r.URL.Query()
	q.Del("refresh")
	withQuery := func(v url.Values) string {
		if len(v) == 0 {
			return base
		}
		return base + "?" + v.Encode()
	}
	off = withQuery(q)
	q10 := cloneValues(q)
	q10.Set("refresh", "10")
	r10 = withQuery(q10)
	q30 := cloneValues(q)
	q30.Set("refresh", "30")
	r30 = withQuery(q30)
	return off, r10, r30
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vals := range v {
		out[k] = append([]string(nil), vals...)
	}
	return out
}

// sanitizeSeverity validates a ?severity= value against model's allowlist.
// An unknown value is ignored (treated as "no filter") rather than passed
// through to the store or reflected back into the selected <option>.
func sanitizeSeverity(v string) string {
	if v == "" || model.ValidSeverity(v) {
		return v
	}
	return ""
}

// sanitizeStatus is sanitizeSeverity for ?status=, against the two known
// finding statuses.
func sanitizeStatus(v string) string {
	if v == "" || v == model.StatusOpen || v == model.StatusStale {
		return v
	}
	return ""
}

// clampLimit parses ?limit=, falling back to def on anything invalid, and
// never exceeding max. This is the one user-facing limit knob (/analyses);
// every other page uses a fixed internal bound.
func clampLimit(v string, def, max int) int {
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

// --- handlers ---

// feedState is the snapshot half of the status and blocklist pages. It is a
// value rather than the Feed itself so a nil feed renders as "off" instead of
// panicking in the template.
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
	pageData
	Counts     store.Counts
	HasQueue   bool
	QueueDepth int
	QueueCap   int
	Workers    int
	Feed       feedState
	Config     []ConfigItem
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	counts, err := s.reader.Counts(r.Context())
	if err != nil {
		s.storeError(w, "status", err)
		return
	}
	data := statusPageData{
		pageData: s.newPageData(r, "status"),
		Counts:   counts,
		HasQueue: s.rt != nil,
		Workers:  s.info.Workers,
		Feed:     s.feedState(),
		Config:   s.info.Config,
	}
	if s.rt != nil {
		data.QueueDepth = s.rt.Depth()
		data.QueueCap = s.rt.Cap()
	}
	s.render(w, "status.html", data)
}

type systemsPageData struct {
	pageData
	Systems []store.SystemRow
}

func (s *server) handleSystems(w http.ResponseWriter, r *http.Request) {
	systems, err := s.reader.ListSystems(r.Context())
	if err != nil {
		s.storeError(w, "systems", err)
		return
	}
	s.render(w, "systems.html", systemsPageData{
		pageData: s.newPageData(r, "systems"),
		Systems:  systems,
	})
}

type findingsPageData struct {
	pageData
	Findings   []model.Finding
	System     string
	Status     string
	Severity   string
	Severities []string
}

func (s *server) handleFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	systemID := q.Get("system")
	status := sanitizeStatus(q.Get("status"))
	severity := sanitizeSeverity(q.Get("severity"))

	findings, err := s.reader.ListAllFindings(r.Context(), systemID, status, severity, findingsLimit)
	if err != nil {
		s.storeError(w, "findings", err)
		return
	}
	s.render(w, "findings.html", findingsPageData{
		pageData:   s.newPageData(r, "findings"),
		Findings:   findings,
		System:     systemID,
		Status:     status,
		Severity:   severity,
		Severities: model.Severities,
	})
}

type analysesPageData struct {
	pageData
	Analyses []store.AnalysisRow
	System   string
	Limit    int
}

func (s *server) handleAnalyses(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	systemID := q.Get("system")
	limit := clampLimit(q.Get("limit"), analysesDefaultLim, analysesMaxLimit)

	analyses, err := s.reader.ListAnalyses(r.Context(), systemID, limit)
	if err != nil {
		s.storeError(w, "analyses", err)
		return
	}
	s.render(w, "analyses.html", analysesPageData{
		pageData: s.newPageData(r, "analyses"),
		Analyses: analyses,
		System:   systemID,
		Limit:    limit,
	})
}

type gatePageData struct {
	pageData
	Rows []store.GateRow
}

func (s *server) handleGate(w http.ResponseWriter, r *http.Request) {
	rows, err := s.reader.GateRollup(r.Context())
	if err != nil {
		s.storeError(w, "gate", err)
		return
	}
	s.render(w, "gate.html", gatePageData{
		pageData: s.newPageData(r, "gate"),
		Rows:     rows,
	})
}

type costPageData struct {
	pageData
	Rows []store.CostRow
}

func (s *server) handleCost(w http.ResponseWriter, r *http.Request) {
	rows, err := s.reader.CostRollup(r.Context())
	if err != nil {
		s.storeError(w, "cost", err)
		return
	}
	s.render(w, "cost.html", costPageData{
		pageData: s.newPageData(r, "cost"),
		Rows:     rows,
	})
}

type templatesPageData struct {
	pageData
	Templates []store.TemplateRow
	System    string
}

func (s *server) handleTemplates(w http.ResponseWriter, r *http.Request) {
	systemID := r.URL.Query().Get("system")
	templates, err := s.reader.ListTemplates(r.Context(), systemID, templatesLimit)
	if err != nil {
		s.storeError(w, "templates", err)
		return
	}
	s.render(w, "templates.html", templatesPageData{
		pageData:  s.newPageData(r, "templates"),
		Templates: templates,
		System:    systemID,
	})
}

type baselinesPageData struct {
	pageData
	Baselines []store.BaselineRow
	System    string
}

func (s *server) handleBaselines(w http.ResponseWriter, r *http.Request) {
	systemID := r.URL.Query().Get("system")
	baselines, err := s.reader.ListBaselines(r.Context(), systemID)
	if err != nil {
		s.storeError(w, "baselines", err)
		return
	}
	s.render(w, "baselines.html", baselinesPageData{
		pageData:  s.newPageData(r, "baselines"),
		Baselines: baselines,
		System:    systemID,
	})
}

// --- Threat Shield pages ---

type blocklistPageData struct {
	pageData
	Feed      feedState
	Entries   []store.BlocklistRow
	Allowlist []store.AllowlistRow
	Egress    []store.EgressRow
	Now       int64
}

// handleBlocklist shows what the fleet currently agrees on, plus the two
// exclusion sets. "Why is this IP listed" and "why is this IP never listed"
// are both operator questions, and both are answered on one page.
func (s *server) handleBlocklist(w http.ResponseWriter, r *http.Request) {
	entries, err := s.reader.ListBlocklistEntries(r.Context(), blocklistLimit)
	if err != nil {
		s.storeError(w, "blocklist", err)
		return
	}
	allowlist, err := s.reader.ListThreatAllowlist(r.Context())
	if err != nil {
		s.storeError(w, "blocklist", err)
		return
	}
	egress, err := s.reader.ListSystemEgress(r.Context())
	if err != nil {
		s.storeError(w, "blocklist", err)
		return
	}
	s.render(w, "blocklist.html", blocklistPageData{
		pageData:  s.newPageData(r, "blocklist"),
		Feed:      s.feedState(),
		Entries:   entries,
		Allowlist: allowlist,
		Egress:    egress,
		Now:       time.Now().UnixMilli(),
	})
}

type threatEventsPageData struct {
	pageData
	Events []store.ThreatEventRow
	System string
	IP     string
	Limit  int
}

func (s *server) handleThreatEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	systemID := q.Get("system")
	// Not validated as an address on purpose: an unmatched filter returning
	// nothing is a clearer answer than silently ignoring what was typed. It is
	// a bind parameter either way.
	ip := q.Get("ip")
	limit := clampLimit(q.Get("limit"), threatEventsDefLim, threatEventsMaxLim)

	events, err := s.reader.ListThreatEvents(r.Context(), systemID, ip, limit)
	if err != nil {
		s.storeError(w, "threat-events", err)
		return
	}
	s.render(w, "threat-events.html", threatEventsPageData{
		pageData: s.newPageData(r, "threat-events"),
		Events:   events,
		System:   systemID,
		IP:       ip,
		Limit:    limit,
	})
}

type threatStatsPageData struct {
	pageData
	Daily  []store.ThreatDailyRow
	Ingest []store.ThreatIngestRow
}

func (s *server) handleThreatStats(w http.ResponseWriter, r *http.Request) {
	daily, err := s.reader.ThreatDailyStats(r.Context(), threatStatsLimit)
	if err != nil {
		s.storeError(w, "threat-stats", err)
		return
	}
	ingest, err := s.reader.ThreatIngestStats(r.Context(), threatStatsLimit)
	if err != nil {
		s.storeError(w, "threat-stats", err)
		return
	}
	s.render(w, "threat-stats.html", threatStatsPageData{
		pageData: s.newPageData(r, "threat-stats"),
		Daily:    daily,
		Ingest:   ingest,
	})
}

// --- logging ---
//
// Copied from internal/api rather than exported from it: the plan is
// explicit that internal/ui must not couple to internal/api.

// loggingHandler logs method, path, status and duration for every request.
// The UI is unauthenticated, so there is no Authorization header to worry
// about withholding here -- unlike api.loggingHandler, which this mirrors.
type loggingHandler struct {
	next http.Handler
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (h *loggingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	slog.Debug("ui request received",
		"method", r.Method,
		"path", r.URL.Path,
		"query", r.URL.RawQuery,
		"remote_addr", r.RemoteAddr,
	)

	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	h.next.ServeHTTP(rec, r)

	slog.Info("ui request",
		"method", r.Method,
		"path", r.URL.Path,
		"status", rec.status,
		"duration_ms", time.Since(start).Milliseconds(),
	)
}
