// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package ui serves an optional, off-by-default operator dashboard for
// insightsd. It replaces the shell helper that used to need sqlite3, root on
// the node and the podman volume path, and adds the live process state a
// query over the database could never see: queue depth, uptime, and the
// effective configuration.
//
// Reads are unauthenticated and fleet-wide -- every GET shows every
// system's findings, templates, baselines and spend, across tenants, exactly
// as before. That is why most of the constraints here are not optional:
//
//   - Zero JavaScript. Interactions are <meta refresh>, <form> and
//     <details>, never a <script> tag.
//   - Every list is bounded server-side.
//   - Secrets never render: Info.Config arrives already redacted by the
//     caller, and this package never reads the environment.
//
// A small, explicit, enumerated set of routes also answers POST: adding and
// removing a threat_allowlist entry, and approving/rejecting a client's
// allowlist request. Every one of those authenticates with HTTP Basic
// against ADMIN_API_KEY before doing anything, and is registered at all only
// when a key was configured -- with none set, this package behaves exactly
// like the read-only dashboard it used to be. See writableRoutes and
// route() for the one place this rule is enforced. The Basic username
// becomes the actor recorded with the write and in the audit trail; this is
// not a security control (anyone holding the key can claim any name), only
// a readable trail.
package ui

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
	"github.com/nethesis/nethesis-insights/internal/sizing"
	"github.com/nethesis/nethesis-insights/internal/store"
	"github.com/nethesis/nethesis-insights/internal/threat"
	"github.com/nethesis/nethesis-insights/internal/ui/chrome"
)

// pageAssets embeds this dashboard's own content templates -- layout.html
// and static/ live in chrome's embed.FS instead, since chrome owns the
// shared chrome (see internal/ui/chrome).
//
//go:embed templates
var pageAssets embed.FS

// Reader is the read-only slice of store.Store the UI needs. *store.SQLiteStore
// satisfies it.
type Reader interface {
	Counts(ctx context.Context) (store.Counts, error)
	ListSystems(ctx context.Context) ([]store.SystemRow, error)
	ListAnalyses(ctx context.Context, systemID string, limit int) ([]store.AnalysisRow, error)
	GateRollup(ctx context.Context, since int64) ([]store.GateRow, error)
	CostRollup(ctx context.Context) ([]store.CostRow, error)
	ListAllFindings(ctx context.Context, systemID, status, severity, idLike, sort string, limit int) ([]model.Finding, error)
	ListTemplates(ctx context.Context, systemID string, limit int) ([]store.TemplateRow, error)
	ListBaselines(ctx context.Context, systemID string) ([]store.BaselineRow, error)

	// Threat Shield.
	ListBlocklistEntries(ctx context.Context, limit int) ([]store.BlocklistRow, error)
	ListThreatEvents(ctx context.Context, systemID, attackerIP string, limit int) ([]store.ThreatEventRow, error)
	ThreatDailyStats(ctx context.Context, limit int) ([]store.ThreatDailyRow, error)
	ThreatIngestStats(ctx context.Context, limit int) ([]store.ThreatIngestRow, error)
	ListThreatSystems(ctx context.Context) ([]store.ThreatSystemRow, error)
	ListThreatAllowlist(ctx context.Context) ([]store.AllowlistRow, error)

	// Fleet sizing -- the third pipeline's two pages. These rows carry
	// per-customer commercial data (mailbox and PBX user counts, product
	// mix), so the loopback-bind advice that applies to every page here
	// applies to them too, recorded explicitly rather than inherited by
	// accident.
	ListSizingNodes(ctx context.Context, systemID string, limit int) ([]store.SizingNodeUIRow, error)
	ListSizingModules(ctx context.Context, systemID string, limit int) ([]store.SizingModuleUIRow, error)
	ListSizingCohorts(ctx context.Context, kind string, limit int) ([]store.SizingCohortRow, error)
	SizingIngestStats(ctx context.Context, limit int) ([]store.SizingIngestRow, error)
	SizingCounts(ctx context.Context) (store.SizingCounts, error)

	// PendingAllowlistRequests backs the /allowlist-requests review queue.
	// This is a read: the queue is visible to anyone who can reach this
	// listener, exactly like every other page here, and it carries no more
	// than a ranked list of CIDRs someone asked about. Only acting on an
	// entry (approve/reject) requires the admin key.
	PendingAllowlistRequests(ctx context.Context, limit int) ([]store.AllowlistRequestRow, error)
}

// Writer is the slice of store.Store the UI's write routes need: adding or
// removing a threat_allowlist entry, and turning a request into an approval
// or a rejection. It is wired in, and its routes are registered, only when
// ADMIN_API_KEY is set -- see NewServer and writableRoutes.
//
// *store.SQLiteStore satisfies it, exactly like Reader.
type Writer interface {
	UpsertThreatAllowlistEntry(ctx context.Context, e store.AllowlistRow) error
	DeleteThreatAllowlistEntry(ctx context.Context, cidr string) (bool, error)
	UpsertAllowlistReview(ctx context.Context, cidr, state, decidedBy, note string, now int64) error
	DeleteAllowlistRequests(ctx context.Context, cidr string) (int, error)
	AppendAllowlistAudit(ctx context.Context, cidr, action, actor, detail string, now int64) error
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

// Info is the static half of the status page, built once by the caller. It
// carries Workers, which chrome.Info deliberately does not: queue depth is
// insightsd's alone and does not belong in the shared chrome package. This
// package converts it to a chrome.Info (dropping Workers) when it builds the
// chrome.Base, and keeps Workers itself for its own status page data.
type Info struct {
	StartedAt int64 // unix millis
	Workers   int
	Build     string              // from runtime/debug.ReadBuildInfo; "unknown" if absent
	Config    []chrome.ConfigItem // explicit list; secrets ALREADY reduced to set/unset by the caller
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
	sizingNodesLimit   = 500
	sizingModulesLimit = 2000
	sizingCohortsLimit = 500
	sizingIngestLimit  = 200
)

// navGroups is this dashboard's nav bar structure, handed to chrome.New as
// chrome.Config.Nav. There is exactly one unlabeled group (Status), which
// chrome renders as a plain top-level link rather than a dropdown.
var navGroups = []chrome.NavGroup{
	{Label: "", Pages: []chrome.NavPage{{Key: "status", Path: "/", Label: "Status"}}},
	{Label: "Logs Pipeline", Pages: []chrome.NavPage{
		{Key: "systems", Path: "/systems", Label: "Systems"},
		{Key: "findings", Path: "/findings", Label: "Findings"},
		{Key: "analyses", Path: "/analyses", Label: "Analyses"},
		{Key: "gate", Path: "/gate", Label: "Gate"},
		{Key: "cost", Path: "/cost", Label: "Cost"},
		{Key: "templates", Path: "/templates", Label: "Templates"},
		{Key: "baselines", Path: "/baselines", Label: "Baselines"},
	}},
	{Label: "Blocklist Pipeline", Pages: []chrome.NavPage{
		{Key: "threat-systems", Path: "/threat-systems", Label: "Systems"},
		{Key: "blocklist", Path: "/blocklist", Label: "Blocklist"},
		{Key: "threat-events", Path: "/threat-events", Label: "Threat events"},
		{Key: "threat-stats", Path: "/threat-stats", Label: "Threat stats"},
		{Key: "allowlist-requests", Path: "/allowlist-requests", Label: "Allowlist requests"},
	}},
	{Label: "Sizing Pipeline", Pages: []chrome.NavPage{
		{Key: "sizing", Path: "/sizing", Label: "Nodes"},
		{Key: "cohorts", Path: "/cohorts", Label: "Recommendations"},
	}},
}

// pages lists the content templates, each combined with chrome's layout
// into its own *template.Template -- see chrome.ParseTemplates.
var pages = []string{
	"status.html", "systems.html", "findings.html", "analyses.html",
	"gate.html", "cost.html", "templates.html", "baselines.html",
	"blocklist.html", "threat-systems.html", "threat-events.html", "threat-stats.html",
	"allowlist-requests.html",
	"sizing.html", "cohorts.html",
}

type server struct {
	chrome *chrome.Base
	reader Reader
	rt     Runtime
	feed   Feed
	info   Info
	writer Writer
}

// NewServer builds the operator UI handler. rt and feed may be nil.
//
// w and adminKey wire the write half: if adminKey is empty, w is never
// consulted and every writable route answers 405 exactly like any other
// non-GET request -- an operator who has not set ADMIN_API_KEY gets the
// plain read-only dashboard, with no write form reachable at all.
//
// This dashboard is not deployed behind Traefik's path-prefix split (it is
// its own listener, meant to be bound to loopback), so it always passes an
// empty BasePath to chrome.
func NewServer(r Reader, rt Runtime, feed Feed, info Info, w Writer, adminKey string) http.Handler {
	pageTemplates, err := fs.Sub(pageAssets, "templates")
	if err != nil {
		// Only reachable if the embed directive above stops matching the
		// templates/ directory -- a build-time programming error, not a
		// runtime condition.
		panic("ui: page templates: " + err.Error())
	}

	base, err := chrome.New(chrome.Config{
		AdminKey: adminKey,
		Info: chrome.Info{
			StartedAt: info.StartedAt,
			Build:     info.Build,
			Config:    info.Config,
		},
		Nav:       navGroups,
		Pages:     pages,
		Templates: pageTemplates,
	})
	if err != nil {
		panic("ui: parsing templates: " + err.Error())
	}

	srv := &server{
		chrome: base,
		reader: r,
		rt:     rt,
		feed:   feed,
		info:   info,
		writer: w,
	}

	mux := http.NewServeMux()
	// Every path, including unknown ones, is dispatched centrally through
	// route() so the GET-only rule (and its small, explicit write exception)
	// and the 404 fallback are enforced in exactly one place, per the plan's
	// "enforce it centrally, once".
	mux.HandleFunc("/", srv.route)

	return httpx.Logging(mux)
}

// canWrite reports whether the write forms should render, and whether a
// write route is reachable at all. It is false whenever ADMIN_API_KEY was
// not configured -- the plan requires that case to leave the UI with "no
// write forms at all", not forms that render and then always 401. chrome's
// CanWrite only knows about the admin key; this package additionally
// requires a store Writer to have been wired in.
func (s *server) canWrite() bool {
	return s.writer != nil && s.chrome.CanWrite()
}

// writableRoutes is the small, explicit, enumerated set of paths that also
// answer POST. It lives here, next to the GET-only check it modifies, so
// "which routes can write" stays answerable by reading this one function --
// see the plan's decision 2. Every route not in this set still 405s on
// anything but GET, exactly as before that plan.
//
// The CIDR itself never travels in these paths: it is always a form field,
// mirroring the admin API's rule that it never travels in a path segment.
var writableRoutes = map[string]bool{
	"/blocklist/allowlist":        true, // add or update an entry
	"/blocklist/allowlist/delete": true, // remove an entry
	"/allowlist-requests/approve": true,
	"/allowlist-requests/reject":  true,
}

func (s *server) route(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		// Every route answers GET. A small, explicit, enumerated set of
		// routes also answers POST, and every one of those authenticates
		// before doing anything -- see the package doc comment. Anything
		// else, including a write route reached without ADMIN_API_KEY
		// configured (s.writer unset or chrome.CanWrite false), is still a
		// plain 405: this is what makes "no key configured" mean "no write
		// forms reachable at all", not "reachable but always unauthorized".
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
	case "/threat-systems":
		s.handleThreatSystems(w, r)
	case "/blocklist":
		s.handleBlocklist(w, r)
	case "/threat-events":
		s.handleThreatEvents(w, r)
	case "/threat-stats":
		s.handleThreatStats(w, r)
	case "/allowlist-requests":
		s.handleAllowlistRequests(w, r)
	case "/sizing":
		s.handleSizing(w, r)
	case "/cohorts":
		s.handleCohorts(w, r)
	default:
		// net/http's ServeMux treats "/" as a subtree covering every
		// unmatched path; because we only ever register "/" itself here and
		// dispatch by hand, an unrecognised path correctly falls through to
		// this 404 rather than silently rendering the status page.
		http.NotFound(w, r)
	}
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
	chrome.PageData
	Counts     store.Counts
	HasQueue   bool
	QueueDepth int
	QueueCap   int
	Workers    int
	Feed       feedState
	Config     []chrome.ConfigItem
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	counts, err := s.reader.Counts(r.Context())
	if err != nil {
		s.chrome.StoreError(w, "status", err)
		return
	}
	data := statusPageData{
		PageData: s.chrome.PageData(r, "status"),
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
	s.chrome.Render(w, "status.html", data)
}

type systemsPageData struct {
	chrome.PageData
	Systems []store.SystemRow
}

func (s *server) handleSystems(w http.ResponseWriter, r *http.Request) {
	systems, err := s.reader.ListSystems(r.Context())
	if err != nil {
		s.chrome.StoreError(w, "systems", err)
		return
	}
	s.chrome.Render(w, "systems.html", systemsPageData{
		PageData: s.chrome.PageData(r, "systems"),
		Systems:  systems,
	})
}

type findingsPageData struct {
	chrome.PageData
	Findings   []model.Finding
	System     string
	Status     string
	Severity   string
	ID         string
	Sort       string
	Severities []string
}

func (s *server) handleFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	systemID := q.Get("system")
	status := sanitizeStatus(q.Get("status"))
	severity := sanitizeSeverity(q.Get("severity"))
	id := q.Get("id")
	sort := sanitizeFindingsSort(q.Get("sort"))

	findings, err := s.reader.ListAllFindings(r.Context(), systemID, status, severity, id, sort, findingsLimit)
	if err != nil {
		s.chrome.StoreError(w, "findings", err)
		return
	}
	s.chrome.Render(w, "findings.html", findingsPageData{
		PageData:   s.chrome.PageData(r, "findings"),
		Findings:   findings,
		System:     systemID,
		Status:     status,
		Severity:   severity,
		ID:         id,
		Sort:       sort,
		Severities: model.Severities,
	})
}

// sanitizeFindingsSort rejects anything but the known sort modes, defaulting
// to "" (the canonical severity/last_seen order) the same way
// sanitizeStatus/sanitizeSeverity default an unrecognized value.
func sanitizeFindingsSort(v string) string {
	if v == store.SortRecent {
		return v
	}
	return ""
}

type analysesPageData struct {
	chrome.PageData
	Analyses []store.AnalysisRow
	System   string
	Limit    int
}

func (s *server) handleAnalyses(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	systemID := q.Get("system")
	limit := chrome.ClampLimit(q.Get("limit"), analysesDefaultLim, analysesMaxLimit)

	analyses, err := s.reader.ListAnalyses(r.Context(), systemID, limit)
	if err != nil {
		s.chrome.StoreError(w, "analyses", err)
		return
	}
	s.chrome.Render(w, "analyses.html", analysesPageData{
		PageData: s.chrome.PageData(r, "analyses"),
		Analyses: analyses,
		System:   systemID,
		Limit:    limit,
	})
}

// gateRange is one option of the /gate page's time scope. An empty Window
// means "all time".
type gateRange struct {
	Key    string // the ?range= value
	Label  string
	Window time.Duration
}

// gateRanges is the enumerated set of scopes /gate accepts. Anything else
// falls back to gateDefaultRange -- the same shape as clampLimit, since a bad
// query string on a dashboard is a typo, not an error worth a page for.
//
// The default is deliberately not "all time": gate reasons are stored exactly
// as the formula that produced them spelled them, so an unbounded rollup mixes
// eras and the page that answers "why are we paying" ends up describing a gate
// that has since been fixed. See store.GateRollup.
var gateRanges = []gateRange{
	{Key: "24h", Label: "last 24 hours", Window: 24 * time.Hour},
	{Key: "7d", Label: "last 7 days", Window: 7 * 24 * time.Hour},
	{Key: "30d", Label: "last 30 days", Window: 30 * 24 * time.Hour},
	{Key: "all", Label: "all time (mixes gate formulas)", Window: 0},
}

const gateDefaultRange = "7d"

// resolveGateRange maps a ?range= value to its scope, falling back to the
// default. The returned since is unix millis, 0 for all time.
func resolveGateRange(v string, now time.Time) (key string, since int64) {
	match := lookupGateRange(v)
	if match == nil {
		match = lookupGateRange(gateDefaultRange)
	}
	if match.Window == 0 {
		return match.Key, 0
	}
	return match.Key, now.Add(-match.Window).UnixMilli()
}

func lookupGateRange(key string) *gateRange {
	for i := range gateRanges {
		if gateRanges[i].Key == key {
			return &gateRanges[i]
		}
	}
	return nil
}

// gateSummary is the /gate page's headline: whether the gate is gating at all.
// Every field is derived from the rows already fetched, so the page costs one
// query.
type gateSummary struct {
	Windows    int
	GatedOut   int
	Called     int
	Paid       int
	ZeroCost   int
	CostMicros int64
	AvgMicros  int64
}

// summarizeGate folds the rollup into the headline. GatedOut is derived as
// Windows-Called rather than read off the nil-Reasons row: the two agree by
// the gate's invariant (a non-empty reason set is what makes the call), and
// deriving it means legacy rows written by an older formula cannot make the
// summary contradict the table.
func summarizeGate(rows []store.GateRow) gateSummary {
	var g gateSummary
	for _, row := range rows {
		g.Windows += row.Windows
		g.Called += row.LLMCalls
		g.Paid += row.PaidCalls
		g.CostMicros += row.CostMicros
	}
	g.GatedOut = g.Windows - g.Called
	g.ZeroCost = g.Called - g.Paid
	if g.Paid > 0 {
		g.AvgMicros = g.CostMicros / int64(g.Paid)
	}
	return g
}

type gatePageData struct {
	chrome.PageData
	Rows    []store.GateRow
	Summary gateSummary
	Range   string
	Ranges  []gateRange
}

func (s *server) handleGate(w http.ResponseWriter, r *http.Request) {
	rangeKey, since := resolveGateRange(r.URL.Query().Get("range"), time.Now())

	rows, err := s.reader.GateRollup(r.Context(), since)
	if err != nil {
		s.chrome.StoreError(w, "gate", err)
		return
	}
	s.chrome.Render(w, "gate.html", gatePageData{
		PageData: s.chrome.PageData(r, "gate"),
		Rows:     rows,
		Summary:  summarizeGate(rows),
		Range:    rangeKey,
		Ranges:   gateRanges,
	})
}

type costPageData struct {
	chrome.PageData
	Days                 []costDayGroup
	GrandTotalCostMicros int64
}

// costDayGroup folds CostRollup's per-day-per-model rows into one group per
// day, plus that day's total across every model -- CostRollup is already
// ordered by day, then model (internal/store/ui.go), so a single linear pass
// suffices.
type costDayGroup struct {
	Day             string
	Rows            []store.CostRow
	TotalCostMicros int64
}

func (s *server) handleCost(w http.ResponseWriter, r *http.Request) {
	rows, err := s.reader.CostRollup(r.Context())
	if err != nil {
		s.chrome.StoreError(w, "cost", err)
		return
	}
	var days []costDayGroup
	var grandTotal int64
	for _, row := range rows {
		if len(days) == 0 || days[len(days)-1].Day != row.Day {
			days = append(days, costDayGroup{Day: row.Day})
		}
		g := &days[len(days)-1]
		g.Rows = append(g.Rows, row)
		g.TotalCostMicros += row.CostMicros
		grandTotal += row.CostMicros
	}
	s.chrome.Render(w, "cost.html", costPageData{
		PageData:             s.chrome.PageData(r, "cost"),
		Days:                 days,
		GrandTotalCostMicros: grandTotal,
	})
}

type templatesPageData struct {
	chrome.PageData
	Templates []store.TemplateRow
	System    string
}

func (s *server) handleTemplates(w http.ResponseWriter, r *http.Request) {
	systemID := r.URL.Query().Get("system")
	templates, err := s.reader.ListTemplates(r.Context(), systemID, templatesLimit)
	if err != nil {
		s.chrome.StoreError(w, "templates", err)
		return
	}
	s.chrome.Render(w, "templates.html", templatesPageData{
		PageData:  s.chrome.PageData(r, "templates"),
		Templates: templates,
		System:    systemID,
	})
}

type baselinesPageData struct {
	chrome.PageData
	Baselines []store.BaselineRow
	System    string
}

func (s *server) handleBaselines(w http.ResponseWriter, r *http.Request) {
	systemID := r.URL.Query().Get("system")
	baselines, err := s.reader.ListBaselines(r.Context(), systemID)
	if err != nil {
		s.chrome.StoreError(w, "baselines", err)
		return
	}
	s.chrome.Render(w, "baselines.html", baselinesPageData{
		PageData:  s.chrome.PageData(r, "baselines"),
		Baselines: baselines,
		System:    systemID,
	})
}

// --- Threat Shield pages ---

type threatSystemsPageData struct {
	chrome.PageData
	Systems []store.ThreatSystemRow
}

// handleThreatSystems is the blocklist pipeline's counterpart to
// handleSystems: one row per system that has ever reported threat events,
// including a system whose every report was dropped or duplicate.
func (s *server) handleThreatSystems(w http.ResponseWriter, r *http.Request) {
	systems, err := s.reader.ListThreatSystems(r.Context())
	if err != nil {
		s.chrome.StoreError(w, "threat-systems", err)
		return
	}
	s.chrome.Render(w, "threat-systems.html", threatSystemsPageData{
		PageData: s.chrome.PageData(r, "threat-systems"),
		Systems:  systems,
	})
}

type blocklistPageData struct {
	chrome.PageData
	Feed      feedState
	Entries   []store.BlocklistRow
	Allowlist []store.AllowlistRow
	Now       int64
	CanWrite  bool
}

// handleBlocklist shows what the fleet currently agrees on, plus the
// allowlist exclusion. "Why is this IP listed" and "why is this IP never
// listed" are both operator questions, and both are answered on one page.
func (s *server) handleBlocklist(w http.ResponseWriter, r *http.Request) {
	entries, err := s.reader.ListBlocklistEntries(r.Context(), blocklistLimit)
	if err != nil {
		s.chrome.StoreError(w, "blocklist", err)
		return
	}
	allowlist, err := s.reader.ListThreatAllowlist(r.Context())
	if err != nil {
		s.chrome.StoreError(w, "blocklist", err)
		return
	}
	s.chrome.Render(w, "blocklist.html", blocklistPageData{
		PageData:  s.chrome.PageData(r, "blocklist"),
		Feed:      s.feedState(),
		Entries:   entries,
		Allowlist: allowlist,
		Now:       time.Now().UnixMilli(),
		CanWrite:  s.canWrite(),
	})
}

type threatEventsPageData struct {
	chrome.PageData
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
	limit := chrome.ClampLimit(q.Get("limit"), threatEventsDefLim, threatEventsMaxLim)

	events, err := s.reader.ListThreatEvents(r.Context(), systemID, ip, limit)
	if err != nil {
		s.chrome.StoreError(w, "threat-events", err)
		return
	}
	s.chrome.Render(w, "threat-events.html", threatEventsPageData{
		PageData: s.chrome.PageData(r, "threat-events"),
		Events:   events,
		System:   systemID,
		IP:       ip,
		Limit:    limit,
	})
}

type threatStatsPageData struct {
	chrome.PageData
	Daily  []threatDayGroup
	Ingest []store.ThreatIngestRow
}

// threatDayGroup folds ThreatDailyStats' per-day-per-scenario rows into one
// group per day, plus that day's total hits across every scenario -- the
// same pattern as costDayGroup. TotalHits is additive so it sums cleanly;
// DistinctIPs is deliberately not summed here, since the same address can
// appear under more than one scenario and a naive sum would overcount it.
type threatDayGroup struct {
	Day       string
	Rows      []store.ThreatDailyRow
	TotalHits int64
}

func (s *server) handleThreatStats(w http.ResponseWriter, r *http.Request) {
	dailyRows, err := s.reader.ThreatDailyStats(r.Context(), threatStatsLimit)
	if err != nil {
		s.chrome.StoreError(w, "threat-stats", err)
		return
	}
	var daily []threatDayGroup
	for _, row := range dailyRows {
		if len(daily) == 0 || daily[len(daily)-1].Day != row.Day {
			daily = append(daily, threatDayGroup{Day: row.Day})
		}
		g := &daily[len(daily)-1]
		g.Rows = append(g.Rows, row)
		g.TotalHits += row.TotalHits
	}
	ingest, err := s.reader.ThreatIngestStats(r.Context(), threatStatsLimit)
	if err != nil {
		s.chrome.StoreError(w, "threat-stats", err)
		return
	}
	s.chrome.Render(w, "threat-stats.html", threatStatsPageData{
		PageData: s.chrome.PageData(r, "threat-stats"),
		Daily:    daily,
		Ingest:   ingest,
	})
}

// --- Allowlist requests: the review queue, and its write half ---

// allowlistRequestsLimit bounds the queue the same way every other
// unauthenticated list here is bounded.
const allowlistRequestsLimit = 200

type allowlistRequestsPageData struct {
	chrome.PageData
	Requests []store.AllowlistRequestRow
	CanWrite bool
}

// handleAllowlistRequests shows the pending review queue. It is a GET, and
// therefore unauthenticated like every other page: the queue is a ranked
// list of CIDRs someone asked about, and only acting on one (approve/reject)
// requires the admin key.
func (s *server) handleAllowlistRequests(w http.ResponseWriter, r *http.Request) {
	requests, err := s.reader.PendingAllowlistRequests(r.Context(), allowlistRequestsLimit)
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

// handleAddAllowlist and handleDeleteAllowlist are POST form handlers
// (writableRoutes), reached only after HTTP Basic authentication. Both
// redirect back to /blocklist rather than answering JSON: this is a human
// submitting a form, and the useful response is the updated page, not a
// status code.

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

	if err := s.writer.UpsertThreatAllowlistEntry(r.Context(), store.AllowlistRow{
		CIDR: cidr, Reason: reason, CreatedBy: actor, CreatedAt: now,
	}); err != nil {
		s.chrome.StoreError(w, "blocklist", err)
		return
	}
	if err := s.writer.AppendAllowlistAudit(r.Context(), cidr, "allowlist.upsert", actor, reason, now); err != nil {
		slog.Error("ui: append allowlist audit failed", "cidr", cidr, "error", err)
	}
	http.Redirect(w, r, s.chrome.Link("/blocklist"), http.StatusSeeOther)
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
		s.chrome.StoreError(w, "blocklist", err)
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
	http.Redirect(w, r, s.chrome.Link("/blocklist"), http.StatusSeeOther)
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

	if err := s.writer.UpsertThreatAllowlistEntry(r.Context(), store.AllowlistRow{
		CIDR: cidr, Reason: reason, CreatedBy: actor, CreatedAt: now,
	}); err != nil {
		s.chrome.StoreError(w, "allowlist-requests", err)
		return
	}
	if err := s.writer.UpsertAllowlistReview(r.Context(), cidr, store.AllowlistReviewApproved, actor, note, now); err != nil {
		slog.Error("ui: record allowlist review failed", "cidr", cidr, "error", err)
	}
	if err := s.writer.AppendAllowlistAudit(r.Context(), cidr, "request.approve", actor, note, now); err != nil {
		slog.Error("ui: append allowlist audit failed", "cidr", cidr, "error", err)
	}
	// Retire the handled request, last: see store.DeleteAllowlistRequests
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

	if err := s.writer.UpsertAllowlistReview(r.Context(), cidr, store.AllowlistReviewRejected, actor, note, now); err != nil {
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

// --- Fleet sizing pages ---

type sizingPageData struct {
	chrome.PageData
	Counts     store.SizingCounts
	Nodes      []store.SizingNodeUIRow
	Modules    []store.SizingModuleUIRow
	Ingest     []store.SizingIngestRow
	Thresholds []sizing.Threshold
	Version    int
	System     string
}

// handleSizing is the sizing pipeline's node view: one row per node, showing
// its most recent day's utilization percentiles, the per-axis penalties, the
// pressure they combine into and the multi-day verdict.
//
// The threshold table is on the page deliberately. Most of the score's knees
// are guesses awaiting calibration against ~30 days of fleet data, and a
// dashboard that renders a guess with no label attached is presenting it as
// advice. See sizing.Thresholds.
func (s *server) handleSizing(w http.ResponseWriter, r *http.Request) {
	systemID := r.URL.Query().Get("system")

	counts, err := s.reader.SizingCounts(r.Context())
	if err != nil {
		s.chrome.StoreError(w, "sizing", err)
		return
	}
	nodes, err := s.reader.ListSizingNodes(r.Context(), systemID, sizingNodesLimit)
	if err != nil {
		s.chrome.StoreError(w, "sizing", err)
		return
	}
	modules, err := s.reader.ListSizingModules(r.Context(), systemID, sizingModulesLimit)
	if err != nil {
		s.chrome.StoreError(w, "sizing", err)
		return
	}
	ingest, err := s.reader.SizingIngestStats(r.Context(), sizingIngestLimit)
	if err != nil {
		s.chrome.StoreError(w, "sizing", err)
		return
	}

	s.chrome.Render(w, "sizing.html", sizingPageData{
		PageData:   s.chrome.PageData(r, "sizing"),
		Counts:     counts,
		Nodes:      nodes,
		Modules:    modules,
		Ingest:     ingest,
		Thresholds: sizing.Thresholds(),
		Version:    sizing.PressureVersion,
		System:     systemID,
	})
}

type cohortGroup struct {
	Kind    string
	Label   string
	Caption string
	Rows    []store.SizingCohortRow
}

type cohortsPageData struct {
	chrome.PageData
	Groups []cohortGroup
	Floors struct {
		DistinctSystems int
		Nodes           int
	}
	CensorRAMUtil float64
	Empty         bool
}

// handleCohorts shows the published baselines.
//
// An empty page is the **correct** output for a fleet below the floor, not a
// bug: publishing a percentile computed from three nodes would be worse than
// publishing nothing, and this pipeline's "never serve blank" is the other way
// round from Threat Shield's for exactly that reason.
//
// Each group's caption says what its numbers can be used for. Only
// family_solo is safe to quote as a recommendation; family is co-tenanted with
// whatever else happened to be installed.
//
// "Only this module" is stated on the page as "plus the platform modules every
// cluster runs", because that is what sizing.IsPlatform ignores and therefore
// what the number includes: every node measured was also running log
// shipping, the identity proxy, metrics and intrusion prevention. Printing it
// as an unqualified per-module cost would overstate what was measured.
func (s *server) handleCohorts(w http.ResponseWriter, r *http.Request) {
	cohorts, err := s.reader.ListSizingCohorts(r.Context(), "", sizingCohortsLimit)
	if err != nil {
		s.chrome.StoreError(w, "cohorts", err)
		return
	}

	groups := []cohortGroup{
		{Kind: sizing.CohortFamilySolo, Label: "Nodes running only this module",
			Caption: "Use these numbers when sizing a new node for this module. These nodes run nothing else a customer chose, but they do run the platform modules every cluster has, so their cost is included."},
		{Kind: sizing.CohortFamily, Label: "Nodes running this module plus others",
			Caption: "Context only. These nodes share their hardware, so the numbers are not this module's cost."},
	}
	for i := range groups {
		for _, c := range cohorts {
			if c.CohortKind == groups[i].Kind {
				groups[i].Rows = append(groups[i].Rows, c)
			}
		}
	}

	data := cohortsPageData{
		PageData:      s.chrome.PageData(r, "cohorts"),
		Groups:        groups,
		CensorRAMUtil: sizing.CensorRAMUtil,
		Empty:         len(cohorts) == 0,
	}
	// The floor is a property of the pass, not of this page; it is echoed
	// from whichever cohort published so the page never states a floor the
	// running configuration does not use.
	if len(cohorts) > 0 {
		data.Floors.DistinctSystems = cohorts[0].MinDistinctSystems
		data.Floors.Nodes = cohorts[0].MinNodes
	}
	s.chrome.Render(w, "cohorts.html", data)
}
