// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package logs serves insightsd's operator dashboard: findings, systems, the
// analyses cost ledger, the gate rollup, per-day spend, the stored
// templates and baselines, and the trigger review queue. It replaces the shell helper that used to need
// sqlite3, root on the node and the podman volume path, and adds the live
// process state a query over the database could never see: queue depth and
// worker count, uptime, and the effective configuration.
//
// It sits on chrome the same way threatd's and sizingd's dashboards do -- see
// internal/ui/chrome's own doc comment for the shared layout and route
// discipline. What is specific here:
//
//   - Reads are unauthenticated and fleet-wide -- every GET shows every
//     system's findings, templates, baselines and spend, for every customer.
//     That is why most of the constraints below are not optional.
//   - Zero JavaScript. Interactions are <meta refresh>, <form>, <details>
//     and <dialog> opened by a command/commandfor invoker button, never a
//     <script> tag.
//   - Every list is bounded server-side.
//   - Secrets never render: cfg.Info.Config arrives already redacted by the
//     caller, and this package never reads the environment.
//   - The only writes are the trigger review decisions (writableRoutes),
//     reachable only when ADMIN_API_KEY is set, with the same discipline as
//     Threat Shield's allowlist routes (internal/ui/threat): POST only, the
//     admin key, a cross-site refusal, and an audit row per decision.
//   - insightsd's queue is the analysis pipeline's bundle queue (see
//     internal/queue), not the generic internal/platform/ingestq threatd
//     uses for its ingest bound -- the two are unrelated types that happen
//     to satisfy the same Depth/Cap/Workers shape. See Runtime and
//     statusPageData.
package logs

import (
	"context"
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/platform/httpx"
	logsstore "github.com/nethesis/nethesis-insights/internal/store/logs"
	"github.com/nethesis/nethesis-insights/internal/ui/chrome"
)

// pageAssets embeds this dashboard's own content templates -- layout.html
// and static/ live in chrome's embed.FS instead, since chrome owns the
// shared chrome (see internal/ui/chrome).
//
//go:embed templates
var pageAssets embed.FS

// Reader is the read-only slice of logsstore.Store the UI needs.
// *logsstore.Store satisfies it.
type Reader interface {
	Counts(ctx context.Context) (logsstore.Counts, error)
	ListSystems(ctx context.Context) ([]logsstore.SystemRow, error)
	ListAnalyses(ctx context.Context, systemID string, limit int) ([]logsstore.AnalysisRow, error)
	GateRollup(ctx context.Context, since int64) ([]logsstore.GateRow, error)
	CostRollup(ctx context.Context) ([]logsstore.CostRow, error)
	ListAllFindings(ctx context.Context, systemID, status, severity, idLike, sort string, limit int) ([]model.Finding, error)
	ResolveNodesFleet(ctx context.Context, findings []model.Finding) error
	ListTemplates(ctx context.Context, systemID string, limit int) ([]logsstore.TemplateRow, error)
	ListBaselines(ctx context.Context, systemID string) ([]logsstore.BaselineRow, error)
	ListTriggers(ctx context.Context, f logsstore.TriggerFilter) ([]logsstore.TriggerRow, error)
	TriggerStats(ctx context.Context) ([]logsstore.TriggerStatsRow, error)
	ListTriggerDecisions(ctx context.Context, limit int) ([]logsstore.TriggerDecision, error)
}

// Writer is the slice of logsstore.Store the review routes need, one method
// per decision. Each is a single transaction that also appends the
// decision's trigger_decisions row, so a trigger never changes without the
// record of who changed it. It is wired in, and its routes are reachable,
// only when ADMIN_API_KEY is set -- see NewServer and writableRoutes.
// *logsstore.Store satisfies it.
type Writer interface {
	SetTriggerVisibility(ctx context.Context, key, visibility, actor string, now int64) error
	IgnoreTrigger(ctx context.Context, key string, until int64, actor string, now int64) error
	MergeTrigger(ctx context.Context, key, into, actor string, now int64) error
	SetTriggerSeverity(ctx context.Context, key, severity, actor string, now int64) error
	SetTriggerDocRef(ctx context.Context, key, docRef, actor string, now int64) error
}

// Runtime reports live process state. *queue.Queue satisfies it. rt may be
// nil -- tests, and a future caller without a queue -- in which case the
// queue section of the status page renders "n/a" rather than panicking.
type Runtime interface {
	Depth() int
	Cap() int
	Workers() int
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
	reviewLimit        = 200
	reviewAuditLimit   = 500
)

// Review input bounds. A trigger key is "t1:" plus 64 hex characters; the
// cap only has to refuse garbage, not describe the format. An ignore is
// between a day and a year: it always ends (IgnoreTrigger refuses the past),
// and a year is long enough that a longer one is a decision nobody will
// remember making.
const (
	maxTriggerKeyLen = 128
	maxDocRefLen     = 512
	maxIgnoreDays    = 365
	maxReviewForm    = 16 << 10 // 16 KiB; see internal/ui/threat's maxAllowlistFormSize
)

// writableRoutes is the small, explicit, enumerated set of paths that also
// answer POST -- and POST alone; see route(). Every one authenticates
// against ADMIN_API_KEY and refuses a cross-site request first, exactly like
// internal/ui/threat's: Traefik's BasicAuth in front of this subtree is
// still Basic auth, which a browser replays on a forged cross-site POST.
// The trigger key is always a form field, never part of the path.
var writableRoutes = map[string]bool{
	"/review/deliver":  true,
	"/review/internal": true,
	"/review/ignore":   true,
	"/review/merge":    true,
	"/review/severity": true,
	"/review/doc-ref":  true,
}

// nav is this dashboard's nav bar structure. A single group with no label
// renders as a flat row, the same shape threatd's and sizingd's dashboards
// use.
var nav = []chrome.NavGroup{
	{Pages: []chrome.NavPage{
		{Key: "index", Path: "/", Label: "Findings"},
	}},
	{Label: "Review", Pages: []chrome.NavPage{
		{Key: "review", Path: "/review", Label: "Queue"},
		{Key: "review-stats", Path: "/review/stats", Label: "Stats"},
		{Key: "review-audit", Path: "/review/audit", Label: "Audit"},
	}},
	{Pages: []chrome.NavPage{
		{Key: "systems", Path: "/systems", Label: "Systems"},
		{Key: "analyses", Path: "/analyses", Label: "Analyses"},
		{Key: "gate", Path: "/gate", Label: "Gate"},
		{Key: "cost", Path: "/cost", Label: "Cost"},
		{Key: "templates", Path: "/templates", Label: "Templates"},
		{Key: "baselines", Path: "/baselines", Label: "Baselines"},
		{Key: "status", Path: "/status", Label: "Status"},
	}},
}

// pages lists the content templates, each combined with chrome's layout
// into its own *template.Template -- see chrome.ParseTemplates.
var pages = []string{
	"index.html", "systems.html", "analyses.html",
	"gate.html", "cost.html", "templates.html", "baselines.html", "status.html",
	"review.html", "review-stats.html", "review-audit.html",
}

type server struct {
	chrome *chrome.Base
	reader Reader
	writer Writer
	rt     Runtime
	config []chrome.ConfigItem
	now    func() int64
}

// NewServer builds insightsd's operator UI handler. w and rt may be nil: a
// nil writer (equivalently, cfg.AdminKey == "") leaves every review route
// unreachable and renders no decision form, and a nil rt renders the status
// page's queue section as "n/a".
func NewServer(r Reader, w Writer, rt Runtime, cfg chrome.Config) (http.Handler, error) {
	pageTemplates, err := fs.Sub(pageAssets, "templates")
	if err != nil {
		// Only reachable if the embed directive above stops matching the
		// templates/ directory -- a build-time programming error, not a
		// runtime condition.
		return nil, err
	}

	cfg.Name = "insightsd"
	cfg.Nav = nav
	cfg.Pages = pages
	cfg.Templates = pageTemplates
	cfg.Funcs = template.FuncMap{"fmtIgnoreUntil": fmtIgnoreUntil}

	base, err := chrome.New(cfg)
	if err != nil {
		return nil, err
	}

	srv := &server{
		chrome: base,
		reader: r,
		writer: w,
		rt:     rt,
		config: cfg.Info.Config,
		now:    func() int64 { return time.Now().UnixMilli() },
	}

	mux := http.NewServeMux()
	// Every path, including unknown ones, is dispatched centrally through
	// route() so the GET-only rule and the 404 fallback are enforced in
	// exactly one place.
	mux.HandleFunc("/", srv.route)

	return httpx.Logging(mux, nil), nil
}

// canWrite reports whether the decision forms render and the review routes
// are reachable at all: never without ADMIN_API_KEY.
func (s *server) canWrite() bool {
	return s.writer != nil && s.chrome.CanWrite()
}

// route is the central method gate as well as the dispatcher: GET reaches the
// read pages, POST reaches an enumerated write route, and every other method
// is refused before any handler runs. The write branch tests for POST, not
// for "not GET" -- see internal/ui/threat's route() for why a HEAD must
// never reach a write handler.
func (s *server) route(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		if r.Method != http.MethodPost || !s.canWrite() || !writableRoutes[r.URL.Path] {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		actor, ok := s.chrome.AuthenticateWrite(w, r)
		if !ok {
			return
		}
		s.handleDecision(w, r, actor)
		return
	}

	if s.chrome.ServeStatic(w, r) {
		return
	}

	switch r.URL.Path {
	case "/":
		s.handleFindings(w, r)
	case "/systems":
		s.handleSystems(w, r)
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
	case "/status":
		s.handleStatus(w, r)
	case "/review":
		s.handleReview(w, r)
	case "/review/stats":
		s.handleReviewStats(w, r)
	case "/review/audit":
		s.handleReviewAudit(w, r)
	default:
		// net/http's ServeMux treats "/" as a subtree covering every
		// unmatched path; because we only ever register "/" itself here and
		// dispatch by hand, an unrecognised path correctly falls through to
		// this 404 rather than silently rendering the findings page.
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

// statusPageData carries queue depth, cap and worker count as its own
// fields: chrome.Info has no Workers field, so this dashboard's own page
// data is where that number lives.
type statusPageData struct {
	chrome.PageData
	Counts     logsstore.Counts
	HasQueue   bool
	QueueDepth int
	QueueCap   int
	Workers    int
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
		Config:   s.config,
	}
	if s.rt != nil {
		data.QueueDepth = s.rt.Depth()
		data.QueueCap = s.rt.Cap()
		data.Workers = s.rt.Workers()
	}
	s.chrome.Render(w, "status.html", data)
}

type systemsPageData struct {
	chrome.PageData
	Systems []logsstore.SystemRow
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
		s.chrome.StoreError(w, "index", err)
		return
	}
	// Names are joined here, not stored on the finding: one machine has one
	// name in the database, so a rename shows up everywhere at once. Losing
	// the join costs the names, never the page -- the node ids are on the
	// rows already and are the attribution that matters.
	if err := s.reader.ResolveNodesFleet(r.Context(), findings); err != nil {
		slog.Warn("resolving node names failed", "error", err)
	}
	s.chrome.Render(w, "index.html", findingsPageData{
		PageData:   s.chrome.PageData(r, "index"),
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
	if v == logsstore.SortRecent {
		return v
	}
	return ""
}

type analysesPageData struct {
	chrome.PageData
	Analyses []logsstore.AnalysisRow
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
// that has since been fixed. See logsstore.GateRollup.
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
	Suppressed int
	Paid       int
	ZeroCost   int
	CostMicros int64
	AvgMicros  int64
}

// summarizeGate folds the rollup into the headline. GatedOut is derived as
// Windows-Called-Suppressed rather than read off the nil-Reasons row: the
// two agree by the gate's invariant (a non-empty reason set is what makes
// the call, unless a budget limit or the trigger memory stopped it, which
// suppressed_by records), and deriving it means legacy rows written by an
// older formula cannot make the summary contradict the table.
func summarizeGate(rows []logsstore.GateRow) gateSummary {
	var g gateSummary
	for _, row := range rows {
		g.Windows += row.Windows
		g.Called += row.LLMCalls
		g.Suppressed += row.Suppressed
		g.Paid += row.PaidCalls
		g.CostMicros += row.CostMicros
	}
	g.GatedOut = g.Windows - g.Called - g.Suppressed
	g.ZeroCost = g.Called - g.Paid
	if g.Paid > 0 {
		g.AvgMicros = g.CostMicros / int64(g.Paid)
	}
	return g
}

type gatePageData struct {
	chrome.PageData
	Rows    []logsstore.GateRow
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
// ordered by day, then model (internal/store/logs/ui.go), so a single linear
// pass suffices.
type costDayGroup struct {
	Day             string
	Rows            []logsstore.CostRow
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
	Templates []logsstore.TemplateRow
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
	Baselines []logsstore.BaselineRow
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
