// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package sizing serves sizingd's operator dashboard: per-node pressure and
// verdicts, the published cohort recommendations, and pipeline status. It
// sits on chrome the same way insightsd's internal/ui does -- see that
// package's doc comment for the shared shape (zero JavaScript, every list
// bounded, secrets never rendered) and this file for what is specific to
// fleet sizing.
//
// sizingd has no write routes at all: unlike Threat Shield's allowlist, there
// is nothing here for an operator to approve or reject.
package sizing

import (
	"context"
	"embed"
	"io/fs"
	"net/http"

	"github.com/nethesis/nethesis-insights/internal/platform/httpx"
	"github.com/nethesis/nethesis-insights/internal/sizing"
	sizingstore "github.com/nethesis/nethesis-insights/internal/store/sizing"
	"github.com/nethesis/nethesis-insights/internal/ui/chrome"
)

// pageAssets embeds this dashboard's own content templates -- layout.html
// and static/ live in chrome's embed.FS instead.
//
//go:embed templates
var pageAssets embed.FS

// Reader is the read-only slice of sizingstore.Store the UI needs.
// *sizingstore.Store satisfies it.
type Reader interface {
	ListSizingNodes(ctx context.Context, systemID string, limit int) ([]sizingstore.SizingNodeUIRow, error)
	ListSizingModules(ctx context.Context, systemID string, limit int) ([]sizingstore.SizingModuleUIRow, error)
	ListSizingCohorts(ctx context.Context, kind string, limit int) ([]sizingstore.SizingCohortRow, error)
	SizingIngestStats(ctx context.Context, limit int) ([]sizingstore.SizingIngestRow, error)
	SizingCounts(ctx context.Context) (sizingstore.SizingCounts, error)
}

// Bounds on unbounded-by-default queries. This is a fleet-wide,
// unauthenticated surface and no list here is allowed to be unbounded.
const (
	sizingNodesLimit   = 500
	sizingModulesLimit = 2000
	sizingCohortsLimit = 500
	sizingIngestLimit  = 200
)

// nav is this dashboard's nav bar structure. A single group with no label
// renders as a flat row, which is right for three pages.
var nav = []chrome.NavGroup{
	{Pages: []chrome.NavPage{
		{Key: "index", Path: "/", Label: "Nodes"},
		{Key: "cohorts", Path: "/cohorts", Label: "Recommendations"},
		{Key: "status", Path: "/status", Label: "Status"},
	}},
}

// pages lists the content templates, each combined with chrome's layout into
// its own *template.Template -- see chrome.ParseTemplates.
var pages = []string{"index.html", "cohorts.html", "status.html"}

type server struct {
	chrome *chrome.Base
	reader Reader
	config []chrome.ConfigItem
}

// NewServer builds sizingd's operator UI handler.
func NewServer(r Reader, cfg chrome.Config) (http.Handler, error) {
	pageTemplates, err := fs.Sub(pageAssets, "templates")
	if err != nil {
		// Only reachable if the embed directive above stops matching the
		// templates/ directory -- a build-time programming error, not a
		// runtime condition.
		return nil, err
	}

	cfg.Name = "sizingd"
	cfg.Nav = nav
	cfg.Pages = pages
	cfg.Templates = pageTemplates

	base, err := chrome.New(cfg)
	if err != nil {
		return nil, err
	}

	srv := &server{chrome: base, reader: r, config: cfg.Info.Config}

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.route)

	return httpx.Logging(mux), nil
}

func (s *server) route(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		// sizingd has no write routes at all: there is nothing here for an
		// operator to approve or reject.
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.chrome.ServeStatic(w, r) {
		return
	}

	switch r.URL.Path {
	case "/":
		s.handleIndex(w, r)
	case "/cohorts":
		s.handleCohorts(w, r)
	case "/status":
		s.handleStatus(w, r)
	default:
		http.NotFound(w, r)
	}
}

// --- handlers ---

type statusPageData struct {
	chrome.PageData
	Counts sizingstore.SizingCounts
	Config []chrome.ConfigItem
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	counts, err := s.reader.SizingCounts(r.Context())
	if err != nil {
		s.chrome.StoreError(w, "status", err)
		return
	}
	s.chrome.Render(w, "status.html", statusPageData{
		PageData: s.chrome.PageData(r, "status"),
		Counts:   counts,
		Config:   s.config,
	})
}

type indexPageData struct {
	chrome.PageData
	Nodes      []sizingstore.SizingNodeUIRow
	Modules    []sizingstore.SizingModuleUIRow
	Ingest     []sizingstore.SizingIngestRow
	Thresholds []sizing.Threshold
	Version    int
	System     string
}

// handleIndex is the sizing pipeline's node view: one row per node, showing
// its most recent day's utilization percentiles, the per-axis penalties, the
// pressure they combine into and the multi-day verdict.
//
// The threshold table is on the page deliberately. Most of the score's knees
// are guesses awaiting calibration against ~30 days of fleet data, and a
// dashboard that renders a guess with no label attached is presenting it as
// advice. See sizing.Thresholds.
func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	systemID := r.URL.Query().Get("system")

	nodes, err := s.reader.ListSizingNodes(r.Context(), systemID, sizingNodesLimit)
	if err != nil {
		s.chrome.StoreError(w, "index", err)
		return
	}
	modules, err := s.reader.ListSizingModules(r.Context(), systemID, sizingModulesLimit)
	if err != nil {
		s.chrome.StoreError(w, "index", err)
		return
	}
	ingest, err := s.reader.SizingIngestStats(r.Context(), sizingIngestLimit)
	if err != nil {
		s.chrome.StoreError(w, "index", err)
		return
	}

	s.chrome.Render(w, "index.html", indexPageData{
		PageData:   s.chrome.PageData(r, "index"),
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
	Rows    []sizingstore.SizingCohortRow
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
