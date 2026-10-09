// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package logs

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/nethesis/nethesis-insights/internal/model"
	logsstore "github.com/nethesis/nethesis-insights/internal/store/logs"
	"github.com/nethesis/nethesis-insights/internal/threat"
	"github.com/nethesis/nethesis-insights/internal/ui/chrome"
)

// reviewView is one option of the review queue's ?view= filter.
type reviewView struct {
	Key        string // the ?view= value
	Label      string
	Visibility string // the store filter; "" for every visibility
}

// reviewViews is the enumerated set /review accepts; anything else falls
// back to the first, the pending queue.
var reviewViews = []reviewView{
	{Key: "pending", Label: "pending review", Visibility: logsstore.VisibilityPending},
	{Key: "customer", Label: "delivered", Visibility: logsstore.VisibilityCustomer},
	{Key: "operator", Label: "internal", Visibility: logsstore.VisibilityOperator},
	{Key: "dismissed", Label: "dismissed", Visibility: logsstore.VisibilityDismissed},
	{Key: "all", Label: "all but dismissed", Visibility: ""},
}

func lookupReviewView(key string) reviewView {
	for _, v := range reviewViews {
		if v.Key == key {
			return v
		}
	}
	return reviewViews[0]
}

// reviewColumn is one sortable column of the review queue's table.
type reviewColumn struct {
	Sort       string // the ?sort= value, a logsstore.ClassSort* key
	Label      string
	DefaultDir string // the direction a first click sorts in
	Num        bool   // right-aligned, like every count column
}

// reviewColumns is the queue table's header, in display order. A first click
// sorts numbers, dates and severity "most first" and text A to Z.
var reviewColumns = []reviewColumn{
	{Sort: logsstore.ClassSortTitle, Label: "Class", DefaultDir: logsstore.SortAsc},
	{Sort: logsstore.ClassSortModule, Label: "Module", DefaultDir: logsstore.SortAsc},
	{Sort: logsstore.ClassSortSeverity, Label: "Severity", DefaultDir: logsstore.SortDesc},
	{Sort: logsstore.ClassSortVisibility, Label: "Visibility", DefaultDir: logsstore.SortAsc},
	{Sort: logsstore.ClassSortSystems, Label: "Systems", DefaultDir: logsstore.SortDesc, Num: true},
	{Sort: logsstore.ClassSortFindings, Label: "Findings", DefaultDir: logsstore.SortDesc, Num: true},
	{Sort: logsstore.ClassSortLastSeen, Label: "Last seen", DefaultDir: logsstore.SortDesc},
}

// sanitizeClassSort accepts only a reviewColumns sort key, returning ("", "")
// -- the queue's default order -- for anything else. A known key with a
// direction that is neither asc nor desc sorts in that column's default
// direction.
func sanitizeClassSort(sort, dir string) (string, string) {
	for _, c := range reviewColumns {
		if c.Sort != sort {
			continue
		}
		if dir != logsstore.SortAsc && dir != logsstore.SortDesc {
			dir = c.DefaultDir
		}
		return sort, dir
	}
	return "", ""
}

// reviewHeader is one rendered column header: a plain link that sorts the
// queue by that column, flipping the direction when it is already the one
// sorted on.
type reviewHeader struct {
	Label    string
	Href     string
	Num      bool
	AriaSort string // "ascending"/"descending" on the active column, else ""
	Arrow    string // the visible direction marker on the active column
}

// reviewHeaders builds the header links in Go, so the template only prints
// them. Each carries the current view and key filter, so sorting never
// drops the filter the operator is looking at. group is the same kind of filter.
func (s *server) reviewHeaders(view, key, group, sort, dir string) []reviewHeader {
	out := make([]reviewHeader, 0, len(reviewColumns))
	for _, c := range reviewColumns {
		h := reviewHeader{Label: c.Label, Num: c.Num}
		next := c.DefaultDir
		if c.Sort == sort {
			if dir == logsstore.SortAsc {
				h.AriaSort, h.Arrow, next = "ascending", "▲", logsstore.SortDesc
			} else {
				h.AriaSort, h.Arrow, next = "descending", "▼", logsstore.SortAsc
			}
		}
		q := url.Values{"view": {view}, "sort": {c.Sort}, "dir": {next}}
		if key != "" {
			q.Set("key", key)
		}
		if group != "" {
			q.Set("group", group)
		}
		h.Href = s.chrome.Link("/review") + "?" + q.Encode()
		out = append(out, h)
	}
	return out
}

// groupAction is one "decide the whole group" form of the group view.
type groupAction struct {
	Visibility string
	Label      string
}

var groupActions = []groupAction{
	{logsstore.VisibilityCustomer, "Deliver all pending in this group"},
	{logsstore.VisibilityOperator, "Keep all pending in this group internal"},
	{logsstore.VisibilityDismissed, "Dismiss all pending in this group"},
}

// suggestionLabel names a suggested visibility in the words of the per-class
// buttons.
func suggestionLabel(v string) string {
	switch v {
	case logsstore.VisibilityCustomer:
		return "Deliver"
	case logsstore.VisibilityOperator:
		return "Keep internal"
	case logsstore.VisibilityDismissed:
		return "Dismiss"
	}
	return v
}

type reviewPageData struct {
	chrome.PageData
	Rows         []logsstore.ClassRow
	View         string
	Views        []reviewView
	Key          string
	Group        string
	GroupActions []groupAction
	Sort         string
	Dir          string
	Headers      []reviewHeader
	CanWrite     bool
	Severities   []string
}

// handleReview shows the class queue: finding classes ranked by how many
// systems raised them, then how many findings they cover, unless a column
// header asked for another order. A GET, unauthenticated like every page
// here; only acting on a class needs the admin key.
func (s *server) handleReview(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	view := lookupReviewView(q.Get("view"))
	key := q.Get("key")
	group := strings.TrimSpace(q.Get("group"))
	if len(group) > maxClassKeyLen {
		group = ""
	}
	if (key != "" || group != "") && q.Get("view") == "" {
		// A link to one class (from a finding) or to one group must find
		// every member whatever it was decided, not only while pending.
		view = lookupReviewView("all")
	}
	sort, dir := sanitizeClassSort(q.Get("sort"), q.Get("dir"))
	rows, err := s.reader.ListClasses(r.Context(), logsstore.ClassFilter{
		Visibility: view.Visibility, Key: key, Group: group, Sort: sort, Dir: dir, Limit: reviewLimit,
	})
	if err != nil {
		s.chrome.StoreError(w, "review", err)
		return
	}
	s.chrome.Render(w, "review.html", reviewPageData{
		PageData:     s.chrome.PageData(r, "review"),
		Rows:         rows,
		View:         view.Key,
		Views:        reviewViews,
		Key:          key,
		Group:        group,
		GroupActions: groupActions,
		Sort:         sort,
		Dir:          dir,
		Headers:      s.reviewHeaders(view.Key, key, group, sort, dir),
		CanWrite:     s.canWrite(),
		Severities:   model.Severities,
	})
}

type reviewStatsPageData struct {
	chrome.PageData
	Rows []logsstore.ClassStatsRow
}

func (s *server) handleReviewStats(w http.ResponseWriter, r *http.Request) {
	rows, err := s.reader.ClassStats(r.Context())
	if err != nil {
		s.chrome.StoreError(w, "review-stats", err)
		return
	}
	s.chrome.Render(w, "review-stats.html", reviewStatsPageData{
		PageData: s.chrome.PageData(r, "review-stats"),
		Rows:     rows,
	})
}

type reviewAuditPageData struct {
	chrome.PageData
	Decisions []logsstore.ClassDecision
}

// handleReviewAudit is the only reader of class_decisions: without it the
// trail every review route appends to would be write-only.
func (s *server) handleReviewAudit(w http.ResponseWriter, r *http.Request) {
	decisions, err := s.reader.ListClassDecisions(r.Context(), reviewAuditLimit)
	if err != nil {
		s.chrome.StoreError(w, "review-audit", err)
		return
	}
	s.chrome.Render(w, "review-audit.html", reviewAuditPageData{
		PageData:  s.chrome.PageData(r, "review-audit"),
		Decisions: decisions,
	})
}

// handleDecision serves every writableRoutes path, reached only after
// AuthenticateWrite. /review/group applies one visibility to every pending
// class of a group, one audit row each; the rest
// apply to the whole class -- every
// finding in it, on every system, now and when it recurs -- never to one
// finding.
func (s *server) handleDecision(w http.ResponseWriter, r *http.Request, actor string) {
	r.Body = http.MaxBytesReader(w, r.Body, maxReviewForm)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	// PostFormValue, never FormValue: a write takes its parameters from the
	// body it was submitted with, not from the query string.
	field := "key"
	if r.URL.Path == "/review/group" {
		field = "anchor"
	}
	key, ok := formKey(r, field)
	if !ok {
		http.Error(w, "a class key is required", http.StatusBadRequest)
		return
	}
	ctx, now := r.Context(), s.now()

	var err error
	switch r.URL.Path {
	case "/review/deliver":
		err = s.writer.SetClassVisibility(ctx, key, logsstore.VisibilityCustomer, actor, now)
	case "/review/internal":
		err = s.writer.SetClassVisibility(ctx, key, logsstore.VisibilityOperator, actor, now)
	case "/review/dismiss":
		err = s.writer.SetClassVisibility(ctx, key, logsstore.VisibilityDismissed, actor, now)
	case "/review/group":
		visibility := r.PostFormValue("visibility")
		switch visibility {
		case logsstore.VisibilityCustomer, logsstore.VisibilityOperator, logsstore.VisibilityDismissed:
		default:
			http.Error(w, "visibility must be customer, operator or dismissed", http.StatusBadRequest)
			return
		}
		// Only the group's pending classes change; the count is not shown.
		_, err = s.writer.SetGroupVisibility(ctx, key, visibility, actor, now)
	case "/review/security":
		security, ok := parseOnOff(r.PostFormValue("security"))
		if !ok {
			http.Error(w, "security must be on or off", http.StatusBadRequest)
			return
		}
		err = s.writer.SetClassSecurity(ctx, key, security, actor, now)
	case "/review/severity":
		severity := r.PostFormValue("severity")
		if severity != "" && !model.ValidSeverity(severity) {
			http.Error(w, "unknown severity", http.StatusBadRequest)
			return
		}
		err = s.writer.SetClassSeverity(ctx, key, severity, actor, now)
	case "/review/doc-ref":
		docRef, ok := cleanDocRef(r.PostFormValue("doc_ref"))
		if !ok {
			http.Error(w, "doc_ref must be an absolute http(s) URL", http.StatusBadRequest)
			return
		}
		err = s.writer.SetClassDocRef(ctx, key, docRef, actor, now)
	default:
		// Reachable only if a path is added to writableRoutes with no case
		// here -- err would stay nil and fall through to the redirect below
		// as if the (nonexistent) decision had succeeded.
		http.NotFound(w, r)
		return
	}

	switch {
	case err == nil:
		http.Redirect(w, r, s.reviewReturn(r), http.StatusSeeOther)
	case errors.Is(err, logsstore.ErrUnknownClass):
		http.Error(w, "no such class", http.StatusNotFound)
	case errors.Is(err, logsstore.ErrInvalidSeverity), errors.Is(err, logsstore.ErrInvalidVisibility):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		s.chrome.StoreError(w, "review", err)
	}
}

// parseOnOff reads the /review/security form's security field: "on" or
// "off", nothing else -- there is no implicit default, so a stale or
// malformed form is refused rather than silently toggling either way.
func parseOnOff(v string) (on bool, ok bool) {
	switch v {
	case "on":
		return true, true
	case "off":
		return false, true
	default:
		return false, false
	}
}

// formKey reads a class key from the form body: trimmed, non-empty and
// bounded. Its format is the store's business -- an unknown key is a 404
// there, not a parse error here.
func formKey(r *http.Request, name string) (string, bool) {
	k := strings.TrimSpace(r.PostFormValue(name))
	return k, k != "" && len(k) <= maxClassKeyLen
}

// cleanDocRef accepts "" (clear it) or an absolute http(s) URL. Nothing else:
// the value reaches the customer's UI, where anything else rendered as a
// link -- a javascript: URL above all -- is an injection, not documentation.
func cleanDocRef(raw string) (string, bool) {
	v := threat.CleanText(raw, maxDocRefLen)
	if v == "" {
		return "", true
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", false
	}
	return u.String(), true
}

// reviewReturn is where a decision redirects: back to the queue view, filter
// and sort order the form was submitted from, re-validated rather than
// echoed.
func (s *server) reviewReturn(r *http.Request) string {
	q := url.Values{}
	if v := r.PostFormValue("view"); v != "" {
		q.Set("view", lookupReviewView(v).Key)
	}
	if k, ok := formKey(r, "filter"); ok {
		q.Set("key", k)
	}
	if g, ok := formKey(r, "group"); ok {
		q.Set("group", g)
	}
	if sort, dir := sanitizeClassSort(r.PostFormValue("sort"), r.PostFormValue("dir")); sort != "" {
		q.Set("sort", sort)
		q.Set("dir", dir)
	}
	target := s.chrome.Link("/review")
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	return target
}
