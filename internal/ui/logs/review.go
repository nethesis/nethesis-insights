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
	{Key: "all", Label: "all", Visibility: ""},
}

func lookupReviewView(key string) reviewView {
	for _, v := range reviewViews {
		if v.Key == key {
			return v
		}
	}
	return reviewViews[0]
}

type reviewPageData struct {
	chrome.PageData
	Rows       []logsstore.ClassRow
	View       string
	Views      []reviewView
	Key        string
	CanWrite   bool
	Severities []string
}

// handleReview shows the class queue: finding classes ranked by how many
// systems raised them, then how many findings they cover. A GET,
// unauthenticated like every page here; only acting on a class needs the
// admin key.
func (s *server) handleReview(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	view := lookupReviewView(q.Get("view"))
	key := q.Get("key")
	if key != "" && q.Get("view") == "" {
		// A link to one class (from a finding) must find it whatever it was
		// decided, not only while it is pending.
		view = lookupReviewView("all")
	}
	rows, err := s.reader.ListClasses(r.Context(), logsstore.ClassFilter{
		Visibility: view.Visibility, Key: key, Limit: reviewLimit,
	})
	if err != nil {
		s.chrome.StoreError(w, "review", err)
		return
	}
	s.chrome.Render(w, "review.html", reviewPageData{
		PageData:   s.chrome.PageData(r, "review"),
		Rows:       rows,
		View:       view.Key,
		Views:      reviewViews,
		Key:        key,
		CanWrite:   s.canWrite(),
		Severities: model.Severities,
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
// AuthenticateWrite. Each decision applies to the whole class -- every
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
	key, ok := formKey(r, "key")
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

// reviewReturn is where a decision redirects: back to the queue view the
// form was submitted from, re-validated rather than echoed.
func (s *server) reviewReturn(r *http.Request) string {
	q := url.Values{}
	if v := r.PostFormValue("view"); v != "" {
		q.Set("view", lookupReviewView(v).Key)
	}
	if k, ok := formKey(r, "filter"); ok {
		q.Set("key", k)
	}
	target := s.chrome.Link("/review")
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	return target
}
