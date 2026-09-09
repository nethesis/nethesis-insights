// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package chrome holds everything the three operator dashboards --
// insightsd's, threatd's and sizingd's -- share: the page layout and
// stylesheet, the timestamp/byte/percent formatters in view.go, the GET-only
// route discipline with its small enumerated write exception, and
// base-path-aware link building.
//
// Traefik serves all three behind one host, giving each pipeline a path
// prefix (/logs, /blocklist, /sizing) and stripping it before proxying.
// Handlers therefore keep routing on unprefixed paths, but every URL a page
// emits -- nav entries, the stylesheet, a form action, a redirect, the
// auto-refresh links -- has to put the prefix back, or the link escapes the
// pipeline's subtree. Link is the one place that knows the base exists;
// PageData and refreshLinks are built through it so every page gets this for
// free.
package chrome

import (
	"bytes"
	"crypto/subtle"
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/nethesis/nethesis-insights/internal/model"
	"github.com/nethesis/nethesis-insights/internal/threat"
)

//go:embed templates/layout.html static
var assets embed.FS

// ConfigItem is one row of a status page's configuration table. The caller
// builds these explicitly, field by field, from its own env config -- this
// package never reads os.Environ() and never sees a raw secret.
type ConfigItem struct {
	Name  string
	Value string
}

// Info is the static half of a status page, shared by every dashboard.
// Anything specific to one pipeline -- insightsd's queue depth, threatd's
// blocklist feed state -- stays out of here and travels in that pipeline's
// own page data instead.
type Info struct {
	StartedAt int64        // unix millis
	Build     string       // from runtime/debug.ReadBuildInfo; "unknown" if absent
	Config    []ConfigItem // explicit list; secrets ALREADY reduced to set/unset by the caller
}

// NavPage is one entry in the nav bar.
type NavPage struct {
	Key, Path, Label string
}

// NavGroup is a section of the nav bar. A group with no Label renders as a
// plain top-level link; a labeled group renders as a Pico
// <details class="dropdown"> menu, so a dashboard with many pages doesn't
// put them all in one flat row.
type NavGroup struct {
	Label string
	Pages []NavPage
}

// Config configures a Base.
type Config struct {
	// BasePath is the deployment's path prefix ("", "blocklist",
	// "/blocklist", ...). See normalizeBase and Link.
	BasePath string
	// AdminKey, when non-empty, is compared against the HTTP Basic password
	// on every write route. Empty means no write route is reachable at all
	// -- see CanWrite.
	AdminKey string
	// Info is the static half of the status page.
	Info Info
	// Nav is this dashboard's nav bar structure.
	Nav []NavGroup
	// Pages lists the content templates, each combined with the shared
	// layout into its own *template.Template -- html/template errors on a
	// duplicate block name within one parsed set, and every page legitimately
	// defines a block named "content".
	Pages []string
	// Templates is the caller's own page templates -- pages only, rooted so
	// each of Pages resolves directly (e.g. "status.html"). It never
	// contains layout.html: chrome owns that in its own embed.FS, so one
	// field cannot be asked to mean both the shared layout and the caller's
	// pages.
	Templates fs.FS
	// Funcs are merged into the shared func map (the Fmt* helpers in
	// view.go) when parsing every page.
	Funcs template.FuncMap
}

// Base is the shared chrome: the parsed templates, the static file server,
// and the base path every emitted URL must carry.
type Base struct {
	basePath string
	adminKey string
	info     Info
	nav      []NavGroup
	tmpl     map[string]*template.Template
	static   http.Handler
}

// New builds a Base from cfg.
func New(cfg Config) (*Base, error) {
	tmpl, err := ParseTemplates(cfg)
	if err != nil {
		return nil, err
	}
	staticFS, err := fs.Sub(assets, "static")
	if err != nil {
		// Only reachable if the embed directive above stops matching the
		// static/ directory -- a build-time programming error, not a runtime
		// condition.
		return nil, err
	}
	return &Base{
		basePath: normalizeBase(cfg.BasePath),
		adminKey: cfg.AdminKey,
		info:     cfg.Info,
		nav:      cfg.Nav,
		tmpl:     tmpl,
		static:   http.FileServer(http.FS(staticFS)),
	}, nil
}

// ParseTemplates combines each of cfg.Pages with chrome's own embedded
// layout.html into its own isolated *template.Template, so that every page's
// {{define "content"}} block lives in an isolated namespace.
func ParseTemplates(cfg Config) (map[string]*template.Template, error) {
	fm := template.FuncMap{}
	for k, v := range funcMap {
		fm[k] = v
	}
	for k, v := range cfg.Funcs {
		fm[k] = v
	}
	out := make(map[string]*template.Template, len(cfg.Pages))
	for _, p := range cfg.Pages {
		t, err := template.New("layout.html").Funcs(fm).ParseFS(assets, "templates/layout.html")
		if err != nil {
			return nil, err
		}
		if t, err = t.ParseFS(cfg.Templates, p); err != nil {
			return nil, err
		}
		out[p] = t
	}
	return out, nil
}

// normalizeBase turns "", "blocklist", "/blocklist" and "/blocklist/" into
// "" or "/blocklist" -- exactly one leading slash, no trailing one -- so
// Link can concatenate without thinking about it.
func normalizeBase(s string) string {
	s = strings.Trim(s, "/")
	if s == "" {
		return ""
	}
	return "/" + s
}

// Link returns an absolute URL for an internal path, with the deployment's
// base path prepended. Traefik strips the prefix before proxying, so the
// handlers route on unprefixed paths and every URL the page emits -- nav
// entries, form actions, redirects, the stylesheet, the refresh links --
// must be built here.
func (b *Base) Link(path string) string {
	if b.basePath == "" {
		return path
	}
	if path == "/" {
		return b.basePath + "/"
	}
	return b.basePath + path
}

// navItem is one rendered nav-bar link.
type navItem struct {
	Path, Label string
	Active      bool
}

// navGroupData is one rendered nav section. Active is set when one of Items
// is the current page, so layout.html can keep that dropdown open by
// default -- the current section stays visible without a click.
type navGroupData struct {
	Label  string
	Items  []navItem
	Active bool
}

// PageData is the chrome embedded in every page's template data, so
// layout.html's nav/refresh/footer chrome renders the same way regardless of
// which page is on screen.
type PageData struct {
	Base       string
	Nav        []navGroupData
	Refresh    int
	RefreshOff string
	Refresh10  string
	Refresh30  string
	Build      string
	Uptime     string
}

// PageData builds the chrome shared by every page: nav with the active entry
// underlined and every link carrying the base path, the meta-refresh value,
// and the three refresh links (off/10s/30s) that preserve the rest of the
// current query string.
func (b *Base) PageData(r *http.Request, active string) PageData {
	nav := make([]navGroupData, len(b.nav))
	for i, g := range b.nav {
		items := make([]navItem, len(g.Pages))
		var groupActive bool
		for j, p := range g.Pages {
			isActive := p.Key == active
			items[j] = navItem{Path: b.Link(p.Path), Label: p.Label, Active: isActive}
			groupActive = groupActive || isActive
		}
		nav[i] = navGroupData{Label: g.Label, Items: items, Active: groupActive}
	}
	off, r10, r30 := b.refreshLinks(r)
	return PageData{
		Base:       b.basePath,
		Nav:        nav,
		Refresh:    ParseRefresh(r),
		RefreshOff: off,
		Refresh10:  r10,
		Refresh30:  r30,
		Build:      b.info.Build,
		Uptime:     FmtAgo(b.info.StartedAt),
	}
}

// ParseRefresh returns the positive integer from ?refresh=N, or 0 for a
// missing, zero, negative or non-numeric value. The raw string is never
// returned or rendered -- only this validated int reaches the template,
// which is what keeps an invalid value from ever being reflected into the
// page.
func ParseRefresh(r *http.Request) int {
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

// refreshLinks builds the three nav "auto-refresh" links against the current
// path and query string, with only the refresh parameter changed -- every
// other filter (system, status, severity, limit, ...) survives. r.URL.Path
// is post-strip (Traefik already removed the base path), so it is rebuilt
// through Link or every refresh link would escape the pipeline's subtree.
func (b *Base) refreshLinks(r *http.Request) (off, r10, r30 string) {
	base := b.Link(r.URL.Path)
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

// ClampLimit parses ?limit=, falling back to def on anything invalid, and
// never exceeding max.
func ClampLimit(v string, def, max int) int {
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

// Render executes page's parsed template set against data and writes the
// result, or a 500 on a template error.
func (b *Base) Render(w http.ResponseWriter, page string, data any) {
	var buf bytes.Buffer
	if err := b.tmpl[page].ExecuteTemplate(&buf, "layout.html", data); err != nil {
		slog.Error("chrome: render failed", "page", page, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// StoreError logs a store failure and answers 503: a transient store problem
// is retryable, unlike a template bug.
func (b *Base) StoreError(w http.ResponseWriter, page string, err error) {
	slog.Error("chrome: store query failed", "page", page, "error", err)
	http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
}

// ServeStatic answers a /static/... request from chrome's own embedded
// assets and reports whether it did. r.URL.Path is always unprefixed here --
// Traefik has already stripped the deployment's base path -- so no Link
// translation is needed to match it.
func (b *Base) ServeStatic(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/static/") {
		return false
	}
	http.StripPrefix("/static/", b.static).ServeHTTP(w, r)
	return true
}

// sameOriginWrite reports whether a write request plausibly came from this
// UI's own pages rather than from another site.
//
// This matters more here than the usual CSRF case. The write routes
// authenticate with HTTP Basic, and a browser that has been given Basic
// credentials once **replays them automatically on every later request to
// the same origin** -- including a form POST triggered by an unrelated page
// the operator happens to visit afterwards. Without this check, any site
// could auto-submit a form at the dashboard's origin and perform an
// authenticated write silently and permanently.
//
// Two headers, both sent by browsers and neither forgeable by a cross-site
// page:
//
//   - Sec-Fetch-Site must be same-origin (or "none" for a direct address-bar
//     action). A cross-site form POST arrives as "cross-site".
//   - Origin, when present, must name this host.
//
// A request carrying neither header is allowed: that is a non-browser client
// (curl, a script), which has no ambient credential to be abused in the
// first place -- CSRF is a browser problem, and refusing curl would only
// break the legitimate scripted path without closing anything.
func sameOriginWrite(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Host == r.Host
}

// AuthenticateWrite checks HTTP Basic against AdminKey and returns the
// sanitized username as the actor to record with the write. The browser
// prompts for these credentials natively -- this costs no JavaScript, no
// cookie and no session state.
func (b *Base) AuthenticateWrite(w http.ResponseWriter, r *http.Request) (string, bool) {
	// Checked before the credential: a cross-site request must be refused
	// whether or not the browser attached a valid cached one, and answering
	// 401 here would prompt the operator for a password on a forged form.
	if !sameOriginWrite(r) {
		slog.Warn("chrome: refused a cross-site write",
			"path", r.URL.Path,
			"origin", r.Header.Get("Origin"),
			"sec_fetch_site", r.Header.Get("Sec-Fetch-Site"),
			"remote_addr", r.RemoteAddr)
		http.Error(w, "cross-site writes are refused", http.StatusForbidden)
		return "", false
	}

	username, password, ok := r.BasicAuth()
	if !ok || subtle.ConstantTimeCompare([]byte(password), []byte(b.adminKey)) != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="operator admin"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", false
	}
	actor := threat.CleanText(username, model.MaxAdminActorLen)
	if actor == "" {
		http.Error(w, "a non-empty username is required as the actor", http.StatusBadRequest)
		return "", false
	}
	return actor, true
}

// CanWrite reports whether an admin key was configured at all. A caller that
// also needs a store writer wired in must check that separately -- chrome
// has no notion of a store.
func (b *Base) CanWrite() bool {
	return b.adminKey != ""
}
