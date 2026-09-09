// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Command threatd runs Threat Shield as its own service: CrowdSec ban
// decisions in, the fleet-consensus blocklist out, and the allowlist review
// queue -- see internal/api/threat and internal/ui/threat. Authentication
// happens at the proxy (Traefik's forwardAuth calls authd); this process
// trusts a request only when it arrives from a configured trusted proxy
// (TRUSTED_PROXY_CIDRS), which is also what makes X-Forwarded-For safe to
// read for the reporter-own-address check.
package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	threatapi "github.com/nethesis/nethesis-insights/internal/api/threat"
	"github.com/nethesis/nethesis-insights/internal/blocklist"
	"github.com/nethesis/nethesis-insights/internal/platform/httpx"
	threatstore "github.com/nethesis/nethesis-insights/internal/store/threat"
	"github.com/nethesis/nethesis-insights/internal/threat"
	"github.com/nethesis/nethesis-insights/internal/ui/chrome"
	threatui "github.com/nethesis/nethesis-insights/internal/ui/threat"
)

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func getenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// setupLogger honours LOG_LEVEL=debug|info|warn|error.
func setupLogger(level string) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})))
}

// secretState reduces a secret to its mere presence. The status page and the
// logs get this, never the value.
func secretState(set bool) string {
	if set {
		return "set"
	}
	return "unset"
}

// isLoopbackBind reports whether addr binds a loopback address only. It is
// deliberately strict: anything that is not a literal loopback IP -- an empty
// host, a name, an unparseable value -- is treated as a wider bind, because
// the failure mode of a false "yes" is a silently exposed fleet-wide page.
func isLoopbackBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// warnIfNotLoopback warns when the operator UI is bound anywhere other than a
// loopback address. GET is unauthenticated and fleet-wide -- every promoted
// address, every reported event -- so a wider bind must never happen
// silently. threatd does not refuse it: the operator asked for the choice to
// be theirs.
func warnIfNotLoopback(addr string) {
	if isLoopbackBind(addr) {
		return
	}
	slog.Warn("the operator UI is unauthenticated and fleet-wide but is not bound to a loopback address; "+
		"bind it to 127.0.0.1 or a trusted management network",
		"ui_listen_addr", addr)
}

// newUIServer builds threatd's operator UI listener, or nil when
// UI_LISTEN_ADDR is empty -- the UI is off unless an operator explicitly
// turns it on.
func newUIServer(addr, basePath string, r threatui.Reader, feed threatui.Feed, w threatui.Writer, adminKey string, info chrome.Info) *http.Server {
	if addr == "" {
		return nil
	}
	handler, err := threatui.NewServer(r, feed, w, chrome.Config{
		BasePath: basePath,
		AdminKey: adminKey,
		Info:     info,
	})
	if err != nil {
		slog.Error("failed to build the operator UI", "error", err)
		os.Exit(1)
	}
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
}

func main() {
	startedAt := time.Now().UnixMilli()

	logLevel := getenv("LOG_LEVEL", "info")
	setupLogger(logLevel)

	listenAddr := getenv("LISTEN_ADDR", ":9595")
	// Empty by default: the operator UI is unauthenticated and fleet-wide, so
	// enabling it is one explicit operator act, never a default.
	uiListenAddr := getenv("UI_LISTEN_ADDR", "")
	uiBasePath := getenv("UI_BASE_PATH", "")
	dbPath := getenv("DB_PATH", "/var/lib/threat/threat.db")
	trustedProxyCIDRs := getenv("TRUSTED_PROXY_CIDRS", "127.0.0.0/8")
	// Off by default: writing the allowlist is the one operation that can
	// stop the fleet blocking an address, so it stays off until an operator
	// turns it on explicitly.
	adminAPIKey := getenv("ADMIN_API_KEY", "")

	// Threat Shield. Every one has a default, so an existing deployment
	// picks the pipeline up without being reconfigured.
	consensusInterval := getenvDuration("BLOCKLIST_CONSENSUS_INTERVAL", 5*time.Minute)
	blocklistWindow := getenvDuration("BLOCKLIST_WINDOW", time.Hour)
	blocklistMinSystems := getenvInt("BLOCKLIST_MIN_SYSTEMS", 3)
	blocklistTTL := getenvDuration("BLOCKLIST_TTL", 24*time.Hour)
	blocklistMaxEntries := getenvInt("BLOCKLIST_MAX_ENTRIES", 50000)
	threatRetention := getenvDuration("THREAT_EVENT_RETENTION", 168*time.Hour)
	threatMaxDecisions := getenvInt("THREAT_MAX_DECISIONS_PER_REQUEST", threat.DefaultMaxDecisions)

	trusted, err := httpx.ParseTrustedProxies(trustedProxyCIDRs)
	if err != nil {
		slog.Error("invalid TRUSTED_PROXY_CIDRS", "error", err)
		os.Exit(1)
	}

	if dir := filepath.Dir(dbPath); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			slog.Error("failed to create db parent directory", "dir", dir, "error", err)
			os.Exit(1)
		}
	}

	s, err := threatstore.Open(dbPath)
	if err != nil {
		slog.Error("failed to open store", "error", err)
		os.Exit(1)
	}
	defer s.Close()

	ctx := context.Background()
	if err := s.Init(ctx); err != nil {
		slog.Error("failed to init store", "error", err)
		os.Exit(1)
	}

	// Threat Shield's consensus pass: no LLM, no gate, no queue.
	snapshot := blocklist.NewSnapshot()
	consensus := blocklist.New(s, snapshot, blocklist.Config{
		Window:     blocklistWindow,
		MinSystems: blocklistMinSystems,
		TTL:        blocklistTTL,
		MaxEntries: blocklistMaxEntries,
		Retention:  threatRetention,
	})

	handler := threatapi.NewServer(s, snapshot, trusted, threatapi.Config{
		MaxDecisions: threatMaxDecisions,
		Now:          func() int64 { return time.Now().UnixMilli() },
	})

	httpServer := &http.Server{
		Addr:    listenAddr,
		Handler: handler,
	}

	// The status page's configuration table, built here field by field and
	// never by iterating os.Environ(): an accidental new secret in the
	// environment must not appear on an unauthenticated page just because it
	// was set.
	cfgItems := []chrome.ConfigItem{
		{Name: "LISTEN_ADDR", Value: listenAddr},
		{Name: "UI_LISTEN_ADDR", Value: uiListenAddr},
		{Name: "UI_BASE_PATH", Value: uiBasePath},
		{Name: "DB_PATH", Value: dbPath},
		{Name: "LOG_LEVEL", Value: logLevel},
		{Name: "TRUSTED_PROXY_CIDRS", Value: trustedProxyCIDRs},
		{Name: "ADMIN_API_KEY", Value: secretState(adminAPIKey != "")},
		{Name: "BLOCKLIST_CONSENSUS_INTERVAL", Value: consensusInterval.String()},
		{Name: "BLOCKLIST_WINDOW", Value: blocklistWindow.String()},
		{Name: "BLOCKLIST_MIN_SYSTEMS", Value: strconv.Itoa(blocklistMinSystems)},
		{Name: "BLOCKLIST_TTL", Value: blocklistTTL.String()},
		{Name: "BLOCKLIST_MAX_ENTRIES", Value: strconv.Itoa(blocklistMaxEntries)},
		{Name: "THREAT_EVENT_RETENTION", Value: threatRetention.String()},
		{Name: "THREAT_MAX_DECISIONS_PER_REQUEST", Value: strconv.Itoa(threatMaxDecisions)},
	}

	// s satisfies both threatui.Reader and threatui.Writer; the write routes
	// are reachable only when adminAPIKey is non-empty (chrome.CanWrite), so
	// wiring the writer unconditionally is safe -- an operator who has not
	// set ADMIN_API_KEY still gets the plain read-only dashboard.
	uiServer := newUIServer(uiListenAddr, uiBasePath, s, snapshot, s, adminAPIKey, chrome.Info{
		StartedAt: startedAt,
		Build:     chrome.BuildInfo(),
		Config:    cfgItems,
	})

	// NEVER log the API key or any credential.
	slog.Info("starting threatd", "listen_addr", listenAddr, "ui_listen_addr", uiListenAddr,
		"db_path", dbPath, "log_level", logLevel, "trusted_proxy_cidrs", trustedProxyCIDRs)

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("http server error", "error", err)
			os.Exit(1)
		}
	}()

	if uiServer != nil {
		warnIfNotLoopback(uiListenAddr)
		slog.Info("operator UI enabled", "ui_listen_addr", uiListenAddr,
			"writes_enabled", adminAPIKey != "")
		go func() {
			if err := uiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("ui server error", "error", err)
				os.Exit(1)
			}
		}()
	}

	// The consensus loop is started after the listeners so a slow first pass
	// cannot delay readiness. The first pass runs immediately rather than one
	// interval in, so a restart does not leave the feed answering 503 for
	// five minutes with a database full of promoted entries.
	consensusCtx, stopConsensus := context.WithCancel(context.Background())
	consensusDone := runPassLoop(consensusCtx, "blocklist consensus", consensus, consensusInterval)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("graceful shutdown failed", "error", err)
	}
	if uiServer != nil {
		if err := uiServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("ui graceful shutdown failed", "error", err)
		}
	}

	// The consensus loop holds no acknowledged work -- a cancelled pass just
	// leaves the previous snapshot in place -- so it is stopped last and
	// simply waited on.
	stopConsensus()
	<-consensusDone
	slog.Info("consensus loop stopped")
}

// pass is a periodic background job. The Threat Shield consensus pass
// satisfies it.
type pass interface {
	Run(ctx context.Context, now int64) error
}

// runPassLoop runs a pass immediately and then every interval until ctx is
// cancelled. A failed pass is logged and the loop continues: whatever it did
// not replace keeps being served, which is the designed degradation.
func runPassLoop(ctx context.Context, name string, r pass, interval time.Duration) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if err := r.Run(ctx, time.Now().UnixMilli()); err != nil && ctx.Err() == nil {
				slog.Error("background pass failed", "pass", name, "error", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return done
}
