// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Command sizingd runs fleet sizing as its own service: NS8 cluster leaders
// post one complete-UTC-day workload and performance report per cluster, the
// cohort pass scores nodes and folds a multi-day verdict, and the operator UI
// publishes cohort hardware baselines -- see internal/api/sizing,
// internal/baseline and internal/ui/sizing. Authentication happens at the
// proxy (Traefik's forwardAuth calls authd); this process trusts a request
// only when it arrives from a configured trusted proxy (TRUSTED_PROXY_CIDRS).
//
// No LLM call, no gate, no fingerprint, no queue. There is no admin API key:
// sizingd has no write route at all.
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

	sizingapi "github.com/nethesis/nethesis-insights/internal/api/sizing"
	"github.com/nethesis/nethesis-insights/internal/baseline"
	"github.com/nethesis/nethesis-insights/internal/platform/httpx"
	"github.com/nethesis/nethesis-insights/internal/sizing"
	sizingstore "github.com/nethesis/nethesis-insights/internal/store/sizing"
	"github.com/nethesis/nethesis-insights/internal/ui/chrome"
	sizingui "github.com/nethesis/nethesis-insights/internal/ui/sizing"
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
// loopback address. GET is unauthenticated and fleet-wide -- every cluster's
// node pressure and published cohorts -- so a wider bind must never happen
// silently. sizingd does not refuse it: the operator asked for the choice to
// be theirs.
func warnIfNotLoopback(addr string) {
	if isLoopbackBind(addr) {
		return
	}
	slog.Warn("the operator UI is unauthenticated and fleet-wide but is not bound to a loopback address; "+
		"bind it to 127.0.0.1 or a trusted management network",
		"ui_listen_addr", addr)
}

// newUIServer builds sizingd's operator UI listener, or nil when
// UI_LISTEN_ADDR is empty -- the UI is off unless an operator explicitly
// turns it on.
func newUIServer(addr, basePath string, r sizingui.Reader, info chrome.Info) *http.Server {
	if addr == "" {
		return nil
	}
	handler, err := sizingui.NewServer(r, chrome.Config{
		BasePath: basePath,
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
	dbPath := getenv("DB_PATH", "/var/lib/sizing/sizing.db")
	trustedProxyCIDRs := getenv("TRUSTED_PROXY_CIDRS", "127.0.0.0/8")

	// Fleet sizing. Every one has a default, so an existing deployment picks
	// the pipeline up without being reconfigured. The pass interval is an
	// hour because the inputs are whole days: running it faster cannot
	// produce a different answer.
	sizingRetention := getenvDuration("SIZING_RETENTION", 100*24*time.Hour)
	sizingPassInterval := getenvDuration("SIZING_PASS_INTERVAL", time.Hour)
	sizingWindowDays := getenvInt("SIZING_WINDOW_DAYS", sizing.VerdictWindowDays)
	sizingMinDistinctSystems := getenvInt("SIZING_MIN_DISTINCT_SYSTEMS", 20)
	sizingMinNodes := getenvInt("SIZING_MIN_NODES", 30)
	sizingMinDaysPresent := getenvInt("SIZING_MIN_DAYS_PRESENT", sizing.MinDaysPresent)
	sizingMaxNodesPerReport := getenvInt("SIZING_MAX_NODES_PER_REPORT", sizing.DefaultMaxNodes)

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

	s, err := sizingstore.Open(dbPath)
	if err != nil {
		slog.Error("failed to open store", "error", err)
		os.Exit(1)
	}
	defer func() { _ = s.Close() }()

	ctx := context.Background()
	if err := s.Init(ctx); err != nil {
		slog.Error("failed to init store", "error", err)
		os.Exit(1)
	}

	// Fleet sizing's cohort pass: no LLM, no gate, no queue.
	cohortPass := baseline.New(s, baseline.Config{
		WindowDays:         sizingWindowDays,
		MinDistinctSystems: sizingMinDistinctSystems,
		MinNodes:           sizingMinNodes,
		MinDaysPresent:     sizingMinDaysPresent,
		Retention:          sizingRetention,
	})

	handler := sizingapi.NewServer(s, trusted, sizingapi.Config{
		MaxNodes: sizingMaxNodesPerReport,
		Now:      func() int64 { return time.Now().UnixMilli() },
	})

	httpServer := &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
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
		{Name: "SIZING_RETENTION", Value: sizingRetention.String()},
		{Name: "SIZING_PASS_INTERVAL", Value: sizingPassInterval.String()},
		{Name: "SIZING_WINDOW_DAYS", Value: strconv.Itoa(sizingWindowDays)},
		{Name: "SIZING_MIN_DISTINCT_SYSTEMS", Value: strconv.Itoa(sizingMinDistinctSystems)},
		{Name: "SIZING_MIN_NODES", Value: strconv.Itoa(sizingMinNodes)},
		{Name: "SIZING_MIN_DAYS_PRESENT", Value: strconv.Itoa(sizingMinDaysPresent)},
		{Name: "SIZING_MAX_NODES_PER_REPORT", Value: strconv.Itoa(sizingMaxNodesPerReport)},
	}

	uiServer := newUIServer(uiListenAddr, uiBasePath, s, chrome.Info{
		StartedAt: startedAt,
		Build:     chrome.BuildInfo(),
		Config:    cfgItems,
	})

	slog.Info("starting sizingd", "listen_addr", listenAddr, "ui_listen_addr", uiListenAddr,
		"db_path", dbPath, "log_level", logLevel, "trusted_proxy_cidrs", trustedProxyCIDRs)

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("http server error", "error", err)
			os.Exit(1)
		}
	}()

	if uiServer != nil {
		warnIfNotLoopback(uiListenAddr)
		slog.Info("operator UI enabled", "ui_listen_addr", uiListenAddr)
		go func() {
			if err := uiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("ui server error", "error", err)
				os.Exit(1)
			}
		}()
	}

	// The cohort pass runs on its own loop, started after the listeners so a
	// slow first pass cannot delay readiness. Step 1 of the pass recomputes
	// stale pressure_version rows and must still run before cohorts are
	// built -- see baseline.Runner.Run.
	sizingCtx, stopSizing := context.WithCancel(context.Background())
	sizingDone := runPassLoop(sizingCtx, "sizing cohort", cohortPass, sizingPassInterval)

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

	// The cohort loop holds no acknowledged work -- a cancelled pass just
	// leaves the previous verdicts and cohorts in place -- so it is stopped
	// last and simply waited on.
	stopSizing()
	<-sizingDone
	slog.Info("sizing cohort loop stopped")
}

// pass is a periodic background job. The fleet-sizing cohort pass satisfies
// it.
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
