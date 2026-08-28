// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/nethesis/nethesis-insights/internal/analyzer"
	"github.com/nethesis/nethesis-insights/internal/api"
	"github.com/nethesis/nethesis-insights/internal/auth"
	"github.com/nethesis/nethesis-insights/internal/blocklist"
	"github.com/nethesis/nethesis-insights/internal/llm"
	"github.com/nethesis/nethesis-insights/internal/queue"
	"github.com/nethesis/nethesis-insights/internal/store"
	"github.com/nethesis/nethesis-insights/internal/threat"
	"github.com/nethesis/nethesis-insights/internal/ui"
)

// defaultAuthValidateURL is Nethesis's own subscription/auth endpoint. It
// forwards the edge's Authorization: Basic header verbatim and answers 200
// (valid), 401 (invalid) or an empty body either way -- no tenant/org id.
const defaultAuthValidateURL = "https://my.nethesis.it/auth"

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
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

// setupLogger honours LOG_LEVEL=debug|info|warn|error. Debug adds the request,
// gate, prompt and provider detail needed to explain a rejected or slow
// bundle; it never adds credentials.
func setupLogger(level string) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})))
}

// randomPepper returns a fresh 32-byte hex key. It exits on a rand.Reader
// failure, matching this project's other os.Exit(1)-on-startup-error style
// -- a broken entropy source is not a condition to run degraded under.
func randomPepper() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		slog.Error("failed to generate a random AUTH_PEPPER", "error", err)
		os.Exit(1)
	}
	return hex.EncodeToString(b)
}

// secretState reduces a secret to its mere presence. The status page and the
// logs get this, never the value.
func secretState(set bool) string {
	if set {
		return "set"
	}
	return "unset"
}

// newUIServer builds the operator UI's own listener, or nil when
// UI_LISTEN_ADDR is empty -- the UI is off unless an operator explicitly turns
// it on. Split out of main so that off-by-default behaviour is testable
// without booting the process.
//
// It gets its own http.Server, deliberately: the public ingest socket must
// never serve an unauthenticated fleet-wide page, so a reverse-proxy or
// firewall mistake on :9595 cannot expose it.
func newUIServer(addr string, r ui.Reader, rt ui.Runtime, feed ui.Feed, info ui.Info) *http.Server {
	if addr == "" {
		return nil
	}
	return &http.Server{
		Addr:              addr,
		Handler:           ui.NewServer(r, rt, feed, info),
		ReadHeaderTimeout: 10 * time.Second,
	}
}

// isLoopbackBind reports whether addr binds a loopback address only. It is
// deliberately strict: anything that is not a literal loopback IP -- an empty
// host (":9596", which binds every interface), a name, an unparseable value --
// is treated as a wider bind, because the failure mode of a false "yes" is a
// silently exposed fleet-wide page.
func isLoopbackBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// warnIfNotLoopback warns when the operator UI is bound anywhere other than a
// loopback address. The UI is unauthenticated and fleet-wide -- every tenant's
// findings, templates and spend -- so a wider bind must never happen silently.
// insightsd does not refuse it: the operator asked for the choice to be theirs.
func warnIfNotLoopback(addr string) {
	if isLoopbackBind(addr) {
		return
	}
	slog.Warn("the operator UI is unauthenticated and fleet-wide but is not bound to a loopback address; "+
		"bind it to 127.0.0.1 or a trusted management network",
		"ui_listen_addr", addr)
}

func main() {
	startedAt := time.Now().UnixMilli()

	logLevel := getenv("LOG_LEVEL", "info")
	setupLogger(logLevel)

	listenAddr := getenv("LISTEN_ADDR", ":9595")
	// Empty by default: the operator UI is unauthenticated and fleet-wide, so
	// enabling it is one explicit operator act, never a default.
	uiListenAddr := getenv("UI_LISTEN_ADDR", "")
	dbPath := getenv("DB_PATH", "/var/lib/insights/insights.db")
	llmBaseURL := getenv("LLM_BASE_URL", "")
	llmModel := getenv("LLM_MODEL", "")
	llmAPIKey := getenv("LLM_API_KEY", "")
	authValidateURL := getenv("AUTH_VALIDATE_URL", defaultAuthValidateURL)
	authPepper := getenv("AUTH_PEPPER", "")
	authCacheTTL := getenvDuration("AUTH_CACHE_TTL", 5*time.Minute)
	authNegCacheTTL := getenvDuration("AUTH_NEG_CACHE_TTL", 30*time.Second)
	authTimeout := getenvDuration("AUTH_TIMEOUT", 5*time.Second)
	gateTolerance := getenvFloat("GATE_TOLERANCE", 3.0)
	staleAfter := getenvDuration("STALE_AFTER", 24*time.Hour)
	ewmaAlpha := getenvFloat("EWMA_ALPHA", 0.3)
	priceInput := getenvFloat("LLM_PRICE_INPUT_PER_MTOK", 0)
	priceOutput := getenvFloat("LLM_PRICE_OUTPUT_PER_MTOK", 0)
	llmTimeout := getenvDuration("LLM_TIMEOUT", 120*time.Second)
	queueSize := getenvInt("QUEUE_SIZE", 256)
	queueWorkers := getenvInt("QUEUE_WORKERS", 2)
	analysisTimeout := getenvDuration("ANALYSIS_TIMEOUT", 5*time.Minute)
	// Threat Shield. Every one has a default, so an existing deployment picks
	// the pipeline up without being reconfigured.
	consensusInterval := getenvDuration("BLOCKLIST_CONSENSUS_INTERVAL", 5*time.Minute)
	blocklistWindow := getenvDuration("BLOCKLIST_WINDOW", time.Hour)
	blocklistMinSystems := getenvInt("BLOCKLIST_MIN_SYSTEMS", 3)
	blocklistTTL := getenvDuration("BLOCKLIST_TTL", 24*time.Hour)
	blocklistMaxEntries := getenvInt("BLOCKLIST_MAX_ENTRIES", 50000)
	threatRetention := getenvDuration("THREAT_EVENT_RETENTION", 168*time.Hour)
	threatMaxDecisions := getenvInt("THREAT_MAX_DECISIONS_PER_REQUEST", threat.DefaultMaxDecisions)

	if dir := filepath.Dir(dbPath); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			slog.Error("failed to create db parent directory", "dir", dir, "error", err)
			os.Exit(1)
		}
	}

	s, err := store.Open(dbPath)
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

	client := llm.NewOpenAI(llmBaseURL, llmAPIKey, llmTimeout)

	cfg := analyzer.Config{
		Tolerance:     gateTolerance,
		StaleAfter:    staleAfter,
		EWMAAlpha:     ewmaAlpha,
		Model:         llmModel,
		InputPerMTok:  priceInput,
		OutputPerMTok: priceOutput,
	}
	az := analyzer.New(s, client, cfg, func() int64 { return time.Now().UnixMilli() })

	// Ingest hands bundles to the queue and answers immediately; the workers
	// own the analysis on their own context, so an edge that gives up waiting
	// does not cancel work already in flight.
	q := queue.New(queueSize, analysisTimeout, az.Process)
	q.Start(queueWorkers)

	// Captured before the fallback below overwrites authPepper, so the status
	// page can distinguish an operator-supplied pepper from a generated one.
	authPepperSupplied := authPepper != ""
	if authPepper == "" {
		// A pepper is only defense in depth here -- the cache it keys never
		// leaves memory (spec §10) -- so an unset AUTH_PEPPER gets a random
		// one for this process's lifetime rather than refusing to start.
		authPepper = randomPepper()
		slog.Warn("AUTH_PEPPER not set, generated an ephemeral one for this process")
	}
	authenticator := auth.New(authValidateURL, authPepper, authTimeout, time.Now)
	authenticator.PositiveTTL = authCacheTTL
	authenticator.NegativeTTL = authNegCacheTTL

	// Threat Shield: a second pipeline sharing this listener and this
	// authenticator, and nothing else. No LLM, no gate, no queue.
	snapshot := blocklist.NewSnapshot()
	consensus := blocklist.New(s, snapshot, blocklist.Config{
		Window:     blocklistWindow,
		MinSystems: blocklistMinSystems,
		TTL:        blocklistTTL,
		MaxEntries: blocklistMaxEntries,
		Retention:  threatRetention,
	})

	handler := api.NewServer(q, s, authenticator, api.ThreatConfig{
		Store:        s,
		Feed:         snapshot,
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
	// was set. This mirrors the slog.Debug("configuration", ...) block below,
	// including its treatment of LLM_API_KEY, extended to AUTH_PEPPER.
	authPepperState := "set (ephemeral)"
	if authPepperSupplied {
		authPepperState = "set"
	}
	cfgItems := []ui.ConfigItem{
		{Name: "LISTEN_ADDR", Value: listenAddr},
		{Name: "UI_LISTEN_ADDR", Value: uiListenAddr},
		{Name: "DB_PATH", Value: dbPath},
		{Name: "LOG_LEVEL", Value: logLevel},
		{Name: "LLM_BASE_URL", Value: llmBaseURL},
		{Name: "LLM_MODEL", Value: llmModel},
		{Name: "LLM_API_KEY", Value: secretState(llmAPIKey != "")},
		{Name: "LLM_TIMEOUT", Value: llmTimeout.String()},
		{Name: "LLM_PRICE_INPUT_PER_MTOK", Value: strconv.FormatFloat(priceInput, 'f', -1, 64)},
		{Name: "LLM_PRICE_OUTPUT_PER_MTOK", Value: strconv.FormatFloat(priceOutput, 'f', -1, 64)},
		{Name: "AUTH_VALIDATE_URL", Value: authValidateURL},
		{Name: "AUTH_PEPPER", Value: authPepperState},
		{Name: "AUTH_CACHE_TTL", Value: authCacheTTL.String()},
		{Name: "AUTH_NEG_CACHE_TTL", Value: authNegCacheTTL.String()},
		{Name: "AUTH_TIMEOUT", Value: authTimeout.String()},
		{Name: "GATE_TOLERANCE", Value: strconv.FormatFloat(gateTolerance, 'f', -1, 64)},
		{Name: "STALE_AFTER", Value: staleAfter.String()},
		{Name: "EWMA_ALPHA", Value: strconv.FormatFloat(ewmaAlpha, 'f', -1, 64)},
		{Name: "QUEUE_SIZE", Value: strconv.Itoa(queueSize)},
		{Name: "QUEUE_WORKERS", Value: strconv.Itoa(queueWorkers)},
		{Name: "ANALYSIS_TIMEOUT", Value: analysisTimeout.String()},
		{Name: "BLOCKLIST_CONSENSUS_INTERVAL", Value: consensusInterval.String()},
		{Name: "BLOCKLIST_WINDOW", Value: blocklistWindow.String()},
		{Name: "BLOCKLIST_MIN_SYSTEMS", Value: strconv.Itoa(blocklistMinSystems)},
		{Name: "BLOCKLIST_TTL", Value: blocklistTTL.String()},
		{Name: "BLOCKLIST_MAX_ENTRIES", Value: strconv.Itoa(blocklistMaxEntries)},
		{Name: "THREAT_EVENT_RETENTION", Value: threatRetention.String()},
		{Name: "THREAT_MAX_DECISIONS_PER_REQUEST", Value: strconv.Itoa(threatMaxDecisions)},
	}

	// BuildInfo reads runtime/debug once here, not per request.
	uiServer := newUIServer(uiListenAddr, s, q, snapshot, ui.Info{
		StartedAt: startedAt,
		Workers:   queueWorkers,
		Build:     ui.BuildInfo(),
		Config:    cfgItems,
	})

	// NEVER log the API key, the pepper, or any credential.
	slog.Info("starting insightsd", "listen_addr", listenAddr, "ui_listen_addr", uiListenAddr,
		"model", llmModel, "db_path", dbPath,
		"log_level", logLevel, "queue_size", queueSize, "queue_workers", queueWorkers,
		"auth_validate_url", authValidateURL)
	slog.Debug("configuration",
		"llm_base_url", llmBaseURL,
		"llm_timeout", llmTimeout.String(),
		"analysis_timeout", analysisTimeout.String(),
		"llm_api_key_set", llmAPIKey != "",
		"auth_validate_url", authValidateURL,
		"auth_cache_ttl", authCacheTTL.String(),
		"auth_neg_cache_ttl", authNegCacheTTL.String(),
		"auth_timeout", authTimeout.String(),
		"gate_tolerance", gateTolerance,
		"stale_after", staleAfter.String(),
		"ewma_alpha", ewmaAlpha,
		"price_input_per_mtok", priceInput,
		"price_output_per_mtok", priceOutput,
	)

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

	// The consensus loop is started after the listeners so a slow first pass
	// cannot delay readiness. The first pass runs immediately rather than one
	// interval in, so a restart does not leave the feed answering 503 for five
	// minutes with a database full of promoted entries.
	consensusCtx, stopConsensus := context.WithCancel(context.Background())
	consensusDone := runConsensusLoop(consensusCtx, consensus, consensusInterval)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	slog.Info("shutting down", "queue_depth", q.Depth())
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

	// Stop accepting first, then drain: every queued bundle was already
	// acknowledged to an edge that will not send it again.
	q.Stop()
	slog.Info("queue drained")

	// The consensus loop holds no acknowledged work -- a cancelled pass just
	// leaves the previous snapshot in place -- so it is stopped last and
	// simply waited on.
	stopConsensus()
	<-consensusDone
	slog.Info("consensus loop stopped")
}

// runConsensusLoop runs a pass immediately and then every interval until ctx
// is cancelled. A failed pass is logged and the loop continues: the snapshot
// it did not replace keeps being served, which is the designed degradation.
func runConsensusLoop(ctx context.Context, r *blocklist.Runner, interval time.Duration) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if err := r.Run(ctx, time.Now().UnixMilli()); err != nil && ctx.Err() == nil {
				slog.Error("blocklist consensus pass failed", "error", err)
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
