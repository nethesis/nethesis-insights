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
	"errors"
	"fmt"
	"log/slog"
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
	"github.com/nethesis/nethesis-insights/internal/platform/ingestq"
	"github.com/nethesis/nethesis-insights/internal/platform/metrics"
	"github.com/nethesis/nethesis-insights/internal/platform/svc"
	threatstore "github.com/nethesis/nethesis-insights/internal/store/threat"
	"github.com/nethesis/nethesis-insights/internal/threat"
	"github.com/nethesis/nethesis-insights/internal/ui/chrome"
	threatui "github.com/nethesis/nethesis-insights/internal/ui/threat"
)

// newUIServer builds threatd's operator UI listener, or nil when
// UI_LISTEN_ADDR is empty -- the UI is off unless an operator explicitly
// turns it on.
func newUIServer(addr, basePath string, r threatui.Reader, feed threatui.Feed, w threatui.Writer, rt threatui.Runtime, adminKey string, info chrome.Info) *http.Server {
	if addr == "" {
		return nil
	}
	handler, err := threatui.NewServer(r, feed, w, rt, chrome.Config{
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

// ingestLimits is every threatd setting outside blocklist.Config that must
// also be positive to start safely: the ingest queue's bounds and the two
// per-request caps. Grouped only so validateConfig takes one extra parameter
// instead of five.
type ingestLimits struct {
	QueueSize             int
	QueueWorkers          int
	QueueTimeout          time.Duration
	MaxDecisions          int
	MaxAllowlistPerSystem int
}

// validateConfig refuses a Threat Shield configuration threatd must not run
// with. Every problem is reported at once, each naming its variable, so the
// line in systemctl status says what to fix. It no longer covers only the
// consensus pass: the ingest queue and the two per-request caps have no
// floor of their own, and a zero or negative value there loses data as
// silently as a bad consensus setting does.
func validateConfig(cfg blocklist.Config, interval time.Duration, limits ingestLimits) error {
	var errs []error
	if interval <= 0 {
		// time.NewTicker panics on it: a crash loop under Restart=always.
		errs = append(errs, fmt.Errorf("BLOCKLIST_CONSENSUS_INTERVAL must be positive, got %s", interval))
	}
	if cfg.MinSystems < blocklist.MinSystemsFloor {
		errs = append(errs, fmt.Errorf("BLOCKLIST_MIN_SYSTEMS must be at least %d, got %d", blocklist.MinSystemsFloor, cfg.MinSystems))
	}
	if cfg.Window <= 0 {
		errs = append(errs, fmt.Errorf("BLOCKLIST_WINDOW must be positive, got %s", cfg.Window))
	}
	if interval > 0 && cfg.Window > 0 && interval > cfg.Window {
		// A pass counts ConsensusCandidates(now - Window); a sighting that
		// both lands and ages out of the window between two passes is never
		// seen by any of them. Equal is fine -- every sighting is still
		// inside the window for at least one pass.
		errs = append(errs, fmt.Errorf("BLOCKLIST_CONSENSUS_INTERVAL (%s) must not exceed BLOCKLIST_WINDOW (%s)", interval, cfg.Window))
	}
	if cfg.TTL < cfg.Window {
		// A listing expires TTL after its last sighting, which is inside the
		// window: a shorter TTL writes an entry already expired.
		errs = append(errs, fmt.Errorf("BLOCKLIST_TTL (%s) must be at least BLOCKLIST_WINDOW (%s)", cfg.TTL, cfg.Window))
	}
	if cfg.MaxEntries <= 0 {
		errs = append(errs, fmt.Errorf("BLOCKLIST_MAX_ENTRIES must be positive, got %d", cfg.MaxEntries))
	}
	if cfg.Retention < cfg.Window {
		// Events pruned before the window closes are never counted.
		errs = append(errs, fmt.Errorf("THREAT_EVENT_RETENTION (%s) must be at least BLOCKLIST_WINDOW (%s)", cfg.Retention, cfg.Window))
	}
	if cfg.AllowlistRequestRetention <= 0 {
		errs = append(errs, fmt.Errorf("THREAT_ALLOWLIST_REQUEST_RETENTION must be positive, got %s", cfg.AllowlistRequestRetention))
	}
	if cfg.IngestRetention <= 0 {
		errs = append(errs, fmt.Errorf("THREAT_INGEST_RETENTION must be positive, got %s", cfg.IngestRetention))
	}
	if limits.QueueSize <= 0 {
		errs = append(errs, fmt.Errorf("THREAT_QUEUE_SIZE must be positive, got %d", limits.QueueSize))
	}
	if limits.QueueWorkers <= 0 {
		errs = append(errs, fmt.Errorf("THREAT_QUEUE_WORKERS must be positive, got %d", limits.QueueWorkers))
	}
	if limits.QueueTimeout <= 0 {
		// ingestq.process calls context.WithTimeout(bg, limits.QueueTimeout):
		// zero or negative makes every queued write fail immediately, after
		// the reporter has already been told 202.
		errs = append(errs, fmt.Errorf("THREAT_QUEUE_TIMEOUT must be positive, got %s", limits.QueueTimeout))
	}
	if limits.MaxDecisions <= 0 {
		errs = append(errs, fmt.Errorf("THREAT_MAX_DECISIONS_PER_REQUEST must be positive, got %d", limits.MaxDecisions))
	}
	if limits.MaxAllowlistPerSystem <= 0 {
		// Silently disables the per-system review-queue cap rather than
		// refusing requests past it.
		errs = append(errs, fmt.Errorf("THREAT_MAX_ALLOWLIST_REQUESTS_PER_SYSTEM must be positive, got %d", limits.MaxAllowlistPerSystem))
	}
	return errors.Join(errs...)
}

// loadStartupConfig reads every one of threatd's numeric and duration
// settings with the strict svc.Getenv* variants and then range-checks the
// result with validateConfig. A set-but-unparseable value -- e.g.
// THREAT_EVENT_RETENTION=30d, which time.ParseDuration rejects -- is
// collected as an error exactly like an in-range check that fails, so a
// startup with several problems reports all of them in one error instead of
// only the first one found or, worse, silently running on whichever
// defaults the bad values happened to fall back to.
func loadStartupConfig() (blocklist.Config, time.Duration, ingestLimits, error) {
	var errs []error
	add := func(err error) { errs = append(errs, err) }

	// Threat Shield. Every one has a default, so an existing deployment
	// picks the pipeline up without being reconfigured.
	consensusInterval, err := svc.GetenvDurationStrict("BLOCKLIST_CONSENSUS_INTERVAL", 5*time.Minute)
	add(err)
	blocklistWindow, err := svc.GetenvDurationStrict("BLOCKLIST_WINDOW", time.Hour)
	add(err)
	blocklistMinSystems, err := svc.GetenvIntStrict("BLOCKLIST_MIN_SYSTEMS", 3)
	add(err)
	blocklistTTL, err := svc.GetenvDurationStrict("BLOCKLIST_TTL", 24*time.Hour)
	add(err)
	blocklistMaxEntries, err := svc.GetenvIntStrict("BLOCKLIST_MAX_ENTRIES", 50000)
	add(err)
	threatRetention, err := svc.GetenvDurationStrict("THREAT_EVENT_RETENTION", 168*time.Hour)
	add(err)
	threatMaxDecisions, err := svc.GetenvIntStrict("THREAT_MAX_DECISIONS_PER_REQUEST", threat.DefaultMaxDecisions)
	add(err)
	// The review queue's two bounds. A client allowlist request is a
	// permanent row that only a human decision ever deletes, so without
	// these the table grows for the life of the deployment and the review
	// queue reads it. 25 distinct pending CIDRs is far more than a customer
	// with a real exemption to ask for ever needs; 90 days is long enough
	// that a queue nobody has looked at in a quarter is the actual problem,
	// and a pruned ask can simply be made again.
	allowlistMaxPerSystem, err := svc.GetenvIntStrict("THREAT_MAX_ALLOWLIST_REQUESTS_PER_SYSTEM", 25)
	add(err)
	allowlistRequestRetention, err := svc.GetenvDurationStrict("THREAT_ALLOWLIST_REQUEST_RETENTION", 2160*time.Hour)
	add(err)
	// 90 days, long enough that a node that has gone quiet still shows up on
	// /systems for a quarter, well past THREAT_EVENT_RETENTION's default
	// week -- ListThreatSystems is driven by this table, not threat_events.
	threatIngestRetention, err := svc.GetenvDurationStrict("THREAT_INGEST_RETENTION", 2160*time.Hour)
	add(err)

	// The ingest queue. It does not make the writes serial -- SetMaxOpenConns(1)
	// plus the store's write mutex already do that -- it bounds how many
	// decoded, sanitized reports can be waiting on that single writer at once,
	// so a burst of reporters sheds load at the edge with a 503 instead of
	// growing the process until it dies.
	threatQueueSize, err := svc.GetenvIntStrict("THREAT_QUEUE_SIZE", 256)
	add(err)
	threatQueueWorkers, err := svc.GetenvIntStrict("THREAT_QUEUE_WORKERS", 2)
	add(err)
	threatQueueTimeout, err := svc.GetenvDurationStrict("THREAT_QUEUE_TIMEOUT", 30*time.Second)
	add(err)

	cfg := blocklist.Config{
		Window:     blocklistWindow,
		MinSystems: blocklistMinSystems,
		TTL:        blocklistTTL,
		MaxEntries: blocklistMaxEntries,
		Retention:  threatRetention,

		IngestRetention:           threatIngestRetention,
		AllowlistRequestRetention: allowlistRequestRetention,
	}
	limits := ingestLimits{
		QueueSize:             threatQueueSize,
		QueueWorkers:          threatQueueWorkers,
		QueueTimeout:          threatQueueTimeout,
		MaxDecisions:          threatMaxDecisions,
		MaxAllowlistPerSystem: allowlistMaxPerSystem,
	}
	add(validateConfig(cfg, consensusInterval, limits))
	return cfg, consensusInterval, limits, errors.Join(errs...)
}

func main() {
	startedAt := time.Now().UnixMilli()

	logLevel := svc.Getenv("LOG_LEVEL", "info")
	svc.SetupLogger(logLevel)

	listenAddr := svc.Getenv("LISTEN_ADDR", ":9595")
	// Empty by default: the operator UI is unauthenticated and fleet-wide, so
	// enabling it is one explicit operator act, never a default.
	uiListenAddr := svc.Getenv("UI_LISTEN_ADDR", "")
	uiBasePath := svc.Getenv("UI_BASE_PATH", "")
	dbPath := svc.Getenv("DB_PATH", "/var/lib/threat/threat.db")
	trustedProxyCIDRs := svc.Getenv("TRUSTED_PROXY_CIDRS", "127.0.0.0/8")
	// Off by default: writing the allowlist is the one operation that can
	// stop the fleet blocking an address, so it stays off until an operator
	// turns it on explicitly.
	adminAPIKey := svc.Getenv("ADMIN_API_KEY", "")

	consensusCfg, consensusInterval, limits, err := loadStartupConfig()
	if err != nil {
		slog.Error("invalid Threat Shield configuration", "error", err)
		os.Exit(1)
	}

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
	defer func() { _ = s.Close() }()

	ctx := context.Background()
	if err := s.Init(ctx); err != nil {
		slog.Error("failed to init store", "error", err)
		os.Exit(1)
	}

	// One registry for the whole process: /metrics on the API mux exposes
	// everything registered into it. consensusName is named once and
	// used twice -- to pre-create the pass metrics' children at 0 and to tag
	// the loop itself -- so the metric and the log line cannot disagree.
	const consensusName = "blocklist consensus"
	// The service name prefixes every metric this package defines
	// (threatd_http_requests_total, ...); the standard go_*/process_*
	// collectors deliberately stay unprefixed.
	reg := metrics.NewRegistry("threatd")
	httpMetrics := metrics.NewHTTP(reg)
	passMetrics := metrics.NewPass(reg, consensusName)
	ingestFullMetrics := metrics.NewIngestQueueFull(reg)

	// Threat Shield's consensus pass: no LLM, no gate, no fingerprint.
	snapshot := blocklist.NewSnapshot()
	consensus := blocklist.New(s, snapshot, consensusCfg)

	// The queue's handler is bound to the store here, before either the queue
	// or the API server exists: the queue's handler must be fixed at
	// construction, and NewServer takes the already-built queue as a
	// parameter, so this is the one order that works.
	ingestQueue := ingestq.New(limits.QueueSize, limits.QueueTimeout, threatapi.NewConsumer(s))
	ingestQueue.Metrics = &ingestq.Metrics{Full: ingestFullMetrics.Counter("threat_events")}
	ingestQueue.Start(limits.QueueWorkers)
	metrics.RegisterQueueGauges(reg, "threat_events", ingestQueue.Depth, ingestQueue.Cap, ingestQueue.Workers)

	handler := threatapi.NewServer(s, ingestQueue, snapshot, trusted, threatapi.Config{
		MaxDecisions:               limits.MaxDecisions,
		MaxAllowlistRequestsPerSys: limits.MaxAllowlistPerSystem,
		MaxEventAge:                consensusCfg.Retention,
		Now:                        func() int64 { return time.Now().UnixMilli() },
	}, metrics.Handler(reg), httpMetrics)

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
		{Name: "ADMIN_API_KEY", Value: svc.SecretState(adminAPIKey != "")},
		{Name: "BLOCKLIST_CONSENSUS_INTERVAL", Value: consensusInterval.String()},
		{Name: "BLOCKLIST_WINDOW", Value: consensusCfg.Window.String()},
		{Name: "BLOCKLIST_MIN_SYSTEMS", Value: strconv.Itoa(consensusCfg.MinSystems)},
		{Name: "BLOCKLIST_TTL", Value: consensusCfg.TTL.String()},
		{Name: "BLOCKLIST_MAX_ENTRIES", Value: strconv.Itoa(consensusCfg.MaxEntries)},
		{Name: "THREAT_EVENT_RETENTION", Value: consensusCfg.Retention.String()},
		{Name: "THREAT_INGEST_RETENTION", Value: consensusCfg.IngestRetention.String()},
		{Name: "THREAT_MAX_DECISIONS_PER_REQUEST", Value: strconv.Itoa(limits.MaxDecisions)},
		{Name: "THREAT_MAX_ALLOWLIST_REQUESTS_PER_SYSTEM", Value: strconv.Itoa(limits.MaxAllowlistPerSystem)},
		{Name: "THREAT_ALLOWLIST_REQUEST_RETENTION", Value: consensusCfg.AllowlistRequestRetention.String()},
		{Name: "THREAT_QUEUE_SIZE", Value: strconv.Itoa(limits.QueueSize)},
		{Name: "THREAT_QUEUE_WORKERS", Value: strconv.Itoa(limits.QueueWorkers)},
		{Name: "THREAT_QUEUE_TIMEOUT", Value: limits.QueueTimeout.String()},
	}

	// s satisfies both threatui.Reader and threatui.Writer; the write routes
	// are reachable only when adminAPIKey is non-empty (chrome.CanWrite), so
	// wiring the writer unconditionally is safe -- an operator who has not
	// set ADMIN_API_KEY still gets the plain read-only dashboard. ingestQueue
	// satisfies threatui.Runtime (Depth/Cap/Workers), the same shape
	// insightsd's queue already reports through logsui.Runtime.
	uiServer := newUIServer(uiListenAddr, uiBasePath, s, snapshot, s, ingestQueue, adminAPIKey, chrome.Info{
		StartedAt: startedAt,
		Build:     chrome.BuildInfo(),
		Config:    cfgItems,
	})

	// NEVER log the API key or any credential.
	slog.Info("starting threatd", "listen_addr", listenAddr, "ui_listen_addr", uiListenAddr,
		"db_path", dbPath, "log_level", logLevel, "trusted_proxy_cidrs", trustedProxyCIDRs,
		"queue_size", limits.QueueSize, "queue_workers", limits.QueueWorkers)

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("http server error", "error", err)
			os.Exit(1)
		}
	}()

	if uiServer != nil {
		svc.WarnIfNotLoopback(uiListenAddr)
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
	consensusDone := svc.RunPassLoop(consensusCtx, consensusName, consensus, consensusInterval, passMetrics)

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

	// Stop accepting first, then drain: every queued report was already
	// acknowledged to a reporter that will not send it again.
	ingestQueue.Stop()
	slog.Info("ingest queue drained")

	// The consensus loop holds no acknowledged work -- a cancelled pass just
	// leaves the previous snapshot in place -- so it is stopped last and
	// simply waited on.
	stopConsensus()
	<-consensusDone
	slog.Info("consensus loop stopped")
}
