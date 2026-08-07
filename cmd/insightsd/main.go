// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/nethesis/nethesis-insights/internal/analyzer"
	"github.com/nethesis/nethesis-insights/internal/api"
	"github.com/nethesis/nethesis-insights/internal/llm"
	"github.com/nethesis/nethesis-insights/internal/queue"
	"github.com/nethesis/nethesis-insights/internal/store"
)

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

func main() {
	logLevel := getenv("LOG_LEVEL", "info")
	setupLogger(logLevel)

	listenAddr := getenv("LISTEN_ADDR", ":9595")
	dbPath := getenv("DB_PATH", "/var/lib/insights/insights.db")
	llmBaseURL := getenv("LLM_BASE_URL", "")
	llmModel := getenv("LLM_MODEL", "")
	llmAPIKey := getenv("LLM_API_KEY", "")
	authSystemID := getenv("AUTH_SYSTEM_ID", "")
	authSecret := getenv("AUTH_SECRET", "")
	gateTolerance := getenvFloat("GATE_TOLERANCE", 3.0)
	staleAfter := getenvDuration("STALE_AFTER", 24*time.Hour)
	ewmaAlpha := getenvFloat("EWMA_ALPHA", 0.3)
	priceInput := getenvFloat("LLM_PRICE_INPUT_PER_MTOK", 0)
	priceOutput := getenvFloat("LLM_PRICE_OUTPUT_PER_MTOK", 0)
	llmTimeout := getenvDuration("LLM_TIMEOUT", 120*time.Second)
	queueSize := getenvInt("QUEUE_SIZE", 256)
	queueWorkers := getenvInt("QUEUE_WORKERS", 2)
	analysisTimeout := getenvDuration("ANALYSIS_TIMEOUT", 5*time.Minute)

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

	auth := api.StaticAuth{SystemID: authSystemID, Secret: authSecret}
	handler := api.NewServer(q, s, auth)

	httpServer := &http.Server{
		Addr:    listenAddr,
		Handler: handler,
	}

	// NEVER log the API key.
	slog.Info("starting insightsd", "listen_addr", listenAddr, "model", llmModel, "db_path", dbPath,
		"log_level", logLevel, "queue_size", queueSize, "queue_workers", queueWorkers)
	slog.Debug("configuration",
		"llm_base_url", llmBaseURL,
		"llm_timeout", llmTimeout.String(),
		"analysis_timeout", analysisTimeout.String(),
		"llm_api_key_set", llmAPIKey != "",
		"auth_system_id", authSystemID,
		"auth_secret_set", authSecret != "",
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

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	slog.Info("shutting down", "queue_depth", q.Depth())
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("graceful shutdown failed", "error", err)
	}

	// Stop accepting first, then drain: every queued bundle was already
	// acknowledged to an edge that will not send it again.
	q.Stop()
	slog.Info("queue drained")
}
