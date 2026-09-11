// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Command authd validates edge credentials on behalf of the proxy.
//
// Traefik has no cache of its own, and internal/platform/auth's doc comment
// explains why one is mandatory rather than an optimization: at fleet scale
// an uncached forwardAuth is one upstream call per bundle for credentials
// that essentially never change. Running the cache as its own service also
// means one cache serves all three pipelines instead of three.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/nethesis/nethesis-insights/internal/platform/auth"
	"github.com/nethesis/nethesis-insights/internal/platform/metrics"
)

const defaultAuthValidateURL = "https://my.nethesis.it/auth"

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
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

func getenvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// setupLogging honours LOG_LEVEL=debug|info|warn|error. Debug adds the
// request detail needed to explain a rejected or slow request; it never
// adds credentials.
func setupLogging(level string) {
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

// resolvePepper decides the forward-auth pepper the way main() used to
// inline: AUTH_PEPPER verbatim when set, otherwise a fresh randomPepper()
// for this process's lifetime. It takes getenv as a parameter -- rather than
// calling the package-level getenv directly, as main()'s other settings do
// -- purely so a test can supply a fake without mutating the real
// environment; production code always calls it as resolvePepper(getenv).
//
// A pepper is only defense in depth -- the cache it keys never leaves
// memory -- so an unset AUTH_PEPPER gets a random one rather than refusing
// to start. But it must never default to empty: with an empty HMAC key the
// cache key is computable offline by anyone, and after the pipeline split
// this process holds the whole fleet's credential cache. The two source
// values ("configured", "ephemeral") are logged and reported in the
// effective-config output; preserve them verbatim.
func resolvePepper(getenv func(string, string) string) (pepper, source string) {
	if p := getenv("AUTH_PEPPER", ""); p != "" {
		return p, "configured"
	}
	return randomPepper(), "ephemeral"
}

func main() {
	setupLogging(getenv("LOG_LEVEL", "info"))

	listenAddr := getenv("AUTH_LISTEN_ADDR", ":9590")
	validateURL := getenv("AUTH_VALIDATE_URL", defaultAuthValidateURL)
	timeout := getenvDuration("AUTH_TIMEOUT", 5*time.Second)

	pepper, pepperSource := resolvePepper(getenv)
	if pepperSource == "ephemeral" {
		slog.Info("AUTH_PEPPER not set, generated an ephemeral one for this process")
	}

	fa := auth.New(validateURL, pepper, timeout, time.Now)
	fa.PositiveTTL = getenvDuration("AUTH_CACHE_TTL", 5*time.Minute)
	fa.NegativeTTL = getenvDuration("AUTH_NEG_CACHE_TTL", 30*time.Second)
	// Bounding the cache is not tuning: unbounded, every distinct wrong
	// credential is a permanent entry, so anyone who can reach the proxy
	// can grow this process until the box kills it.
	fa.MaxPositiveEntries = getenvInt("AUTH_CACHE_MAX_ENTRIES", fa.MaxPositiveEntries)
	fa.MaxNegativeEntries = getenvInt("AUTH_NEG_CACHE_MAX_ENTRIES", fa.MaxNegativeEntries)

	// One registry for the whole process: /metrics on the mux exposes
	// everything registered into it, standard Go collectors plus the
	// forward-auth cache/upstream counters wired in below.
	// The upstream vocabulary comes from internal/platform/auth, the package
	// that produces it, so each outcome's child is pre-created at 0 -- an
	// alert on authd_upstream_results_total{result="unavailable"} must
	// evaluate against a real zero on a fresh process, not no data.
	// The service name prefixes every metric this package defines
	// (authd_http_requests_total, ...); the standard go_*/process_*
	// collectors deliberately stay unprefixed.
	reg := metrics.NewRegistry("authd")
	httpMetrics := metrics.NewHTTP(reg)
	authMetrics := metrics.NewAuth(reg,
		auth.UpstreamValid, auth.UpstreamInvalid, auth.UpstreamUnavailable)
	fa.Metrics = &auth.Metrics{
		CacheHit:  authMetrics.CacheHit,
		CacheMiss: authMetrics.CacheMiss,
		Upstream:  authMetrics.Upstream,
	}

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           newHandler(fa, metrics.Handler(reg), httpMetrics),
		ReadHeaderTimeout: 10 * time.Second,
	}

	slog.Info("authd: listening",
		"addr", listenAddr,
		"validate_url", validateURL,
		"pepper", pepperSource,
		"positive_ttl", fa.PositiveTTL,
		"negative_ttl", fa.NegativeTTL,
		"max_positive_entries", fa.MaxPositiveEntries,
		"max_negative_entries", fa.MaxNegativeEntries)

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("authd: listen", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("authd: shutdown", "err", err)
	}
}
