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
	"syscall"
	"time"

	"github.com/nethesis/nethesis-insights/internal/platform/auth"
)

const defaultAuthValidateURL = "https://my.nethesis.it/auth"

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

func main() {
	setupLogging(getenv("LOG_LEVEL", "info"))

	listenAddr := getenv("AUTH_LISTEN_ADDR", ":9590")
	validateURL := getenv("AUTH_VALIDATE_URL", defaultAuthValidateURL)
	pepper := getenv("AUTH_PEPPER", "")
	timeout := getenvDuration("AUTH_TIMEOUT", 5*time.Second)

	pepperSource := "configured"
	if pepper == "" {
		// A pepper is only defense in depth -- the cache it keys never
		// leaves memory -- so an unset AUTH_PEPPER gets a random one for
		// this process's lifetime rather than refusing to start. But it
		// must never default to empty: with an empty HMAC key the cache
		// key is computable offline by anyone, and after the pipeline
		// split this process holds the whole fleet's credential cache.
		pepper = randomPepper()
		pepperSource = "ephemeral"
		slog.Info("AUTH_PEPPER not set, generated an ephemeral one for this process")
	}

	fa := auth.New(validateURL, pepper, timeout, time.Now)
	fa.PositiveTTL = getenvDuration("AUTH_CACHE_TTL", 5*time.Minute)
	fa.NegativeTTL = getenvDuration("AUTH_NEG_CACHE_TTL", 30*time.Second)

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           newHandler(fa),
		ReadHeaderTimeout: 10 * time.Second,
	}

	slog.Info("authd: listening",
		"addr", listenAddr,
		"validate_url", validateURL,
		"pepper", pepperSource,
		"positive_ttl", fa.PositiveTTL,
		"negative_ttl", fa.NegativeTTL)

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
