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

// setOrUnset reduces a secret to its mere presence. The status log gets
// this, never the value.
func setOrUnset(v string) string {
	if v != "" {
		return "set"
	}
	return "unset"
}

func main() {
	setupLogging(getenv("LOG_LEVEL", "info"))

	listenAddr := getenv("AUTH_LISTEN_ADDR", ":9590")
	validateURL := getenv("AUTH_VALIDATE_URL", defaultAuthValidateURL)
	pepper := getenv("AUTH_PEPPER", "")
	timeout := getenvDuration("AUTH_TIMEOUT", 5*time.Second)

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
		"pepper", setOrUnset(pepper),
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
