// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// scrapeRegistry runs h (a Handler(reg)) and returns the exposition body --
// the "does the endpoint expose the expected metric names" assertion every
// constructor in this package needs.
func scrapeRegistry(t *testing.T, h http.Handler) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	return w.Body.String()
}

// A fresh registry must expose the standard Go runtime/process collectors --
// the whole reason NewRegistry exists rather than a bare
// prometheus.NewRegistry() at every call site.
func TestHandlerExposesStandardCollectors(t *testing.T) {
	reg := NewRegistry()
	body := scrapeRegistry(t, Handler(reg))

	for _, want := range []string{"go_goroutines", "go_memstats_alloc_bytes", "process_start_time_seconds"} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape body missing %q", want)
		}
	}
}

func TestHTTPObserveExposesRequestsAndDuration(t *testing.T) {
	reg := NewRegistry()
	h := NewHTTP(reg)
	h.Observe("GET", "/v1/findings", 200, 42*time.Millisecond)

	body := scrapeRegistry(t, Handler(reg))
	for _, want := range []string{
		`http_requests_total{method="GET",route="/v1/findings",status="200"} 1`,
		"http_request_duration_seconds_bucket",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape body missing %q\nbody:\n%s", want, body)
		}
	}
}

func TestRegisterQueueGaugesReflectsLiveAccessors(t *testing.T) {
	reg := NewRegistry()
	depth, capacity, workers := 3, 10, 2
	RegisterQueueGauges(reg, "bundle",
		func() int { return depth },
		func() int { return capacity },
		func() int { return workers },
	)

	body := scrapeRegistry(t, Handler(reg))
	for _, want := range []string{
		`queue_depth{queue="bundle"} 3`,
		`queue_capacity{queue="bundle"} 10`,
		`queue_workers{queue="bundle"} 2`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape body missing %q\nbody:\n%s", want, body)
		}
	}

	// GaugeFunc reads live at scrape time: change the backing value with no
	// re-registration and the next scrape must reflect it.
	depth = 7
	body = scrapeRegistry(t, Handler(reg))
	if !strings.Contains(body, `queue_depth{queue="bundle"} 7`) {
		t.Errorf("scrape body did not reflect the updated depth\nbody:\n%s", body)
	}
}

func TestLLMCallRecordsResultAndCost(t *testing.T) {
	reg := NewRegistry()
	l := NewLLM(reg)
	l.Call(LLMResultSuccess, 1500)
	l.Call(LLMResultTransient, 0)
	l.Call(LLMResultPermanent, 0)
	l.Call(LLMResultParse, 0)

	body := scrapeRegistry(t, Handler(reg))
	for _, want := range []string{
		`llm_calls_total{result="success"} 1`,
		`llm_calls_total{result="transient"} 1`,
		`llm_calls_total{result="permanent"} 1`,
		`llm_calls_total{result="parse"} 1`,
		`llm_cost_micros_total 1500`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape body missing %q\nbody:\n%s", want, body)
		}
	}
}

func TestBudgetRejectedRecordsReason(t *testing.T) {
	reg := NewRegistry()
	b := NewBudget(reg, "system_call_cap")
	b.Rejected("system_call_cap")
	b.Rejected("system_call_cap")

	body := scrapeRegistry(t, Handler(reg))
	if !strings.Contains(body, `budget_rejections_total{reason="system_call_cap"} 2`) {
		t.Errorf("scrape body missing the expected counter\nbody:\n%s", body)
	}
}

func TestPassObserveRecordsRunsDurationAndLastSuccess(t *testing.T) {
	reg := NewRegistry()
	p := NewPass(reg, "blocklist consensus")

	p.Observe("blocklist consensus", nil, 250*time.Millisecond, 1_700_000_000_000)
	body := scrapeRegistry(t, Handler(reg))
	for _, want := range []string{
		`pass_runs_total{pass="blocklist consensus",result="success"} 1`,
		`pass_last_success_timestamp_seconds{pass="blocklist consensus"} 1.7e+09`,
		"pass_duration_seconds_bucket",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape body missing %q\nbody:\n%s", want, body)
		}
	}

	p.Observe("blocklist consensus", errTest{}, 10*time.Millisecond, 1_700_000_001_000)
	body = scrapeRegistry(t, Handler(reg))
	if !strings.Contains(body, `pass_runs_total{pass="blocklist consensus",result="failure"} 1`) {
		t.Errorf("scrape body missing the failure counter\nbody:\n%s", body)
	}
	// A failed run must not advance the last-success gauge.
	if !strings.Contains(body, `pass_last_success_timestamp_seconds{pass="blocklist consensus"} 1.7e+09`) {
		t.Errorf("last-success gauge moved on a failed run\nbody:\n%s", body)
	}
}

type errTest struct{}

func (errTest) Error() string { return "boom" }

func TestAuthCacheAndUpstreamResults(t *testing.T) {
	reg := NewRegistry()
	a := NewAuth(reg, "valid", "invalid", "unavailable")
	a.CacheHit()
	a.CacheHit()
	a.CacheMiss()
	a.Upstream("valid")
	a.Upstream("unavailable")

	body := scrapeRegistry(t, Handler(reg))
	for _, want := range []string{
		`auth_cache_results_total{result="hit"} 2`,
		`auth_cache_results_total{result="miss"} 1`,
		`auth_upstream_results_total{result="valid"} 1`,
		`auth_upstream_results_total{result="unavailable"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape body missing %q\nbody:\n%s", want, body)
		}
	}
}

// A prometheus CounterVec creates a child only on the first
// WithLabelValues call, and a family with no children is absent from the
// scrape output entirely -- no HELP, no TYPE, no series. An alert like
// `rate(llm_calls_total{result="permanent"}[5m]) > 0` then evaluates
// against NO DATA rather than 0 on a freshly restarted process, so it never
// fires until the first permanent error has already happened.
//
// This is the regression test for that: every enumerable child must be
// present at 0 before anything is ever recorded.
func TestEnumerableChildrenArePreCreatedAtZero(t *testing.T) {
	reg := NewRegistry()

	NewLLM(reg)
	NewBudget(reg, "system_call_cap")
	NewAuth(reg, "valid", "invalid", "unavailable")
	NewPass(reg, "blocklist consensus")
	NewIngestQueueFull(reg).Counter("threat_events")

	// Nothing is recorded: no Call, no Rejected, no CacheHit, no Observe,
	// no queue saturation. Every series below must still be exported.
	body := scrapeRegistry(t, Handler(reg))

	want := []string{
		`llm_calls_total{result="success"} 0`,
		`llm_calls_total{result="transient"} 0`,
		`llm_calls_total{result="permanent"} 0`,
		`llm_calls_total{result="parse"} 0`,
		`llm_cost_micros_total 0`,
		`budget_rejections_total{reason="system_call_cap"} 0`,
		`auth_cache_results_total{result="hit"} 0`,
		`auth_cache_results_total{result="miss"} 0`,
		`auth_upstream_results_total{result="valid"} 0`,
		`auth_upstream_results_total{result="invalid"} 0`,
		`auth_upstream_results_total{result="unavailable"} 0`,
		`pass_runs_total{pass="blocklist consensus",result="success"} 0`,
		`pass_runs_total{pass="blocklist consensus",result="failure"} 0`,
		`ingestq_full_total{queue="threat_events"} 0`,
	}
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("series absent before its first event: %q\nbody:\n%s", w, body)
		}
	}

	// The HELP/TYPE header is what a dashboard's metric browser reads, and
	// it too only appears once a family has a child.
	for _, family := range []string{
		"llm_calls_total", "budget_rejections_total",
		"auth_cache_results_total", "auth_upstream_results_total",
		"pass_runs_total", "ingestq_full_total",
	} {
		if !strings.Contains(body, "# TYPE "+family) {
			t.Errorf("family %q has no TYPE line before its first event", family)
		}
	}
}

// The last-success gauge is the one thing that must NOT be pre-created: a
// zero reads as "last succeeded at the Unix epoch", so a staleness alert
// (`time() - pass_last_success_timestamp_seconds > 3600`) would fire
// immediately on every restart. Absent is the honest representation of "has
// not succeeded yet".
func TestPassLastSuccessIsAbsentUntilAPassSucceeds(t *testing.T) {
	reg := NewRegistry()
	p := NewPass(reg, "sizing cohort")

	body := scrapeRegistry(t, Handler(reg))
	if strings.Contains(body, "pass_last_success_timestamp_seconds") {
		t.Fatalf("last-success gauge exported before any pass succeeded -- a 0 here "+
			"means 1970 to every staleness alert\nbody:\n%s", body)
	}

	// A FAILED run must not conjure it either.
	p.Observe("sizing cohort", errTest{}, time.Second, 1_700_000_000_000)
	body = scrapeRegistry(t, Handler(reg))
	if strings.Contains(body, "pass_last_success_timestamp_seconds") {
		t.Fatalf("last-success gauge exported after a FAILED run\nbody:\n%s", body)
	}

	// It appears only once a pass actually succeeds.
	p.Observe("sizing cohort", nil, time.Second, 1_700_000_000_000)
	body = scrapeRegistry(t, Handler(reg))
	if !strings.Contains(body, `pass_last_success_timestamp_seconds{pass="sizing cohort"} 1.7e+09`) {
		t.Fatalf("last-success gauge missing after a successful run\nbody:\n%s", body)
	}
}

// The HTTP families are deliberately left lazy: `status` and `method` are
// not closed sets, so pre-creating would invent series for combinations
// that can never occur. This pins that decision so nobody "fixes" the
// pre-creation rule into applying here too.
func TestHTTPFamiliesAreDeliberatelyNotPreCreated(t *testing.T) {
	reg := NewRegistry()
	h := NewHTTP(reg)

	body := scrapeRegistry(t, Handler(reg))
	if strings.Contains(body, "http_requests_total") {
		t.Errorf("http_requests_total exported before any request -- (method, route, "+
			"status) is not a closed set and must not be enumerated\nbody:\n%s", body)
	}

	h.Observe("GET", "/v1/findings", 200, time.Millisecond)
	body = scrapeRegistry(t, Handler(reg))
	if !strings.Contains(body, `http_requests_total{method="GET",route="/v1/findings",status="200"} 1`) {
		t.Errorf("http_requests_total missing after a request\nbody:\n%s", body)
	}
}

func TestIngestQueueFullCounterIsPerQueue(t *testing.T) {
	reg := NewRegistry()
	m := NewIngestQueueFull(reg)
	incThreat := m.Counter("threat_events")
	incThreat()
	incThreat()

	body := scrapeRegistry(t, Handler(reg))
	if !strings.Contains(body, `ingestq_full_total{queue="threat_events"} 2`) {
		t.Errorf("scrape body missing the expected counter\nbody:\n%s", body)
	}
}
