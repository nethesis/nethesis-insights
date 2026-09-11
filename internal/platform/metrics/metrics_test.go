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

// testService is the service name every test registry is built with, and
// "svc_" is therefore the prefix every family this package defines carries
// in the assertions below. A deliberately unreal name: the real ones are
// insightsd/threatd/sizingd/authd, and using one of those here would read
// as if this package knew which binary it was serving.
const testService = "svc"

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
	reg := NewRegistry(testService)
	body := scrapeRegistry(t, Handler(reg))

	for _, want := range []string{"go_goroutines", "go_memstats_alloc_bytes", "process_start_time_seconds"} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape body missing %q", want)
		}
	}
}

// The service prefix must reach everything this package defines and NOTHING
// else. The standard collectors keep their conventional names because every
// off-the-shelf Go/Grafana dashboard and every go_*-based alert rule queries
// those exact strings -- so a later refactor that "tidies up" by wrapping
// the whole registry, rather than only the registerer this package's
// constructors use, has to fail here.
func TestStandardCollectorsAreNotPrefixed(t *testing.T) {
	reg := NewRegistry(testService)
	// Register one of this package's own families too, so the test proves
	// the prefix is applied selectively rather than simply not applied.
	NewHTTP(reg)
	NewLLM(reg)

	body := scrapeRegistry(t, Handler(reg))

	for _, unprefixed := range []string{
		"go_goroutines",
		"go_memstats_alloc_bytes",
		"process_start_time_seconds",
		"process_resident_memory_bytes",
		"promhttp_metric_handler_errors_total",
	} {
		if !strings.Contains(body, unprefixed) {
			t.Errorf("standard collector %q missing entirely", unprefixed)
		}
		if prefixed := testService + "_" + unprefixed; strings.Contains(body, prefixed) {
			t.Errorf("standard collector was prefixed as %q -- go_*/process_*/promhttp_* "+
				"must keep their conventional names, or every stock dashboard and "+
				"go_*-based alert rule stops matching", prefixed)
		}
	}

	// The other half of the same rule: this package's own families must NOT
	// appear unprefixed.
	for _, mustBePrefixed := range []string{"llm_calls_total", "llm_cost_micros_total"} {
		if !strings.Contains(body, testService+"_"+mustBePrefixed) {
			t.Errorf("%q is missing its service prefix", mustBePrefixed)
		}
		// Search for the bare name at a line start, since the prefixed form
		// contains the bare name as a substring.
		for _, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(line, mustBePrefixed) {
				t.Errorf("%q exported unprefixed: %q", mustBePrefixed, line)
			}
		}
	}
}

func TestHTTPObserveExposesRequestsAndDuration(t *testing.T) {
	reg := NewRegistry(testService)
	h := NewHTTP(reg)
	h.Observe("GET", "/v1/findings", 200, 42*time.Millisecond)

	body := scrapeRegistry(t, Handler(reg))
	for _, want := range []string{
		`svc_http_requests_total{method="GET",route="/v1/findings",status="200"} 1`,
		"svc_http_request_duration_seconds_bucket",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape body missing %q\nbody:\n%s", want, body)
		}
	}
}

func TestRegisterQueueGaugesReflectsLiveAccessors(t *testing.T) {
	reg := NewRegistry(testService)
	depth, capacity, workers := 3, 10, 2
	RegisterQueueGauges(reg, "bundle",
		func() int { return depth },
		func() int { return capacity },
		func() int { return workers },
	)

	body := scrapeRegistry(t, Handler(reg))
	for _, want := range []string{
		`svc_queue_depth{queue="bundle"} 3`,
		`svc_queue_capacity{queue="bundle"} 10`,
		`svc_queue_workers{queue="bundle"} 2`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape body missing %q\nbody:\n%s", want, body)
		}
	}

	// GaugeFunc reads live at scrape time: change the backing value with no
	// re-registration and the next scrape must reflect it.
	depth = 7
	body = scrapeRegistry(t, Handler(reg))
	if !strings.Contains(body, `svc_queue_depth{queue="bundle"} 7`) {
		t.Errorf("scrape body did not reflect the updated depth\nbody:\n%s", body)
	}
}

func TestLLMCallRecordsResultAndCost(t *testing.T) {
	reg := NewRegistry(testService)
	l := NewLLM(reg)
	l.Call(LLMResultSuccess, 1500)
	l.Call(LLMResultTransient, 0)
	l.Call(LLMResultPermanent, 0)
	l.Call(LLMResultParse, 0)

	body := scrapeRegistry(t, Handler(reg))
	for _, want := range []string{
		`svc_llm_calls_total{result="success"} 1`,
		`svc_llm_calls_total{result="transient"} 1`,
		`svc_llm_calls_total{result="permanent"} 1`,
		`svc_llm_calls_total{result="parse"} 1`,
		`svc_llm_cost_micros_total 1500`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape body missing %q\nbody:\n%s", want, body)
		}
	}
}

func TestBudgetRejectedRecordsReason(t *testing.T) {
	reg := NewRegistry(testService)
	b := NewBudget(reg, "system_call_cap")
	b.Rejected("system_call_cap")
	b.Rejected("system_call_cap")

	body := scrapeRegistry(t, Handler(reg))
	if !strings.Contains(body, `svc_budget_rejections_total{reason="system_call_cap"} 2`) {
		t.Errorf("scrape body missing the expected counter\nbody:\n%s", body)
	}
}

func TestPassObserveRecordsRunsDurationAndLastSuccess(t *testing.T) {
	reg := NewRegistry(testService)
	p := NewPass(reg, "blocklist consensus")

	p.Observe("blocklist consensus", nil, 250*time.Millisecond, 1_700_000_000_000)
	body := scrapeRegistry(t, Handler(reg))
	for _, want := range []string{
		`svc_pass_runs_total{pass="blocklist consensus",result="success"} 1`,
		`svc_pass_last_success_timestamp_seconds{pass="blocklist consensus"} 1.7e+09`,
		"svc_pass_duration_seconds_bucket",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape body missing %q\nbody:\n%s", want, body)
		}
	}

	p.Observe("blocklist consensus", errTest{}, 10*time.Millisecond, 1_700_000_001_000)
	body = scrapeRegistry(t, Handler(reg))
	if !strings.Contains(body, `svc_pass_runs_total{pass="blocklist consensus",result="failure"} 1`) {
		t.Errorf("scrape body missing the failure counter\nbody:\n%s", body)
	}
	// A failed run must not advance the last-success gauge.
	if !strings.Contains(body, `svc_pass_last_success_timestamp_seconds{pass="blocklist consensus"} 1.7e+09`) {
		t.Errorf("last-success gauge moved on a failed run\nbody:\n%s", body)
	}
}

type errTest struct{}

func (errTest) Error() string { return "boom" }

func TestAuthCacheAndUpstreamResults(t *testing.T) {
	reg := NewRegistry(testService)
	a := NewAuth(reg, "valid", "invalid", "unavailable")
	a.CacheHit()
	a.CacheHit()
	a.CacheMiss()
	a.Upstream("valid")
	a.Upstream("unavailable")

	body := scrapeRegistry(t, Handler(reg))
	for _, want := range []string{
		`svc_cache_results_total{result="hit"} 2`,
		`svc_cache_results_total{result="miss"} 1`,
		`svc_upstream_results_total{result="valid"} 1`,
		`svc_upstream_results_total{result="unavailable"} 1`,
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
	reg := NewRegistry(testService)

	NewLLM(reg)
	NewBudget(reg, "system_call_cap")
	NewAuth(reg, "valid", "invalid", "unavailable")
	NewPass(reg, "blocklist consensus")
	NewIngestQueueFull(reg).Counter("threat_events")

	// Nothing is recorded: no Call, no Rejected, no CacheHit, no Observe,
	// no queue saturation. Every series below must still be exported.
	body := scrapeRegistry(t, Handler(reg))

	want := []string{
		`svc_llm_calls_total{result="success"} 0`,
		`svc_llm_calls_total{result="transient"} 0`,
		`svc_llm_calls_total{result="permanent"} 0`,
		`svc_llm_calls_total{result="parse"} 0`,
		`svc_llm_cost_micros_total 0`,
		`svc_budget_rejections_total{reason="system_call_cap"} 0`,
		`svc_cache_results_total{result="hit"} 0`,
		`svc_cache_results_total{result="miss"} 0`,
		`svc_upstream_results_total{result="valid"} 0`,
		`svc_upstream_results_total{result="invalid"} 0`,
		`svc_upstream_results_total{result="unavailable"} 0`,
		`svc_pass_runs_total{pass="blocklist consensus",result="success"} 0`,
		`svc_pass_runs_total{pass="blocklist consensus",result="failure"} 0`,
		`svc_ingestq_full_total{queue="threat_events"} 0`,
	}
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("series absent before its first event: %q\nbody:\n%s", w, body)
		}
	}

	// The HELP/TYPE header is what a dashboard's metric browser reads, and
	// it too only appears once a family has a child.
	for _, family := range []string{
		"svc_llm_calls_total", "svc_budget_rejections_total",
		"svc_cache_results_total", "svc_upstream_results_total",
		"svc_pass_runs_total", "svc_ingestq_full_total",
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
	reg := NewRegistry(testService)
	p := NewPass(reg, "sizing cohort")

	body := scrapeRegistry(t, Handler(reg))
	if strings.Contains(body, "svc_pass_last_success_timestamp_seconds") {
		t.Fatalf("last-success gauge exported before any pass succeeded -- a 0 here "+
			"means 1970 to every staleness alert\nbody:\n%s", body)
	}

	// A FAILED run must not conjure it either.
	p.Observe("sizing cohort", errTest{}, time.Second, 1_700_000_000_000)
	body = scrapeRegistry(t, Handler(reg))
	if strings.Contains(body, "svc_pass_last_success_timestamp_seconds") {
		t.Fatalf("last-success gauge exported after a FAILED run\nbody:\n%s", body)
	}

	// It appears only once a pass actually succeeds.
	p.Observe("sizing cohort", nil, time.Second, 1_700_000_000_000)
	body = scrapeRegistry(t, Handler(reg))
	if !strings.Contains(body, `svc_pass_last_success_timestamp_seconds{pass="sizing cohort"} 1.7e+09`) {
		t.Fatalf("last-success gauge missing after a successful run\nbody:\n%s", body)
	}
}

// The HTTP families are deliberately left lazy: `status` and `method` are
// not closed sets, so pre-creating would invent series for combinations
// that can never occur. This pins that decision so nobody "fixes" the
// pre-creation rule into applying here too.
func TestHTTPFamiliesAreDeliberatelyNotPreCreated(t *testing.T) {
	reg := NewRegistry(testService)
	h := NewHTTP(reg)

	body := scrapeRegistry(t, Handler(reg))
	if strings.Contains(body, "svc_http_requests_total") {
		t.Errorf("svc_http_requests_total exported before any request -- (method, route, "+
			"status) is not a closed set and must not be enumerated\nbody:\n%s", body)
	}

	h.Observe("GET", "/v1/findings", 200, time.Millisecond)
	body = scrapeRegistry(t, Handler(reg))
	if !strings.Contains(body, `svc_http_requests_total{method="GET",route="/v1/findings",status="200"} 1`) {
		t.Errorf("svc_http_requests_total missing after a request\nbody:\n%s", body)
	}
}

func TestIngestQueueFullCounterIsPerQueue(t *testing.T) {
	reg := NewRegistry(testService)
	m := NewIngestQueueFull(reg)
	incThreat := m.Counter("threat_events")
	incThreat()
	incThreat()

	body := scrapeRegistry(t, Handler(reg))
	if !strings.Contains(body, `svc_ingestq_full_total{queue="threat_events"} 2`) {
		t.Errorf("scrape body missing the expected counter\nbody:\n%s", body)
	}
}
