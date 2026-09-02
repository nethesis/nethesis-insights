// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package sizing

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/nethesis/nethesis-insights/internal/model"
)

// now is a fixed instant so the day-window assertions are not clock
// sensitive. 2026-09-02T12:00:00Z, matching the day the ground truth for this
// pipeline was read off a live cluster.
var now = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC).UnixMilli()

func day(s string) string { return s }

func report(days ...model.SizingDay) model.SizingReport {
	return model.SizingReport{SchemaVersion: model.SizingSchemaVersion, Days: days}
}

func oneNode(n model.SizingNode) model.SizingDay {
	return model.SizingDay{Day: day("2026-09-01"), Nodes: []model.SizingNode{n}}
}

func healthyNode() model.SizingNode {
	return model.SizingNode{
		NodeID:         1,
		MetricsPresent: true,
		SampleCoverage: 0.99,
		Hardware:       model.SizingHardware{CPUCores: 4, MemTotalBytes: 8 << 30},
	}
}

// TestSanitizeAcceptsEveryMetricKey is the executable form of the
// open-vocabulary rule, and the direct analogue of threat's
// TestSanitizeAcceptsEveryScenario. There is deliberately no list of known
// metrics: the NS8 module set grows continuously, and a fixed set would
// silently discard every new product's metric until someone shipped a server
// release.
func TestSanitizeAcceptsEveryMetricKey(t *testing.T) {
	keys := []string{
		"users", "mailboxes", "trunks", "queues", "shared_folders",
		"total_users", "active_users", "task_count",
		// Vocabulary nobody has invented yet, and one that never will be:
		"a", "z9", "future_product_metric_nobody_planned",
		strings.Repeat("k", MaxMetricKeyLen),
	}
	for _, key := range keys {
		n := healthyNode()
		n.Modules = []model.SizingModule{{
			Family: "somefutureproduct", Instances: 1, FactsOK: 1,
			Workload: map[string]float64{key: 7},
		}}
		res := Sanitize(report(oneNode(n)), Options{}, now)
		if len(res.Days) != 1 || len(res.Days[0].Nodes) != 1 {
			t.Fatalf("key %q: node was dropped", key)
		}
		mods := res.Days[0].Nodes[0].Modules
		if len(mods) != 1 || mods[0].Workload[key] != 7 {
			t.Errorf("key %q was not accepted: %#v", key, mods)
		}
		if res.Counters.DroppedMetricKey != 0 {
			t.Errorf("key %q incremented DroppedMetricKey", key)
		}
	}
}

func TestSanitizeRejectsMalformedMetricKeys(t *testing.T) {
	keys := []string{
		"", " ", "Users", "9users", "_users", "user-count", "user.count",
		"users!", "utenti_à", strings.Repeat("k", MaxMetricKeyLen+1),
	}
	for _, key := range keys {
		n := healthyNode()
		n.Modules = []model.SizingModule{{
			Family: "mail", Instances: 1, FactsOK: 1,
			Workload: map[string]float64{key: 7},
		}}
		res := Sanitize(report(oneNode(n)), Options{}, now)
		mods := res.Days[0].Nodes[0].Modules
		if len(mods) != 1 {
			t.Fatalf("key %q: the family itself was dropped", key)
		}
		if len(mods[0].Workload) != 0 {
			t.Errorf("key %q was accepted: %#v", key, mods[0].Workload)
		}
		if res.Counters.DroppedMetricKey != 1 {
			t.Errorf("key %q: DroppedMetricKey = %d, want 1", key, res.Counters.DroppedMetricKey)
		}
	}
}

// TestSanitizeRejectsEveryNonNumericValue is the executable form of the
// privacy rule. "Number" is the entire control: an FQDN, an IP address, a
// hostname or a DMI serial cannot be encoded in a float, which is a stronger
// guarantee than any field blocklist somebody has to maintain.
//
// Two halves, because the rule is enforced in two places. A non-numeric JSON
// value cannot even decode into the wire type, so the identifying string
// never reaches the sanitizer at all; and a value that IS a number but is not
// finite and non-negative is dropped with a counter.
func TestSanitizeRejectsEveryNonNumericValue(t *testing.T) {
	nonNumeric := []string{
		`"node1.example.com"`,
		`"203.0.113.7"`,
		`"VMware-42 1a 2b"`,
		`true`,
		`{"nested": 1}`,
		`["a"]`,
		`null`,
	}
	for _, raw := range nonNumeric {
		body := `{"schema_version":1,"days":[{"day":"2026-09-01","nodes":[` +
			`{"node_id":1,"metrics_present":true,"sample_coverage":0.99,` +
			`"hardware":{"cpu_cores":4,"mem_total_bytes":8589934592},` +
			`"modules":[{"family":"mail","instances":1,"facts_ok":1,"workload":{"leaked":` + raw + `}}]}]}]}`

		var r model.SizingReport
		err := json.Unmarshal([]byte(body), &r)
		if raw == `null` {
			// JSON null decodes to the zero value rather than erroring; it is
			// then an ordinary 0, which carries no identifying information.
			if err != nil {
				t.Fatalf("null: unexpected decode error: %v", err)
			}
			continue
		}
		if err == nil {
			t.Errorf("value %s decoded into a float64 workload map", raw)
		}
	}

	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), -1, -0.0001} {
		n := healthyNode()
		n.Modules = []model.SizingModule{{
			Family: "mail", Instances: 1, FactsOK: 1,
			Workload: map[string]float64{"mailboxes": v},
		}}
		res := Sanitize(report(oneNode(n)), Options{}, now)
		if got := res.Days[0].Nodes[0].Modules[0].Workload; len(got) != 0 {
			t.Errorf("value %v was accepted: %#v", v, got)
		}
		if res.Counters.DroppedMetricValue != 1 {
			t.Errorf("value %v: DroppedMetricValue = %d, want 1", v, res.Counters.DroppedMetricValue)
		}
	}
}

func TestSanitizeDayWindow(t *testing.T) {
	cases := []struct {
		name   string
		day    string
		wantOK bool
	}{
		{"yesterday, the newest complete day", "2026-09-01", true},
		{"today is still accumulating", "2026-09-02", false},
		{"tomorrow cannot exist", "2026-09-03", false},
		{"inside Prometheus retention", "2026-08-19", true},
		{"exactly the retention edge", "2026-08-18", true},
		{"older than retention", "2026-08-17", false},
		{"unparseable", "01/09/2026", false},
		{"an instant, not a day", "2026-09-01T00:00:00Z", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := healthyNode()
			res := Sanitize(report(model.SizingDay{Day: tc.day, Nodes: []model.SizingNode{n}}), Options{}, now)
			if tc.wantOK {
				if len(res.Days) != 1 {
					t.Fatalf("day %q was rejected", tc.day)
				}
				if res.Counters.DroppedDay != 0 {
					t.Errorf("DroppedDay = %d, want 0", res.Counters.DroppedDay)
				}
				return
			}
			if len(res.Days) != 0 {
				t.Fatalf("day %q was accepted", tc.day)
			}
			if res.Counters.DroppedDay != 1 {
				t.Errorf("DroppedDay = %d, want 1", res.Counters.DroppedDay)
			}
		})
	}
}

// A malformed node must be dropped and counted while its siblings store: a
// cluster with one broken node must not lose the other fifteen.
func TestSanitizeDropsOneNodeAndKeepsSiblings(t *testing.T) {
	good1, good2 := healthyNode(), healthyNode()
	good2.NodeID = 2
	bad := healthyNode()
	bad.NodeID = 0

	res := Sanitize(report(model.SizingDay{
		Day:   "2026-09-01",
		Nodes: []model.SizingNode{good1, bad, good2},
	}), Options{}, now)

	if len(res.Days) != 1 || len(res.Days[0].Nodes) != 2 {
		t.Fatalf("stored nodes = %d, want 2", len(res.Days[0].Nodes))
	}
	if res.Counters.DroppedNode != 1 {
		t.Errorf("DroppedNode = %d, want 1", res.Counters.DroppedNode)
	}
	if res.Counters.AcceptedNodes != 2 {
		t.Errorf("AcceptedNodes = %d, want 2", res.Counters.AcceptedNodes)
	}
	if res.Days[0].Nodes[0].NodeID != 1 || res.Days[0].Nodes[1].NodeID != 2 {
		t.Error("nodes are not sorted by node_id")
	}
}

func TestSanitizeFoldsDuplicateFamilies(t *testing.T) {
	n := healthyNode()
	n.Modules = []model.SizingModule{
		{Family: "nethvoice20", Instances: 1, FactsOK: 1, Versions: []string{"1.4.2"},
			Workload: map[string]float64{"users": 100}},
		{Family: "nethvoice47", Instances: 1, FactsOK: 0, Versions: []string{"1.4.2"},
			Workload: map[string]float64{"users": 30, "trunks": 4}},
	}
	res := Sanitize(report(oneNode(n)), Options{}, now)

	mods := res.Days[0].Nodes[0].Modules
	if len(mods) != 1 {
		t.Fatalf("families = %d, want 1 (both normalize to nethvoice)", len(mods))
	}
	m := mods[0]
	if m.Family != "nethvoice" {
		t.Errorf("family = %q, want nethvoice", m.Family)
	}
	if m.Instances != 2 || m.FactsOK != 1 {
		t.Errorf("instances/facts_ok = %d/%d, want 2/1", m.Instances, m.FactsOK)
	}
	// Workload metrics are extensive, so they sum across instances.
	if m.Workload["users"] != 130 || m.Workload["trunks"] != 4 {
		t.Errorf("workload = %#v, want users=130 trunks=4", m.Workload)
	}
	if len(m.Versions) != 1 {
		t.Errorf("versions = %#v, want one deduplicated entry", m.Versions)
	}
}

// facts_ok above instances can only come from a reporter bug, and clamping
// keeps "facts_ok == instances" a usable "every call succeeded" test.
func TestSanitizeClampsFactsOK(t *testing.T) {
	n := healthyNode()
	n.Modules = []model.SizingModule{{Family: "mail", Instances: 1, FactsOK: 9}}
	res := Sanitize(report(oneNode(n)), Options{}, now)
	if got := res.Days[0].Nodes[0].Modules[0].FactsOK; got != 1 {
		t.Errorf("facts_ok = %d, want 1", got)
	}
}

func TestSanitizeCapsTruncateRatherThanReject(t *testing.T) {
	n := healthyNode()
	for i := 0; i < MaxMetricsPerFamily+5; i++ {
		if n.Modules == nil {
			n.Modules = []model.SizingModule{{Family: "mail", Instances: 1, FactsOK: 1, Workload: map[string]float64{}}}
		}
		n.Modules[0].Workload[string(rune('a'+i%26))+string(rune('a'+i/26))] = float64(i)
	}
	res := Sanitize(report(oneNode(n)), Options{}, now)
	got := res.Days[0].Nodes[0].Modules[0].Workload
	if len(got) != MaxMetricsPerFamily {
		t.Errorf("metrics = %d, want %d", len(got), MaxMetricsPerFamily)
	}
	if res.Counters.TruncatedMetrics != 5 {
		t.Errorf("TruncatedMetrics = %d, want 5", res.Counters.TruncatedMetrics)
	}
}

func TestSanitizeNodeCapTruncates(t *testing.T) {
	var nodes []model.SizingNode
	for i := 1; i <= DefaultMaxNodes+3; i++ {
		n := healthyNode()
		n.NodeID = i
		nodes = append(nodes, n)
	}
	res := Sanitize(report(model.SizingDay{Day: "2026-09-01", Nodes: nodes}), Options{}, now)
	if len(res.Days[0].Nodes) != DefaultMaxNodes {
		t.Errorf("nodes = %d, want %d", len(res.Days[0].Nodes), DefaultMaxNodes)
	}
	if res.Counters.TruncatedNodes != 3 {
		t.Errorf("TruncatedNodes = %d, want 3", res.Counters.TruncatedNodes)
	}
}

// A degraded report -- Prometheus unreachable, no measurements -- must still
// store: "what is deployed on what hardware" is worth answering, and dropping
// it would bias the fleet view toward metrics-healthy clusters.
func TestSanitizeKeepsDegradedReport(t *testing.T) {
	n := model.SizingNode{
		NodeID:   3,
		Hardware: model.SizingHardware{CPUCores: 2, MemTotalBytes: 4 << 30},
		Modules:  []model.SizingModule{{Family: "mail", Instances: 1, FactsOK: 1}},
	}
	res := Sanitize(report(oneNode(n)), Options{}, now)
	if len(res.Days) != 1 || len(res.Days[0].Nodes) != 1 {
		t.Fatal("a facts-only report was dropped")
	}
	got := res.Days[0].Nodes[0]
	if got.MetricsPresent {
		t.Error("MetricsPresent must stay false")
	}
	if len(got.Modules) != 1 {
		t.Error("the module inventory must survive")
	}
}

// The five free-text descriptors are the only free text in the payload, and
// each is control-stripped and length-capped.
func TestSanitizeCleansFreeText(t *testing.T) {
	n := healthyNode()
	n.Hardware.CPUModel = " AMD\tEPYC\x00 7282 " + strings.Repeat("x", MaxTextLen)
	n.Hardware.OSID = "rocky\n"
	res := Sanitize(report(oneNode(n)), Options{}, now)

	hw := res.Days[0].Nodes[0].Hardware
	if strings.ContainsAny(hw.CPUModel, "\t\n\x00") {
		t.Errorf("cpu_model kept a control character: %q", hw.CPUModel)
	}
	if len([]rune(hw.CPUModel)) > MaxTextLen {
		t.Errorf("cpu_model is %d runes, want at most %d", len([]rune(hw.CPUModel)), MaxTextLen)
	}
	if hw.OSID != "rocky" {
		t.Errorf("os_id = %q, want rocky", hw.OSID)
	}
}

func TestSanitizeSumsClusterUserDomains(t *testing.T) {
	d := oneNode(healthyNode())
	d.Cluster = &model.SizingCluster{UserDomains: []map[string]float64{
		{"total_users": 100, "total_groups": 8},
		{"total_users": 110, "total_groups": 10},
	}}
	res := Sanitize(report(d), Options{}, now)
	got := res.Days[0].ClusterWorkload
	if got["total_users"] != 210 || got["total_groups"] != 18 {
		t.Errorf("cluster workload = %#v, want total_users=210 total_groups=18", got)
	}
}

// A resource field that is not a finite non-negative number becomes ABSENT,
// not zero: a zero says "measured, and fine", which is the opposite.
func TestSanitizeMakesBadResourceAbsent(t *testing.T) {
	nan := math.NaN()
	neg := -0.5
	n := healthyNode()
	n.Resources.RAMUtilP95 = &nan
	n.Stress.OOMKills = &neg
	res := Sanitize(report(oneNode(n)), Options{}, now)

	got := res.Days[0].Nodes[0]
	if got.Resources.RAMUtilP95 != nil {
		t.Error("a NaN ram_util_p95 must become absent, not zero")
	}
	if got.Stress.OOMKills != nil {
		t.Error("a negative oom_kills must become absent, not zero")
	}
	if res.Counters.DroppedResourceValue != 2 {
		t.Errorf("DroppedResourceValue = %d, want 2", res.Counters.DroppedResourceValue)
	}
}

// A p95 utilization of 1.0000001 is a rounding artifact, not a broken
// reporter, so a fraction above 1 is clamped rather than dropped.
func TestSanitizeClampsFractionsAbove1(t *testing.T) {
	over := 1.0000001
	n := healthyNode()
	n.Resources.RAMUtilP95 = &over
	res := Sanitize(report(oneNode(n)), Options{}, now)
	got := res.Days[0].Nodes[0].Resources.RAMUtilP95
	if got == nil || *got != 1 {
		t.Errorf("ram_util_p95 = %v, want clamped to 1", got)
	}
	if res.Counters.DroppedResourceValue != 0 {
		t.Error("a clamped fraction must not be counted as dropped")
	}
}

func TestSanitizeIsDeterministic(t *testing.T) {
	n := healthyNode()
	n.Modules = []model.SizingModule{
		{Family: "traefik", Instances: 1, FactsOK: 1, Workload: map[string]float64{"routes": 12}},
		{Family: "mail", Instances: 1, FactsOK: 1, Workload: map[string]float64{"mailboxes": 210, "domains": 3}},
	}
	first := Sanitize(report(oneNode(n)), Options{}, now)
	for i := 0; i < 20; i++ {
		again := Sanitize(report(oneNode(n)), Options{}, now)
		if len(again.Days[0].Nodes[0].Modules) != len(first.Days[0].Nodes[0].Modules) {
			t.Fatal("module count is not stable")
		}
		for j, m := range again.Days[0].Nodes[0].Modules {
			if m.Family != first.Days[0].Nodes[0].Modules[j].Family {
				t.Fatalf("module order is not stable: %q vs %q",
					m.Family, first.Days[0].Nodes[0].Modules[j].Family)
			}
		}
	}
}

func TestDayStringRoundTrips(t *testing.T) {
	for _, label := range []string{"2026-09-01", "2026-08-19", "2026-01-01", "2025-12-31"} {
		idx, ok := parseDay(label)
		if !ok {
			t.Fatalf("parseDay(%q) failed", label)
		}
		if got := DayString(idx); got != label {
			t.Errorf("DayString(parseDay(%q)) = %q", label, got)
		}
	}
}
