// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package model

import "encoding/json"

// Fleet-sizing wire and internal types.
//
// This is a third pipeline, beside the bundle/gate/LLM path and Threat Shield.
// It shares the HTTP listener, the Authenticator, the SQLite file and
// ModuleFamily below -- deliberately, because ModuleFamily is already the
// single definition of module identity and a second one would eventually
// disagree -- and nothing else. No LLM call, no gate, no fingerprint, no
// queue.
//
// The wire -> sanitized -> counters split mirrors threat.go: the Sizing*
// types below are what a reporter sends, the Sanitized* types are what the
// store accepts, and nothing crosses from one to the other except through
// sizing.Sanitize.
//
// The full contract is docs/specs/2026-09-02-sizing-ingest-contract.md.

// SizingSchemaVersion is the envelope version reporters must send. Like
// ThreatSchemaVersion it is independent of SchemaVersion (the bundle
// envelope): the three pipelines version separately because they evolve
// separately.
const SizingSchemaVersion = 1

// SizingReport is the POST /v1/sizing-reports body. One report is one
// cluster, carrying one or more complete UTC days, each with one entry per
// node in the cluster.
//
// SystemID is optional -- the authenticated credential is what identifies the
// reporter -- but when present it must equal the authenticated system,
// exactly like Bundle and ThreatReport.
type SizingReport struct {
	SchemaVersion   int         `json:"schema_version"`
	SystemID        string      `json:"system_id,omitempty"`
	ReporterVersion string      `json:"reporter_version,omitempty"`
	Days            []SizingDay `json:"days"`
}

// SizingDay is one complete UTC day for one cluster.
//
// Day is sent explicitly as "YYYY-MM-DD" rather than inferred from arrival
// time, and the reporter computes every value over the absolute range
// [day 00:00 UTC, day+1 00:00 UTC). That is what makes a day an absolute fact
// and therefore what makes the three daily sends byte-identical restatements:
// redelivery is free and the upsert recomputes rather than accumulates. A
// relative [24h] query with the same schedule would store a random 24-hour
// slice under a day label.
type SizingDay struct {
	Day     string         `json:"day"`
	Nodes   []SizingNode   `json:"nodes"`
	Cluster *SizingCluster `json:"cluster,omitempty"`
}

// WireInt decodes a wire integer field that a reporter may legitimately send
// with a fractional part. node_id, cpu_cores, mem_total_bytes, instances and
// facts_ok are all logically integers, but a reporter that derives one from
// Prometheus -- which has no integer type -- can only ever emit a float
// literal ("mem_total_bytes": 8054087680.0 is exactly what ns8-core's
// cluster/get-facts sends, read off a live cluster). encoding/json's default
// int/int64 unmarshaling refuses any fractional literal outright, which would
// reject the entire report over one cosmetic float. WireInt accepts both "12"
// and "12.0" and truncates toward zero; a JSON string, bool, array or object
// still fails to decode, so the numbers-only privacy rule for workload maps
// is untouched.
//
// WireInt exists only at the wire boundary: the fields below decode into it
// via a private shadow type and immediately copy out to a plain int/int64, so
// every Sanitized* type and every store column stays exactly as before this
// type existed.
type WireInt int64

func (w *WireInt) UnmarshalJSON(b []byte) error {
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	if i, err := n.Int64(); err == nil {
		*w = WireInt(i)
		return nil
	}
	// Has a fractional part (or is in exponent form) -- fall back to a float
	// and truncate. n.Float64() rejects anything that is not a JSON number at
	// all, so a string/bool/array/object still fails here.
	f, err := n.Float64()
	if err != nil {
		return err
	}
	*w = WireInt(int64(f))
	return nil
}

// SizingNode is one node's day.
//
// MetricsPresent false marks a degraded report -- Prometheus unreachable or
// the metrics module removed -- carrying hardware, OS and module inventory
// but no measurements. Such a report is stored and scores no pressure:
// "what is deployed on what hardware" is still worth answering, and dropping
// it would bias the fleet view toward metrics-healthy clusters.
type SizingNode struct {
	NodeID         int             `json:"node_id"`
	MetricsPresent bool            `json:"metrics_present"`
	SampleCoverage float64         `json:"sample_coverage"`
	Hardware       SizingHardware  `json:"hardware"`
	Resources      SizingResources `json:"resources"`
	Stress         SizingStress    `json:"stress"`
	Modules        []SizingModule  `json:"modules"`
}

// UnmarshalJSON accepts NodeID as a JSON number with a fractional part (see
// WireInt) while keeping the struct field a plain int for everything
// downstream.
func (n *SizingNode) UnmarshalJSON(b []byte) error {
	var w struct {
		NodeID         WireInt         `json:"node_id"`
		MetricsPresent bool            `json:"metrics_present"`
		SampleCoverage float64         `json:"sample_coverage"`
		Hardware       SizingHardware  `json:"hardware"`
		Resources      SizingResources `json:"resources"`
		Stress         SizingStress    `json:"stress"`
		Modules        []SizingModule  `json:"modules"`
	}
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*n = SizingNode{
		NodeID:         int(w.NodeID),
		MetricsPresent: w.MetricsPresent,
		SampleCoverage: w.SampleCoverage,
		Hardware:       w.Hardware,
		Resources:      w.Resources,
		Stress:         w.Stress,
		Modules:        w.Modules,
	}
	return nil
}

// SizingHardware is the node's installed capacity plus the handful of
// free-text descriptors worth keeping.
//
// What is deliberately absent: nodename, FQDN, main IP address, DMI serial and
// board asset tag. They are identifying, the server has no use for them, and
// the operator UI's GET is unauthenticated and fleet-wide.
type SizingHardware struct {
	CPUCores       int    `json:"cpu_cores"`
	MemTotalBytes  int64  `json:"mem_total_bytes"`
	CPUModel       string `json:"cpu_model,omitempty"`
	OSID           string `json:"os_id,omitempty"`
	OSVersion      string `json:"os_version,omitempty"`
	KernelRelease  string `json:"kernel_release,omitempty"`
	Virtualization string `json:"virtualization,omitempty"`
}

// UnmarshalJSON accepts CPUCores and MemTotalBytes as a JSON number with a
// fractional part (see WireInt): mem_total_bytes in particular is read off
// Prometheus, which has no integer type, so a real reporter sends
// "mem_total_bytes": 8054087680.0. MemTotalBytes stays int64-width -- a
// node's RAM in bytes can exceed the range of a 32-bit int.
func (h *SizingHardware) UnmarshalJSON(b []byte) error {
	var w struct {
		CPUCores       WireInt `json:"cpu_cores"`
		MemTotalBytes  WireInt `json:"mem_total_bytes"`
		CPUModel       string  `json:"cpu_model,omitempty"`
		OSID           string  `json:"os_id,omitempty"`
		OSVersion      string  `json:"os_version,omitempty"`
		KernelRelease  string  `json:"kernel_release,omitempty"`
		Virtualization string  `json:"virtualization,omitempty"`
	}
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*h = SizingHardware{
		CPUCores:       int(w.CPUCores),
		MemTotalBytes:  int64(w.MemTotalBytes),
		CPUModel:       w.CPUModel,
		OSID:           w.OSID,
		OSVersion:      w.OSVersion,
		KernelRelease:  w.KernelRelease,
		Virtualization: w.Virtualization,
	}
	return nil
}

// SizingResources holds the day's utilization percentiles.
//
// Every field is a pointer because a missing input must make its penalty term
// **absent**, not zero: a term reading zero says "measured, and fine", which
// is the opposite of "not measured". sizing.Evaluate depends on the
// difference.
//
// These are a fixed vocabulary rather than an open map (unlike Workload
// below) because they are the score's inputs and they are stored as
// first-class columns -- which is what makes a threshold recalibration a
// single recompute pass over stored data instead of a fleet-wide
// reconfiguration.
type SizingResources struct {
	RAMUtilP95       *float64 `json:"ram_util_p95,omitempty"`
	RAMUsedBytesP95  *float64 `json:"ram_used_bytes_p95,omitempty"`
	CPUUtilP95       *float64 `json:"cpu_util_p95,omitempty"`
	CPUCoresUsedP95  *float64 `json:"cpu_cores_used_p95,omitempty"`
	Load15PerCoreP95 *float64 `json:"load15_per_core_p95,omitempty"`
	FSUsedFracMax    *float64 `json:"fs_used_frac_max,omitempty"`
	FSDaysToFull     *float64 `json:"fs_days_to_full,omitempty"`

	// DiskIOUtilP95 is stored but never scored: io_time saturation is
	// meaningless on NVMe, where the device is happily servicing a queue at
	// "100% utilized". Kept as a diagnostic.
	DiskIOUtilP95 *float64 `json:"disk_io_util_p95,omitempty"`
}

// SizingStress holds the day's stress evidence.
//
// IOWaitBusyFrac is a **duration** -- the fraction of the day spent above the
// iowait threshold -- never a 24-hour max. A max of a 5-minute average cannot
// tell a 25-minute nightly backup (1.7 % of the day) from a node starved for
// seven hours (30 %); a duration has a denominator.
//
// SwapInPPSP95 is swap **in**, not out. Eviction is routine on a healthy
// Linux box; a page read back from swap is the one that proves a stall.
type SizingStress struct {
	IOWaitBusyFrac *float64 `json:"iowait_busy_frac,omitempty"`
	SwapInPPSP95   *float64 `json:"swapin_pps_p95,omitempty"`
	OOMKills       *float64 `json:"oom_kills,omitempty"`

	// Reboots exists because increase() extrapolates across counter resets:
	// rather than trying to correct OOMKills for a reboot mid-day, the day is
	// recorded as having had one and the verdict discounts it.
	Reboots *float64 `json:"reboots,omitempty"`
}

// SizingModule is one module family's presence and workload on one node.
//
// Family is the family (ModuleFamily), never the instance: two instances of
// one module run the same image and the same code path, so 82 nethvoice
// instances are one deployment profile and not 82.
//
// FactsOK is load-bearing and must be sent honestly. get-facts fails per
// instance, and a zero mailbox count from a failed call is indistinguishable
// from a genuinely empty mail server -- the cohort pass's idle handling turns
// on exactly that difference.
type SizingModule struct {
	Family    string             `json:"family"`
	Instances int                `json:"instances"`
	FactsOK   int                `json:"facts_ok"`
	Versions  []string           `json:"versions,omitempty"`
	Workload  map[string]float64 `json:"workload,omitempty"`
}

// UnmarshalJSON accepts Instances and FactsOK as a JSON number with a
// fractional part (see WireInt). Workload is untouched: it decodes as a plain
// map[string]float64, so a non-numeric value there still fails to decode at
// all, which is the numbers-only privacy rule.
func (m *SizingModule) UnmarshalJSON(b []byte) error {
	var w struct {
		Family    string             `json:"family"`
		Instances WireInt            `json:"instances"`
		FactsOK   WireInt            `json:"facts_ok"`
		Versions  []string           `json:"versions,omitempty"`
		Workload  map[string]float64 `json:"workload,omitempty"`
	}
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*m = SizingModule{
		Family:    w.Family,
		Instances: int(w.Instances),
		FactsOK:   int(w.FactsOK),
		Versions:  w.Versions,
		Workload:  w.Workload,
	}
	return nil
}

// SizingCluster carries the cluster-wide counters that belong to no single
// node. UserDomains is one entry per user domain, each an open map of numbers
// under the same rules as SizingModule.Workload; the server sums them across
// domains because they are extensive.
//
// This is where cluster/get-facts' total_users / total_groups / active_users
// land. openldap has no get-facts of its own and needs none.
type SizingCluster struct {
	UserDomains []map[string]float64 `json:"user_domains,omitempty"`
}

// --- Sanitized forms ---

// SanitizedSizingDay is one cluster-day as the store accepts it. Day is a UTC
// day index (unix millis / 86400000), never a formatted string: the tables it
// keys are range-queried constantly, and an index does that with the integer
// arithmetic the codebase already performs.
type SanitizedSizingDay struct {
	Day             int64
	Nodes           []SanitizedSizingNode
	ClusterWorkload map[string]float64
}

// SanitizedSizingNode is one node-day, validated and normalized.
type SanitizedSizingNode struct {
	NodeID         int
	MetricsPresent bool
	SampleCoverage float64
	Hardware       SizingHardware
	Resources      SizingResources
	Stress         SizingStress
	Modules        []SanitizedSizingModule
}

// SanitizedSizingModule is one family, folded across duplicate entries and
// with its workload map reduced to keys and values that passed every rule.
type SanitizedSizingModule struct {
	Family    string
	Instances int
	FactsOK   int
	Versions  []string
	Workload  map[string]float64
}

// SizingCounters accounts for everything in a report that did not become a
// stored row. Ingest is fail-open on content: a malformed node, family or
// metric is dropped and counted, never a reason to reject the report, because
// a cluster with one broken module must not lose the other fifteen.
//
// The counters are returned to the reporter and accumulated per day in
// sizing_ingest_daily, so "why is this cluster contributing nothing" is
// answerable from the operator UI instead of from logs.
type SizingCounters struct {
	AcceptedNodes   int `json:"accepted_nodes"`
	AcceptedModules int `json:"accepted_modules"`
	AcceptedMetrics int `json:"accepted_metrics"`

	// DroppedDay counts days that were unparseable or outside
	// [today-15, today-1]: older than Prometheus' retention means the numbers
	// cannot have been computed from real data, and a future day cannot exist.
	DroppedDay       int `json:"dropped_day"`
	DroppedDuplicate int `json:"dropped_duplicate"`
	DroppedNode      int `json:"dropped_node"`
	DroppedFamily    int `json:"dropped_family"`

	// DroppedMetricKey counts workload keys failing the key shape, and
	// DroppedMetricValue counts values that were not finite and non-negative
	// numbers. The two are separate because they mean different reporter bugs.
	DroppedMetricKey   int `json:"dropped_metric_key"`
	DroppedMetricValue int `json:"dropped_metric_value"`

	// DroppedResourceValue counts fixed-vocabulary resource/stress fields
	// rejected the same way. Such a field becomes absent, so its penalty term
	// is absent too rather than reading zero.
	DroppedResourceValue int `json:"dropped_resource_value"`

	TruncatedDays     int `json:"truncated_days"`
	TruncatedNodes    int `json:"truncated_nodes"`
	TruncatedFamilies int `json:"truncated_families"`
	TruncatedMetrics  int `json:"truncated_metrics"`
}

// Add accumulates another request's counters, for the per-day rollup.
func (c *SizingCounters) Add(o SizingCounters) {
	c.AcceptedNodes += o.AcceptedNodes
	c.AcceptedModules += o.AcceptedModules
	c.AcceptedMetrics += o.AcceptedMetrics
	c.DroppedDay += o.DroppedDay
	c.DroppedDuplicate += o.DroppedDuplicate
	c.DroppedNode += o.DroppedNode
	c.DroppedFamily += o.DroppedFamily
	c.DroppedMetricKey += o.DroppedMetricKey
	c.DroppedMetricValue += o.DroppedMetricValue
	c.DroppedResourceValue += o.DroppedResourceValue
	c.TruncatedDays += o.TruncatedDays
	c.TruncatedNodes += o.TruncatedNodes
	c.TruncatedFamilies += o.TruncatedFamilies
	c.TruncatedMetrics += o.TruncatedMetrics
}
