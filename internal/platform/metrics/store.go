// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// ActiveWindow is how recently a system must have reported to count on an
// active_systems gauge. One value for every binary, so insightsd's and
// threatd's counts mean the same thing side by side on the dashboard.
const ActiveWindow = 24 * time.Hour

// StoreGauge is one gauge family whose value lives in a database rather than
// in the process: how many systems reported recently, how many findings are
// open. A counter cannot answer those -- the answer goes down as well as up,
// and it must survive a restart.
type StoreGauge struct {
	Name, Help string

	// Label names the family's one label, or is empty for an unlabelled
	// family.
	Label string

	// Values is Label's closed vocabulary. Every value is exported, at 0 when
	// the reading did not mention it -- an absent status means "none", not
	// "unknown". A value the reading carries that is not listed here is
	// ignored, which is what keeps the label set closed whatever the database
	// holds.
	Values []string
}

// StoreReading is one read of every StoreGauge: family name, then label
// value ("" for an unlabelled family), then the value. A family missing from
// the reading is not exported.
type StoreReading map[string]map[string]float64

// StoreGauges serves the last StoreReading its owner Set. The owner is the
// pipeline's own periodic pass, never the scrape: each pipeline has exactly
// one SQLite writer, and a query per scrape would compete with it on the
// scraper's schedule rather than the pipeline's. Before the first Set every
// family is absent -- "not counted yet" must not read as "none".
type StoreGauges struct {
	gauges []StoreGauge
	descs  []*prometheus.Desc

	mu      sync.Mutex
	reading StoreReading
}

// NewStoreGauges builds and registers the families into reg.
func NewStoreGauges(reg *Registry, gauges ...StoreGauge) *StoreGauges {
	g := &StoreGauges{gauges: gauges}
	for _, sg := range gauges {
		var labels []string
		if sg.Label != "" {
			labels = []string{sg.Label}
		}
		g.descs = append(g.descs, prometheus.NewDesc(sg.Name, sg.Help, labels, nil))
	}
	reg.prefixed.MustRegister(g)
	return g
}

// Set replaces the served reading. A pass whose read failed simply does not
// call it, so the last good reading stays up while pass_runs_total records
// the failure.
func (g *StoreGauges) Set(r StoreReading) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.reading = r
}

func (g *StoreGauges) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range g.descs {
		ch <- d
	}
}

func (g *StoreGauges) Collect(ch chan<- prometheus.Metric) {
	g.mu.Lock()
	reading := g.reading
	g.mu.Unlock()
	for i, sg := range g.gauges {
		values, ok := reading[sg.Name]
		if !ok {
			continue
		}
		if sg.Label == "" {
			if v, ok := values[""]; ok {
				ch <- prometheus.MustNewConstMetric(g.descs[i], prometheus.GaugeValue, v)
			}
			continue
		}
		for _, lv := range sg.Values {
			ch <- prometheus.MustNewConstMetric(g.descs[i], prometheus.GaugeValue, values[lv], lv)
		}
	}
}
