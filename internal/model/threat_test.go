// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package model

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// TestThreatCounterResultsMatchTheFields keeps the metric vocabulary and
// ByResult in step with the struct: a counter added to ThreatCounters and
// forgotten in either would silently never be exported.
func TestThreatCounterResultsMatchTheFields(t *testing.T) {
	typ := reflect.TypeFor[ThreatCounters]()
	var tags []string
	c := ThreatCounters{}
	v := reflect.ValueOf(&c).Elem()
	for i := range typ.NumField() {
		tags = append(tags, strings.Split(typ.Field(i).Tag.Get("json"), ",")[0])
		v.Field(i).SetInt(int64(i + 1))
	}
	if !slices.Equal(tags, ThreatCounterResults) {
		t.Fatalf("ThreatCounterResults = %v, struct tags = %v", ThreatCounterResults, tags)
	}
	got := c.ByResult()
	for i, n := range got {
		if n != i+1 {
			t.Fatalf("ByResult()[%d] = %d, want %d (%s)", i, n, i+1, tags[i])
		}
	}
	if len(got) != len(tags) {
		t.Fatalf("ByResult has %d entries, want %d", len(got), len(tags))
	}
}
