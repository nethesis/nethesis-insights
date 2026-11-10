// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package decide

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRulesFileChangeNeedsVersionBump(t *testing.T) {
	sum := sha256.Sum256([]byte(Rules))
	if got := hex.EncodeToString(sum[:]); got != rulesSHA256 {
		t.Fatalf("rules.md changed: bump RulesVersion and update rulesSHA256 (got %s)", got)
	}
}

func sampleClass() Class {
	return Describe([]string{"mail1"}, []string{"a", "b"}, "T", "S")
}

func TestBuildRequestShape(t *testing.T) {
	ps := []Precedent{{Class: sampleClass(), Decision: "customer", Similarity: 0.9}}
	raw, err := BuildRequest("gpt-6-luna", sampleClass(), ps)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["model"] != "gpt-6-luna" {
		t.Fatalf("model = %v", m["model"])
	}
	in := m["input"].([]any)
	if len(in) != 1 || in[0].(map[string]any)["role"] != "user" {
		t.Fatalf("input = %v", in)
	}
	parts := in[0].(map[string]any)["content"].([]any)
	if len(parts) != 4 {
		t.Fatalf("parts = %d", len(parts))
	}
	wantType := []string{"input_text", "input_json", "input_text", "input_json"}
	for i, p := range parts {
		if p.(map[string]any)["type"] != wantType[i] {
			t.Fatalf("part %d type = %v", i, p.(map[string]any)["type"])
		}
	}
	if parts[0].(map[string]any)["text"] != "Finding class to decide:" {
		t.Fatalf("part 0 = %v", parts[0])
	}
	if parts[2].(map[string]any)["text"] != "The 15 most similar classes the review team already decided, most similar first, with their decision:" {
		t.Fatalf("part 2 = %v", parts[2])
	}
	if _, ok := parts[3].(map[string]any)["data"].(map[string]any)["precedents"]; !ok {
		t.Fatalf("part 3 has no precedents: %v", parts[3])
	}
	qs := m["questions"].([]any)
	if len(qs) != 1 {
		t.Fatalf("questions = %d", len(qs))
	}
	q := qs[0].(map[string]any)
	if q["type"] != "choice" || q["name"] != "decision" {
		t.Fatalf("question = %v", q)
	}
	if !strings.HasSuffix(q["instructions"].(string), Rules) {
		t.Fatal("instructions do not end with Rules")
	}
	ch := q["choices"].([]any)
	for i, want := range []string{"customer", "operator", "dismissed"} {
		if ch[i].(map[string]any)["value"] != want {
			t.Fatalf("choice %d = %v", i, ch[i])
		}
	}

	zero, err := BuildRequest("gpt-6-luna", sampleClass(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var zm map[string]any
	if err := json.Unmarshal(zero, &zm); err != nil {
		t.Fatal(err)
	}
	zp := zm["input"].([]any)[0].(map[string]any)["content"].([]any)
	if len(zp) != 2 {
		t.Fatalf("zero-shot parts = %d", len(zp))
	}
}

func TestBuildRequestIsDeterministic(t *testing.T) {
	ps := []Precedent{{Class: sampleClass(), Decision: "operator", Similarity: 0.5}}
	a, _ := BuildRequest("m", sampleClass(), ps)
	b, _ := BuildRequest("m", sampleClass(), ps)
	if string(a) != string(b) {
		t.Fatal("not deterministic")
	}
}

func TestDescribeCutsRunes(t *testing.T) {
	long := strings.Repeat("è", 500)
	c := Describe(nil, []string{long, "2", "3", "4", "5", "6", "7", "8"}, "t", "s")
	if len(c.Evidence) != MaxLines {
		t.Fatalf("lines = %d", len(c.Evidence))
	}
	if !utf8.ValidString(c.Evidence[0]) || utf8.RuneCountInString(c.Evidence[0]) != MaxRunes {
		t.Fatalf("runes = %d", utf8.RuneCountInString(c.Evidence[0]))
	}
	raw, _ := json.Marshal(Describe(nil, nil, "t", "s"))
	if !strings.Contains(string(raw), `"modules":[]`) || !strings.Contains(string(raw), `"evidence":[]`) {
		t.Fatalf("nil slices not []: %s", raw)
	}
}

func TestNearest(t *testing.T) {
	var pool []Candidate
	for i := 0; i < 20; i++ {
		pool = append(pool, Candidate{Class: sampleClass(), Decision: "customer",
			Vector: []float32{1, float32(i) * 0.1}})
	}
	got := Nearest([]float32{1, 0}, pool, K)
	if len(got) != K {
		t.Fatalf("len = %d", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i].Similarity > got[i-1].Similarity {
			t.Fatalf("not descending at %d", i)
		}
	}
	r := Nearest([]float32{1, 0}, []Candidate{{Vector: []float32{0.12345, 1}}}, 1)
	// cosine of (1,0) and (0.12345,1) is not 0.12345; check rounding on a known value
	if x := r[0].Similarity * 1000; x != float64(int64(x+0.5)) {
		t.Fatalf("not rounded to 3 decimals: %v", r[0].Similarity)
	}
}

const sampleResp = `{"model": "gpt-6-luna", "answers": [{"type": "choice", "name": "decision", "choice": "dismissed", "probabilities": [{"value": "customer", "probability": 0.01}], "confidence": 0.43}], "usage": {"input_tokens": 4727, "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 3102}, "output_tokens": 0, "total_tokens": 4727}}`

func TestParseResponse(t *testing.T) {
	a, u, err := ParseResponse([]byte(sampleResp))
	if err != nil {
		t.Fatal(err)
	}
	if a.Choice != "dismissed" || a.Confidence != 0.43 || a.Refused {
		t.Fatalf("answer = %+v", a)
	}
	if u != (Usage{4727, 0, 0}) {
		t.Fatalf("usage = %+v", u)
	}

	a, _, err = ParseResponse([]byte(`{"answers":[{"type":"refusal","name":"decision"}],"usage":{"input_tokens":5}}`))
	if err != nil || !a.Refused {
		t.Fatalf("refusal: %+v %v", a, err)
	}
	if _, _, err = ParseResponse([]byte(`{"answers":[{"type":"choice","choice":"bogus","confidence":0.9}]}`)); err == nil {
		t.Fatal("unknown choice accepted")
	}
	if _, _, err = ParseResponse([]byte(`{"answers":[]}`)); err == nil {
		t.Fatal("no answers accepted")
	}
	if _, _, err = ParseResponse([]byte(`not json`)); err == nil {
		t.Fatal("bad json accepted")
	}
}

func TestCostMicros(t *testing.T) {
	p := Prices{InputPerMTok: 1, CachedInputPerMTok: 0.1, OutputPerMTok: 4}
	if got := p.CostMicros(Usage{1_000_000, 200_000, 10_000}); got != 860_000 {
		t.Fatalf("cost = %d", got)
	}
}
