// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package classdecide

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/nethesis/nethesis-insights/internal/decide"
	"github.com/nethesis/nethesis-insights/internal/decisions"
	logsstore "github.com/nethesis/nethesis-insights/internal/store/logs"
)

type fakeStore struct {
	security   []string
	delivered  []string
	cands      []logsstore.DecisionCandidate
	pool       []decide.Candidate
	asks       []logsstore.DecisionAsk
	recordRes  string
	embedModel string
	err        error
}

func (f *fakeStore) PendingSecurityClasses(context.Context) ([]string, error) {
	return f.security, f.err
}
func (f *fakeStore) DecisionCandidates(context.Context, string, string, string, int) ([]logsstore.DecisionCandidate, error) {
	return f.cands, f.err
}
func (f *fakeStore) DecisionPrecedents(context.Context, string) ([]decide.Candidate, error) {
	return f.pool, nil
}
func (f *fakeStore) RecordDecisionAsk(_ context.Context, a logsstore.DecisionAsk) (string, error) {
	f.asks = append(f.asks, a)
	if f.recordRes != "" {
		return f.recordRes, nil
	}
	return a.Result, nil
}
func (f *fakeStore) DeliverSecurityClass(_ context.Context, k string, _ int64) (bool, error) {
	f.delivered = append(f.delivered, k)
	return true, nil
}
func (f *fakeStore) CurrentEmbedModel(context.Context) (string, error) { return f.embedModel, nil }

type reply struct {
	body []byte
	err  error
}

type fakeClient struct {
	replies []reply
	bodies  [][]byte
}

func (f *fakeClient) Decide(_ context.Context, body []byte) ([]byte, error) {
	f.bodies = append(f.bodies, body)
	r := f.replies[len(f.bodies)-1]
	return r.body, r.err
}

func answer(choice string, conf float64) reply {
	return reply{body: []byte(fmt.Sprintf(
		`{"answers":[{"type":"choice","choice":%q,"confidence":%v}],"usage":{"input_tokens":1000000,"input_tokens_details":{"cached_tokens":0},"output_tokens":0}}`,
		choice, conf))}
}

func cand(key string) logsstore.DecisionCandidate {
	return logsstore.DecisionCandidate{Key: key, Class: decide.Class{Title: key}, Vector: []float32{1, 0}}
}

var cfg = Config{Model: "gpt-6-luna", MinConfidence: 0.9, Batch: 10, Prices: decide.Prices{InputPerMTok: 2}}

func run(t *testing.T, s Store, c Client, cf Config) {
	t.Helper()
	if err := New(s, c, cf).Run(context.Background(), 5); err != nil {
		t.Fatal(err)
	}
}

func TestSecurityClassIsDeliveredWithoutAsking(t *testing.T) {
	s := &fakeStore{security: []string{"sec"}}
	c := &fakeClient{}
	run(t, s, c, cfg)
	if len(c.bodies) != 0 || len(s.delivered) != 1 || s.delivered[0] != "sec" {
		t.Fatalf("calls=%d delivered=%v", len(c.bodies), s.delivered)
	}
}

func TestConfidentAnswerIsApplied(t *testing.T) {
	s := &fakeStore{cands: []logsstore.DecisionCandidate{cand("a")}}
	run(t, s, &fakeClient{replies: []reply{answer("customer", 0.95)}}, cfg)
	a := s.asks[0]
	if a.Result != "applied" || a.Choice != "customer" || a.Detail != "rules r5, gpt-6-luna, confidence 0.95" {
		t.Fatalf("%+v", a)
	}
}

func TestUnsureAnswerIsRecordedNotApplied(t *testing.T) {
	s := &fakeStore{cands: []logsstore.DecisionCandidate{cand("a")}}
	run(t, s, &fakeClient{replies: []reply{answer("customer", 0.89)}}, cfg)
	if s.asks[0].Result != "unsure" {
		t.Fatalf("%+v", s.asks[0])
	}
}

func TestRefusalIsFailed(t *testing.T) {
	s := &fakeStore{cands: []logsstore.DecisionCandidate{cand("a")}}
	run(t, s, &fakeClient{replies: []reply{{body: []byte(`{"answers":[{"type":"refusal"}]}`)}}}, cfg)
	if a := s.asks[0]; a.Result != "failed" || a.Choice != "" || a.Confidence != 0 {
		t.Fatalf("%+v", a)
	}
}

func TestFailedClassDoesNotBlockQueue(t *testing.T) {
	s := &fakeStore{cands: []logsstore.DecisionCandidate{cand("a"), cand("b")}}
	c := &fakeClient{replies: []reply{
		{err: &decisions.StatusError{StatusCode: 400}}, answer("operator", 0.99)}}
	run(t, s, c, cfg)
	if len(s.asks) != 2 || s.asks[0].Result != "failed" || s.asks[1].Result != "applied" || len(c.bodies) != 2 {
		t.Fatalf("%+v", s.asks)
	}
}

func TestMalformedResponseIsFailed(t *testing.T) {
	s := &fakeStore{cands: []logsstore.DecisionCandidate{cand("a")}}
	run(t, s, &fakeClient{replies: []reply{{body: []byte(`not json`)}}}, cfg)
	if s.asks[0].Result != "failed" {
		t.Fatalf("%+v", s.asks)
	}
}

func TestFatalErrorEndsPass(t *testing.T) {
	s := &fakeStore{cands: []logsstore.DecisionCandidate{cand("a"), cand("b")}}
	c := &fakeClient{replies: []reply{{err: &decisions.StatusError{StatusCode: 401}}}}
	run(t, s, c, cfg)
	if len(s.asks) != 0 || len(c.bodies) != 1 {
		t.Fatalf("asks=%v calls=%d", s.asks, len(c.bodies))
	}
}

func TestRetryableErrorRecordsNothing(t *testing.T) {
	for _, e := range []error{&decisions.StatusError{StatusCode: 503}, errors.New("dial tcp: refused")} {
		s := &fakeStore{cands: []logsstore.DecisionCandidate{cand("a"), cand("b")}}
		c := &fakeClient{replies: []reply{{err: e}}}
		run(t, s, c, cfg)
		if len(s.asks) != 0 || len(c.bodies) != 1 {
			t.Fatalf("%v: asks=%v calls=%d", e, s.asks, len(c.bodies))
		}
	}
}

func TestWaitsForVector(t *testing.T) {
	g := cfg
	g.Grouping = true
	s := &fakeStore{embedModel: "m", cands: []logsstore.DecisionCandidate{{Key: "a"}}}
	c := &fakeClient{}
	run(t, s, c, g)
	if len(c.bodies) != 0 || len(s.asks) != 0 {
		t.Fatal("asked a class with no vector")
	}
}

func TestZeroShotWhenGroupingOff(t *testing.T) {
	s := &fakeStore{cands: []logsstore.DecisionCandidate{cand("a")}}
	c := &fakeClient{replies: []reply{answer("customer", 1)}}
	run(t, s, c, cfg)
	want, _ := decide.BuildRequest(cfg.Model, s.cands[0].Class, nil)
	if !bytes.Equal(c.bodies[0], want) {
		t.Fatal("request is not zero-shot")
	}
}

func TestEmptyPoolIsZeroShotWhenGroupingOn(t *testing.T) {
	g := cfg
	g.Grouping = true
	s := &fakeStore{embedModel: "m", cands: []logsstore.DecisionCandidate{cand("a")}}
	c := &fakeClient{replies: []reply{answer("customer", 1)}}
	run(t, s, c, g)
	want, _ := decide.BuildRequest(cfg.Model, s.cands[0].Class, nil)
	if !bytes.Equal(c.bodies[0], want) {
		t.Fatal("empty pool did not give a zero-shot request")
	}
}

func TestCostIsRecorded(t *testing.T) {
	var costs []int64
	var results []string
	cf := cfg
	cf.Metrics = &Metrics{Cost: func(m int64) { costs = append(costs, m) }, Result: func(r string) { results = append(results, r) }}
	s := &fakeStore{cands: []logsstore.DecisionCandidate{cand("a")}}
	run(t, s, &fakeClient{replies: []reply{answer("customer", 0.95)}}, cf)
	if s.asks[0].CostMicros != 2000000 || len(costs) != 1 || costs[0] != 2000000 || len(results) != 1 || results[0] != "applied" {
		t.Fatalf("%+v %v %v", s.asks[0], costs, results)
	}
}

func TestLateIsCountedAsReturned(t *testing.T) {
	var results []string
	cf := cfg
	cf.Metrics = &Metrics{Result: func(r string) { results = append(results, r) }}
	s := &fakeStore{recordRes: "late", cands: []logsstore.DecisionCandidate{cand("a")}}
	run(t, s, &fakeClient{replies: []reply{answer("customer", 0.95)}}, cf)
	if len(results) != 1 || results[0] != "late" {
		t.Fatal(results)
	}
}

func TestStoreErrorIsReturned(t *testing.T) {
	s := &fakeStore{err: errors.New("db")}
	if err := New(s, &fakeClient{}, cfg).Run(context.Background(), 5); err == nil {
		t.Fatal("want error")
	}
}
