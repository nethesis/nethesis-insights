// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package budget

import (
	"context"
	"sync"
	"testing"
	"time"
)

type fakeLedger struct {
	spendMicros int64
	calls       map[string]int
	since       int64
}

func (f *fakeLedger) DailySpendMicros(_ context.Context, since int64) (int64, error) {
	f.since = since
	return f.spendMicros, nil
}

func (f *fakeLedger) SystemCallsSince(_ context.Context, systemID string, since int64) (int, error) {
	f.since = since
	return f.calls[systemID], nil
}

func at(s string) func() int64 {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return func() int64 { return t.UnixMilli() }
}

func TestSystemCallCapSuppresses(t *testing.T) {
	ledger := &fakeLedger{calls: map[string]int{"sys1": 12, "sys2": 11}}
	c := New(ledger, Config{MaxCallsPerSystemPerDay: 12}, at("2026-09-01T14:00:00Z"))

	v, err := c.Check(context.Background(), "sys1")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if v.Suppressed != SuppressedSystemCap {
		t.Fatalf("expected the cap to suppress, got %+v", v)
	}

	// One call short of the cap still passes: the cap is a ceiling, not a
	// budget to be left unspent.
	if v, _ := c.Check(context.Background(), "sys2"); v.Suppressed != "" {
		t.Fatalf("expected sys2 to pass, got %+v", v)
	}
}

// Both limits are counted from the start of the UTC day, off the ledger. An
// in-process counter would reset on restart, which would make a crash loop a
// way to spend without limit.
func TestLimitsCountFromStartOfUTCDay(t *testing.T) {
	ledger := &fakeLedger{calls: map[string]int{}}
	c := New(ledger, Config{MaxCallsPerSystemPerDay: 5}, at("2026-09-01T14:37:11Z"))
	if _, err := c.Check(context.Background(), "sys1"); err != nil {
		t.Fatalf("check: %v", err)
	}

	want, _ := time.Parse(time.RFC3339, "2026-09-01T00:00:00Z")
	if ledger.since != want.UnixMilli() {
		t.Fatalf("counted from %d, want midnight UTC %d", ledger.since, want.UnixMilli())
	}
}

// The spend cap degrades the gate rather than stopping it. A cap that blinded
// the system to a break-in would be worse than the invoice it prevents.
func TestSpendCapDegradesToSecurityOnly(t *testing.T) {
	ledger := &fakeLedger{spendMicros: 5_000_000, calls: map[string]int{}}
	c := New(ledger, Config{DailySpendCapUSD: 5}, at("2026-09-01T14:00:00Z"))

	v, err := c.Check(context.Background(), "sys1")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !v.SecurityOnly {
		t.Fatal("expected the spend cap to degrade the gate")
	}
	if v.Suppressed != "" {
		t.Fatalf("the spend cap must not suppress the window outright, got %q", v.Suppressed)
	}

	ledger.spendMicros = 4_999_999
	if v, _ := c.Check(context.Background(), "sys1"); v.SecurityOnly {
		t.Fatal("expected no degrade below the cap")
	}
}

func TestZeroMeansUnlimited(t *testing.T) {
	ledger := &fakeLedger{spendMicros: 1 << 40, calls: map[string]int{"sys1": 10000}}
	c := New(ledger, Config{}, at("2026-09-01T14:00:00Z"))

	v, err := c.Check(context.Background(), "sys1")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if v.Suppressed != "" || v.SecurityOnly {
		t.Fatalf("unset limits must not restrict anything, got %+v", v)
	}
}

func TestAcquireBoundsConcurrency(t *testing.T) {
	c := New(&fakeLedger{calls: map[string]int{}}, Config{MaxConcurrency: 2}, at("2026-09-01T14:00:00Z"))
	ctx := context.Background()

	r1, err := c.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	r2, err := c.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	// The third waits until one of the first two is released.
	var wg sync.WaitGroup
	got := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		r3, err := c.Acquire(ctx)
		if err != nil {
			t.Errorf("acquire: %v", err)
			return
		}
		close(got)
		r3()
	}()

	select {
	case <-got:
		t.Fatal("a third call was admitted past a concurrency of 2")
	case <-time.After(20 * time.Millisecond):
	}

	r1()
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("releasing a slot did not admit the waiting call")
	}
	wg.Wait()
	r2()
}

// A cancelled context must not leave a caller blocked on a slot forever.
func TestAcquireRespectsContext(t *testing.T) {
	c := New(&fakeLedger{calls: map[string]int{}}, Config{MaxConcurrency: 1}, at("2026-09-01T14:00:00Z"))
	release, err := c.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer release()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Acquire(ctx); err == nil {
		t.Fatal("expected a cancelled context to abandon the wait")
	}
}
