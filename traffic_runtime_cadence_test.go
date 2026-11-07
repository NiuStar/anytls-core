package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	ts "github.com/NiuStar/anytls-core/internal/trafficstats"
)

func cadenceHeader() cr.Header {
	return cr.Header{SchemaVersion: 1, ConfigIdentity: strings.Repeat("a", 64), Binding: cr.Binding{InstanceID: strings.Repeat("1", 32), Generation: strings.Repeat("2", 32), ManifestID: strings.Repeat("3", 64)}, RuntimeSHA256: strings.Repeat("4", 64), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
}

// This uses the real reporter loop, sampler and codec; only the owned sink is
// substituted. No production store/helper access or privileged UID is needed.
func TestRunTrafficChangedPayloadBeforeOneSecond(t *testing.T) {
	p := newRunTrafficReporter()
	sampler := ts.New(p.counter, cadenceHeader())
	updates := make(chan ts.Snapshot, 32)
	go p.report(sampler, time.Now, func(s ts.Snapshot) error { updates <- s; return nil })
	defer p.close()
	await := func(want func(ts.Snapshot) bool) ts.Snapshot {
		t.Helper()
		deadline := time.NewTimer(time.Second)
		defer deadline.Stop()
		for {
			select {
			case s := <-updates:
				if want(s) {
					return s
				}
			case <-deadline.C:
				t.Fatal("real producer did not publish changed payload within one second")
				return ts.Snapshot{}
			}
		}
	}
	await(func(s ts.Snapshot) bool { return s.State == "STARTING" })
	p.running.Store(true)
	p.counter.Upload(4096)
	burst := await(func(s ts.Snapshot) bool { return s.State == "RUNNING" && s.Upload == "4096" })
	zero := await(func(s ts.Snapshot) bool { return s.Rate != nil && s.Rate.Upload == "0" && s.Rate.Download == "0" })
	if zero.Upload != burst.Upload {
		t.Fatal("zero transition lost totals")
	}
	// Now running is established: prove a positive interval followed by zero,
	// rather than merely the startup nil-rate to first-zero transition.
	p.counter.Download(8192)
	await(func(s ts.Snapshot) bool { return s.Rate != nil && s.Rate.Download == "8192" })
	await(func(s ts.Snapshot) bool { return s.Download == "8192" && s.Rate != nil && s.Rate.Download == "0" })
}

func TestTrafficCadenceBoundariesAndIdleHistory(t *testing.T) {
	c := new(ts.Counter)
	sampler := ts.New(c, cadenceHeader())
	var policy trafficPublication
	start := time.Now()
	publications := 0
	var previous time.Time
	for i := 0; i <= int(2*time.Minute/trafficObservationInterval); i++ {
		now := start.Add(time.Duration(i) * trafficObservationInterval)
		if i >= 1 && i <= 4 {
			for n := 0; n < 1000; n++ {
				c.Upload(1)
			}
		}
		snap := sampler.Sample(now, "RUNNING") // Must run even when no publication is due.
		if i == int(2*time.Minute/trafficObservationInterval) {
			if len(snap.History) != 2 || snap.History[0].Upload != "4000" || snap.History[1].Upload != "0" {
				t.Fatalf("idle minute aggregation lost: %+v", snap.History)
			}
		}
		due := policy.due(now, snap)
		if i == 5 && (!due || snap.Rate == nil || snap.Rate.Upload != "0") {
			t.Fatal("burst did not publish zero on next tick")
		}
		if !due {
			continue
		}
		if !previous.IsZero() && now.Sub(previous) < trafficObservationInterval {
			t.Fatal("publication exceeded observation bound")
		}
		previous = now
		publications++
	}
	if publications > 30 {
		t.Fatalf("idle snapshots not coalesced: %d", publications)
	}
	// Exact heartbeat boundary, not sampled_at or elapsed_ns changes each tick.
	var idle trafficPublication
	s := sampler.Sample(start.Add(3*time.Minute), "RUNNING")
	if !idle.due(start, s) || idle.due(start.Add(5*time.Second-time.Nanosecond), s) || !idle.due(start.Add(5*time.Second), s) {
		t.Fatal("heartbeat boundary incorrect")
	}
	s.State = "STARTING"
	if !idle.due(start.Add(5250*time.Millisecond), s) {
		t.Fatal("state transition coalesced away")
	}
}

func TestTrafficCadence250msVersusOneSecond(t *testing.T) {
	for _, interval := range []time.Duration{250 * time.Millisecond, time.Second} {
		c := new(ts.Counter)
		sampler := ts.New(c, cadenceHeader())
		var policy trafficPublication
		start := time.Now()
		sampler.Sample(start, "RUNNING")
		published := 0
		var total cr.Decimal
		for now := interval; now <= time.Second; now += interval {
			// Identical 1000 byte/s input, coalesced at the chosen observation boundary.
			c.Upload(int64(interval / time.Millisecond))
			s := sampler.Sample(start.Add(now), "RUNNING")
			if policy.due(start.Add(now), s) {
				published++
				total = s.Upload
			}
		}
		if total != "1000" || published != int(time.Second/interval) {
			t.Fatalf("interval=%v writes=%d total=%s", interval, published, total)
		}
		t.Logf("observation=%v writes=%d/s totals=%s; counter callbacks unchanged", interval, published, total)
	}
}

func BenchmarkTrafficSampleEncodeFullHistory(b *testing.B) {
	c := new(ts.Counter)
	sampler := ts.New(c, cadenceHeader())
	now := time.Now()
	sampler.Sample(now, "RUNNING")
	for i := 0; i < ts.MaxHistory; i++ {
		now = now.Add(time.Minute)
		c.Upload(1024)
		sampler.Sample(now, "RUNNING")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		now = now.Add(250 * time.Millisecond)
		c.Download(1024)
		s := sampler.Sample(now, "RUNNING")
		if _, e := ts.Encode(s); e != nil {
			b.Fatal(e)
		}
	}
}

func TestRunTrafficLoopSamplesIdleHistory(t *testing.T) {
	p := newRunTrafficReporter()
	p.running.Store(true)
	now := time.Now()
	polls := 0
	var last ts.Snapshot
	go p.report(ts.New(p.counter, cadenceHeader()), func() time.Time {
		at := now.Add(time.Duration(polls) * 30 * time.Second)
		polls++
		return at
	}, func(s ts.Snapshot) error {
		last = s
		if polls == 5 {
			p.once.Do(func() { close(p.stop) })
		}
		return nil
	})
	defer p.close()
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
		t.Fatal("idle sampling fixture stalled")
	}
	if polls != 5 || len(last.History) != 2 || last.History[0].Upload != "0" || last.History[1].Download != "0" {
		t.Fatalf("actual reporter lost idle minute history: polls=%d history=%+v", polls, last.History)
	}
}

func TestRunTrafficSlowSinkDoesNotCatchUp(t *testing.T) {
	p := newRunTrafficReporter()
	p.running.Store(true)
	var previousEnd time.Time
	calls := 0
	var gap time.Duration
	go p.report(ts.New(p.counter, cadenceHeader()), time.Now, func(s ts.Snapshot) error {
		if !previousEnd.IsZero() {
			gap = time.Since(previousEnd)
			close(p.stop)
			return nil
		}
		calls++
		// Let a fixed ticker accumulate a pending event during a slow durable write.
		time.Sleep(350 * time.Millisecond)
		p.counter.Upload(1)
		previousEnd = time.Now()
		return nil
	})
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
		t.Fatal("slow sink fixture stalled")
	}
	if calls != 1 || gap < trafficObservationInterval-10*time.Millisecond {
		t.Fatalf("queued timer caused catch-up write: gap=%v", gap)
	}
}

func TestTrafficFullHistoryMeasuredCost(t *testing.T) {
	// testing.Benchmark reports actual ns/allocs even through the official wrapper,
	// whose intentionally narrow supported flags exclude -bench.
	r := testing.Benchmark(BenchmarkTrafficSampleEncodeFullHistory)
	t.Logf("full-history sample+validate+encode: %s %s", r.String(), r.MemString())
}

func TestRunTrafficOwnedDurableSink(t *testing.T) {
	dir := t.TempDir()
	p := newRunTrafficReporter()
	p.running.Store(true)
	var writes atomic.Int64
	go p.report(ts.New(p.counter, cadenceHeader()), time.Now, func(s ts.Snapshot) error {
		data, e := ts.Encode(s)
		if e != nil {
			return e
		}
		f, e := os.CreateTemp(dir, "traffic-")
		if e != nil {
			return e
		}
		defer os.Remove(f.Name())
		if _, e = f.Write(data); e != nil {
			f.Close()
			return e
		}
		if e = f.Sync(); e != nil {
			f.Close()
			return e
		}
		if e = f.Close(); e != nil {
			return e
		}
		if e = os.Rename(f.Name(), filepath.Join(dir, "traffic.json")); e != nil {
			return e
		}
		d, e := os.Open(dir)
		if e != nil {
			return e
		}
		e = d.Sync()
		d.Close()
		if e == nil {
			writes.Add(1)
		}
		return e
	})
	defer p.close()
	producer := time.NewTicker(5 * time.Millisecond)
	defer producer.Stop()
	end := time.NewTimer(1200 * time.Millisecond)
	defer end.Stop()
loop:
	for {
		select {
		case <-producer.C:
			p.counter.Download(100)
		case <-end.C:
			break loop
		}
	}
	p.close()
	n := writes.Load()
	if n < 3 || n > 5 {
		t.Fatalf("durable publication bound: %d writes/1.2s", n)
	}
	data, e := os.ReadFile(filepath.Join(dir, "traffic.json"))
	if e != nil {
		t.Fatal(e)
	}
	var s ts.Snapshot
	if e = ts.Decode(data, &s); e != nil {
		t.Fatal(e)
	}
	if s.Download == "0" {
		t.Fatal("real atomic counters not in durable payload")
	}
	t.Logf("owned durable sink: %d publications/1.2s; final bytes=%d download=%s", n, len(data), s.Download)
}
