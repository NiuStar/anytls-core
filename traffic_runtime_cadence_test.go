package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// writeOwnedTraffic is a test-owned sink, not a copy of the privileged store
// contract. Success follows real write, file sync, close, rename and directory
// sync. The caller observes completion only after every required operation.
func writeOwnedTraffic(dir string, s ts.Snapshot) error {
	data, err := ts.Encode(s)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "traffic-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(dir, "traffic.json")); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	closeErr := d.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func joinTrafficReporter(t *testing.T, p *runTrafficReporter) {
	t.Helper()
	select {
	case <-p.done:
	case <-time.After(3 * time.Second): // Existing reporter-fixture join bound, not a disk throughput target.
		t.Error("reporter did not terminate after fixture release")
	}
}

func TestRunTrafficOwnedDurableSink(t *testing.T) {
	// Cadence/max-rate belongs to the deterministic policy tests above; disk
	// latency is not a minimum-writes SLA. Keep the original 1.2s watchdog for
	// one actual durable publication, then stop and inspect its terminal bytes.
	dir := t.TempDir()
	p := newRunTrafficReporter()
	p.running.Store(true)
	p.counter.Upload(4096)
	p.counter.Download(8192)
	header := cadenceHeader()
	published := make(chan ts.Snapshot, 1)
	var calls atomic.Int64
	go p.report(ts.New(p.counter, header), time.Now, func(s ts.Snapshot) error {
		calls.Add(1)
		if err := writeOwnedTraffic(dir, s); err != nil {
			return err
		}
		// A terminal sequence witness, not an assumed count in a time window.
		p.once.Do(func() { close(p.stop) })
		published <- s
		return nil
	})
	defer func() { p.close(); joinTrafficReporter(t, p) }()
	deadline := time.NewTimer(1200 * time.Millisecond)
	defer deadline.Stop()
	var emitted ts.Snapshot
	select {
	case emitted = <-published:
	case <-p.done:
		// Publication and done may both already be ready.
		select {
		case emitted = <-published:
		default:
			t.Fatal("reporter exited without a durable publication")
		}
	case <-deadline.C:
		t.Fatal("no durable publication within original 1.2s watchdog")
	}
	select {
	case <-p.done:
	case <-deadline.C:
		t.Fatal("reporter did not terminate within original 1.2s watchdog")
	}
	if calls.Load() != 1 {
		t.Fatalf("terminal sink invoked %d times", calls.Load())
	}
	data, err := os.ReadFile(filepath.Join(dir, "traffic.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored ts.Snapshot
	if err = ts.Decode(data, &stored); err != nil {
		t.Fatal(err)
	}
	want, err := ts.Encode(emitted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, want) || stored.Header != header || stored.State != "RUNNING" || stored.Upload != "4096" || stored.Download != "8192" {
		t.Fatalf("durable content differs from actual sampler publication: %+v", stored)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "traffic.json" {
		t.Fatalf("temporary publication not cleaned: entries=%v err=%v", entries, err)
	}
	t.Logf("durable terminal publication: calls=%d bytes=%d upload=%s download=%s", calls.Load(), len(data), stored.Upload, stored.Download)
}

func TestRunTrafficOwnedSinkErrorStopsReporter(t *testing.T) {
	// An actual CreateTemp error, not a synthetic codec error or callback error.
	// No directory is created: failure must terminate the real reporter once.
	dir := filepath.Join(t.TempDir(), "missing")
	p := newRunTrafficReporter()
	p.counter.Upload(1)
	var calls atomic.Int64
	errorsSeen := make(chan error, 1)
	go p.report(ts.New(p.counter, cadenceHeader()), time.Now, func(s ts.Snapshot) error {
		calls.Add(1)
		err := writeOwnedTraffic(dir, s)
		select {
		case errorsSeen <- err:
		default:
		}
		return err
	})
	defer func() { p.close(); joinTrafficReporter(t, p) }()
	select {
	case <-p.done:
	case <-time.After(1200 * time.Millisecond):
		t.Fatal("sink failure did not terminate reporter")
	}
	select {
	case err := <-errorsSeen:
		var pathErr *os.PathError
		if !errors.As(err, &pathErr) || !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("underlying filesystem error not propagated: %v", err)
		}
	default:
		t.Fatal("reporter skipped actual owned writer")
	}
	if calls.Load() != 1 {
		t.Fatalf("failed sink retried: calls=%d", calls.Load())
	}
	if _, err := os.Stat(filepath.Join(dir, "traffic.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed publication left a payload: %v", err)
	}
}

func TestRunTrafficBlockedSinkCountersAndClose(t *testing.T) {
	p := newRunTrafficReporter()
	p.running.Store(true)
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	var calls atomic.Int64
	go p.report(ts.New(p.counter, cadenceHeader()), time.Now, func(ts.Snapshot) error {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		return nil
	})
	// Release even on Fatal, then exercise the unchanged production close and
	// join bound. No blocked reporter may outlive this fixture's cleanup.
	defer func() { p.once.Do(func() { close(p.stop) }); unblock(); p.close(); joinTrafficReporter(t, p) }()
	select {
	case <-entered:
	case <-time.After(1200 * time.Millisecond):
		t.Fatal("reporter did not enter held sink")
	}
	counted := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			p.counter.Upload(1)
			p.counter.Download(2)
		}
		close(counted)
	}()
	select {
	case <-counted:
	case <-time.After(1200 * time.Millisecond):
		t.Fatal("counter callbacks blocked behind owned sink")
	}
	if up, down, saturated := p.counter.Totals(); up != 1000 || down != 2000 || saturated {
		t.Fatalf("atomic counter ownership lost: up=%d down=%d saturated=%v", up, down, saturated)
	}
	closed := make(chan struct{})
	go func() { p.close(); close(closed) }()
	select {
	case <-p.stop:
	case <-time.After(1200 * time.Millisecond):
		t.Fatal("close did not invalidate reporter while sink held")
	}
	select {
	case <-p.done:
		t.Fatal("reporter claimed completion while sink still held")
	default:
	}
	// Stop is established before releasing IO, so no second publish is legal.
	// Do not hold for the production 1s timeout merely to test this join path.
	unblock()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("close failed to return after sink release")
	}
	joinTrafficReporter(t, p)
	if calls.Load() != 1 {
		t.Fatalf("shutdown retried held sink: calls=%d", calls.Load())
	}
}
