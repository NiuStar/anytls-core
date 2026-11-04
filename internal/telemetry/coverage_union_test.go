package telemetry

import (
	"context"
	"path/filepath"
	"testing"
	"time"
	"unsafe"
)

// Original metrics-r3 negative fixture, unchanged except gofmt.
func TestR4RollbackCoverageUnion(t *testing.T) {
	// Serial 60-second sampler. At second probe wall clock rolls back 120s.
	// Third completion has same wall interval as first, but distinct monotonic ext.
	base := time.Now().Add(-4 * time.Minute)
	s := New(filepath.Join(t.TempDir(), "history.json"))
	defer s.Close(context.Background())
	s.Record(base, base.Add(10*time.Millisecond), nil)
	second := base.Add(time.Minute)
	end := second.Add(10 * time.Millisecond)
	*(*uint64)(unsafe.Pointer(&second)) -= uint64(120) << 30
	*(*uint64)(unsafe.Pointer(&end)) -= uint64(120) << 30
	s.Record(second, end, context.DeadlineExceeded)
	third := base.Add(2 * time.Minute)
	thirdEnd := third.Add(10 * time.Millisecond)
	*(*uint64)(unsafe.Pointer(&third)) -= uint64(120) << 30
	*(*uint64)(unsafe.Pointer(&thirdEnd)) -= uint64(120) << 30
	if third.UTC() != base.UTC() || thirdEnd.Sub(third) != 10*time.Millisecond {
		t.Fatal("invalid fixture")
	}
	s.Record(third, thirdEnd, nil)
	g := s.Snapshot(time.Now())
	t.Logf("attempts=%d success=%d coverage=%g clock=%s", g.Network.Attempts, g.Network.Succeeded, g.Network.ObservedProbeSeconds, g.Network.ClockStatus)
	if g.Network.Attempts != 3 || g.Network.Succeeded != 2 {
		t.Fatal("completed outcome lost")
	}
	if g.Network.ObservedProbeSeconds > 0.010000001 {
		t.Errorf("overlapping wall intervals double counted: got %g; union <=0.01", g.Network.ObservedProbeSeconds)
	}
	flushStore(t, s)
	r := New(s.path)
	defer r.Close(context.Background())
	reloaded := r.Snapshot(time.Now())
	t.Logf("restart attempts=%d coverage=%g clock=%s history=%s", reloaded.Network.Attempts, reloaded.Network.ObservedProbeSeconds, reloaded.Network.ClockStatus, reloaded.Network.HistoryStatus)
	if reloaded.Network.Attempts != 3 || reloaded.Network.ObservedProbeSeconds > 0.010000001 {
		t.Error("restart preserves duplicate wall coverage", reloaded.Network)
	}
}

func TestR4CoverageUnionBeforeBinClipping(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	begin := now.Add(-24 * time.Hour)
	boundary := begin.Add(5 * time.Minute)
	row := func(start, end time.Time, unknown bool) sample {
		return sample{Start: start, End: end, Outcome: "OK", ElapsedNS: int64(end.Sub(start)), ClockUnknown: unknown}
	}
	s := New("")
	// Unsorted, nested and partially overlapping known intervals. Unknown must
	// neither add coverage nor bridge the gap; outcome counts remain literal.
	s.rows = []sample{
		row(boundary.Add(-time.Second), boundary.Add(2*time.Second), false),
		row(begin.Add(-time.Second), begin.Add(time.Second), false),
		row(boundary.Add(-2*time.Second), boundary.Add(time.Second), false),
		row(boundary, boundary.Add(time.Second), false),
		row(boundary.Add(3*time.Second), boundary.Add(4*time.Second), false),
		row(boundary.Add(time.Second), boundary.Add(4*time.Second), true),
	}
	g := s.Snapshot(now)
	if g.Network.Attempts != 6 || g.Network.Succeeded != 6 || g.Network.ObservedProbeSeconds != 6 || g.Bins[0].ObservedProbeSeconds != 3 || g.Bins[1].ObservedProbeSeconds != 3 {
		t.Fatalf("union/clipping mismatch: %+v / %+v", g.Network, g.Bins[:2])
	}
	if g.SchemaVersion != 1 || g.Network.ClockStatus != "DISCONTINUITY" {
		t.Fatal("schema or unknown semantics changed", g)
	}
}
