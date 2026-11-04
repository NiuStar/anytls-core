package telemetry

import (
	"context"
	"testing"
	"time"
)

func TestWindowBoundariesCoverageClippingAndSnapshotIsolation(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	start := now.Add(-24 * time.Hour)
	s := New("")
	s.Record(start.Add(-time.Second), start, nil) // exact left boundary excluded
	s.Record(start.Add(time.Second), start.Add(3*time.Second), nil)
	boundary := start.Add(5 * time.Minute)
	s.Record(boundary.Add(-time.Second), boundary.Add(time.Second), context.DeadlineExceeded)
	s.Record(now.Add(time.Second), now.Add(2*time.Second), nil) // not from the future
	g := s.Snapshot(now)
	if g.Network.Attempts != 2 || g.Network.ObservedProbeSeconds != 4 || g.Bins[0].Attempts != 1 || g.Bins[1].Attempts != 1 || g.Bins[0].ObservedProbeSeconds != 3 || g.Bins[1].ObservedProbeSeconds != 1 {
		t.Fatalf("boundary accounting: %+v / %+v", g.Network, g.Bins[:2])
	}
	for i, b := range g.Bins {
		if !b.Start.Equal(start.Add(time.Duration(i)*5*time.Minute)) || b.End.Sub(b.Start) != 5*time.Minute {
			t.Fatal("bins not consecutive", i)
		}
	}
	g.Bins[0].Attempts = 12345
	if got := s.Snapshot(now); got.Bins[0].Attempts != 1 {
		t.Fatal("snapshot aliases store")
	}
	// Clipping a real execution straddling the left window counts only its in-window second.
	clipped := New("")
	clipped.Record(start.Add(-time.Second), start.Add(time.Second), nil)
	if g = clipped.Snapshot(now); g.Network.ObservedProbeSeconds != 1 || g.Network.Attempts != 1 {
		t.Fatal(g.Network)
	}
}

func TestInvalidAndOverlappingIntervalsNeverInflateCoverage(t *testing.T) {
	now := time.Now()
	s := New("")
	s.Record(now, now.Add(time.Second), nil)
	s.Record(now, now.Add(2*time.Second), nil)
	s.Record(now.Add(3*time.Second), now.Add(2*time.Second), nil)
	s.Record(now.Add(2*time.Second), now.Add(time.Hour), nil)
	if g := s.Snapshot(now.Add(time.Hour)); g.Network.Attempts != 1 || g.Network.ObservedProbeSeconds != 1 {
		t.Fatal(g.Network)
	}
}
