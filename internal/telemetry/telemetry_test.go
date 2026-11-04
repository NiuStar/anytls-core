package telemetry

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestSnapshotCountsOnlyObservedProbeIntervals(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	s := New("")
	s.Record(now.Add(-time.Minute), now.Add(-time.Minute+2*time.Second), nil)
	s.Record(now.Add(-time.Second), now, context.DeadlineExceeded)
	got := s.Snapshot(now)
	if got.Network.Attempts != 2 || got.Network.Succeeded != 1 || got.Network.SampleSuccessRatio == nil || *got.Network.SampleSuccessRatio != .5 || got.Network.ObservedProbeSeconds != 3 {
		t.Fatalf("real sample denominator/coverage lost: %+v", got.Network)
	}
	if got.Network.LatencyMS != nil || got.Network.State != "FAILED" || got.Network.Availability24h != nil {
		t.Fatalf("failure/SLA invented: %+v", got.Network)
	}
	if len(got.Bins) != 288 || got.Traffic.DownloadBPS != nil || got.Traffic.RecordedDownloadBytes != nil || got.Traffic.Quality != "NOT_OBSERVED" {
		t.Fatalf("unobserved bytes invented: %+v", got)
	}
	var attempts int
	var observed float64
	for _, b := range got.Bins {
		attempts += b.Attempts
		observed += b.ObservedProbeSeconds
		if b.DownloadBytes != nil || b.UploadBytes != nil {
			t.Fatal("invented bytes")
		}
	}
	if attempts != 2 || observed != 3 {
		t.Fatalf("bins disagree: %d %f", attempts, observed)
	}
}

func TestEmptyAndStaleAreNotCurrentSuccess(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	s := New("")
	if g := s.Snapshot(now); g.Network.SampleSuccessRatio != nil || g.Network.State != "NOT_OBSERVED" {
		t.Fatal(g.Network)
	}
	s.Record(now.Add(-3*time.Minute), now.Add(-3*time.Minute+time.Second), nil)
	if g := s.Snapshot(now); g.Network.State != "STALE" || g.Network.LatencyMS != nil {
		t.Fatal(g.Network)
	}
	s.Record(now.Add(-time.Second), now, nil)
	if g := s.Snapshot(now); g.Network.State != "OK" || g.Network.LatencyMS == nil || *g.Network.LatencyMS != 1000 {
		t.Fatal(g.Network)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = s.Snapshot(now)
			}
		}()
	}
	wg.Wait()
}
