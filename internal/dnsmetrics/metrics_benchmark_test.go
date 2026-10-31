package dnsmetrics

import (
	"testing"
	"time"
)

var benchmarkSnapshot Snapshot

func BenchmarkObserve(b *testing.B) {
	var s Store
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Observe(UpstreamAttempt, A, NoError, 7*time.Millisecond)
	}
	b.StopTimer()
	if s.Snapshot().Layers[UpstreamAttempt].Total != uint64(b.N) {
		b.Fatal("lost observations")
	}
}

// Cold includes constructing a fresh store, unlike steady-state Observe.
func BenchmarkObserveCold(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var s Store
		s.Observe(UpstreamAttempt, A, NoError, 7*time.Millisecond)
	}
}

func BenchmarkObserveDisabled(b *testing.B) {
	var s *Store
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.Observe(UpstreamAttempt, A, NoError, 7*time.Millisecond)
	}
}

func BenchmarkObserveParallel(b *testing.B) {
	var s Store
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.Observe(UpstreamAttempt, A, NoError, 7*time.Millisecond)
		}
	})
	b.StopTimer()
	if s.Snapshot().Layers[UpstreamAttempt].Total != uint64(b.N) {
		b.Fatal("lost observations")
	}
}

func BenchmarkSnapshot(b *testing.B) {
	var s Store
	s.Observe(UpstreamAttempt, A, NoError, time.Millisecond)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkSnapshot = s.Snapshot()
	}
}
