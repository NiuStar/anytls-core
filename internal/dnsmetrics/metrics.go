// Package dnsmetrics aggregates completed DNS events without names or raw errors.
// It does not instrument a resolver or infer cache hits, retries, or transport errors.
package dnsmetrics

import (
	"sync"
	"time"
)

// Kind separates completed logical queries from completed upstream attempts.
// Retries may produce several UpstreamAttempt events for one QueryCompleted.
type Kind uint8

const (
	QueryCompleted Kind = iota
	UpstreamAttempt
	OtherKind
	KindCount
)

// QType is a category, not a DNS wire type. Callers must map A/AAAA explicitly.
type QType uint8

const (
	A QType = iota
	AAAA
	OtherQType
	QTypeCount
)

// Outcome is classified by the caller using typed results/errors, not raw text.
// The first four values mean a DNS reply was received; NoError means RCODE 0,
// not that every received reply was successful. Transport failures are separate.
type Outcome uint8

const (
	NoError Outcome = iota
	NXDomain
	ServFail
	OtherRCode
	Timeout
	Canceled
	TLSFailure
	HTTP503
	OtherError
	OutcomeCount
)

// DurationBucketCount includes the final unbounded overflow bucket.
const DurationBucketCount = 8

func durationUpperBounds() [DurationBucketCount - 1]time.Duration {
	return [DurationBucketCount - 1]time.Duration{time.Millisecond, 5 * time.Millisecond, 10 * time.Millisecond, 25 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond, time.Second}
}

// Counters has independent, fixed-cardinality marginals, not cross-product labels.
type Counters struct {
	Total           uint64                      `json:"total"`
	QTypes          [QTypeCount]uint64          `json:"qtypes"`
	Outcomes        [OutcomeCount]uint64        `json:"outcomes"`
	DurationBuckets [DurationBucketCount]uint64 `json:"duration_buckets"`
	MaxDuration     time.Duration               `json:"max_duration_ns"`
}

// Snapshot is an independent, consistent copy from one critical section.
// Arrays use the enum order above. Duration buckets are disjoint: <=1ms,
// (1ms,5ms], (5ms,10ms], (10ms,25ms], (25ms,50ms], (50ms,100ms],
// (100ms,1s], >1s. They are not cumulative and do not imply an exact percentile.
type Snapshot struct {
	Layers              [KindCount]Counters                    `json:"layers"`
	DurationUpperBounds [DurationBucketCount - 1]time.Duration `json:"duration_upper_bounds_ns"`
}

// Store's zero value is ready to use. Do not copy a Store after first use.
type Store struct {
	mu     sync.Mutex
	layers [KindCount]Counters
}

// Observe records one completed event with O(1) bounded work and no allocation.
// Callers supply elapsed time (prefer time.Since on a monotonic start time).
// Negative durations clamp to zero; unknown enums go to their Other category.
// A nil receiver disables collection. No clocks, logs, files, or goroutines run.
func (s *Store) Observe(kind Kind, qtype QType, outcome Outcome, elapsed time.Duration) {
	if s == nil {
		return
	}
	if kind >= KindCount {
		kind = OtherKind
	}
	if qtype >= QTypeCount {
		qtype = OtherQType
	}
	if outcome >= OutcomeCount {
		outcome = OtherError
	}
	if elapsed < 0 {
		elapsed = 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := &s.layers[kind]
	c.Total++
	c.QTypes[qtype]++
	c.Outcomes[outcome]++
	bucket := 0
	for _, upper := range durationUpperBounds() {
		if elapsed <= upper {
			break
		}
		bucket++
	}
	c.DurationBuckets[bucket]++
	if elapsed > c.MaxDuration {
		c.MaxDuration = elapsed
	}
}

func (s *Store) Snapshot() Snapshot {
	if s == nil {
		return Snapshot{DurationUpperBounds: durationUpperBounds()}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return Snapshot{Layers: s.layers, DurationUpperBounds: durationUpperBounds()}
}
