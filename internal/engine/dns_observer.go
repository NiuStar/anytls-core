package engine

import (
	"context"
	"sync"
	"time"

	"github.com/NiuStar/anytls-core/internal/dnsmetrics"
)

type dnsMetricsContextKey struct{}

// DNSMetrics is a run-owned, fixed-cardinality collector. Its zero value is ready
// to use. Do not copy it after use. No names, messages or errors are retained.
type DNSMetrics struct {
	store       dnsmetrics.Store
	mu          sync.Mutex
	connections DNSConnectionMetrics
}

// WithDNSMetrics opts one engine run into HTTPS upstream instrumentation. The
// ordinary context value survives the fresh SDK service-registry boundary.
// A nil collector leaves the original HTTPS constructor and exchange path intact.
func WithDNSMetrics(ctx context.Context, metrics *DNSMetrics) context.Context {
	return context.WithValue(ctx, dnsMetricsContextKey{}, metrics)
}

// DNSConnectionMetrics counts HTTP connection-acquisition events, not exchanges
// or unique sockets. Retries may yield multiple events; dial failures yield none.
type DNSConnectionMetrics struct {
	Acquisitions uint64 `json:"acquisitions"`
	New          uint64 `json:"new"`
	Reused       uint64 `json:"reused"`
	WasIdle      uint64 `json:"was_idle"`
}

// DNSMetricsSnapshot v1 contains only the actually instrumented upstream layer.
// Store and connection sections are individually coherent but sampled separately;
// no cross-section equality is promised, even after completion (HTTP retries).
// Outcomes and QTypes use dnsmetrics enum order; HTTP503 is unavailable in the
// SDK's untyped status error and is reported as OtherError, never parsed as text.
type DNSMetricsSnapshot struct {
	Version             uint8                                             `json:"version"`
	Enabled             bool                                              `json:"enabled"`
	Hijacked            string                                            `json:"hijacked"`
	CacheHit            string                                            `json:"cache_hit"`
	Coalesced           string                                            `json:"coalesced"`
	HTTPStatus          string                                            `json:"http_status"`
	UpstreamExchange    dnsmetrics.Counters                               `json:"upstream_exchange"`
	DurationUpperBounds [dnsmetrics.DurationBucketCount - 1]time.Duration `json:"duration_upper_bounds_ns"`
	Connections         DNSConnectionMetrics                              `json:"connections"`
}

func (m *DNSMetrics) Snapshot() DNSMetricsSnapshot {
	s := (*dnsmetrics.Store)(nil).Snapshot()
	result := DNSMetricsSnapshot{Version: 1, Enabled: m != nil, Hijacked: "NOT_OBSERVED", CacheHit: "NOT_OBSERVED", Coalesced: "NOT_OBSERVED", HTTPStatus: "NOT_OBSERVED", DurationUpperBounds: s.DurationUpperBounds}
	if m != nil {
		s = m.store.Snapshot()
		result.UpstreamExchange = s.Layers[dnsmetrics.UpstreamAttempt]
		m.mu.Lock()
		result.Connections = m.connections
		m.mu.Unlock()
	}
	return result
}
