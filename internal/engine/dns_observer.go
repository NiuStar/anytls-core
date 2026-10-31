package engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http/httptrace"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

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

// Embedding the concrete transport preserves Referrer and idle-connection
// lifecycle interfaces used by the SDK reference manager; interface embedding
// would silently lose them and alter detour/connection retention semantics.
type observedHTTPS struct {
	*transport.HTTPSTransport
	metrics *DNSMetrics
}

var (
	_ adapter.DNSTransport         = (*observedHTTPS)(nil)
	_ adapter.Referrer             = (*observedHTTPS)(nil)
	_ adapter.IdleConnectionKeeper = (*observedHTTPS)(nil)
)

func newObservedHTTPS(ctx context.Context, logger log.ContextLogger, tag string, options option.RemoteHTTPSDNSServerOptions) (adapter.DNSTransport, error) {
	upstream, err := transport.NewHTTPS(ctx, logger, tag, options)
	if err != nil {
		return nil, err
	}
	metrics, _ := ctx.Value(dnsMetricsContextKey{}).(*DNSMetrics)
	if metrics == nil {
		return upstream, nil
	}
	return wrapHTTPS(upstream, metrics)
}

func wrapHTTPS(upstream adapter.DNSTransport, metrics *DNSMetrics) (adapter.DNSTransport, error) {
	if metrics == nil {
		return upstream, nil
	}
	concrete, ok := upstream.(*transport.HTTPSTransport)
	if !ok || concrete == nil {
		return nil, fmt.Errorf("HTTPS metrics: unexpected transport implementation")
	}
	return &observedHTTPS{HTTPSTransport: concrete, metrics: metrics}, nil
}

func (t *observedHTTPS) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	start, qtype := time.Now(), dnsMetricQType(q)
	response, err := t.HTTPSTransport.Exchange(t.metrics.traceContext(ctx), q)
	t.metrics.complete(qtype, response, err, time.Since(start))
	return response, err
}

func (t *observedHTTPS) ExchangeAsync(ctx context.Context, q *dns.Msg, callback func(*dns.Msg, error)) {
	start, qtype := time.Now(), dnsMetricQType(q)
	// Delegate directly to the SDK async method, not to our Exchange: exactly
	// one observation at completion, before forwarding the untouched callback.
	t.HTTPSTransport.ExchangeAsync(t.metrics.traceContext(ctx), q, func(response *dns.Msg, err error) {
		t.metrics.complete(qtype, response, err, time.Since(start))
		callback(response, err)
	})
}

func (m *DNSMetrics) traceContext(ctx context.Context) context.Context {
	// WithClientTrace composes existing callbacks; never replace caller tracing.
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: m.gotConn})
}
func (m *DNSMetrics) gotConn(info httptrace.GotConnInfo) {
	m.mu.Lock()
	m.connections.Acquisitions++
	if info.Reused {
		m.connections.Reused++
	} else {
		m.connections.New++
	}
	if info.WasIdle {
		m.connections.WasIdle++
	}
	m.mu.Unlock()
}
func dnsMetricQType(q *dns.Msg) dnsmetrics.QType {
	if q != nil && len(q.Question) > 0 {
		switch q.Question[0].Qtype {
		case dns.TypeA:
			return dnsmetrics.A
		case dns.TypeAAAA:
			return dnsmetrics.AAAA
		}
	}
	return dnsmetrics.OtherQType
}
func (m *DNSMetrics) complete(qtype dnsmetrics.QType, response *dns.Msg, err error, elapsed time.Duration) {
	if m == nil {
		return
	}
	m.store.Observe(dnsmetrics.UpstreamAttempt, qtype, dnsMetricOutcome(response, err), elapsed)
}
func dnsMetricOutcome(response *dns.Msg, err error) dnsmetrics.Outcome {
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return dnsmetrics.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return dnsmetrics.Timeout
		}
		var cert *tls.CertificateVerificationError
		var unknown x509.UnknownAuthorityError
		var hostname x509.HostnameError
		var invalid x509.CertificateInvalidError
		var record tls.RecordHeaderError
		if errors.As(err, &cert) || errors.As(err, &unknown) || errors.As(err, &hostname) || errors.As(err, &invalid) || errors.As(err, &record) {
			return dnsmetrics.TLSFailure
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return dnsmetrics.Timeout
		}
		// SDK HTTP status errors (including 503) have no typed status. Do not parse
		// strings, and never interpret an unavailable HTTP503 bucket as success.
		return dnsmetrics.OtherError
	}
	if response == nil {
		return dnsmetrics.OtherError
	}
	switch response.Rcode {
	case dns.RcodeSuccess:
		return dnsmetrics.NoError
	case dns.RcodeNameError:
		return dnsmetrics.NXDomain
	case dns.RcodeServerFailure:
		return dnsmetrics.ServFail
	default:
		return dnsmetrics.OtherRCode
	}
}
