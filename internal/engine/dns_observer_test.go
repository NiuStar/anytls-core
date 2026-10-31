package engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NiuStar/anytls-core/internal/dnsmetrics"
	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	sdns "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func TestDNSMetricsTypedOutcomes(t *testing.T) {
	tests := []struct {
		name     string
		response *dns.Msg
		err      error
		want     dnsmetrics.Outcome
	}{
		{"success", &dns.Msg{}, nil, dnsmetrics.NoError},
		{"nxdomain", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}, nil, dnsmetrics.NXDomain},
		{"servfail", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}}, nil, dnsmetrics.ServFail},
		{"other-rcode", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeRefused}}, nil, dnsmetrics.OtherRCode},
		{"missing", nil, nil, dnsmetrics.OtherError},
		{"canceled", nil, fmt.Errorf("wrapped: %w", context.Canceled), dnsmetrics.Canceled},
		{"deadline", nil, fmt.Errorf("wrapped: %w", context.DeadlineExceeded), dnsmetrics.Timeout},
		{"network-timeout", nil, &net.DNSError{IsTimeout: true}, dnsmetrics.Timeout},
		{"network", nil, &net.OpError{Err: net.ErrClosed}, dnsmetrics.OtherError},
		{"ca", nil, x509.UnknownAuthorityError{}, dnsmetrics.TLSFailure},
		{"hostname", nil, x509.HostnameError{}, dnsmetrics.TLSFailure},
		{"certificate", nil, &tls.CertificateVerificationError{Err: errors.New("private")}, dnsmetrics.TLSFailure},
		{"invalid-cert", nil, x509.CertificateInvalidError{}, dnsmetrics.TLSFailure},
		{"tls-record", nil, tls.RecordHeaderError{}, dnsmetrics.TLSFailure},
		{"untyped-503", nil, errors.New("unexpected status: 503 Service Unavailable"), dnsmetrics.OtherError},
		{"untyped-tls", nil, errors.New("tls: private.example: certificate"), dnsmetrics.OtherError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dnsMetricOutcome(tt.response, tt.err); got != tt.want {
				t.Fatalf("got=%v want=%v", got, tt.want)
			}
		})
	}
	for _, q := range []*dns.Msg{nil, {}, {Question: []dns.Question{{Qtype: dns.TypeTXT}}}} {
		if dnsMetricQType(q) != dnsmetrics.OtherQType {
			t.Fatal("invalid/other question")
		}
	}
	for _, tt := range []struct {
		wire uint16
		want dnsmetrics.QType
	}{{dns.TypeA, dnsmetrics.A}, {dns.TypeAAAA, dnsmetrics.AAAA}} {
		q := new(dns.Msg).SetQuestion("private.invalid.", tt.wire)
		before := q.String()
		if dnsMetricQType(q) != tt.want || q.String() != before {
			t.Fatal("question changed")
		}
	}
}

func TestDNSMetricsTraceComposition(t *testing.T) {
	m := new(DNSMetrics)
	var called int
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { called++ }})
	trace := httptrace.ContextClientTrace(m.traceContext(ctx))
	trace.GotConn(httptrace.GotConnInfo{})
	trace.GotConn(httptrace.GotConnInfo{Reused: true, WasIdle: true})
	s := m.Snapshot()
	if called != 2 || s.Connections != (DNSConnectionMetrics{Acquisitions: 2, New: 1, Reused: 1, WasIdle: 1}) || s.UpstreamExchange.Total != 0 {
		t.Fatalf("trace=%+v caller=%d", s, called)
	}
}

func TestDNSMetricsSchemaIsolationAndDisabled(t *testing.T) {
	var disabled *DNSMetrics
	if disabled.Snapshot().Enabled {
		t.Fatal("nil enabled")
	}
	// Nil completion must not inspect/classify an error or allocate.
	if n := testing.AllocsPerRun(1000, func() { disabled.complete(dnsmetrics.A, nil, panicMetricError{}, 0) }); n != 0 {
		t.Fatalf("disabled allocs=%v", n)
	}
	m := new(DNSMetrics)
	m.complete(dnsmetrics.A, &dns.Msg{}, nil, time.Millisecond)
	s := m.Snapshot()
	s.UpstreamExchange.Total = 999
	if m.Snapshot().UpstreamExchange.Total != 1 {
		t.Fatal("snapshot aliases store")
	}
	b, err := json.Marshal(m.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	want := []string{"version", "enabled", "hijacked", "cache_hit", "coalesced", "http_status", "upstream_exchange", "duration_upper_bounds_ns", "connections"}
	if len(fields) != len(want) {
		t.Fatal(string(b))
	}
	for _, key := range want {
		if _, ok := fields[key]; !ok {
			t.Fatal(key)
		}
	}
	if strings.Contains(string(b), "layers") || strings.Contains(string(b), "private") {
		t.Fatal(string(b))
	}
	if m.Snapshot().Hijacked != "NOT_OBSERVED" || m.Snapshot().CacheHit != "NOT_OBSERVED" || m.Snapshot().Coalesced != "NOT_OBSERVED" || m.Snapshot().HTTPStatus != "NOT_OBSERVED" {
		t.Fatal(string(b))
	}
}

type panicMetricError struct{}

func (panicMetricError) Error() string { panic("raw error inspected") }
func (panicMetricError) Is(error) bool { panic("disabled classified error") }

func TestDNSMetricsConcurrentSnapshot(t *testing.T) {
	m := new(DNSMetrics)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				m.complete(dnsmetrics.A, &dns.Msg{}, nil, time.Millisecond)
				m.gotConn(httptrace.GotConnInfo{Reused: true})
				s := m.Snapshot()
				if s.UpstreamExchange.Total != s.UpstreamExchange.QTypes[dnsmetrics.A] || s.Connections.Acquisitions != s.Connections.New+s.Connections.Reused {
					t.Error("inconsistent section")
				}
			}
		}()
	}
	wg.Wait()
	if m.Snapshot().UpstreamExchange.Total != 8000 || m.Snapshot().Connections.Reused != 8000 {
		t.Fatal(m.Snapshot())
	}
}

func TestDNSMetricsRegistryOptInIsolation(t *testing.T) {
	rawJSON := []byte(`{"dns":{"servers":[{"type":"https","tag":"fixture","server":"127.0.0.1"}]}}`)
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			var m *DNSMetrics
			if enabled {
				m = new(DNSMetrics)
			}
			ctx, opts, err := decodeOptions(WithDNSMetrics(context.Background(), m), rawJSON)
			if err != nil {
				t.Fatal(err)
			}
			upstream, err := service.FromContext[adapter.DNSTransportRegistry](ctx).CreateDNSTransport(ctx, logger.NOP(), "fixture", C.DNSTypeHTTPS, opts.DNS.Servers[0].Options)
			if err != nil {
				t.Fatal(err)
			}
			defer upstream.Reset()
			_, wrapped := upstream.(*observedHTTPS)
			if wrapped != enabled {
				t.Fatalf("wrapped=%t enabled=%t", wrapped, enabled)
			}
			if !enabled {
				if _, ok := upstream.(*transport.HTTPSTransport); !ok {
					t.Fatal("disabled not original concrete")
				}
			}
		})
	}
	first, second := new(DNSMetrics), new(DNSMetrics)
	first.complete(dnsmetrics.A, &dns.Msg{}, nil, 0)
	if second.Snapshot().UpstreamExchange.Total != 0 {
		t.Fatal("run collectors shared")
	}
}

func TestDNSMetricsWrapperTypeAndLifecycle(t *testing.T) {
	upstream := new(transport.HTTPSTransport)
	if got, err := wrapHTTPS(upstream, nil); got != upstream || err != nil {
		t.Fatal("disabled wrapper changed identity")
	}
	if n := testing.AllocsPerRun(1000, func() { _, _ = wrapHTTPS(upstream, nil) }); n != 0 {
		t.Fatal(n)
	}
	if _, err := wrapHTTPS(nil, new(DNSMetrics)); err == nil {
		t.Fatal("unexpected type accepted")
	}
	var typednil *transport.HTTPSTransport
	if _, err := wrapHTTPS(typednil, new(DNSMetrics)); err == nil {
		t.Fatal("nil concrete accepted")
	}
	wrapped, err := wrapHTTPS(upstream, new(DNSMetrics))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := wrapped.(adapter.Referrer); !ok {
		t.Fatal("lost References")
	}
	if _, ok := wrapped.(adapter.IdleConnectionKeeper); !ok {
		t.Fatal("lost idle keeper")
	}
	if !reflect.DeepEqual(wrapped.(adapter.Referrer).References(), upstream.References()) || wrapped.Type() != upstream.Type() || wrapped.Tag() != upstream.Tag() || !reflect.DeepEqual(wrapped.Dependencies(), upstream.Dependencies()) {
		t.Fatal("metadata changed")
	}
}

type dnsMetricFailDialer struct{ err error }

func (d dnsMetricFailDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, d.err
}
func (d dnsMetricFailDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, d.err
}

func TestDNSMetricsAsyncErrorIdentity(t *testing.T) {
	original := errors.New("synthetic private dial error")
	raw := transport.NewHTTPSRaw(sdns.NewTransportAdapter(C.DNSTypeHTTPS, "fixture", nil), logger.NOP(), dnsMetricFailDialer{original}, &url.URL{Scheme: "https", Host: "fixture.invalid"}, http.Header{}, M.ParseSocksaddr("127.0.0.1:443"), nil)
	defer raw.Reset()
	m := new(DNSMetrics)
	w, err := wrapHTTPS(raw, m)
	if err != nil {
		t.Fatal(err)
	}
	q := new(dns.Msg).SetQuestion("private.invalid.", dns.TypeAAAA)
	before := q.String()
	var calls atomic.Int32
	done := make(chan struct{})
	w.ExchangeAsync(context.Background(), q, func(response *dns.Msg, err error) {
		defer close(done)
		calls.Add(1)
		if response != nil || err != original {
			t.Errorf("callback identity response=%p err_same=%t", response, err == original)
		}
		if m.Snapshot().UpstreamExchange.Total != 1 {
			t.Error("not observed at completion")
		}
	})
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("async not joined")
	}
	if calls.Load() != 1 || q.String() != before || m.Snapshot().UpstreamExchange.Total != 1 || m.Snapshot().UpstreamExchange.QTypes[dnsmetrics.AAAA] != 1 {
		t.Fatal("async doubled or mutated")
	}
	response, err := w.Exchange(context.Background(), q)
	if response != nil || err != original || m.Snapshot().UpstreamExchange.Total != 2 {
		t.Fatal("sync identity/count")
	}
}

// Real TLS constructor path, strict fixture CA (no insecure switch). The main
// protocol fixture separately proves selected-node AnyTLS, h2 and server counts.
func TestDNSMetricsRealHTTPSAsync(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		b, e := io.ReadAll(r.Body)
		if e != nil {
			t.Error(e)
			return
		}
		q := new(dns.Msg)
		if e = q.Unpack(b); e != nil {
			t.Error(e)
			return
		}
		a := new(dns.Msg).SetReply(q)
		wire, e := a.Pack()
		if e != nil {
			t.Error(e)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	}))
	defer server.Close()
	// httptest's certificate is DER; trusted via the SDK public inline PEM option.
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	addr := server.Listener.Addr().(*net.TCPAddr)
	content := []byte(fmt.Sprintf(`{"dns":{"servers":[{"type":"https","tag":"fixture","server":"127.0.0.1","server_port":%d,"tls":{"server_name":"example.com","certificate":[%q]}}]},"outbounds":[{"type":"direct","tag":"direct"}]}`, addr.Port, certPEM))
	m := new(DNSMetrics)
	ctx, opts, e := decodeOptions(WithDNSMetrics(context.Background(), m), content)
	if e != nil {
		t.Fatal(e)
	}
	// Use the actual owned registry constructor without starting any inbound.
	registry := service.FromContext[adapter.DNSTransportRegistry](ctx)
	raw, e := registry.CreateDNSTransport(ctx, logger.NOP(), "fixture", C.DNSTypeHTTPS, opts.DNS.Servers[0].Options)
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Reset()
	var callerTrace atomic.Int32
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { callerTrace.Add(1) }})
	for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
		q := new(dns.Msg).SetQuestion("private.invalid.", typ)
		before := q.String()
		done := make(chan struct{})
		raw.ExchangeAsync(ctx, q, func(response *dns.Msg, err error) {
			defer close(done)
			if err != nil || response == nil || !response.Response || !reflect.DeepEqual(response.Question, q.Question) {
				t.Errorf("real async response=%v err=%v", response, err)
			}
		})
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("real async join")
		}
		if q.String() != before {
			t.Fatal("query mutated")
		}
	}
	s := m.Snapshot()
	if requests.Load() != 2 || s.UpstreamExchange.Total != 2 || s.UpstreamExchange.QTypes[dnsmetrics.A] != 1 || s.UpstreamExchange.QTypes[dnsmetrics.AAAA] != 1 || s.UpstreamExchange.Outcomes[dnsmetrics.NoError] != 2 || callerTrace.Load() != int32(s.Connections.Acquisitions) {
		t.Fatalf("requests=%d trace=%d snapshot=%+v", requests.Load(), callerTrace.Load(), s)
	}
}

func BenchmarkDNSMetricsTransport(b *testing.B) {
	// Paired real SDK invocation with deterministic dial failure: includes SDK
	// packing, request setup and sync/async behavior, but no network RTT or TLS.
	for _, async := range []bool{false, true} {
		for _, enabled := range []bool{false, true} {
			b.Run(fmt.Sprintf("async_%t/enabled_%t", async, enabled), func(b *testing.B) {
				original := errors.New("benchmark-dial")
				raw := transport.NewHTTPSRaw(sdns.NewTransportAdapter(C.DNSTypeHTTPS, "fixture", nil), logger.NOP(), dnsMetricFailDialer{original}, &url.URL{Scheme: "https", Host: "fixture.invalid"}, http.Header{}, M.ParseSocksaddr("127.0.0.1:443"), nil)
				defer raw.Reset()
				var m *DNSMetrics
				if enabled {
					m = new(DNSMetrics)
				}
				upstream, err := wrapHTTPS(raw, m)
				if err != nil {
					b.Fatal(err)
				}
				q := new(dns.Msg).SetQuestion("synthetic.invalid.", dns.TypeA)
				done := make(chan struct{}, 1)
				callback := func(response *dns.Msg, err error) {
					if response != nil || err != original {
						b.Error("identity changed")
					}
					done <- struct{}{}
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if async {
						upstream.ExchangeAsync(context.Background(), q, callback)
						<-done
					} else {
						response, err := upstream.Exchange(context.Background(), q)
						if response != nil || err != original {
							b.Fatal("identity changed")
						}
					}
				}
			})
		}
	}
}

func BenchmarkDNSMetricsCompletion(b *testing.B) {
	response := new(dns.Msg)
	for _, enabled := range []bool{false, true} {
		b.Run(fmt.Sprintf("enabled_%t", enabled), func(b *testing.B) {
			var m *DNSMetrics
			if enabled {
				m = new(DNSMetrics)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m.complete(dnsmetrics.A, response, nil, time.Millisecond)
			}
		})
	}
}
