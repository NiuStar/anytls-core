package engine

import (
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	sdns "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type browserUntrustedDNS struct {
	sdns.TransportAdapter
	calls atomic.Int64
	fail  bool
}

func (*browserUntrustedDNS) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (*browserUntrustedDNS) Close() error                                   { return nil }
func (*browserUntrustedDNS) Reset()                                         {}
func (*browserUntrustedDNS) Tag() string                                    { return "fixture" }
func (*browserUntrustedDNS) Type() string                                   { return "https" }
func (u *browserUntrustedDNS) Exchange(_ context.Context, q *dns.Msg) (*dns.Msg, error) {
	u.calls.Add(1)
	if u.fail {
		return nil, context.DeadlineExceeded
	}
	_, r := browserAnswer(q.Question[0].Name, dns.TypeAAAA, "2001:db8::1", 60)
	r.Id = q.Id
	return r, nil
}
func (u *browserUntrustedDNS) ExchangeAsync(ctx context.Context, q *dns.Msg, cb func(*dns.Msg, error)) {
	r, e := u.Exchange(ctx, q)
	cb(r, e)
}

// Real SDK Router return/cache seams, with the concrete engine-owned strict
// HTTPSTransport. No direct call to observe/trust may mint the positive receipt.
func TestBrowserSDKDNSReturnSyncAsyncCacheIdentity(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		wire, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if e := q.Unpack(wire); e != nil {
			t.Error(e)
			return
		}
		_, answer := browserAnswer(q.Question[0].Name, dns.TypeAAAA, "2001:db8::1", 60)
		answer.Id = q.Id
		wire, _ = answer.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(wire)
	}))
	defer server.Close()
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	raw := []byte(fmt.Sprintf(`{"dns":{"servers":[{"type":"https","tag":"fixture","server":"127.0.0.1","server_port":%d,"tls":{"server_name":"example.com","certificate":[%q]}}]},"outbounds":[{"type":"direct","tag":"direct"}]}`, server.Listener.Addr().(*net.TCPAddr).Port, cert))
	ctx, opts, e := decodeOptions(context.Background(), raw)
	if e != nil {
		t.Fatal(e)
	}
	instance, e := box.New(box.Options{Options: opts, Context: ctx})
	if e != nil {
		t.Fatal(e)
	}
	defer instance.Close()
	if e = instance.Start(); e != nil {
		t.Fatal(e)
	}
	router := service.FromContext[adapter.DNSRouter](ctx)
	manager := service.FromContext[adapter.DNSTransportManager](ctx)
	trusted := manager.Default()
	if _, ok := trusted.(*transport.HTTPSTransport); !ok {
		t.Fatalf("not actual owned concrete HTTPS: %T", trusted)
	}
	s := service.FromContext[browserDNSObserver](ctx).(*browserProvenance)
	ip := netip.MustParseAddr("2001:db8::1")
	for _, async := range []bool{false, true} {
		name := fmt.Sprintf("async-%t.invalid.", async)
		for hit := 0; hit < 2; hit++ {
			scope := browserClientScope{inbound: fmt.Sprintf("browser-%t-%d", async, hit), source: netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", 10+hit))}
			queryCtx, m := adapter.ExtendContext(ctx)
			m.Inbound = scope.inbound
			m.Source = M.Socksaddr{Addr: scope.source}
			q := new(dns.Msg).SetQuestion(name, dns.TypeAAAA)
			before := requests.Load()
			check := func(r *dns.Msg, err error) {
				if err != nil || r == nil || r.Id != q.Id || len(r.Question) != 1 || r.Question[0] != q.Question[0] {
					t.Errorf("accepted response mismatch: %v", err)
					return
				}
				receipt, ok := s.receipt(scope, ip)
				if !ok || receipt.name != name || receipt.transport != trusted.Tag() {
					t.Errorf("receipt missing before return/callback async=%t hit=%d", async, hit)
				}
			}
			if async {
				done := make(chan struct{})
				router.ExchangeAsync(queryCtx, q, adapter.DNSQueryOptions{}, func(r *dns.Msg, err error) { check(r, err); close(done) })
				select {
				case <-done:
				case <-time.After(4 * time.Second):
					t.Fatal("callback did not join")
				}
			} else {
				r, err := router.Exchange(queryCtx, q, adapter.DNSQueryOptions{})
				check(r, err)
			}
			want := int64(1)
			if hit == 1 {
				want = 0
			}
			if requests.Load()-before != want {
				t.Fatalf("cache transport query delta=%d want=%d", requests.Load()-before, want)
			}
			wrong := scope
			wrong.source = netip.MustParseAddr("192.0.2.99")
			if _, ok := s.receipt(wrong, ip); ok {
				t.Fatal("cross-client authority")
			}
			wrong = scope
			wrong.inbound = "other"
			if _, ok := s.receipt(wrong, ip); ok {
				t.Fatal("cross-inbound authority")
			}
			t.Logf("SDK_RETURN async=%t cache_hit=%t question=%s requests_delta=%d receipt_before_delivery=true", async, hit == 1, name, want)
		}
	}
	for _, async := range []bool{false, true} {
		for _, failure := range []bool{false, true} {
			for hit := 0; hit < 2; hit++ {
				untrusted := &browserUntrustedDNS{TransportAdapter: sdns.NewTransportAdapter(C.DNSTypeHTTPS, "fixture", nil), fail: failure}
				scope := browserClientScope{inbound: fmt.Sprintf("untrusted-%t-%t-%d", async, failure, hit), source: netip.MustParseAddr("192.0.2.55")}
				qctx, m := adapter.ExtendContext(ctx)
				m.Inbound = scope.inbound
				m.Source = M.Socksaddr{Addr: scope.source}
				q := new(dns.Msg).SetQuestion(fmt.Sprintf("untrusted-%t-%t.invalid.", async, failure), dns.TypeAAAA)
				options := adapter.DNSQueryOptions{Transport: untrusted}
				if async {
					done := make(chan struct{})
					router.ExchangeAsync(qctx, q, options, func(_ *dns.Msg, _ error) { close(done) })
					select {
					case <-done:
					case <-time.After(4 * time.Second):
						t.Fatal("untrusted async did not join")
					}
				} else {
					router.Exchange(qctx, q, options)
				}
				if _, ok := s.receipt(scope, ip); ok {
					t.Fatal("same tag/type untrusted transport or injected cache minted authority")
				}
				if !failure && hit == 1 {
					// The cache entry was produced by the untrusted same-tag stub.
					// A later default lookup must not launder it into strict TLS authority.
					injected, m2 := adapter.ExtendContext(ctx)
					m2.Inbound = fmt.Sprintf("cache-injection-%t", async)
					m2.Source = M.ParseSocksaddr("192.0.2.77:53")
					before := requests.Load()
					router.Exchange(injected, q.Copy(), adapter.DNSQueryOptions{})
					injectedScope, _ := browserScope(*m2)
					if _, ok := s.receipt(injectedScope, ip); !ok || requests.Load()-before != 1 {
						t.Fatal("untrusted cache contaminated registered transport or failed fresh strict query", ok, requests.Load()-before)
					}
					t.Logf("CACHE_INJECTION async=%t untrusted_cache_denied=true fresh_strict_query=1", async)
				}
			}
		}
	}
	// Lookup shares the same SDK cache; it must not inject an unregistered
	// transport answer that a later registered Exchange could certify.
	{
		stub := &browserUntrustedDNS{TransportAdapter: sdns.NewTransportAdapter(C.DNSTypeHTTPS, "fixture", nil)}
		qctx, m := adapter.ExtendContext(ctx)
		m.Inbound = "lookup-injection"
		m.Source = M.ParseSocksaddr("192.0.2.66:53")
		router.Lookup(qctx, "lookup-injection.invalid", adapter.DNSQueryOptions{Transport: stub, Strategy: C.DomainStrategyIPv6Only})
		before := requests.Load()
		question := new(dns.Msg).SetQuestion("lookup-injection.invalid.", dns.TypeAAAA)
		response, err := router.Exchange(qctx, question, adapter.DNSQueryOptions{})
		scope, _ := browserScope(*m)
		if _, ok := s.receipt(scope, ip); err != nil || response == nil || !ok || requests.Load()-before != 1 {
			t.Fatal("Lookup unregistered cache injection", ok, requests.Load()-before, err)
		}
	}
	// Even a direct forged observer invocation with a same-tag HTTPS stub is not
	// authority; standard EDNS remains deliberately UNKNOWN in the bounded parser.
	q, r := browserAnswer("forged.invalid", dns.TypeAAAA, "2001:db8::1", 60)
	forged, m := adapter.ExtendContext(ctx)
	m.Inbound = "forged"
	m.Source = M.ParseSocksaddr("192.0.2.88:53")
	s.ObserveBrowserDNS(forged, q, r, &browserUntrustedDNS{})
	scope, _ := browserScope(*m)
	if _, ok := s.receipt(scope, ip); ok {
		t.Fatal("forged callback authority")
	}
	q.SetEdns0(1232, true)
	r.SetReply(q)
	if _, ok := browserRRSet(q, r, time.Now()); ok {
		t.Fatal("EDNS incorrectly certified")
	}
}
