//go:build embedded_core && with_utls

package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	"github.com/NiuStar/anytls-core/internal/dnsmetrics"
	"github.com/NiuStar/anytls-core/internal/engine"
	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/miekg/dns"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks"
)

// Protocol characterization only: private HTTPS over a real authenticated AnyTLS
// peer, not a mock resolver, native TUN, WAN, or a production-policy change.
// Existing wire helpers own/join their peers and calibrate plaintext observers.
type dnsPerfFixture struct {
	addr, prefix                          string
	doh                                   *httptest.Server
	peer                                  *unifiedDNSPeer
	trap                                  *unifiedDNSTrap
	baseline                              int64
	mu                                    sync.Mutex
	questions                             map[string]int
	protocols                             map[int]int
	connections                           map[net.Conn]int
	states                                map[net.Conn]http.ConnState
	requestsByConn                        map[int]int
	handshakes                            map[net.Conn]bool
	nextConn                              int
	accepted, closed                      atomic.Int64
	tlsComplete                           atomic.Int64
	shutdown                              func()
	metrics                               *engine.DNSMetrics
	traceAcquired, traceReused, traceIdle atomic.Uint64
	answer                                func(http.ResponseWriter, *http.Request, *dns.Msg)
	badTLS, badAuth                       atomic.Bool
}

type dnsPerfConnKey struct{}

func dnsPerfStart(t *testing.T, answer func(http.ResponseWriter, *http.Request, *dns.Msg)) *dnsPerfFixture {
	return dnsPerfStartFault(t, answer, "")
}

func dnsPerfStartFault(t *testing.T, answer func(http.ResponseWriter, *http.Request, *dns.Msg), fault string) *dnsPerfFixture {
	t.Helper()
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	f := &dnsPerfFixture{prefix: hex.EncodeToString(nonce), questions: map[string]int{}, protocols: map[int]int{}, connections: map[net.Conn]int{}, states: map[net.Conn]http.ConnState{}, requestsByConn: map[int]int{}, answer: answer}
	f.badTLS.Store(fault == "doh_tls")
	f.handshakes = map[net.Conn]bool{}
	f.badAuth.Store(fault == "password")
	f.trap = unifiedDNSStartTrap(t, 0, false)
	f.trap.control(t, "before")
	f.baseline = f.trap.count.Load()
	t.Log("LOCAL_DIRECT_53_TRAP_NOT_RUN: high-port calibrated observer only; no privileged bind attempted")
	ca, cert := runtimeCertificate(t)
	f.doh = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/dns-query" || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "invalid DoH request", 400)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
		var q dns.Msg
		if err != nil || q.Unpack(body) != nil || len(q.Question) != 1 {
			http.Error(w, "invalid DNS", 400)
			return
		}
		f.mu.Lock()
		f.questions[dnsPerfKey(&q)]++
		f.protocols[r.ProtoMajor]++
		f.requestsByConn[r.Context().Value(dnsPerfConnKey{}).(int)]++
		f.mu.Unlock()
		if answer != nil {
			answer(w, r, &q)
		} else {
			dnsPerfWrite(w, unifiedDNSAnswer(&q, false))
		}
	}))
	f.doh.EnableHTTP2 = true
	_, wrongCert := runtimeCertificate(t)
	f.doh.TLS = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		if f.badTLS.Load() {
			return &wrongCert, nil
		}
		return &cert, nil
	}}
	f.doh.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		f.mu.Lock()
		f.nextConn++
		id := f.nextConn
		f.connections[c] = id
		f.mu.Unlock()
		return context.WithValue(ctx, dnsPerfConnKey{}, id)
	}
	f.doh.Config.ConnState = func(c net.Conn, s http.ConnState) {
		f.mu.Lock()
		f.states[c] = s
		if s == http.StateActive && !f.handshakes[c] {
			if tc, ok := c.(*tls.Conn); ok && tc.ConnectionState().HandshakeComplete {
				f.handshakes[c] = true
				f.tlsComplete.Add(1)
			}
		}
		f.mu.Unlock()
		if s == http.StateNew {
			f.accepted.Add(1)
		}
		if s == http.StateClosed {
			f.closed.Add(1)
		}
	}
	f.doh.StartTLS()
	target := f.doh.Listener.Addr().String()
	t.Cleanup(func() { f.doh.Close(); unifiedDNSRebind(t, "tcp", target) })
	var peerPort int
	if fault == "password" {
		f.peer, peerPort = dnsPerfAuthPeer(t, target, cert, &f.badAuth)
	} else {
		f.peer, peerPort = unifiedDNSStartPeer(t, target, cert)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	runtimeWrite(t, caPath, ca, 0600)
	path := filepath.Join(dir, "config.yaml")
	runtimeWrite(t, path, []byte(fmt.Sprintf("nodes:\n - {name: P, type: anytls, server: 127.0.0.1, port: %d, password: synthetic-unified-only, sni: g21.invalid, ca: %q, min-idle-session: 0}\nrules:\n - IP-CIDR,127.0.0.1/32,DIRECT\n - MATCH,P\n", peerPort, caPath)), 0600)
	compiled, err := prepareRuntimeWithRecords(&runtimeOptions{Config: path, NodeName: "P", Mode: "tun", LocalPort: 11080})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err = json.Unmarshal(compiled.JSON, &cfg); err != nil {
		t.Fatal(err)
	}
	m := compiled.Manifest
	rules := cfg["route"].(map[string]any)["rules"].([]any)
	if m == nil || m.RuntimeSHA256 != shaHex(compiled.JSON) || len(m.Rules) != len(rules) {
		t.Fatal("compiler manifest mismatch")
	}
	if digest, e := cr.ManifestDigest(*m, cr.ManifestBudget(m)); e != nil || digest != m.ManifestID {
		t.Fatal("compiler manifest digest mismatch")
	}
	for i, want := range []string{"hijack-dns", "sniff", "hijack-dns"} {
		if rules[i].(map[string]any)["action"] != want {
			t.Fatal("compiler DNS prefix changed")
		}
	}
	if rules[0].(map[string]any)["port"] != float64(53) || !reflect.DeepEqual(rules[2].(map[string]any)["protocol"], []any{"dns"}) {
		t.Fatal("compiler DNS capture predicates changed")
	}
	d := cfg["dns"].(map[string]any)
	servers := d["servers"].([]any)
	if len(servers) != 1 || d["final"] != "secure-dns" || d["reverse_mapping"] != true {
		t.Fatal("compiler DNS final/server set changed")
	}
	server := servers[0].(map[string]any)
	stls := server["tls"].(map[string]any)
	if server["type"] != "https" || server["server"] != "1.1.1.1" || server["tag"] != "secure-dns" || server["detour"] != "anytls-out" || stls["server_name"] != "cloudflare-dns.com" || stls["insecure"] == true {
		t.Fatal("compiler strict selected-node DoH policy changed")
	}
	endpoint := f.doh.Listener.Addr().(*net.TCPAddr)
	server["server"] = "127.0.0.1"
	server["server_port"] = endpoint.Port
	server["tls"] = map[string]any{"enabled": true, "server_name": "g21.invalid", "certificate": []string{string(ca)}}
	spare, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mixedPort := spare.Addr().(*net.TCPAddr).Port
	f.addr = spare.Addr().String()
	spare.Close()
	cfg["inbounds"] = []any{map[string]any{"type": "mixed", "tag": "dns-perf-mixed", "listen": "127.0.0.1", "listen_port": mixedPort}}
	wire, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	f.metrics = new(engine.DNSMetrics)
	ctx = engine.WithDNSMetrics(ctx, f.metrics)
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		f.traceAcquired.Add(1)
		if info.Reused {
			f.traceReused.Add(1)
		}
		if info.WasIdle {
			f.traceIdle.Add(1)
		}
	}})
	ended := make(chan error, 1)
	go func() { ended <- engine.Run(ctx, wire) }()
	var once sync.Once
	f.shutdown = func() {
		once.Do(func() {
			cancel()
			select {
			case e := <-ended:
				if e != nil && !errors.Is(e, context.Canceled) {
					t.Errorf("engine join: %v", e)
				}
			case <-time.After(4 * time.Second):
				t.Error("engine join deadline")
			}
			unifiedDNSRebind(t, "tcp", f.addr)
			unifiedDNSRebind(t, "udp", f.addr)
		})
	}
	t.Cleanup(func() {
		f.shutdown()
		deadline := time.Now().Add(time.Second)
		for f.closed.Load() != f.accepted.Load() && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if f.closed.Load() != f.accepted.Load() {
			t.Errorf("owned DoH connections not closed after engine join: accepted=%d closed=%d", f.accepted.Load(), f.closed.Load())
		}
		if f.peer.denied.Load() != 0 || f.peer.streams.Load() == 0 || f.peer.payload.Load() == 0 {
			t.Error("missing authenticated AnyTLS DoH payload or unexpected destination")
		}
		if delta := f.trap.count.Load() - f.baseline; delta != 0 {
			t.Errorf("plaintext fallback trap delta=%d", delta)
		}
		f.trap.control(t, "after")
		f.mu.Lock()
		defer f.mu.Unlock()
		t.Logf("DNS_PERF_FINAL questions=%v protocols=%v requests_per_tls_conn=%v tls_accepted=%d tls_handshakes_complete=%d tls_closed_before_server_cleanup=%d anytls_tls=%d anytls_streams=%d plaintext_delta=0 engine_join_attempted=true", f.questions, f.protocols, f.requestsByConn, f.accepted.Load(), f.tlsComplete.Load(), f.closed.Load(), f.peer.authenticated.Load(), f.peer.streams.Load())
	})
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, e := net.DialTimeout("tcp", f.addr, 50*time.Millisecond)
		if e == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("mixed listener readiness deadline")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return f
}

func (f *dnsPerfFixture) checkMetrics(t *testing.T, exchanges uint64) {
	t.Helper()
	snapshot := f.metrics.Snapshot()
	if snapshot.UpstreamExchange.Total != exchanges {
		t.Errorf("metrics upstream_exchange=%d want=%d", snapshot.UpstreamExchange.Total, exchanges)
	}
	if snapshot.Connections.Acquisitions != f.traceAcquired.Load() || snapshot.Connections.Reused != f.traceReused.Load() || snapshot.Connections.WasIdle != f.traceIdle.Load() {
		t.Errorf("caller trace composition differs: metrics=%+v independent=%d/%d/%d", snapshot.Connections, f.traceAcquired.Load(), f.traceReused.Load(), f.traceIdle.Load())
	}
	if snapshot.CacheHit != "NOT_OBSERVED" || snapshot.Coalesced != "NOT_OBSERVED" || snapshot.Hijacked != "NOT_OBSERVED" {
		t.Fatal("unavailable layer fabricated")
	}
	b, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("DNS_METRICS_V1 %s", b)
}

func dnsPerfKey(q *dns.Msg) string {
	return fmt.Sprintf("%s/%d", q.Question[0].Name, q.Question[0].Qtype)
}
func dnsPerfWrite(w http.ResponseWriter, a *dns.Msg) {
	b, err := a.Pack()
	if err != nil {
		http.Error(w, "pack", 500)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	_, _ = w.Write(b)
}
func (f *dnsPerfFixture) query(label string, typ uint16) *dns.Msg {
	q := unifiedDNSQuery()
	q.Question[0].Name = label + "-" + f.prefix + ".invalid."
	q.Question[0].Qtype = typ
	return q
}
func (f *dnsPerfFixture) count(q *dns.Msg) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.questions[dnsPerfKey(q)]
}
func (f *dnsPerfFixture) exchange(q *dns.Msg) (*dns.Msg, time.Duration, error) {
	return f.exchangeSent(q, nil)
}
func (f *dnsPerfFixture) exchangeSent(q *dns.Msg, sent func()) (*dns.Msg, time.Duration, error) {
	if sent != nil {
		defer func() {
			if sent != nil {
				sent()
			}
		}()
	}
	start := time.Now()
	client := socks.NewClient(recordsSOCKSDialer{}, M.ParseSocksaddr(f.addr), socks.Version5, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := client.DialContext(ctx, "tcp", M.ParseSocksaddr(f.trap.tcp.Addr().String()))
	if err != nil {
		return nil, time.Since(start), err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2500 * time.Millisecond))
	dc := &dns.Conn{Conn: c}
	if err = dc.WriteMsg(q); err != nil {
		return nil, time.Since(start), err
	}
	if sent != nil {
		sent()
		sent = nil
	}
	a, err := dc.ReadMsg()
	return a, time.Since(start), err
}
func dnsPerfCheck(t *testing.T, q, a *dns.Msg, err error, negative bool) {
	t.Helper()
	if err != nil {
		t.Errorf("DNS exchange id=%d: %v", q.Id, err)
		return
	}
	if a == nil || a.Id != q.Id || !a.Response || !reflect.DeepEqual(a.Question, q.Question) {
		t.Errorf("DNS callback identity mismatch id=%d response=%v", q.Id, a)
		return
	}
	if negative {
		if a.Rcode != dns.RcodeNameError || len(a.Answer) != 0 || len(a.Ns) != 1 {
			t.Errorf("NXDOMAIN/SOA mismatch: %v", a)
			return
		}
		soa, ok := a.Ns[0].(*dns.SOA)
		if !ok || soa.Hdr.Name != "invalid." || soa.Hdr.Class != dns.ClassINET || soa.Ns != "ns.invalid." || soa.Mbox != "hostmaster.invalid." || soa.Serial != 1 || soa.Refresh != 60 || soa.Retry != 60 || soa.Expire != 60 || soa.Minttl != 1 || soa.Hdr.Ttl > 1 {
			t.Errorf("exact negative SOA mismatch: %v", a.Ns)
		}
		return
	}
	want := unifiedDNSAnswer(q, false)
	if a.Rcode != dns.RcodeSuccess || len(a.Answer) != 1 {
		t.Errorf("positive DNS answer mismatch: %v", a)
		return
	}
	gotRR, wantRR := dns.Copy(a.Answer[0]), want.Answer[0]
	if gotRR.Header().Ttl > wantRR.Header().Ttl {
		t.Error("TTL increased")
	}
	gotRR.Header().Ttl = wantRR.Header().Ttl
	if gotRR.String() != wantRR.String() {
		t.Errorf("exact DNS answer mismatch got=%v want=%v", gotRR, wantRR)
	}
}
func dnsPerfRun(t *testing.T, f *dnsPerfFixture, q *dns.Msg, negative bool) time.Duration {
	t.Helper()
	a, elapsed, err := f.exchange(q)
	dnsPerfCheck(t, q, a, err, negative)
	return elapsed
}

func TestDNSPerformanceCache(t *testing.T) {
	f := dnsPerfStart(t, nil)
	var samples []int64
	for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
		for i := 0; i < 10; i++ {
			q := f.query("repeat", typ)
			samples = append(samples, dnsPerfRun(t, f, q, false).Microseconds())
		}
		if n := f.count(f.query("repeat", typ)); n != 1 {
			t.Errorf("sequential cache upstream=%d want=1 type=%d", n, typ)
		}
	}
	dnsPerfRun(t, f, f.query("different", dns.TypeA), false)
	if n := f.count(f.query("different", dns.TypeA)); n != 1 {
		t.Errorf("different-name upstream=%d", n)
	}
	f.shutdown()
	snapshot := f.metrics.Snapshot()
	if got := snapshot.UpstreamExchange.Total; got != 3 {
		t.Errorf("runtime upstream_exchange=%d want=3 (not caller count 21)", got)
	}
	if snapshot.UpstreamExchange.QTypes[dnsmetrics.A] != 2 || snapshot.UpstreamExchange.QTypes[dnsmetrics.AAAA] != 1 || snapshot.UpstreamExchange.Outcomes[dnsmetrics.NoError] != 3 {
		t.Errorf("cache metric categories=%+v", snapshot)
	}
	f.checkMetrics(t, 3)
	t.Logf("DNS_PERF_CACHE caller_count=21 expected_upstream=3 samples_us=%v", samples)
}

func TestDNSPerformanceConcurrentCoalescing(t *testing.T) {
	arrived, release := make(chan struct{}), make(chan struct{})
	var first sync.Once
	f := dnsPerfStart(t, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) {
		first.Do(func() { close(arrived) })
		select {
		case <-release:
			dnsPerfWrite(w, unifiedDNSAnswer(q, false))
		case <-r.Context().Done():
		}
	})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	const callers = 32
	start := make(chan struct{})
	type result struct {
		q, a    *dns.Msg
		elapsed time.Duration
		err     error
	}
	results := make(chan result, callers)
	var joined sync.WaitGroup
	joined.Add(callers)
	var ready, sent sync.WaitGroup
	ready.Add(callers)
	sent.Add(callers)
	for i := 0; i < callers; i++ {
		q := f.query("concurrent", dns.TypeA)
		go func() {
			defer joined.Done()
			ready.Done()
			<-start
			a, elapsed, err := f.exchangeSent(q, sent.Done)
			results <- result{q, a, elapsed, err}
		}()
	}
	ready.Wait()
	close(start)
	sent.Wait()
	select {
	case <-arrived:
	case <-time.After(3 * time.Second):
		t.Error("held upstream never entered")
	}
	// All complete DNS frames have been written to the real mixed inbound.
	// Keep the first upstream response held for a bounded observation window.
	timer := time.NewTimer(150 * time.Millisecond)
	<-timer.C
	heldCount := f.count(f.query("concurrent", dns.TypeA))
	unblock()
	ids := map[uint16]bool{}
	var samples []int64
	for i := 0; i < callers; i++ {
		select {
		case r := <-results:
			if ids[r.q.Id] {
				t.Error("duplicate caller identity")
			}
			ids[r.q.Id] = true
			dnsPerfCheck(t, r.q, r.a, r.err, false)
			samples = append(samples, r.elapsed.Microseconds())
		case <-time.After(4 * time.Second):
			t.Fatal("concurrent caller join deadline")
		}
	}
	if n := f.count(f.query("concurrent", dns.TypeA)); n != 1 {
		t.Errorf("coalescing upstream=%d want=1 held=%d callers=%d", n, heldCount, callers)
	}
	joined.Wait()
	f.shutdown()
	f.checkMetrics(t, 1)
	t.Logf("DNS_PERF_COALESCING callbacks=%d upstream_while_held=%d samples_us=%v", len(ids), heldCount, samples)
}

func TestDNSPerformanceConnectionReuse(t *testing.T) {
	f := dnsPerfStart(t, nil)
	var samples []int64
	for i := 0; i < 20; i++ {
		q := f.query(fmt.Sprintf("miss-%d", i), dns.TypeA)
		samples = append(samples, dnsPerfRun(t, f, q, false).Microseconds())
		if f.count(q) != 1 {
			t.Error("unique cache miss not observed")
		}
	}
	f.mu.Lock()
	connCount, h2 := len(f.requestsByConn), f.protocols[2]
	f.mu.Unlock()
	if f.accepted.Load() != 1 || f.tlsComplete.Load() != 1 || connCount != 1 || h2 != 20 {
		t.Errorf("DoH reuse tls=%d connections=%d h2_requests=%d want=1/1/20", f.accepted.Load(), connCount, h2)
	}
	f.checkMetrics(t, 20)
	cstats := f.metrics.Snapshot().Connections
	if cstats.Acquisitions != 20 || cstats.New != 1 || cstats.Reused != 19 {
		t.Errorf("real h2 connection metrics=%+v want acquisitions20/new1/reused19", cstats)
	}
	// HTTP/2 idle closure is performed on the actual server-side connection, not
	// an HTTP/1-only CloseIdleConnections approximation.
	deadline := time.Now().Add(time.Second)
	for {
		f.mu.Lock()
		idle := len(f.states) == 1
		for _, state := range f.states {
			idle = idle && state == http.StateIdle
		}
		f.mu.Unlock()
		if idle {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("DoH connection never became idle before forced close")
		}
		time.Sleep(time.Millisecond)
	}
	f.mu.Lock()
	var conns []net.Conn
	for c := range f.connections {
		conns = append(conns, c)
	}
	f.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	q := f.query("after-close", dns.TypeAAAA)
	dnsPerfRun(t, f, q, false)
	if f.count(q) != 1 || f.accepted.Load() != 2 || f.tlsComplete.Load() != 2 {
		t.Errorf("same-engine reconnect upstream=%d tls=%d want=1/2", f.count(q), f.accepted.Load())
	}
	f.shutdown()
	f.checkMetrics(t, 21)
	t.Logf("DNS_PERF_REUSE cache_misses=20 h2_requests=%d original_tls_connections=%d reconnect_tls=%d samples_us=%v", h2, connCount, f.accepted.Load(), samples)
}

func TestDNSPerformanceTTLExpiry(t *testing.T) {
	for _, negative := range []bool{false, true} {
		t.Run(fmt.Sprintf("negative_%t", negative), func(t *testing.T) {
			f := dnsPerfStart(t, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) {
				a := unifiedDNSAnswer(q, false)
				if negative {
					a.Rcode = dns.RcodeNameError
					a.Answer = nil
					a.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "invalid.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 1}, Ns: "ns.invalid.", Mbox: "hostmaster.invalid.", Serial: 1, Refresh: 60, Retry: 60, Expire: 60, Minttl: 1}}
				} else {
					a.Answer[0].Header().Ttl = 1
				}
				dnsPerfWrite(w, a)
			})
			q := f.query("ttl", dns.TypeA)
			start := time.Now()
			a, _, err := f.exchange(q)
			dnsPerfCheck(t, q, a, err, negative)
			if !negative && (a == nil || len(a.Answer) != 1 || a.Answer[0].Header().Ttl != 1) {
				t.Error("positive TTL must be exactly one second")
			}
			dnsPerfRun(t, f, f.query("ttl", dns.TypeA), negative)
			if n := f.count(q); n != 1 {
				t.Errorf("pre-expiry upstream=%d want=1", n)
			}
			deadline := time.Now().Add(2500 * time.Millisecond)
			for f.count(q) < 2 && time.Now().Before(deadline) {
				time.Sleep(40 * time.Millisecond)
				dnsPerfRun(t, f, f.query("ttl", dns.TypeA), negative)
			}
			n := f.count(q)
			elapsed := time.Since(start)
			if n != 2 || elapsed < time.Second {
				t.Errorf("TTL expiry upstream=%d elapsed=%s want=2 and >=1s", n, elapsed)
			}
			dnsPerfRun(t, f, f.query("ttl", dns.TypeA), negative)
			if f.count(q) != 2 {
				t.Error("post-expiry result not cached")
			}
			t.Logf("DNS_PERF_TTL negative=%t ttl_seconds=1 upstream=%d expiry_observed_us=%d", negative, n, elapsed.Microseconds())
		})
	}
}

func TestDNSPerformanceHTTPRecovery(t *testing.T) {
	var failing atomic.Bool
	failing.Store(true)
	f := dnsPerfStart(t, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) {
		if failing.Load() {
			w.WriteHeader(503)
			return
		}
		dnsPerfWrite(w, unifiedDNSAnswer(q, false))
	})
	q := f.query("recover", dns.TypeA)
	a, elapsed, err := f.exchange(q)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Errorf("503 failure must close explicitly, not pass on timeout: %v", err)
	}
	if err == nil && (a == nil || a.Id != q.Id || !reflect.DeepEqual(a.Question, q.Question) || a.Rcode == dns.RcodeSuccess || len(a.Answer) != 0) {
		t.Errorf("503 unexpectedly returned success or invalid identity: %v", a)
	}
	if f.count(q) == 0 {
		t.Error("503 never reached actual HTTPS handler")
	}
	t.Logf("DNS_PERF_503 original_error=%v failure_us=%d", err, elapsed.Microseconds())
	failing.Store(false)
	// Same question and same running engine: a failure must not poison the cache.
	dnsPerfRun(t, f, f.query("recover", dns.TypeA), false)
	f.shutdown()
	f.checkMetrics(t, 2)
	snapshot := f.metrics.Snapshot()
	if snapshot.HTTPStatus != "NOT_OBSERVED" || snapshot.UpstreamExchange.Outcomes[dnsmetrics.OtherError] != 1 || snapshot.UpstreamExchange.Outcomes[dnsmetrics.HTTP503] != 0 || snapshot.UpstreamExchange.Outcomes[dnsmetrics.NoError] != 1 {
		t.Errorf("503 must remain unclassifiable typed OtherError: %+v", snapshot)
	}
	if f.count(q) != 2 {
		t.Errorf("same-engine recovery upstream=%d want=2", f.count(q))
	}
}

// The forwarding handler is the existing real AnyTLS peer. Only service selection
// changes at accept time; never mutate Service.users while sessions read it.
func dnsPerfAuthPeer(t *testing.T, target string, cert tls.Certificate, bad *atomic.Bool) (*unifiedDNSPeer, int) {
	t.Helper()
	p := &unifiedDNSPeer{target: target}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	makeService := func(password string) *anytls.Service {
		s, e := anytls.NewService(anytls.ServiceConfig{Users: []anytls.User{{Name: "fixture", Password: password}}, PaddingScheme: padding.DefaultPaddingScheme, Handler: p, Logger: logger.NOP()})
		if e != nil {
			l.Close()
			t.Fatal(e)
		}
		return s
	}
	goodService, badService := makeService("synthetic-unified-only"), makeService("synthetic-rejected-only")
	ctx, cancel := context.WithCancel(context.Background())
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			p.track(c)
			p.accepted.Add(1)
			svc := goodService
			if bad.Load() {
				svc = badService
			}
			p.wg.Add(1)
			go func() {
				defer p.wg.Done()
				defer c.Close()
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
				_ = tc.SetDeadline(time.Now().Add(20 * time.Second))
				if tc.HandshakeContext(ctx) == nil {
					p.authenticated.Add(1)
					_ = svc.NewConnection(ctx, tc, M.SocksaddrFromNet(c.RemoteAddr()), nil)
				}
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		l.Close()
		p.mu.Lock()
		for _, c := range p.conns {
			c.Close()
		}
		p.mu.Unlock()
		done := make(chan struct{})
		go func() { p.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("auth peer join deadline")
		}
		unifiedDNSRebind(t, "tcp", l.Addr().String())
	})
	return p, l.Addr().(*net.TCPAddr).Port
}

func TestDNSPerformanceStrictFaultRecovery(t *testing.T) {
	for _, fault := range []string{"doh_tls", "password"} {
		t.Run(fault, func(t *testing.T) {
			f := dnsPerfStartFault(t, nil, fault)
			q := f.query("strict-recovery", dns.TypeA)
			a, elapsed, err := f.exchange(q)
			if err != nil && !errors.Is(err, io.EOF) {
				t.Errorf("strict failure must close explicitly, not pass on timeout: %v", err)
			}
			if err == nil && (a == nil || a.Id != q.Id || !a.Response || !reflect.DeepEqual(a.Question, q.Question) || a.Rcode == dns.RcodeSuccess || len(a.Answer) != 0) {
				t.Errorf("strict failure returned invalid/success response: %v", a)
			}
			if f.count(q) != 0 {
				t.Error("invalid TLS/auth reached HTTP DNS handler")
			}
			if fault == "password" && (f.peer.authenticated.Load() == 0 || f.peer.streams.Load() != 0) {
				t.Error("password control must complete strict TLS but deny authenticated streams")
			}
			if fault == "doh_tls" && (f.accepted.Load() == 0 || f.peer.streams.Load() == 0) {
				t.Error("bad TLS control never reached DoH TLS listener through AnyTLS")
			}
			t.Logf("DNS_PERF_STRICT_FAILURE fault=%s original_error=%v elapsed_us=%d", fault, err, elapsed.Microseconds())
			f.badTLS.Store(false)
			f.badAuth.Store(false)
			// Restoring only the server-side cert/auth gate: same endpoint, same policy,
			// same question, same live engine, no client reconfiguration/restart.
			dnsPerfRun(t, f, f.query("strict-recovery", dns.TypeA), false)
			if f.count(q) != 1 {
				t.Errorf("strict same-engine recovery upstream=%d want=1", f.count(q))
			}
		})
	}
}

func TestDNSPerformanceBlockedCancellation(t *testing.T) {
	entered, canceled := make(chan struct{}), make(chan struct{})
	var first sync.Once
	f := dnsPerfStart(t, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) {
		first.Do(func() { close(entered) })
		<-r.Context().Done()
		close(canceled)
	})
	result := make(chan error, 1)
	q := f.query("blocked", dns.TypeAAAA)
	go func() {
		a, _, err := f.exchange(q)
		if err == nil {
			err = fmt.Errorf("blocked query returned response: %v", a)
		}
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("blocked handler not entered")
	}
	f.shutdown()
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Error("engine cancel did not cancel blocked HTTP handler")
	}
	select {
	case err := <-result:
		var ne net.Error
		if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
			t.Errorf("timeout cannot prove downstream cancellation: %v", err)
		}
		t.Logf("DNS_PERF_CANCEL original_error=%v handler_canceled=true caller_joined=true engine_joined=true", err)
	case <-time.After(3 * time.Second):
		t.Error("blocked caller not joined")
	}
	if f.count(q) != 1 {
		t.Errorf("blocked upstream count=%d want=1", f.count(q))
	}
}
