//go:build embedded_core && with_utls

package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
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

	"github.com/miekg/dns"
	C "github.com/sagernet/sing-box/constant"
	sdns "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

// The existing fixture has no listener-injection seam. Keep this test-only
// constructor local rather than changing production or the frozen older tests.
// It retains the compiler/policy, strict CA, AnyTLS, trap and lifecycle checks.
type dnsBHFixture struct {
	*dnsPerfFixture
	gate     *dnsBHListener
	ca       []byte
	peerAddr string
}

func dnsBHStart(t *testing.T, answer func(http.ResponseWriter, *http.Request, *dns.Msg)) *dnsBHFixture {
	t.Helper()
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	f := &dnsPerfFixture{prefix: hex.EncodeToString(nonce), questions: map[string]int{}, protocols: map[int]int{}, connections: map[net.Conn]int{}, states: map[net.Conn]http.ConnState{}, requestsByConn: map[int]int{}, answer: answer}
	f.handshakes = map[net.Conn]bool{}
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
	f.doh.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
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
	gate := &dnsBHListener{Listener: f.doh.Listener}
	f.doh.Listener = gate
	f.doh.StartTLS()
	target := f.doh.Listener.Addr().String()
	t.Cleanup(func() { f.doh.Close(); unifiedDNSRebind(t, "tcp", target) })
	var peerPort int
	f.peer, peerPort = unifiedDNSStartPeer(t, target, cert)
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
	return &dnsBHFixture{dnsPerfFixture: f, gate: gate, ca: ca, peerAddr: fmt.Sprintf("127.0.0.1:%d", peerPort)}
}

// A write-only gate below crypto/tls stalls real encrypted server->client
// records. Reads (including peer FIN/RST) remain live; Pause never closes a
// socket, sends FIN, fabricates EOF, drops bytes or changes deadlines. It models
// one-way no-FIN delivery interruption, not firewall/IP packet loss.
type dnsBHListener struct {
	net.Listener
	mu    sync.Mutex
	conns []*dnsBHConn
}

func (l *dnsBHListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	g := &dnsBHConn{Conn: c, done: make(chan struct{})}
	l.mu.Lock()
	l.conns = append(l.conns, g)
	l.mu.Unlock()
	return g, nil
}
func (l *dnsBHListener) first(t *testing.T) *dnsBHConn {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.conns) != 1 {
		t.Fatalf("gate accepted=%d want=1", len(l.conns))
	}
	return l.conns[0]
}

type dnsBHConn struct {
	net.Conn
	mu        sync.Mutex
	resume    chan struct{}
	blocked   chan int
	done      chan struct{}
	once      sync.Once
	forwarded atomic.Int64
	closes    atomic.Int64
	readEOF   atomic.Int64
}

func (c *dnsBHConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	if errors.Is(e, io.EOF) {
		c.readEOF.Add(1)
	}
	return n, e
}
func (c *dnsBHConn) pause() <-chan int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.resume != nil {
		panic("gate already paused")
	}
	c.resume = make(chan struct{})
	c.blocked = make(chan int, 1)
	return c.blocked
}
func (c *dnsBHConn) restore() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.resume != nil {
		close(c.resume)
		c.resume = nil
	}
}
func (c *dnsBHConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	resume, blocked := c.resume, c.blocked
	c.mu.Unlock()
	if resume != nil {
		select {
		case blocked <- len(b):
		default:
		}
		select {
		case <-resume:
		case <-c.done:
			return 0, net.ErrClosed
		}
	}
	n, e := c.Conn.Write(b)
	c.forwarded.Add(int64(n))
	return n, e
}
func (c *dnsBHConn) Close() error {
	var err error
	c.once.Do(func() { c.closes.Add(1); close(c.done); c.restore(); err = c.Conn.Close() })
	return err
}
func dnsBHWait(t *testing.T, ch <-chan struct{}, label string) bool {
	t.Helper()
	select {
	case <-ch:
		return true
	case <-time.After(2 * time.Second):
		t.Errorf("%s not joined", label)
		return false
	}
}
func TestDNSBlackholeGateSelfTest(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	g := &dnsBHListener{Listener: l}
	defer func() { l.Close(); unifiedDNSRebind(t, "tcp", l.Addr().String()) }()
	client, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	server, e := g.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	c := server.(*dnsBHConn)
	if _, e = c.Write([]byte("ok")); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 2)
	if _, e = io.ReadFull(client, b); e != nil || string(b) != "ok" {
		t.Fatal("gate positive control", e)
	}
	blocked := c.pause()
	done := make(chan struct{})
	go func() { defer close(done); _, _ = c.Write([]byte("go")) }()
	defer func() { c.restore(); dnsBHWait(t, done, "gate writer") }()
	select {
	case n := <-blocked:
		if n != 2 {
			t.Error("wrong blocked byte count")
		}
	case <-time.After(time.Second):
		t.Fatal("gate did not block")
	}
	_ = client.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, e = client.Read(b)
	var ne net.Error
	if !errors.As(e, &ne) || !ne.Timeout() {
		t.Errorf("open peer must time out without EOF: %v", e)
	}
	if c.closes.Load() != 0 || c.readEOF.Load() != 0 || c.forwarded.Load() != 2 {
		t.Error("pause closed socket or forwarded blocked bytes")
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	c.restore()
	if _, e = io.ReadFull(client, b); e != nil || string(b) != "go" {
		t.Error("restore changed bytes", e)
	}
	t.Log("DNS_BLACKHOLE_GATE positive_forward=true blocked_ack=true pause_no_close=true pause_no_eof=true same_socket_restored=true")
}

func TestDNSBlackholeNoFINRecovery(t *testing.T) {
	entered := make(chan dnsRecoveryArrival, 1)
	release := make(chan struct{})
	ended := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	f := dnsBHStart(t, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) {
		if q.Question[0].Name[:1] == "x" {
			defer close(ended)
			entered <- dnsRecoveryArrival{r.Context().Value(dnsPerfConnKey{}).(int), r.ProtoMajor, time.Now()}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		dnsPerfWrite(w, unifiedDNSAnswer(q, false))
	})
	defer unblock()
	dnsPerfRun(t, f.dnsPerfFixture, f.query("warm", dns.TypeA), false)
	c := f.gate.first(t)
	if c.forwarded.Load() == 0 {
		t.Fatal("no actual TLS records forwarded")
	}
	done := make(chan dnsRecoveryResult, 1)
	go func() { done <- dnsRecoveryExchange(f.dnsPerfFixture, f.query("x-blackhole", dns.TypeA)) }()
	event := dnsRecoveryArrive(t, entered)
	blocked := c.pause()
	defer c.restore()
	before := c.forwarded.Load()
	unblock()
	n := 0
	select {
	case n = <-blocked:
	case <-time.After(time.Second):
		t.Error("TLS record never blocked")
	}
	if n < 5 || c.closes.Load() != 0 || c.readEOF.Load() != 0 || c.forwarded.Load() != before {
		t.Error("not an open no-FIN TLS delivery gate")
	}
	r := dnsRecoveryReceive(t, done)
	dnsRecoveryFailure(t, r)
	if r.elapsed < 9*time.Second || r.elapsed > 13*time.Second {
		t.Errorf("default SDK deadline not bounded: %s", r.elapsed)
	}
	// A remote close here belongs to the timed-out client, never to fault injection.
	closesAtDeadline := c.closes.Load()
	eofAtDeadline := c.readEOF.Load()
	c.restore()
	dnsBHWait(t, ended, "blackhole response handler")
	dnsRecoveryAfter(t, f.dnsPerfFixture)
	f.shutdown()
	f.checkMetrics(t, 4)
	if f.metrics.Snapshot().UpstreamExchange.Outcomes[dnsmetrics.Timeout] != 1 {
		t.Error("missing real SDK timeout")
	}
	t.Logf("DNS_BLACKHOLE fault=NO_FIN_ONEWAY_TLS_WRITE_GATE shared_conn=%d proto=%d blocked_tls_bytes=%d pre_pause_forwarded=%d a_us=%d deadline_peer_closes=%d deadline_peer_eof=%d same_engine_recovery=2 auto_retry=false", event.conn, event.proto, n, before, r.elapsed.Microseconds(), closesAtDeadline, eofAtDeadline)
}

// This lower seam is deliberate: the mixed inbound's socket Close is not the
// caller context of SDK Exchange. Use the original SDK transport and a real
// authenticated AnyTLS dialer so explicit per-stream cancellation is observable.
type dnsBHRawDialer struct {
	client *anytls.Client
	roots  *x509.CertPool
}

func (d dnsBHRawDialer) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	c, e := d.client.CreateProxy(ctx, dst)
	if e != nil {
		return nil, e
	}
	tc := tls.Client(c, &tls.Config{RootCAs: d.roots, ServerName: "g21.invalid", MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}})
	if e = tc.HandshakeContext(ctx); e != nil {
		c.Close()
		return nil, e
	}
	return tc, nil
}
func (d dnsBHRawDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("test denies UDP")
}
func (f *dnsBHFixture) raw(t *testing.T) *transport.HTTPSTransport {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(f.ca) {
		t.Fatal("invalid fixture CA")
	}
	client, e := anytls.NewClient(context.Background(), anytls.ClientConfig{Password: "synthetic-unified-only", MinIdleSession: 0, Logger: logger.NOP(), DialOut: func(ctx context.Context) (net.Conn, error) {
		c, e := (&net.Dialer{}).DialContext(ctx, "tcp", f.peerAddr)
		if e != nil {
			return nil, e
		}
		tc := tls.Client(c, &tls.Config{RootCAs: roots, ServerName: "g21.invalid", MinVersion: tls.VersionTLS12})
		if e = tc.HandshakeContext(ctx); e != nil {
			c.Close()
			return nil, e
		}
		return tc, nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := client.Close(); e != nil {
			t.Error(e)
		}
	})
	raw := transport.NewHTTPSRaw(sdns.NewTransportAdapter(C.DNSTypeHTTPS, "blackhole-raw", nil), logger.NOP(), dnsBHRawDialer{client, roots}, &url.URL{Scheme: "https", Host: "g21.invalid", Path: "/dns-query"}, http.Header{}, M.ParseSocksaddr(f.doh.Listener.Addr().String()), nil)
	t.Cleanup(raw.Reset)
	return raw
}
func TestDNSBlackholeActiveCancelIsolation(t *testing.T) {
	aIn, bIn := make(chan dnsRecoveryArrival, 1), make(chan dnsRecoveryArrival, 1)
	aEnd, bEnd := make(chan struct{}), make(chan struct{})
	bCanceled := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	f := dnsBHStart(t, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) {
		ev := dnsRecoveryArrival{r.Context().Value(dnsPerfConnKey{}).(int), r.ProtoMajor, time.Now()}
		switch q.Question[0].Name[:1] {
		case "a":
			defer close(aEnd)
			aIn <- ev
			<-r.Context().Done()
		case "b":
			defer close(bEnd)
			bIn <- ev
			select {
			case <-release:
				dnsPerfWrite(w, unifiedDNSAnswer(q, false))
			case <-r.Context().Done():
				close(bCanceled)
			}
		default:
			dnsPerfWrite(w, unifiedDNSAnswer(q, false))
		}
	})
	defer unblock()
	raw := f.raw(t)
	run := func(ctx context.Context, q *dns.Msg) dnsRecoveryResult {
		start := time.Now()
		a, e := raw.Exchange(ctx, q)
		if a != nil {
			a.Id = q.Id
		}
		return dnsRecoveryResult{q, a, time.Since(start), e}
	}
	// Raw SDK intentionally normalizes wire IDs to zero, unlike engine callback.
	ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	warm := run(ctx, f.query("warm", dns.TypeA))
	dnsPerfCheck(t, warm.q, warm.a, warm.err, false)
	ac, cancel := context.WithCancel(ctx)
	defer cancel()
	ad, bd := make(chan dnsRecoveryResult, 1), make(chan dnsRecoveryResult, 1)
	go func() { ad <- run(ac, f.query("a-cancel", dns.TypeA)) }()
	a := dnsRecoveryArrive(t, aIn)
	go func() { bd <- run(ctx, f.query("b-healthy", dns.TypeAAAA)) }()
	b := dnsRecoveryArrive(t, bIn)
	if a.conn != b.conn || a.proto != 2 || b.proto != 2 || f.accepted.Load() != 1 {
		t.Error("not independent streams on same real h2 connection")
	}
	at := time.Now()
	cancel()
	ar := dnsRecoveryReceive(t, ad)
	if !errors.Is(ar.err, context.Canceled) || time.Since(at) > 2*time.Second {
		t.Errorf("explicit cancel not returned promptly: %v", ar.err)
	}
	dnsBHWait(t, aEnd, "explicitly canceled handler")
	select {
	case <-bCanceled:
		t.Error("A cancellation canceled healthy B")
	default:
	}
	unblock()
	br := dnsRecoveryReceive(t, bd)
	dnsPerfCheck(t, br.q, br.a, br.err, false)
	dnsBHWait(t, bEnd, "healthy B handler")
	after := run(ctx, f.query("recovered", dns.TypeA))
	dnsPerfCheck(t, after.q, after.a, after.err, false)
	if f.accepted.Load() != 1 {
		t.Error("explicit cancellation destroyed shared TLS connection")
	}
	raw.Reset()
	f.shutdown()
	t.Logf("DNS_CANCEL_ISOLATION fault=APP_RESPONSE_STALL active_context_cancel=true shared_conn=%d cancel_us=%d b_success=%t same_connection_recovery=true engine_root_canceled=false", a.conn, time.Since(at).Microseconds(), br.err == nil)
}
