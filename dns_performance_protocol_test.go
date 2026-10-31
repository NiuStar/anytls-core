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
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	"github.com/NiuStar/anytls-core/internal/engine"
	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks"
)

// Protocol characterization only: private HTTPS over a real authenticated AnyTLS
// peer, not a mock resolver, native TUN, WAN, or a production-policy change.
// Existing wire helpers own/join their peers and calibrate plaintext observers.
type dnsPerfFixture struct {
	addr, prefix     string
	doh              *httptest.Server
	peer             *unifiedDNSPeer
	trap             *unifiedDNSTrap
	baseline         int64
	mu               sync.Mutex
	questions        map[string]int
	protocols        map[int]int
	connections      map[net.Conn]int
	requestsByConn   map[int]int
	nextConn         int
	accepted, closed atomic.Int64
	shutdown         func()
	answer           func(http.ResponseWriter, *http.Request, *dns.Msg)
}

type dnsPerfConnKey struct{}

func dnsPerfStart(t *testing.T, answer func(http.ResponseWriter, *http.Request, *dns.Msg)) *dnsPerfFixture {
	t.Helper()
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	f := &dnsPerfFixture{prefix: hex.EncodeToString(nonce), questions: map[string]int{}, protocols: map[int]int{}, connections: map[net.Conn]int{}, requestsByConn: map[int]int{}, answer: answer}
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
	f.doh.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	f.doh.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		f.mu.Lock()
		f.nextConn++
		id := f.nextConn
		f.connections[c] = id
		f.mu.Unlock()
		return context.WithValue(ctx, dnsPerfConnKey{}, id)
	}
	f.doh.Config.ConnState = func(c net.Conn, s http.ConnState) {
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
		if f.peer.denied.Load() != 0 || f.peer.streams.Load() == 0 || f.peer.payload.Load() == 0 {
			t.Error("missing authenticated AnyTLS DoH payload or unexpected destination")
		}
		if delta := f.trap.count.Load() - f.baseline; delta != 0 {
			t.Errorf("plaintext fallback trap delta=%d", delta)
		}
		f.trap.control(t, "after")
		f.mu.Lock()
		defer f.mu.Unlock()
		t.Logf("DNS_PERF_FINAL questions=%v protocols=%v requests_per_tls_conn=%v tls_accepted=%d tls_closed_before_server_cleanup=%d anytls_tls=%d anytls_streams=%d plaintext_delta=0 engine_joined=true", f.questions, f.protocols, f.requestsByConn, f.accepted.Load(), f.closed.Load(), f.peer.authenticated.Load(), f.peer.streams.Load())
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
		if !ok || soa.Hdr.Name != "invalid." || soa.Ns != "ns.invalid." || soa.Mbox != "hostmaster.invalid." || soa.Serial != 1 || soa.Minttl != 1 || soa.Hdr.Ttl > 1 {
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
	var ready, sent sync.WaitGroup
	ready.Add(callers)
	sent.Add(callers)
	for i := 0; i < callers; i++ {
		q := f.query("concurrent", dns.TypeA)
		go func() {
			ready.Done()
			<-start
			sent.Done()
			a, elapsed, err := f.exchange(q)
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
	// Hold the first actual upstream response while all barrier-released callers
	// are active. This is a bounded observation window, not a latency assertion.
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
	if f.accepted.Load() != 1 || connCount != 1 || h2 != 20 {
		t.Errorf("DoH reuse tls=%d connections=%d h2_requests=%d want=1/1/20", f.accepted.Load(), connCount, h2)
	}
	// HTTP/2 idle closure is performed on the actual server-side connection, not
	// an HTTP/1-only CloseIdleConnections approximation.
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
	if f.count(q) != 1 || f.accepted.Load() != 2 {
		t.Errorf("same-engine reconnect upstream=%d tls=%d want=1/2", f.count(q), f.accepted.Load())
	}
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
			dnsPerfRun(t, f, q, negative)
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
	if f.count(q) != 2 {
		t.Errorf("same-engine recovery upstream=%d want=2", f.count(q))
	}
}
