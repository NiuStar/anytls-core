//go:build embedded_core && with_utls

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	"github.com/NiuStar/anytls-core/internal/engine"
	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/session"
	"github.com/miekg/dns"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

// Only the compiler-produced TUN inbounds and the DoH endpoint/trust are
// substituted. Route rules, selected-node detour, DNS final and server set are
// never repaired here. Run (not RunWithRecords) deliberately makes no runtime
// records claim after these substitutions. This is NOT a privileged TUN test.
type unifiedDNSPeer struct {
	browser                                           atomic.Bool
	noACK                                             atomic.Bool
	healthy                                           atomic.Bool
	v6, v4                                            atomic.Int64
	target                                            string
	accepted, authenticated, streams, payload, denied atomic.Int64
	mu                                                sync.Mutex
	conns                                             []net.Conn
	destinations                                      []string
	wg                                                sync.WaitGroup
}

func (p *unifiedDNSPeer) track(c net.Conn) {
	p.mu.Lock()
	p.conns = append(p.conns, c)
	p.mu.Unlock()
}
func (p *unifiedDNSPeer) NewConnectionEx(_ context.Context, c net.Conn, _ M.Socksaddr, d M.Socksaddr, _ N.CloseHandlerFunc) {
	p.streams.Add(1)
	p.mu.Lock()
	p.destinations = append(p.destinations, d.String())
	p.mu.Unlock()
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer c.Close()
		if p.browser.Load() {
			if d.Addr.Is6() {
				p.v6.Add(1)
				if p.noACK.Load() {
					io.Copy(io.Discard, c)
					return
				}
				if !p.healthy.Load() {
					c.(*session.Stream).HandshakeFailure(fmt.Errorf("controlled remote IPv6 connect failure"))
					return
				}
			} else {
				p.v4.Add(1)
			}
			// Controlled server forwarding represents recovered node IPv6 egress.
			if d.Addr.Is6() {
				d = M.ParseSocksaddr(p.target)
			}
		}
		// This also rejects AnyTLS UoT magic addresses: no UDP/plain-DNS forwarding.
		if d.String() != p.target {
			p.denied.Add(1)
			return
		}
		up, err := net.DialTimeout("tcp", p.target, time.Second)
		if err != nil {
			return
		}
		p.track(up)
		if p.browser.Load() {
			if err := c.(*session.Stream).HandshakeSuccess(); err != nil {
				up.Close()
				return
			}
		}
		defer up.Close()
		done := make(chan struct{})
		go func() {
			_, _ = io.Copy(up, routingCompiledReader{Reader: c, count: &p.payload})
			up.Close()
			close(done)
		}()
		_, _ = io.Copy(c, up)
		c.Close()
		<-done
	}()
}

func unifiedDNSRebind(t *testing.T, network, addr string) {
	t.Helper()
	if network == "udp" {
		c, err := net.ListenPacket("udp", addr)
		if err != nil {
			t.Errorf("owned UDP listener not released %s: %v", addr, err)
			return
		}
		c.Close()
	} else {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			t.Errorf("owned TCP listener not released %s: %v", addr, err)
			return
		}
		l.Close()
	}
}

func unifiedDNSStartPeer(t *testing.T, target string, cert tls.Certificate) (*unifiedDNSPeer, int) {
	t.Helper()
	p := &unifiedDNSPeer{target: target}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	svc, err := anytls.NewService(anytls.ServiceConfig{Users: []anytls.User{{Name: "fixture", Password: "synthetic-unified-only"}}, PaddingScheme: padding.DefaultPaddingScheme, Handler: p, Logger: logger.NOP()})
	if err != nil {
		l.Close()
		cancel()
		t.Fatal(err)
	}
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
			p.wg.Add(1)
			go func() {
				defer p.wg.Done()
				defer c.Close()
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
				_ = tc.SetDeadline(time.Now().Add(90 * time.Second))
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
			t.Error("AnyTLS fixture goroutines not joined")
		}
		unifiedDNSRebind(t, "tcp", l.Addr().String())
	})
	return p, l.Addr().(*net.TCPAddr).Port
}

type unifiedDNSTrap struct {
	count atomic.Int64
	udp   *net.UDPConn
	tcp   net.Listener
}

func unifiedDNSAnswer(q *dns.Msg, poison bool) *dns.Msg {
	a := new(dns.Msg)
	a.SetReply(q)
	if len(q.Question) != 1 {
		a.Rcode = dns.RcodeFormatError
		return a
	}
	h := dns.RR_Header{Name: q.Question[0].Name, Rrtype: q.Question[0].Qtype, Class: dns.ClassINET, Ttl: 60}
	switch q.Question[0].Qtype {
	case dns.TypeA:
		ip := "192.0.2.41"
		if poison {
			ip = "192.0.2.199"
		}
		a.Answer = []dns.RR{&dns.A{Hdr: h, A: net.ParseIP(ip)}}
	case dns.TypeAAAA:
		ip := "2001:db8::41"
		if poison {
			ip = "2001:db8::199"
		}
		a.Answer = []dns.RR{&dns.AAAA{Hdr: h, AAAA: net.ParseIP(ip)}}
	}
	return a
}

// Reserve both protocol namespaces before starting either DNS server. Only a
// kernel-selected TCP number whose UDP number is busy may be discarded; this
// is bounded fixture allocation, not a retry of engine startup or DNS traffic.
func unifiedDNSListenPair(port int, listen func(string, string) (net.Listener, error), listenUDP func(string, *net.UDPAddr) (*net.UDPConn, error)) (net.Listener, *net.UDPConn, error) {
	attempts := 1
	if port == 0 {
		attempts = 8
	}
	for attempt := 0; attempt < attempts; attempt++ {
		tcp, err := listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return nil, nil, err
		}
		udpAddr, err := net.ResolveUDPAddr("udp", tcp.Addr().String())
		if err != nil {
			tcp.Close()
			return nil, nil, err
		}
		udp, err := listenUDP("udp", udpAddr)
		if err == nil {
			return tcp, udp, nil
		}
		tcp.Close()
		if port != 0 || !errors.Is(err, syscall.EADDRINUSE) || attempt+1 == attempts {
			return nil, nil, err
		}
	}
	panic("unreachable DNS fixture allocation")
}

func unifiedDNSStartTrap(t *testing.T, port int, optional bool) *unifiedDNSTrap {
	t.Helper()
	tcp, udp, err := unifiedDNSListenPair(port, net.Listen, net.ListenUDP)
	if err != nil {
		if optional {
			t.Logf("LOCAL_DIRECT_53_TRAP_NOT_RUN tcp/udp bind: %v; SOCKS destination :53 remains tested", err)
			return nil
		}
		t.Fatal(err)
	}
	addr := tcp.Addr().String()
	p := &unifiedDNSTrap{udp: udp, tcp: tcp}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) { p.count.Add(1); _ = w.WriteMsg(unifiedDNSAnswer(q, true)) })
	us := &dns.Server{PacketConn: udp, Handler: handler}
	ts := &dns.Server{Listener: tcp, Handler: handler}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = us.ActivateAndServe() }()
	go func() { defer wg.Done(); _ = ts.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = us.Shutdown()
		_ = ts.Shutdown()
		udp.Close()
		tcp.Close()
		wg.Wait()
		unifiedDNSRebind(t, "udp", addr)
		unifiedDNSRebind(t, "tcp", addr)
	})
	return p
}

var unifiedDNSSequence atomic.Uint32

func unifiedDNSQuery() *dns.Msg {
	n := unifiedDNSSequence.Add(1)
	q := new(dns.Msg)
	q.SetQuestion(fmt.Sprintf("wire-%d.invalid.", n), dns.TypeA)
	q.Id = uint16(n)
	return q
}
func (p *unifiedDNSTrap) control(t *testing.T, phase string) {
	t.Helper()
	before := p.count.Load()
	for _, network := range []string{"udp", "tcp"} {
		q := unifiedDNSQuery()
		a, _, err := (&dns.Client{Net: network, Timeout: time.Second}).Exchange(q, p.tcp.Addr().String())
		if err != nil || a == nil || len(a.Answer) != 1 || a.Answer[0].String() != unifiedDNSAnswer(q, true).Answer[0].String() {
			t.Fatalf("%s positive plaintext %s trap failed: %v", phase, network, err)
		}
	}
	if p.count.Load() != before+2 {
		t.Fatal("plaintext trap positive counter mismatch")
	}
	t.Logf("PLAINTEXT_OBSERVER_CONTROL phase=%s tcp_udp=2 addr=%s", phase, p.tcp.Addr())
}

type unifiedDNSFixture struct {
	addr      string
	p, q      *unifiedDNSPeer
	httpCount atomic.Int64
	mu        sync.Mutex
	questions map[string]int
	traps     []*unifiedDNSTrap
	baseline  []int64
	failure   string
	shutdown  func()
	hold      *unifiedDNSHold
}

// The first resolver request cannot complete until a distinct later request
// has arrived. This is a fixture-local scheduling witness, never a DNS reply.
type unifiedDNSHold struct {
	first, later, release, handlerDone chan struct{}
	mu sync.Mutex
	firstName string
	seen map[string]bool
	armed bool
	once sync.Once
}
func newUnifiedDNSHold() *unifiedDNSHold {
	return &unifiedDNSHold{first: make(chan struct{}), later: make(chan struct{}), release: make(chan struct{}), handlerDone: make(chan struct{}), seen: make(map[string]bool)}
}
func (h *unifiedDNSHold) arrive(name string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.armed { return false }
	if h.seen[name] { return false }
	h.seen[name] = true
	if name == h.firstName { close(h.first); return true }
	if name != h.firstName { select { case <-h.later: default: close(h.later) } }
	return false
}
func (h *unifiedDNSHold) arm(name string) { h.mu.Lock(); h.firstName = name; h.armed = true; h.mu.Unlock() }
func (h *unifiedDNSHold) unblock() { h.once.Do(func() { close(h.release) }) }

func unifiedDNSStart(t *testing.T, rules, failure string) *unifiedDNSFixture {
	t.Helper()
	// The existing A+AAAA contracts intentionally select dual-stack.
	return unifiedDNSStartPolicy(t, rules, failure, "ipv6: true\n")
}

func unifiedDNSStartPolicy(t *testing.T, rules, failure, policy string) *unifiedDNSFixture {
	t.Helper()
	f := &unifiedDNSFixture{failure: failure, questions: make(map[string]int)}
	if failure == "http503" {
		f.hold = newUnifiedDNSHold()
		t.Cleanup(func() { f.hold.unblock() })
	}
	// High-port trap is mandatory and calibrated. Low-port trap is supplementary:
	// SOCKS clients can address :53 without binding it, including on ordinary UID.
	f.traps = append(f.traps, unifiedDNSStartTrap(t, 0, false))
	if p := unifiedDNSStartTrap(t, 53, true); p != nil {
		f.traps = append(f.traps, p)
	}
	for _, p := range f.traps {
		p.control(t, "before")
		f.baseline = append(f.baseline, p.count.Load())
	}
	ca, cert := runtimeCertificate(t)
	wrongCA, _ := runtimeCertificate(t)
	doh := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.httpCount.Add(1)
		if r.Method != "POST" || r.URL.Path != "/dns-query" || r.Header.Get("Content-Type") != "application/dns-message" {
			w.WriteHeader(400)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
		var query dns.Msg
		if err != nil || query.Unpack(body) != nil || len(query.Question) != 1 {
			w.WriteHeader(400)
			return
		}
		key := fmt.Sprintf("%s/%d", query.Question[0].Name, query.Question[0].Qtype)
		f.mu.Lock()
		f.questions[key]++
		f.mu.Unlock()
		if failure == "http503" {
			if f.hold != nil && f.hold.arrive(query.Question[0].Name) {
				defer close(f.hold.handlerDone)
				select {
				case <-f.hold.release:
				case <-r.Context().Done():
				}
			}
			w.WriteHeader(503)
			return
		}
		wire, _ := unifiedDNSAnswer(&query, false).Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	}))
	doh.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	doh.StartTLS()
	dohAddr := doh.Listener.Addr().String()
	t.Cleanup(func() { doh.Close(); unifiedDNSRebind(t, "tcp", dohAddr) })
	if failure == "disconnect" {
		doh.Close()
	}
	var pPort, qPort int
	f.p, pPort = unifiedDNSStartPeer(t, dohAddr, cert)
	// Q is a distinct real AnyTLS peer; its sole allowed destination is an echo.
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var echoWG sync.WaitGroup
	echoWG.Add(1)
	go func() {
		defer echoWG.Done()
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			echoWG.Add(1)
			go func() {
				defer echoWG.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(4 * time.Second))
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() { echo.Close(); echoWG.Wait(); unifiedDNSRebind(t, "tcp", echo.Addr().String()) })
	f.q, qPort = unifiedDNSStartPeer(t, echo.Addr().String(), cert)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	runtimeWrite(t, caPath, ca, 0600)
	if failure == "node_ca" {
		runtimeWrite(t, caPath, wrongCA, 0600)
	}
	password := "synthetic-unified-only"
	if failure == "password" {
		password = "synthetic-wrong-only"
	}
	config := policy + fmt.Sprintf("nodes:\n - {name: P, type: anytls, server: 127.0.0.1, port: %d, password: %s, sni: g21.invalid, ca: %q, min-idle-session: 0}\n - {name: Q, type: anytls, server: 127.0.0.1, port: %d, password: synthetic-unified-only, sni: g21.invalid, ca: %q, min-idle-session: 0}\nproxy-groups:\n - {name: business, type: select, proxies: [Q], selected: Q}\n", pPort, password, caPath, qPort, caPath)
	if rules == "ruleset" {
		b := []byte(`{"version":3,"rules":[{"ip_cidr":["127.0.0.0/8"]}]}`)
		runtimeWrite(t, filepath.Join(dir, "loop.json"), b, 0600)
		config += fmt.Sprintf("rule-sets:\n loop: {path: loop.json, sha256: %s, resolve-ip: true}\n", shaHex(b))
		rules = "RULE-SET,loop,DIRECT\n - MATCH,business"
	}
	if rules != "" {
		config += "rules:\n - " + rules + "\n"
	}
	configPath := filepath.Join(dir, "config.yaml")
	runtimeWrite(t, configPath, []byte(config), 0600)
	compiled, err := prepareRuntimeWithRecords(&runtimeOptions{Config: configPath, NodeName: "P", Mode: "tun", LocalPort: 11080})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err = json.Unmarshal(compiled.JSON, &cfg); err != nil {
		t.Fatal(err)
	}
	m := compiled.Manifest
	route := cfg["route"].(map[string]any)
	rr := route["rules"].([]any)
	if m == nil || m.RuntimeSHA256 != shaHex(compiled.JSON) || len(m.Rules) != len(rr) {
		t.Fatal("unmodified compiler manifest/runtime mismatch")
	}
	if digest, e := cr.ManifestDigest(*m, cr.ManifestBudget(m)); e != nil || digest != m.ManifestID {
		t.Fatal("unmodified compiler manifest digest mismatch")
	}
	for i, want := range []struct {
		action    string
		synthetic cr.SyntheticKind
	}{{"hijack-dns", cr.SyntheticHijack}, {"sniff", cr.SyntheticSniff}, {"hijack-dns", cr.SyntheticHijack}} {
		if len(rr) <= i || rr[i].(map[string]any)["action"] != want.action || m.Rules[i].Synthetic != want.synthetic {
			t.Fatalf("compiler DNS prefix missing at %d", i)
		}
	}
	if rr[0].(map[string]any)["port"] != float64(53) || !reflect.DeepEqual(rr[2].(map[string]any)["protocol"], []any{"dns"}) {
		t.Fatal("compiler capture predicates changed")
	}
	d := cfg["dns"].(map[string]any)
	servers := d["servers"].([]any)
	if len(servers) != 1 || d["final"] != "secure-dns" || d["reverse_mapping"] != true {
		t.Fatal("compiler single secure DNS policy missing")
	}
	server := servers[0].(map[string]any)
	stls := server["tls"].(map[string]any)
	if server["type"] != "https" || server["server"] != "1.1.1.1" || server["tag"] != "secure-dns" || server["detour"] != "anytls-out" || stls["server_name"] != "cloudflare-dns.com" || stls["insecure"] == true {
		t.Fatal("compiler strict selected-node DoH policy changed")
	}
	host, port, _ := net.SplitHostPort(dohAddr)
	pn, _ := strconv.Atoi(port)
	server["server"] = host
	server["server_port"] = pn
	trust := ca
	if failure == "doh_ca" {
		trust = wrongCA
	}
	sni := "g21.invalid"
	if failure == "doh_san" {
		sni = "wrong.invalid"
	}
	server["tls"] = map[string]any{"enabled": true, "server_name": sni, "certificate": []string{string(trust)}}
	spare, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mixedPort := spare.Addr().(*net.TCPAddr).Port
	spare.Close()
	f.addr = fmt.Sprintf("127.0.0.1:%d", mixedPort)
	cfg["inbounds"] = []any{map[string]any{"type": "mixed", "tag": "protocol-mixed", "listen": "127.0.0.1", "listen_port": mixedPort}}
	runtimeJSON, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	ended := make(chan error, 1)
	go func() { ended <- engine.Run(ctx, runtimeJSON) }()
	var shutdownOnce sync.Once
	f.shutdown = func() {
		shutdownOnce.Do(func() {
			stop()
			select {
			case e := <-ended:
				if e != nil && !errors.Is(e, context.Canceled) {
					t.Errorf("engine shutdown: %v", e)
				}
			case <-time.After(5 * time.Second):
				t.Error("engine shutdown timeout")
			}
			unifiedDNSRebind(t, "tcp", f.addr)
			unifiedDNSRebind(t, "udp", f.addr)
			t.Log("ENGINE_JOIN_AND_MIXED_LISTENER_REBIND complete")
		})
	}
	t.Cleanup(f.shutdown)
	deadline := time.Now().Add(4 * time.Second)
	for {
		c, e := net.DialTimeout("tcp", f.addr, 100*time.Millisecond)
		if e == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("engine mixed not ready")
		}
		select {
		case e := <-ended:
			t.Fatalf("engine ended: %v", e)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Business positive control is meaningful for MATCH Q fixtures, not DIRECT or
	// no-rules. DNS must still use P despite this proven Q data path.
	if strings.HasSuffix(rules, "MATCH,business") && !strings.Contains(rules, "IP-CIDR") && !strings.Contains(rules, "RULE-SET") && !strings.Contains(rules, "GEOIP") && failure == "" {
		client := socks.NewClient(recordsSOCKSDialer{}, M.ParseSocksaddr(f.addr), socks.Version5, "", "")
		c, e := client.DialContext(ctx, "tcp", M.ParseSocksaddr(echo.Addr().String()))
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		nonce := []byte("business-Q-control\x00\xff")
		_, e = c.Write(nonce)
		got := make([]byte, len(nonce))
		_, re := io.ReadFull(c, got)
		c.Close()
		if e != nil || re != nil || !bytes.Equal(got, nonce) || f.q.payload.Load() == 0 || f.p.streams.Load() != 0 {
			t.Fatalf("MATCH Q business control failed: %v %v", e, re)
		}
		t.Log("MATCH_Q_BUSINESS_CONTROL exact echo PASS; P has no business streams")
	}
	t.Logf("COMPILED_TUN_POLICY manifest=%s compiled_sha=%s substituted_no_records=true failure=%s", m.ManifestID, m.RuntimeSHA256, failure)
	return f
}

func (f *unifiedDNSFixture) exchange(t *testing.T, network, dest string, typ uint16, wantSuccess bool) {
	t.Helper()
	q := unifiedDNSQuery()
	q.Question[0].Qtype = typ
	client := socks.NewClient(recordsSOCKSDialer{}, M.ParseSocksaddr(f.addr), socks.Version5, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := client.DialContext(ctx, network, M.ParseSocksaddr(dest))
	if err != nil {
		t.Fatalf("SOCKS %s setup: %v", network, err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	wire, _ := q.Pack()
	var got []byte
	if network == "tcp" {
		dc := &dns.Conn{Conn: c}
		err = dc.WriteMsg(q)
		if err == nil {
			var a *dns.Msg
			a, err = dc.ReadMsg()
			if a != nil {
				got, _ = a.Pack()
			}
		}
	} else {
		_, err = c.Write(wire)
		if err == nil {
			buf := make([]byte, 65535)
			var n int
			var source net.Addr
			n, source, err = c.(net.PacketConn).ReadFrom(buf)
			if err == nil {
				if source.String() != dest {
					t.Fatalf("UDP DNS source %s != %s", source, dest)
				}
				got = buf[:n]
			}
		}
	}
	if !wantSuccess {
		if err == nil {
			var a dns.Msg
			if a.Unpack(got) != nil || len(a.Answer) != 0 || a.Rcode == dns.RcodeSuccess {
				t.Fatalf("failed secure path returned answer/success: %v", a)
			}
		}
		// Timeouts are bounded symptoms only. No-fallback evidence is the single
		// compiler transport + calibrated trap deltas + authenticated peer allowlist.
		t.Logf("FAIL_CLOSED_QUERY network=%s dest=%s type=%s id=%d error=%v response_bytes=%d", network, dest, dns.TypeToString[typ], q.Id, err, len(got))
		return
	}
	if err != nil {
		t.Fatalf("secure DNS %s %s %s: %v", network, dest, dns.TypeToString[typ], err)
	}
	var a dns.Msg
	if a.Unpack(got) != nil || a.Id != q.Id || !a.Response || a.Rcode != dns.RcodeSuccess || !reflect.DeepEqual(a.Question, q.Question) || len(a.Answer) != 1 {
		t.Fatalf("DNS identity/rcode/question/answer mismatch: %v", a)
	}
	expected := unifiedDNSAnswer(q, false)
	packedRR := func(rr dns.RR) []byte {
		b := make([]byte, 1024)
		n, e := dns.PackRR(rr, b, 0, nil, false)
		if e != nil {
			t.Fatal(e)
		}
		return b[:n]
	}
	if !bytes.Equal(packedRR(a.Answer[0]), packedRR(expected.Answer[0])) {
		t.Fatalf("DNS exact answer bytes differ: %v", a.Answer)
	}
	key := fmt.Sprintf("%s/%d", q.Question[0].Name, typ)
	f.mu.Lock()
	count := f.questions[key]
	f.mu.Unlock()
	if count != 1 {
		t.Fatalf("controlled DoH exact question count=%d for %s", count, key)
	}
	t.Logf("EXACT_DNS_PASS network=%s dest=%s type=%s id=%d answer=%s doh_question_count=%d", network, dest, dns.TypeToString[typ], q.Id, a.Answer[0], count)
}
func (f *unifiedDNSFixture) verify(t *testing.T, wantSuccess bool) {
	t.Helper()
	// Drain the exact engine first so a late retry cannot evade final counters.
	f.shutdown()
	if !wantSuccess && (f.q.streams.Load() != 0 || f.q.payload.Load() != 0) {
		t.Fatalf("negative DNS reached business Q: streams=%d payload=%d", f.q.streams.Load(), f.q.payload.Load())
	}
	if f.p.denied.Load() != 0 || f.q.denied.Load() != 0 {
		t.Fatal("unexpected stream/plain DNS destination reached AnyTLS peer")
	}
	if f.p.accepted.Load() == 0 {
		t.Fatal("secure path never attempted AnyTLS P")
	}
	if wantSuccess && (f.httpCount.Load() == 0 || f.p.streams.Load() == 0 || f.p.payload.Load() == 0) {
		t.Fatal("no real AnyTLS -> HTTPS DNS payload witness")
	}
	if f.failure == "http503" && f.httpCount.Load() == 0 {
		t.Fatal("HTTP503 negative never reached resolver")
	}
	if f.failure != "" && f.failure != "http503" && f.httpCount.Load() != 0 {
		t.Fatal("invalid TLS/auth/disconnected path reached HTTP DNS")
	}
	if (f.failure == "password" || f.failure == "node_ca") && f.p.streams.Load() != 0 {
		t.Fatal("bad credentials/node CA created an authenticated stream")
	}
	if f.failure == "password" && f.p.authenticated.Load() == 0 {
		t.Fatal("wrong-password control never completed strict node TLS")
	}
	if f.failure == "node_ca" && f.p.authenticated.Load() != 0 {
		t.Fatal("wrong node CA unexpectedly completed strict TLS")
	}
	for i, p := range f.traps {
		if p.count.Load() != f.baseline[i] {
			t.Fatalf("plaintext trap observed DNS: delta=%d", p.count.Load()-f.baseline[i])
		}
		p.control(t, "after")
	}
	f.p.mu.Lock()
	pd := append([]string(nil), f.p.destinations...)
	f.p.mu.Unlock()
	f.q.mu.Lock()
	qd := append([]string(nil), f.q.destinations...)
	f.q.mu.Unlock()
	for _, d := range pd {
		if d != f.p.target {
			t.Fatal("P forwarded non-DoH destination")
		}
	}
	for _, d := range qd {
		if d != f.q.target {
			t.Fatal("Q received DNS instead of business echo")
		}
	}
	t.Logf("ANYTLS_WITNESS P_accepted=%d P_tls=%d P_streams=%d P_payload=%d P_destinations=%v Q_streams=%d Q_destinations=%v http_queries=%d plaintext_query_delta=0 observer=owned_loopback_only", f.p.accepted.Load(), f.p.authenticated.Load(), f.p.streams.Load(), f.p.payload.Load(), pd, f.q.streams.Load(), qd, f.httpCount.Load())
}

type unifiedDNSNegativeResult struct {
	dest string
	typ uint16
	id uint16
	err error
	responseBytes int
	problem string
}

// Every worker owns its own query, SOCKS association, and 1500ms read window.
func (f *unifiedDNSFixture) negativeUDP(dest string, typ uint16, sent chan<- struct{}, gate <-chan struct{}, arm bool, sockets chan<- net.Conn) (r unifiedDNSNegativeResult) {
	r.dest, r.typ = dest, typ
	q := unifiedDNSQuery()
	q.Question[0].Qtype = typ
	r.id = q.Id
	if arm { f.hold.arm(q.Question[0].Name) }
	client := socks.NewClient(recordsSOCKSDialer{}, M.ParseSocksaddr(f.addr), socks.Version5, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := client.DialContext(ctx, "udp", M.ParseSocksaddr(dest))
	if err != nil { r.problem = fmt.Sprintf("SOCKS udp setup: %v", err); return }
	defer c.Close()
	sockets <- c
	if e := c.SetDeadline(time.Now().Add(1500*time.Millisecond)); e != nil { r.problem = fmt.Sprintf("UDP deadline: %v", e); return }
	wire, e := q.Pack()
	if e != nil { r.problem = fmt.Sprintf("UDP pack: %v", e); return }
	_, r.err = c.Write(wire)
	if r.err == nil {
		close(sent)
		if gate != nil { <-gate }
		buf := make([]byte, 65535)
		var n int
		var source net.Addr
		n, source, r.err = c.(net.PacketConn).ReadFrom(buf)
		if r.err == nil {
			if source.String() != dest { r.problem = fmt.Sprintf("UDP DNS source %s != %s", source, dest); return }
			r.responseBytes = n
			var a dns.Msg
			if a.Unpack(buf[:n]) != nil || len(a.Answer) != 0 || a.Rcode == dns.RcodeSuccess { r.problem = fmt.Sprintf("failed secure path returned answer/success: %v", a) }
		}
	}
	return
}

func (f *unifiedDNSFixture) negativeMatrix(t *testing.T) {
	t.Helper()
	type job struct { dest string; typ uint16; result chan unifiedDNSNegativeResult }
	var jobs []job
	sockets := make(chan net.Conn, 6)
	firstRead := make(chan struct{})
	firstFinished := make(chan struct{})
	var releaseRead sync.Once
	unblock := func() { releaseRead.Do(func(){ close(firstRead) }); if f.hold != nil { f.hold.unblock() } }
	joined := make(map[chan unifiedDNSNegativeResult]bool)
	early := make(map[chan unifiedDNSNegativeResult]unifiedDNSNegativeResult)
	// Also runs on a synchronous TCP Fatal; Cleanup is LIFO, so this runs
	// before fixture shutdown and cannot leave workers using closed fixtures.
	t.Cleanup(func() {
		unblock()
		for { select { case c := <-sockets: c.Close(); default: goto closed } }
	closed:
		for _, j := range jobs { if !joined[j.result] {
			select { case <-j.result: case <-time.After(5*time.Second): t.Errorf("UDP worker not joined during cleanup: %s %s", j.dest, dns.TypeToString[j.typ]) }
		} }
	})
	var problems []string
	for _, dest := range []string{"127.0.0.1:53", "[::1]:53", f.traps[0].tcp.Addr().String()} {
		for _, network := range []string{"tcp", "udp"} {
			for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
				if network == "tcp" { f.exchange(t, network, dest, typ, false); continue }
				first := len(jobs) == 0
				gate := (<-chan struct{})(nil)
				if first && f.hold == nil { gate = firstRead }
				j := job{dest: dest, typ: typ, result: make(chan unifiedDNSNegativeResult, 1)}
				sent := make(chan struct{})
				jobs = append(jobs, j)
				go func() { j.result <- f.negativeUDP(dest, typ, sent, gate, first && f.hold != nil, sockets); if first { close(firstFinished) } }()
				if first {
					select { case <-sent: case r := <-j.result: early[j.result] = r; problems = append(problems, fmt.Sprintf("first UDP never sent: %+v", r)); case <-time.After(4*time.Second): problems = append(problems, "first UDP dispatch timed out") }
					if f.hold != nil && len(problems) == 0 { select { case <-f.hold.first: case <-time.After(4*time.Second): problems = append(problems, "first UDP never arrived at HTTPS") } }
				}
				if len(jobs) == 2 {
					if f.hold != nil {
						select { case <-f.hold.later: case <-firstFinished: problems = append(problems, "first UDP caller completed before later HTTPS arrival"); case <-time.After(4*time.Second): problems = append(problems, "later UDP never reached held HTTPS handler") }
						select { case <-f.hold.handlerDone: problems = append(problems, "first HTTPS handler exited before later arrival"); default: }
						select { case <-firstFinished: problems = append(problems, "first UDP caller completed before overlap witness"); default: if len(problems)==0 { t.Log("UDP_OVERLAP_WITNESS later distinct HTTPS query arrived while first UDP caller and handler held") } }
					} else {
						select { case <-sent: t.Log("UDP_OVERLAP_WITNESS later UDP sent before first reader released"); case r := <-j.result: early[j.result] = r; problems = append(problems, fmt.Sprintf("later UDP never sent: %+v", r)); case <-time.After(4*time.Second): problems = append(problems, "later UDP dispatch timed out") }
					}
					unblock()
				}
			}
		}
	}
	for _, j := range jobs {
		if _, ok := early[j.result]; ok { joined[j.result] = true; continue }
		select {
		case r := <-j.result:
			joined[j.result] = true
			if r.problem != "" { problems = append(problems, fmt.Sprintf("udp %s %s id=%d: %s", j.dest, dns.TypeToString[j.typ], r.id, r.problem)) }
			t.Logf("FAIL_CLOSED_QUERY network=udp dest=%s type=%s id=%d error=%v response_bytes=%d", r.dest, dns.TypeToString[r.typ], r.id, r.err, r.responseBytes)
		case <-time.After(5*time.Second):
			problems = append(problems, fmt.Sprintf("UDP worker not joined: %s %s", j.dest, dns.TypeToString[j.typ]))
			unblock()
			for { select { case c := <-sockets: c.Close(); default: goto socketsClosed } }
			socketsClosed:
			select { case <-j.result: joined[j.result] = true; case <-time.After(5*time.Second): problems = append(problems, "UDP worker still live after owned socket close") }
		}
	}
	if len(problems) != 0 { t.Fatal(strings.Join(problems, "; ")) }
}

func TestUnifiedDNSProtocolSuccess(t *testing.T) {
	for _, tc := range []struct{ name, rules string }{
		{"no_rules", ""},
		{"domain_match_Q", "DOMAIN,unused.invalid,DIRECT\n - MATCH,business"},
		{"early_direct", "IP-CIDR,127.0.0.1/32,DIRECT\n - MATCH,business"},
		{"geoip_no_resolve", "GEOIP,CN,DIRECT,no-resolve\n - MATCH,business"},
		{"geoip_resolve", "GEOIP,CN,DIRECT\n - MATCH,business"},
		{"ruleset_resolve", "ruleset"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := unifiedDNSStart(t, tc.rules, "")
			for _, dest := range []string{"127.0.0.1:53", "[::1]:53", f.traps[0].tcp.Addr().String()} {
				for _, network := range []string{"tcp", "udp"} {
					for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
						f.exchange(t, network, dest, typ, true)
					}
				}
			}
			f.verify(t, true)
		})
	}
}
func TestUnifiedDNSProtocolFailureNoFallback(t *testing.T) {
	for _, failure := range []string{"http503", "doh_ca", "doh_san", "disconnect", "password", "node_ca"} {
		t.Run(failure, func(t *testing.T) {
			f := unifiedDNSStart(t, "DOMAIN,unused.invalid,DIRECT\n - MATCH,business", failure)
			f.negativeMatrix(t)
			f.verify(t, false)
		})
	}
}
