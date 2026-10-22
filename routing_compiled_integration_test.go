//go:build embedded_core && with_utls

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NiuStar/anytls-core/internal/engine"
	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Fresh peer and engine per case: authenticated streams and forwarded payload
// bytes, not accepted TCP connections alone, witness the AnyTLS business path.
type routingCompiledPeer struct {
	target                           string
	accepted, streams, payload, echo atomic.Int64
	mu                               sync.Mutex
	conns                            []net.Conn
	wg                               sync.WaitGroup
}

func (p *routingCompiledPeer) track(c net.Conn) {
	p.mu.Lock()
	p.conns = append(p.conns, c)
	p.mu.Unlock()
}

type routingCompiledReader struct {
	io.Reader
	count *atomic.Int64
}

func (r routingCompiledReader) Read(b []byte) (int, error) {
	n, e := r.Reader.Read(b)
	r.count.Add(int64(n))
	return n, e
}
func (p *routingCompiledPeer) NewConnectionEx(ctx context.Context, c net.Conn, _ M.Socksaddr, d M.Socksaddr, _ N.CloseHandlerFunc) {
	p.streams.Add(1)
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer c.Close()
		// Never dial a non-fixture destination, including unresolved hostnames.
		_, port, _ := net.SplitHostPort(p.target)
		if d.String() != p.target && !(d.Fqdn == "localhost" && strconv.Itoa(int(d.Port)) == port) {
			return
		}
		up, e := net.DialTimeout("tcp", p.target, time.Second)
		if e != nil {
			return
		}
		p.track(up)
		defer up.Close()
		done := make(chan struct{})
		go func() { _, _ = io.Copy(up, routingCompiledReader{c, &p.payload}); up.Close(); close(done) }()
		_, _ = io.Copy(c, up)
		c.Close()
		<-done
	}()
}

func TestRoutingCompiledMixedDirectVsAnyTLS(t *testing.T) {
	cases := []struct {
		name, rules, host, want string
		set                     bool
	}{
		{"literal_direct", "IP-CIDR,127.0.0.1/32,DIRECT\n - MATCH,P", "127.0.0.1", "direct", false},
		{"literal_proxy_control", "IP-CIDR,127.0.0.1/32,P\n - MATCH,P", "127.0.0.1", "proxy", false},
		{"literal_reject", "IP-CIDR,127.0.0.1/32,REJECT\n - MATCH,P", "127.0.0.1", "reject", false},
		{"domain_direct", "DOMAIN,localhost,DIRECT\n - MATCH,P", "localhost", "direct", false},
		{"suffix_direct", "DOMAIN-SUFFIX,localhost,DIRECT\n - MATCH,P", "localhost", "direct", false},
		{"domain_proxy_control", "DOMAIN,localhost,P\n - MATCH,P", "localhost", "proxy", false},
		{"first_proxy_wins", "DOMAIN,localhost,P\n - DOMAIN-SUFFIX,localhost,DIRECT\n - IP-CIDR,127.0.0.0/8,DIRECT\n - MATCH,P", "localhost", "proxy", false},
		{"first_direct_wins", "DOMAIN,localhost,DIRECT\n - DOMAIN-SUFFIX,localhost,P\n - MATCH,P", "localhost", "direct", false},
		{"custom_v3_ruleset_direct", "RULE-SET,loop,DIRECT,no-resolve\n - MATCH,P", "127.0.0.1", "direct", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			ca, cert := runtimeCertificate(t)
			caPath := filepath.Join(dir, "ca.pem")
			runtimeWrite(t, caPath, ca, 0600)
			peer := &routingCompiledPeer{}
			echo, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			peer.target = echo.Addr().String()
			server, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				echo.Close()
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			svc, e := anytls.NewService(anytls.ServiceConfig{Users: []anytls.User{{Name: "fixture", Password: "synthetic-routing-only"}}, PaddingScheme: padding.DefaultPaddingScheme, Handler: peer, Logger: logger.NOP()})
			if e != nil {
				t.Fatal(e)
			}
			serve := func(l net.Listener, fn func(net.Conn)) {
				peer.wg.Add(1)
				go func() {
					defer peer.wg.Done()
					for {
						c, e := l.Accept()
						if e != nil {
							return
						}
						peer.track(c)
						peer.wg.Add(1)
						go func() { defer peer.wg.Done(); defer c.Close(); fn(c) }()
					}
				}()
			}
			serve(echo, func(c net.Conn) { _, _ = io.Copy(c, routingCompiledReader{c, &peer.echo}) })
			serve(server, func(c net.Conn) {
				peer.accepted.Add(1)
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
				_ = tc.SetDeadline(time.Now().Add(8 * time.Second))
				if tc.HandshakeContext(ctx) == nil {
					_ = svc.NewConnection(ctx, tc, M.SocksaddrFromNet(c.RemoteAddr()), nil)
				}
			})
			t.Cleanup(func() {
				cancel()
				echo.Close()
				server.Close()
				peer.mu.Lock()
				for _, c := range peer.conns {
					c.Close()
				}
				peer.mu.Unlock()
				done := make(chan struct{})
				go func() { peer.wg.Wait(); close(done) }()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("fixture cleanup timeout")
				}
			})
			spare, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			mixedPort := spare.Addr().(*net.TCPAddr).Port
			spare.Close()
			_, serverPort, _ := net.SplitHostPort(server.Addr().String())
			yaml := fmt.Sprintf("nodes:\n - {name: P, type: anytls, server: 127.0.0.1, port: %s, password: synthetic-routing-only, sni: g21.invalid, ca: %q, min-idle-session: 0}\n", serverPort, caPath)
			if tc.set {
				b := []byte(`{"version":3,"rules":[{"ip_cidr":["127.0.0.0/8"]}]}`)
				runtimeWrite(t, filepath.Join(dir, "loop.json"), b, 0600)
				yaml += fmt.Sprintf("rule-sets:\n loop: {path: loop.json, sha256: %s, resolve-ip: false}\n", shaHex(b))
			}
			yaml += "rules:\n - " + tc.rules + "\n"
			cfgPath := filepath.Join(dir, "config.yaml")
			runtimeWrite(t, cfgPath, []byte(yaml), 0600)
			cfg, e := prepareRuntime(&runtimeOptions{Config: cfgPath, NodeName: "P", Mode: "proxy", LocalPort: mixedPort})
			if e != nil {
				t.Fatal(e)
			}
			// Fault-restoring calibration only in a separately frozen test-source copy.
			// Mutant replaces the compiled DIRECT outbound, leaving all assertions intact.
			const routingCompiledFault = false
			if routingCompiledFault {
				for _, raw := range cfg["route"].(map[string]any)["rules"].([]any) {
					r := raw.(map[string]any)
					if r["outbound"] == "direct" {
						r["outbound"] = "anytls-out"
					}
				}
			}
			b, e := json.Marshal(cfg)
			if e != nil {
				t.Fatal(e)
			}
			runCtx, stop := context.WithTimeout(ctx, 8*time.Second)
			ended := make(chan error, 1)
			go func() { ended <- engine.Run(runCtx, b) }()
			t.Cleanup(func() {
				stop()
				select {
				case e := <-ended:
					if e != nil && !errors.Is(e, context.Canceled) {
						t.Errorf("engine close: %v", e)
					}
				case <-time.After(3 * time.Second):
					t.Error("engine cleanup timeout")
				}
			})
			addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(mixedPort))
			var c net.Conn
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				c, e = net.DialTimeout("tcp", addr, 100*time.Millisecond)
				if e == nil {
					break
				}
				select {
				case e := <-ended:
					t.Fatalf("engine ended before mixed ready: %v", e)
				default:
				}
				time.Sleep(10 * time.Millisecond)
			}
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(4 * time.Second))
			if _, e = c.Write([]byte{5, 1, 0}); e != nil {
				t.Fatal(e)
			}
			greet := make([]byte, 2)
			if _, e = io.ReadFull(c, greet); e != nil || !bytes.Equal(greet, []byte{5, 0}) {
				t.Fatalf("SOCKS greeting: %v %v", greet, e)
			}
			_, targetPort, _ := net.SplitHostPort(peer.target)
			port, _ := strconv.Atoi(targetPort)
			req := []byte{5, 1, 0}
			if strings.Contains(tc.host, "localhost") {
				req = append(req, 3, byte(len(tc.host)))
				req = append(req, tc.host...)
			} else {
				req = append(req, 1)
				req = append(req, net.ParseIP(tc.host).To4()...)
			}
			req = binary.BigEndian.AppendUint16(req, uint16(port))
			if _, e = c.Write(req); e != nil {
				t.Fatal(e)
			}
			head := make([]byte, 4)
			_, e = io.ReadFull(c, head)
			if e != nil || head[1] != 0 {
				if tc.want != "reject" {
					t.Fatalf("SOCKS connect code=%d error=%v", head[1], e)
				}
				if ne, ok := e.(net.Error); ok && ne.Timeout() {
					t.Fatal("REJECT timeout is not rejection evidence")
				}
			} else {
				// mixed may acknowledge CONNECT before sniffing/routing. A success
				// reply alone is not proof that REJECT leaked target traffic.
				n := 0
				switch head[3] {
				case 1:
					n = 4
				case 4:
					n = 16
				case 3:
					var one [1]byte
					if _, e = io.ReadFull(c, one[:]); e != nil {
						t.Fatal(e)
					}
					n = int(one[0])
				default:
					t.Fatal("bad SOCKS bound ATYP")
				}
				if _, e = io.CopyN(io.Discard, c, int64(n+2)); e != nil {
					t.Fatal(e)
				}
				nonce := make([]byte, 64)
				if _, e = rand.Read(nonce); e != nil {
					t.Fatal(e)
				}
				_, writeErr := c.Write(nonce)
				got := make([]byte, len(nonce))
				_, readErr := io.ReadFull(c, got)
				if tc.want == "reject" {
					if readErr == nil {
						t.Fatal("REJECT unexpectedly returned payload")
					}
					if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
						t.Fatal("REJECT timeout is not rejection evidence")
					}
					t.Logf("REJECT_CLOSE write_error=%t read_error=%T", writeErr != nil, readErr)
				} else if writeErr != nil || readErr != nil || !bytes.Equal(got, nonce) {
					t.Fatalf("binary nonce echo failed: write=%v read=%v", writeErr, readErr)
				}
			}
			c.Close()
			a, s, p, x := peer.accepted.Load(), peer.streams.Load(), peer.payload.Load(), peer.echo.Load()
			t.Logf("ROUTING_COUNTS case=%s want=%s accepted=%d streams=%d anytls_payload_bytes=%d echo_bytes=%d", tc.name, tc.want, a, s, p, x)
			switch tc.want {
			case "direct":
				if x != 64 || a != 0 || s != 0 || p != 0 {
					t.Fatalf("DIRECT business assertion: echo=%d accepted=%d streams=%d bytes=%d", x, a, s, p)
				}
			case "proxy":
				if x != 64 || a < 1 || s < 1 || p != 64 {
					t.Fatalf("PROXY business assertion: echo=%d accepted=%d streams=%d bytes=%d", x, a, s, p)
				}
			case "reject":
				if x != 0 || s != 0 || p != 0 || a != 0 {
					t.Fatalf("REJECT leaked business: %d %d %d %d", x, a, s, p)
				}
			}
		})
	}
}
