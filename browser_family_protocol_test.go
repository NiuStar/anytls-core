//go:build embedded_core && with_utls

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NiuStar/anytls-core/internal/engine"
	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks"
)

// The actual TUN compiler policy is retained; only privileged inbound and
// controlled TLS endpoints/trust are substituted. This is NOT a TUN/site test.
func browserRoots(t *testing.T, ca []byte) *x509.CertPool {
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(ca) {
		t.Fatal("CA")
	}
	return p
}
func containsBrowserBody(b []byte) bool { return bytes.HasSuffix(b, []byte("browser-exact-body")) }
func TestBrowserDefaultCompiledHTTPSFallback(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprint("reject=", reject), func(t *testing.T) {
			ca, cert := runtimeCertificate(t)
			var business, queries atomic.Int64
			target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { business.Add(1); io.WriteString(w, "browser-exact-body") }))
			target.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
			target.StartTLS()
			defer target.Close()
			doh := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				queries.Add(1)
				b, _ := io.ReadAll(r.Body)
				q := new(dns.Msg)
				if q.Unpack(b) != nil {
					w.WriteHeader(400)
					return
				}
				a := unifiedDNSAnswer(q, false)
				for _, rr := range a.Answer {
					switch x := rr.(type) {
					case *dns.A:
						x.A = net.ParseIP("127.0.0.1")
					case *dns.AAAA:
						x.AAAA = net.ParseIP("2001:db8::41")
					}
				}
				b, _ = a.Pack()
				w.Header().Set("Content-Type", "application/dns-message")
				w.Write(b)
			}))
			doh.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
			doh.StartTLS()
			defer doh.Close()
			p, pp := unifiedDNSStartPeer(t, doh.Listener.Addr().String(), cert)
			q, qp := unifiedDNSStartPeer(t, target.Listener.Addr().String(), cert)
			q.browser.Store(true)
			dir := t.TempDir()
			caPath := filepath.Join(dir, "ca.pem")
			runtimeWrite(t, caPath, ca, 0600)
			config := fmt.Sprintf("nodes:\n - {name: P, type: anytls, server: 127.0.0.1, port: %d, password: synthetic-unified-only, sni: g21.invalid, ca: %q, min-idle-session: 0}\n - {name: Q, type: anytls, server: 127.0.0.1, port: %d, password: synthetic-unified-only, sni: g21.invalid, ca: %q, min-idle-session: 0}\nrules:\n", pp, caPath, qp, caPath)
			if reject {
				config += " - IP-CIDR,127.0.0.0/8,REJECT\n"
			}
			config += " - MATCH,Q\n"
			path := filepath.Join(dir, "config.yaml")
			runtimeWrite(t, path, []byte(config), 0600)
			compiled, e := prepareRuntimeWithRecords(&runtimeOptions{Config: path, NodeName: "P", Mode: "tun", LocalPort: 11080})
			if e != nil {
				t.Fatal(e)
			}
			var cfg map[string]any
			json.Unmarshal(compiled.JSON, &cfg)
			route := cfg["route"].(map[string]any)
			rr := route["rules"].([]any)
			if route["auto_detect_interface"] != true || len(rr) < 3 || rr[0].(map[string]any)["action"] != "hijack-dns" || rr[1].(map[string]any)["action"] != "sniff" || rr[2].(map[string]any)["action"] != "hijack-dns" {
				t.Fatal("not actual canonical TUN policy")
			}
			server := cfg["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
			if server["detour"] != "anytls-out" {
				t.Fatal("DNS lost P")
			}
			host, port, _ := net.SplitHostPort(doh.Listener.Addr().String())
			pn, _ := strconv.Atoi(port)
			server["server"] = host
			server["server_port"] = pn
			server["tls"] = map[string]any{"enabled": true, "server_name": "g21.invalid", "certificate": []string{string(ca)}}
			l, _ := net.Listen("tcp", "127.0.0.1:0")
			addr := l.Addr().String()
			proxyPort := l.Addr().(*net.TCPAddr).Port
			l.Close()
			cfg["inbounds"] = []any{map[string]any{"type": "mixed", "tag": "browser", "listen": "127.0.0.1", "listen_port": proxyPort}}
			raw, _ := json.Marshal(cfg)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- engine.Run(ctx, raw) }()
			defer func() {
				cancel()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("engine did not join")
				}
			}()
			deadline := time.Now().Add(4 * time.Second)
			for {
				c, e := net.DialTimeout("tcp", addr, 50*time.Millisecond)
				if e == nil {
					c.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("not listening")
				}
				time.Sleep(10 * time.Millisecond)
			}
			client := socks.NewClient(recordsSOCKSDialer{}, M.ParseSocksaddr(addr), socks.Version5, "", "")
			// Browser receives real AAAA wire bytes from the accepted SDK return seam.
			c, e := client.DialContext(ctx, "tcp", M.ParseSocksaddr("127.0.0.1:53"))
			if e != nil {
				t.Fatal(e)
			}
			c.SetDeadline(time.Now().Add(3 * time.Second))
			dc := &dns.Conn{Conn: c}
			question := new(dns.Msg)
			question.SetQuestion("browser.test.", dns.TypeAAAA)
			if e = dc.WriteMsg(question); e != nil {
				t.Fatal(e)
			}
			answer, e := dc.ReadMsg()
			c.Close()
			if e != nil || len(answer.Answer) != 1 {
				t.Fatal("browser DNS", e)
			}
			six := answer.Answer[0].(*dns.AAAA).AAAA.String()
			_, targetPort, _ := net.SplitHostPort(target.Listener.Addr().String())
			c, e = client.DialContext(ctx, "tcp", M.ParseSocksaddr(net.JoinHostPort(six, targetPort)))
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(6 * time.Second))
			// TLS ClientHello supplies canonical sniff metadata, but no business bytes
			// can leave the proxy before ACK-selected winner.
			roots := target.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
			// httptest's client root is the server leaf we supplied.
			_ = roots
			tlsClient := tls.Client(c, &tls.Config{RootCAs: browserRoots(t, ca), ServerName: "g21.invalid"})
			e = tlsClient.Handshake()
			if reject {
				if e == nil {
					t.Fatal("candidate REJECT bypass")
				}
				if q.v4.Load() != 0 || business.Load() != 0 {
					t.Fatal("REJECT alternate launched")
				}
				t.Logf("REJECT_NO_ALTERNATE q6=%d q4=%d DNS=%d", q.v6.Load(), q.v4.Load(), queries.Load())
				return
			}
			if e != nil {
				t.Fatalf("default browser IPv6 literal did not fallback to HTTPS: %v q6=%d q4=%d DNS=%d", e, q.v6.Load(), q.v4.Load(), queries.Load())
			}
			fmt.Fprintf(tlsClient, "GET / HTTP/1.1\r\nHost: g21.invalid\r\nConnection: close\r\n\r\n")
			body, e := io.ReadAll(tlsClient)
			if e != nil || !containsBrowserBody(body) || business.Load() != 1 || q.v6.Load() != 1 || q.v4.Load() != 1 || queries.Load() != 3 {
				t.Fatalf("wrong exact business result: %s %v counts %d %d %d %d", body, e, business.Load(), q.v6.Load(), q.v4.Load(), queries.Load())
			}
			t.Logf("REAL_DEFAULT_FALLBACK HTTPS_BODY_EXACT business=1 Q_v6=1 Q_v4=1 DNS_P=3 P_streams=%d", p.streams.Load())
		})
	}
}
