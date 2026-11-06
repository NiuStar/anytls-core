//go:build embedded_core && with_utls

package main

import (
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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NiuStar/anytls-core/internal/engine"
	"github.com/miekg/dns"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	sj "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/service"
)

// Unprivileged real SDK acceptance. Only TUN inbound and strict DoH fixture
// endpoint/trust are rebound; policy, detour, routing and business TLS stay intact.
func TestInitialAddressFamilyRealSDKDNSAndHTTPS(t *testing.T) {
	for _, setting := range []string{"", "ipv6: false\n", "ipv6: true\n"} {
		t.Run(strings.TrimSpace(setting), func(t *testing.T) {
			dual := strings.Contains(setting, "true")
			ca, cert := runtimeCertificate(t)
			var aQueries, aaaaQueries, business atomic.Int64
			target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				business.Add(1)
				io.WriteString(w, "initial-family-exact-body")
			}))
			target.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
			target.StartTLS()
			defer target.Close()
			doh := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/dns-query" || r.Header.Get("Content-Type") != "application/dns-message" {
					w.WriteHeader(400)
					return
				}
				raw, err := io.ReadAll(io.LimitReader(r.Body, 65536))
				q := new(dns.Msg)
				if err != nil || q.Unpack(raw) != nil || len(q.Question) != 1 {
					w.WriteHeader(400)
					return
				}
				answer := new(dns.Msg).SetReply(q)
				h := dns.RR_Header{Name: q.Question[0].Name, Rrtype: q.Question[0].Qtype, Class: dns.ClassINET, Ttl: 60}
				switch q.Question[0].Qtype {
				case dns.TypeA:
					aQueries.Add(1)
					answer.Answer = []dns.RR{&dns.A{Hdr: h, A: net.ParseIP("127.0.0.1")}}
				case dns.TypeAAAA:
					aaaaQueries.Add(1)
					answer.Answer = []dns.RR{&dns.AAAA{Hdr: h, AAAA: net.ParseIP("2001:db8::41")}}
				}
				wire, _ := answer.Pack()
				w.Header().Set("Content-Type", "application/dns-message")
				w.Write(wire)
			}))
			doh.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
			doh.StartTLS()
			defer doh.Close()
			p, pp := unifiedDNSStartPeer(t, doh.Listener.Addr().String(), cert)
			q, qp := unifiedDNSStartPeer(t, target.Listener.Addr().String(), cert)
			q.browser.Store(true)
			trap := unifiedDNSStartTrap(t, 0, false)
			trap.control(t, "before")
			trapBaseline := trap.count.Load()
			dir := t.TempDir()
			caPath := filepath.Join(dir, "ca.pem")
			runtimeWrite(t, caPath, ca, 0600)
			source := []byte(fmt.Sprintf("%snodes:\n - {name: P, type: anytls, server: 127.0.0.1, port: %d, password: synthetic-unified-only, sni: g21.invalid, ca: %q}\n - {name: Q, type: anytls, server: 127.0.0.1, port: %d, password: synthetic-unified-only, sni: g21.invalid, ca: %q}\nrules:\n - GEOIP,CN,Q\n - MATCH,Q\n", setting, pp, caPath, qp, caPath))
			path := filepath.Join(dir, "config.yaml")
			runtimeWrite(t, path, source, 0600)
			compiled, err := prepareRuntimeWithRecords(&runtimeOptions{Command: "check", Config: path, NodeName: "P", Mode: "tun"})
			if err != nil {
				t.Fatal(err)
			}
			if compiled.Manifest == nil || compiled.Manifest.RuntimeSHA256 != shaHex(compiled.JSON) || *compiled.Manifest.CapturedSources[0].SHA256 != shaHex(source) {
				t.Fatal("source/runtime closure")
			}
			if err = engine.Check(context.Background(), compiled.JSON); err != nil {
				t.Fatal(err)
			}
			var cfg map[string]any
			if err = json.Unmarshal(compiled.JSON, &cfg); err != nil {
				t.Fatal(err)
			}
			in := cfg["inbounds"].([]any)[0].(map[string]any)
			want := []any{"172.19.0.1/30"}
			if dual {
				want = append(want, "fdfe:dcba:9876::1/126")
			}
			if !reflect.DeepEqual(in["address"], want) {
				t.Errorf("compiled initial addresses: %v", in["address"])
			}
			server := cfg["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
			if server["detour"] != "anytls-out" || server["server"] != "1.1.1.1" {
				t.Fatal("original selected-node strict DNS lost")
			}
			server["server"] = "127.0.0.1"
			server["server_port"] = doh.Listener.Addr().(*net.TCPAddr).Port
			server["tls"] = map[string]any{"enabled": true, "server_name": "g21.invalid", "certificate": []string{string(ca)}}
			spare, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := spare.Addr().String()
			port := spare.Addr().(*net.TCPAddr).Port
			spare.Close()
			cfg["inbounds"] = []any{map[string]any{"type": "mixed", "tag": "family-lab", "listen": "127.0.0.1", "listen_port": port}}
			raw, _ := json.Marshal(cfg)
			// Reuse the product's real minimal registry and the SDK's strict decoder.
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			ctx = engine.Context(service.ContextWithRegistry(ctx, service.NewRegistry()))
			opts, err := sj.UnmarshalExtendedContext[option.Options](ctx, raw)
			if err != nil {
				t.Fatal(err)
			}
			opts.Log = &option.LogOptions{Disabled: true}
			instance, err := box.New(box.Options{Options: opts, Context: ctx})
			if err != nil {
				t.Fatal(err)
			}
			defer instance.Close()
			if err = instance.Start(); err != nil {
				t.Fatal(err)
			}
			router := service.FromContext[adapter.DNSRouter](ctx)
			check := func(question *dns.Msg, response *dns.Msg, err error) {
				t.Helper()
				if err != nil || response == nil {
					t.Fatalf("DNS return: %v", err)
				}
				if response.Id != question.Id || !response.Response || response.Rcode != dns.RcodeSuccess || !reflect.DeepEqual(response.Question, question.Question) {
					t.Fatalf("not matching NOERROR: %v", response)
				}
				wantCount := 1
				if question.Question[0].Qtype == dns.TypeAAAA && !dual {
					wantCount = 0
				}
				if len(response.Answer) != wantCount {
					t.Fatalf("family DNS answers=%v want count=%d", response.Answer, wantCount)
				}
				if wantCount == 1 && response.Answer[0].Header().Rrtype != question.Question[0].Qtype {
					t.Fatal("wrong family answer")
				}
			}
			// Exchange and ExchangeAsync both traverse the actual Router/Client; unique
			// questions avoid allowing one cached positive to mask a different API seam.
			for _, async := range []bool{false, true} {
				for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
					question := new(dns.Msg).SetQuestion(fmt.Sprintf("sync-%t-%d.g21.invalid.", async, typ), typ)
					if async {
						type result struct {
							response *dns.Msg
							err      error
						}
						done := make(chan result, 1)
						router.ExchangeAsync(ctx, question, adapter.DNSQueryOptions{}, func(r *dns.Msg, e error) { done <- result{r, e} })
						select {
						case r := <-done:
							check(question, r.response, r.err)
						case <-ctx.Done():
							t.Fatal(ctx.Err())
						}
					} else {
						r, e := router.Exchange(ctx, question, adapter.DNSQueryOptions{})
						check(question, r, e)
					}
				}
			}
			// The same rebound JSON also runs through the actual engine entry.
			// Direct SDK calls above establish sync/async semantics; wire DNS and
			// HTTPS below exercise the product Run, not a replacement framework.
			businessIP := ""
			if !dual {
				ips, err := router.Lookup(ctx, "g21.invalid", adapter.DNSQueryOptions{})
				if err != nil || len(ips) != 1 || !ips[0].Is4() || ips[0].String() != "127.0.0.1" {
					t.Fatalf("IPv4-only Lookup: %v %v", ips, err)
				}
				businessIP = ips[0].String()
			}
			if err = instance.Close(); err != nil {
				t.Fatal(err)
			}
			engineCtx, stopEngine := context.WithCancel(ctx)
			ended := make(chan error, 1)
			go func() { ended <- engine.Run(engineCtx, raw) }()
			joined := false
			shutdown := func() {
				if joined {
					return
				}
				joined = true
				stopEngine()
				select {
				case err := <-ended:
					if err != nil && !errors.Is(err, context.Canceled) {
						t.Error(err)
					}
				case <-time.After(5 * time.Second):
					t.Error("engine did not join")
				}
			}
			defer shutdown()
			deadline := time.Now().Add(3 * time.Second)
			for {
				c, e := net.DialTimeout("tcp", addr, 50*time.Millisecond)
				if e == nil {
					c.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("engine not ready")
				}
				time.Sleep(10 * time.Millisecond)
			}
			client := socks.NewClient(recordsSOCKSDialer{}, M.ParseSocksaddr(addr), socks.Version5, "", "")
			for _, network := range []string{"tcp", "udp"} {
				for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
					question := new(dns.Msg).SetQuestion(fmt.Sprintf("wire-%s-%d.g21.invalid.", network, typ), typ)
					c, err := client.DialContext(ctx, network, M.ParseSocksaddr(trap.tcp.Addr().String()))
					if err != nil {
						t.Fatal(err)
					}
					c.SetDeadline(time.Now().Add(3 * time.Second))
					var response *dns.Msg
					if network == "tcp" {
						dc := &dns.Conn{Conn: c}
						err = dc.WriteMsg(question)
						if err == nil {
							response, err = dc.ReadMsg()
						}
					} else {
						wire, _ := question.Pack()
						_, err = c.Write(wire)
						if err == nil {
							b := make([]byte, 65535)
							var n int
							var from net.Addr
							n, from, err = c.(net.PacketConn).ReadFrom(b)
							if err == nil {
								if from.String() != trap.tcp.Addr().String() {
									t.Error("redirected DNS reply")
								}
								response = new(dns.Msg)
								err = response.Unpack(b[:n])
							}
						}
					}
					c.Close()
					check(question, response, err)
				}
			}
			// A browser-like client chooses from the returned A/AAAA set. Default mode
			// must have no IPv6 candidate at all, so there is no unavailable flow/retry.
			if !dual {
				_, targetPort, _ := net.SplitHostPort(target.Listener.Addr().String())
				tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: browserRoots(t, ca), ServerName: "g21.invalid", MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return client.DialContext(ctx, network, M.ParseSocksaddr(net.JoinHostPort(businessIP, targetPort)))
				}}
				hc := &http.Client{Transport: tr, Timeout: 4 * time.Second}
				response, err := hc.Get("https://g21.invalid/initial-family")
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				tr.CloseIdleConnections()
				if err != nil || string(body) != "initial-family-exact-body" || response.StatusCode != 200 || business.Load() != 1 {
					t.Fatalf("HTTPS business: %q %v", body, err)
				}
				if q.v6.Load() != 0 || q.v4.Load() != 1 || q.streams.Load() != 1 {
					t.Fatalf("unexpected alternate/IPv6 CONNECT v6=%d v4=%d streams=%d", q.v6.Load(), q.v4.Load(), q.streams.Load())
				}
			}
			shutdown()
			if aQueries.Load() == 0 || (!dual && aaaaQueries.Load() != 0) || (dual && aaaaQueries.Load() != 4) {
				t.Fatalf("upstream query families A=%d AAAA=%d dual=%t", aQueries.Load(), aaaaQueries.Load(), dual)
			}
			if p.denied.Load() != 0 || q.denied.Load() != 0 || trap.count.Load() != trapBaseline {
				t.Fatal("query leaked/redirected or unexpected remote target")
			}
			trap.control(t, "after")
			unifiedDNSRebind(t, "tcp", addr)
			t.Logf("INITIAL_POLICY_REAL_SDK dual=%t UDP_TCP_Exchange_Async=PASS A_upstream=%d AAAA_upstream=%d IPv6_CONNECT=%d IPv4_CONNECT=%d HTTPS_bodies=%d plaintext_delta=0", dual, aQueries.Load(), aaaaQueries.Load(), q.v6.Load(), q.v4.Load(), business.Load())
		})
	}
}
