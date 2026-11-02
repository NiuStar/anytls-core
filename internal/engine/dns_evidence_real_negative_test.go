package engine

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	de "github.com/NiuStar/anytls-core/internal/dnsevidence"
	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSEvidenceRealNegativeMatrix(t *testing.T) {
	for _, mode := range []string{"tls", "unreachable", "cancel"} {
		for _, async := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/async=%t", mode, async), func(t *testing.T) {
				entered := make(chan struct{}, 1)
				release := make(chan struct{})
				exited := make(chan struct{}, 1)
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer func() { exited <- struct{}{} }()
					select {
					case entered <- struct{}{}:
					default:
					}
					select {
					case <-r.Context().Done():
					case <-release:
					}
				}))
				defer server.Close()
				handlerEntered := false
				defer func() {
					close(release)
					if handlerEntered {
						select {
						case <-exited:
						case <-time.After(time.Second):
							t.Error("fixture handler release did not join")
							server.CloseClientConnections()
						}
					}
				}()
				cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
				port := server.Listener.Addr().(*net.TCPAddr).Port
				if mode == "unreachable" {
					server.Close()
				}
				sni := "example.com"
				if mode == "tls" {
					sni = "wrong.invalid"
				}
				raw := []byte(fmt.Sprintf(`{"dns":{"final":"secure-dns","servers":[{"type":"https","tag":"secure-dns","server":"127.0.0.1","server_port":%d,"tls":{"server_name":%q,"certificate":[%q]}}]},"outbounds":[{"type":"direct","tag":"direct"}]}`, port, sni, cert))
				c := de.New(de.Binding{InstanceID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32), ManifestID: strings.Repeat("c", 64), RuntimeSHA256: strings.Repeat("d", 64)})
				ctx, opts, e := decodeOptions(WithDNSEvidence(context.Background(), c), raw)
				if e != nil {
					t.Fatal(e)
				}
				evidenceDecoded(ctx, opts)
				reg := service.FromContext[adapter.DNSTransportRegistry](ctx)
				transport, e := reg.CreateDNSTransport(ctx, logger.NOP(), "secure-dns", C.DNSTypeHTTPS, opts.DNS.Servers[0].Options)
				if e != nil {
					t.Fatal(e)
				}
				defer transport.Reset()
				// Real constructor/exchange fixture, not box.Start or TUN acceptance.
				c.Loaded()
				work, cancel := context.WithTimeout(ctx, 3*time.Second)
				defer cancel()
				var callbacks atomic.Int32
				result := make(chan error, 1)
				q := new(dns.Msg).SetQuestion("private.invalid.", dns.TypeAAAA)
				before := q.String()
				if async {
					transport.ExchangeAsync(work, q, func(r *dns.Msg, e error) {
						callbacks.Add(1)
						if r != nil {
							t.Error("negative returned response")
						}
						result <- e
					})
				} else {
					go func() {
						r, e := transport.Exchange(work, q)
						if r != nil {
							t.Error("negative returned response")
						}
						result <- e
					}()
				}
				if mode == "cancel" {
					select {
					case <-entered:
						handlerEntered = true
					case <-time.After(time.Second):
						t.Fatal("real HTTPS handler not reached")
					}
					cancel()
				}
				select {
				case e = <-result:
				case <-time.After(4 * time.Second):
					t.Fatal("completion not joined")
				}
				if e == nil || q.String() != before {
					t.Fatal("error or query identity changed", e)
				}
				if mode == "cancel" && !errors.Is(e, context.Canceled) {
					t.Fatal("lost cancellation identity", e)
				}
				if async && callbacks.Load() != 1 {
					t.Fatal("callback count", callbacks.Load())
				}
				snapshot := c.Snapshot()
				expected := "OTHER_ERROR"
				if mode == "tls" {
					expected = "TLS_FAILURE"
				}
				if mode == "cancel" {
					expected = "CANCELED"
				}
				if len(snapshot.Events) != 1 || snapshot.Events[0].Outcome != expected {
					t.Fatalf("mode=%s evidence=%+v original=%v", mode, snapshot.Events, e)
				}
			})
		}
	}
}
