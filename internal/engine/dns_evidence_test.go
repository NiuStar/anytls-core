package engine

import (
	"context"
	"encoding/pem"
	"fmt"
	de "github.com/NiuStar/anytls-core/internal/dnsevidence"
	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSEvidenceRealHTTPS(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		b, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if q.Unpack(b) != nil {
			t.Error("unpack")
			return
		}
		a := new(dns.Msg).SetReply(q)
		if q.Question[0].Qtype == dns.TypeAAAA {
			a.Rcode = dns.RcodeNameError
		}
		a.SetEdns0(1232, true)
		wire, _ := a.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	}))
	defer server.Close()
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	port := server.Listener.Addr().(*net.TCPAddr).Port
	raw := []byte(fmt.Sprintf(`{"dns":{"final":"secure-dns","servers":[{"type":"https","tag":"secure-dns","server":"127.0.0.1","server_port":%d,"tls":{"server_name":"example.com","certificate":[%q]}}]},"outbounds":[{"type":"direct","tag":"direct"}]}`, port, cert))
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
	if c.Snapshot().State != "STARTING" {
		t.Fatal("constructor claimed loaded")
	}
	c.Loaded() // Constructor fixture; actual successful Start checked separately.
	q := new(dns.Msg).SetQuestion("secret.invalid.", dns.TypeA)
	before := q.String()
	r, e := transport.Exchange(ctx, q)
	if e != nil || r == nil || q.String() != before {
		t.Fatal("sync result")
	}
	done := make(chan struct{})
	transport.ExchangeAsync(ctx, new(dns.Msg).SetQuestion("secret.invalid.", dns.TypeAAAA), func(r *dns.Msg, e error) {
		defer close(done)
		if e != nil || r == nil || r.Rcode != dns.RcodeNameError {
			t.Error("async result")
		}
	})
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("callback join")
	}
	s := c.Snapshot()
	if len(s.Events) != 2 || requests.Load() != 2 || s.Events[0].Validation != "MATCHED" || s.Events[1].Outcome != "NXDOMAIN" || s.Events[0].Connections.Acquisitions == "0" || s.Policy.Final != "SUPPORTED" || len(s.Policy.Transports) != 1 {
		t.Fatalf("evidence=%+v requests=%d", s, requests.Load())
	}
	b, _ := de.Encode(de.Push{DNSSchema: 1, Action: "dns.push", HelperEpoch: strings.Repeat("e", 32), OperationID: strings.Repeat("f", 32), ConfigIdentity: strings.Repeat("1", 64), Binding: c.Binding(), Snapshot: s})
	if strings.Contains(string(b), "secret") {
		t.Fatal("name leaked")
	}
}
