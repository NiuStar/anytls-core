package engine

import (
	"context"
	"errors"
	de "github.com/NiuStar/anytls-core/internal/dnsevidence"
	"github.com/miekg/dns"
	C "github.com/sagernet/sing-box/constant"
	sdns "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestDNSEvidenceErrorsAndDisabled(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded, errors.New("private error")} {
		c := de.New(de.Binding{InstanceID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32), ManifestID: strings.Repeat("c", 64), RuntimeSHA256: strings.Repeat("d", 64)})
		raw := transport.NewHTTPSRaw(sdns.NewTransportAdapter(C.DNSTypeHTTPS, "fixture", nil), logger.NOP(), dnsMetricFailDialer{cause}, &url.URL{Scheme: "https", Host: "fixture.invalid"}, http.Header{}, M.ParseSocksaddr("127.0.0.1:443"), nil)
		wrapped := &observedHTTPS{HTTPSTransport: raw, evidence: c, transportID: "1"}
		q := new(dns.Msg).SetQuestion("private.invalid.", dns.TypeA)
		r, e := wrapped.Exchange(context.Background(), q)
		if r != nil || e != cause {
			t.Fatal("sync error identity")
		}
		calls := 0
		done := make(chan struct{})
		wrapped.ExchangeAsync(context.Background(), q, func(r *dns.Msg, e error) {
			defer close(done)
			calls++
			if r != nil || e != cause {
				t.Error("async error identity")
			}
		})
		<-done
		if calls != 1 || len(c.Snapshot().Events) != 2 {
			t.Fatal("callback/count")
		}
		raw.Reset()
	}
	raw := loopbackConfig()
	c := de.New(de.Binding{InstanceID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32), ManifestID: strings.Repeat("c", 64), RuntimeSHA256: strings.Repeat("d", 64)})
	if e := Check(WithDNSEvidence(context.Background(), c), raw); e != nil {
		t.Fatal(e)
	}
	if c.Snapshot().State != "STARTING" {
		t.Fatal("Check claimed Start")
	}
	if dnsEvidence(evidenceRuntime(WithDNSEvidence(context.Background(), c), raw)) != nil {
		t.Fatal("digest mismatch admitted")
	}
}
