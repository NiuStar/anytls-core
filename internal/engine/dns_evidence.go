package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	de "github.com/NiuStar/anytls-core/internal/dnsevidence"
	dm "github.com/NiuStar/anytls-core/internal/dnsmetrics"
	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/option"
	"net/http/httptrace"
	"strconv"
	"sync"
	"time"
)

type dnsEvidenceKey struct{}

// WithDNSEvidence is explicit run ownership; Check never calls Loaded.
func WithDNSEvidence(ctx context.Context, c *de.Collector) context.Context {
	return context.WithValue(ctx, dnsEvidenceKey{}, c)
}
func dnsEvidence(ctx context.Context) *de.Collector {
	c, _ := ctx.Value(dnsEvidenceKey{}).(*de.Collector)
	return c
}
func evidenceDecoded(ctx context.Context, o option.Options) {
	c := dnsEvidence(ctx)
	if c == nil {
		return
	}
	p := c.Snapshot().Policy
	if o.DNS != nil && o.DNS.Final == "secure-dns" {
		p.Final = "SUPPORTED"
	}
	c.SetPolicy(p)
}
func evidenceRuntime(ctx context.Context, b []byte) context.Context {
	c := dnsEvidence(ctx)
	if c == nil {
		return ctx
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != c.Binding().RuntimeSHA256 {
		return WithDNSEvidence(ctx, nil)
	}
	return ctx
}
func evidenceFactory(c *de.Collector, o option.RemoteHTTPSDNSServerOptions) string {
	if c == nil {
		return ""
	}
	s := c.Snapshot()
	if len(s.Policy.Transports) >= 4 {
		return ""
	}
	id := strconv.Itoa(len(s.Policy.Transports) + 1)
	// Only the product's fixed safe endpoint projection is public, never arbitrary names or paths.
	ip := "REDACTED"
	if o.Server == "1.1.1.1" || o.Server == "127.0.0.1" || o.Server == "::1" {
		ip = o.Server
	}
	sni := "REDACTED"
	strict := "STRICT_CONFIGURED"
	if o.TLS != nil {
		if o.TLS.ServerName == "cloudflare-dns.com" || o.TLS.ServerName == "example.com" {
			sni = o.TLS.ServerName
		}
		if o.TLS.Insecure || o.TLS.Engine != "" {
			strict = "UNSUPPORTED"
		}
	}
	p := s.Policy
	p.Transports = append(p.Transports, de.Transport{ID: id, Type: "HTTPS", ServerIP: ip, Port: strconv.Itoa(int(o.ServerPort)), SNI: sni, TLS: strict, Detour: "CONFIGURED_ONLY"})
	c.SetPolicy(p)
	return id
}

type evidenceOperation struct {
	mu                   sync.Mutex
	c                    *de.Collector
	e                    de.Event
	start                time.Time
	question             [32]byte
	single               bool
	n, new, reused, idle uint64
}

func beginEvidence(c *de.Collector, id string, q *dns.Msg, ctx context.Context) (context.Context, *evidenceOperation) {
	if c == nil || id == "" {
		return ctx, nil
	}
	op := c.NextOperation()
	if op == "0" {
		return ctx, nil
	}
	o := &evidenceOperation{c: c, start: time.Now(), e: de.Event{OperationID: op, TransportID: id, QType: "OTHER", Validation: "NOT_OBSERVED"}}
	if q != nil && len(q.Question) == 1 && len(q.Question[0].Name) <= 255 {
		o.single = true
		o.question = questionHash(c.Binding().Generation, q.Question[0])
		if q.Question[0].Qtype == dns.TypeA {
			o.e.QType = "A"
		}
		if q.Question[0].Qtype == dns.TypeAAAA {
			o.e.QType = "AAAA"
		}
	}
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) {
		o.mu.Lock()
		defer o.mu.Unlock()
		o.n++
		if i.Reused {
			o.reused++
		} else {
			o.new++
		}
		if i.WasIdle {
			o.idle++
		}
	}}), o
}
func (o *evidenceOperation) finish(r *dns.Msg, err error) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.e.Outcome = evidenceOutcome(r, err)
	if err == nil && r != nil {
		code := strconv.Itoa(r.Rcode)
		o.e.RCODE = &code
		o.e.Validation = "MISMATCH"
		if o.single && r.Response && r.Id == 0 && len(r.Question) == 1 && len(r.Question[0].Name) <= 255 && questionHash(o.c.Binding().Generation, r.Question[0]) == o.question {
			o.e.Validation = "MATCHED"
		}
	}
	o.e.DurationNS = strconv.FormatInt(int64(time.Since(o.start)), 10)
	d := func(n uint64) string { return strconv.FormatUint(n, 10) }
	o.e.Connections = de.Connections{Acquisitions: d(o.n), New: d(o.new), Reused: d(o.reused), Idle: d(o.idle)}
	o.c.Complete(o.e)
}
func questionHash(salt string, q dns.Question) [32]byte {
	return sha256.Sum256([]byte(salt + "\x00" + q.Name + "\x00" + strconv.Itoa(int(q.Qtype)) + ":" + strconv.Itoa(int(q.Qclass))))
}
func evidenceOutcome(r *dns.Msg, e error) string {
	switch dnsMetricOutcome(r, e) {
	case dm.NoError:
		return "NOERROR"
	case dm.NXDomain:
		return "NXDOMAIN"
	case dm.ServFail:
		return "SERVFAIL"
	case dm.OtherRCode:
		return "OTHER_RCODE"
	case dm.Canceled:
		return "CANCELED"
	case dm.Timeout:
		return "TIMEOUT"
	case dm.TLSFailure:
		return "TLS_FAILURE"
	default:
		return "OTHER_ERROR"
	}
}
