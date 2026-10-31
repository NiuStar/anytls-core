//go:build embedded_core && with_utls

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/NiuStar/anytls-core/internal/dnsmetrics"
	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks"
)

type dnsRecoveryResult struct {
	q, a    *dns.Msg
	elapsed time.Duration
	err     error
}
type dnsRecoveryArrival struct {
	conn  int
	proto int
	at    time.Time
}

// A caller's socket outlives the SDK's unchanged ten-second DNS budget. Socket
// timeouts are never accepted as proof of upstream failure or closure.
func dnsRecoveryExchange(f *dnsPerfFixture, q *dns.Msg) dnsRecoveryResult {
	start := time.Now()
	client := socks.NewClient(recordsSOCKSDialer{}, M.ParseSocksaddr(f.addr), socks.Version5, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := client.DialContext(ctx, "tcp", M.ParseSocksaddr(f.trap.tcp.Addr().String()))
	if err != nil {
		return dnsRecoveryResult{q: q, elapsed: time.Since(start), err: err}
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	dc := &dns.Conn{Conn: c}
	if err = dc.WriteMsg(q); err != nil {
		return dnsRecoveryResult{q: q, elapsed: time.Since(start), err: err}
	}
	a, err := dc.ReadMsg()
	return dnsRecoveryResult{q: q, a: a, elapsed: time.Since(start), err: err}
}
func dnsRecoveryReceive(t *testing.T, ch <-chan dnsRecoveryResult) dnsRecoveryResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(17 * time.Second):
		t.Fatal("caller not joined within socket budget")
		return dnsRecoveryResult{}
	}
}
func dnsRecoveryArrive(t *testing.T, ch <-chan dnsRecoveryArrival) dnsRecoveryArrival {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("real HTTPS request did not reach barrier")
		return dnsRecoveryArrival{}
	}
}
func dnsRecoveryFailure(t *testing.T, r dnsRecoveryResult) {
	t.Helper()
	if r.err != nil {
		if !errors.Is(r.err, io.EOF) && !errors.Is(r.err, io.ErrUnexpectedEOF) {
			t.Errorf("failure must be explicit EOF, not caller timeout: %v", r.err)
		}
		return
	}
	if r.a == nil || r.a.Id != r.q.Id || r.a.Rcode == dns.RcodeSuccess || len(r.a.Answer) != 0 {
		t.Error("failed upstream returned invalid or successful answer")
	}
}
func dnsRecoveryAfter(t *testing.T, f *dnsPerfFixture) {
	t.Helper()
	for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
		dnsPerfRun(t, f, f.query(fmt.Sprintf("recovered-%d", typ), typ), false)
	}
}

// Requirement contract (not a characterization assertion): one query's deadline
// must not terminate a healthy, independently budgeted stream on the same h2
// connection. Keep the baseline RED if the pinned SDK resets the whole pool.
func TestDNSRecoveryDeadlinePreservesConcurrentStream(t *testing.T) {
	aEntered, bEntered := make(chan dnsRecoveryArrival, 1), make(chan dnsRecoveryArrival, 1)
	aEnded, bEnded := make(chan struct{}), make(chan struct{})
	bCanceled := make(chan struct{})
	releaseB := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(releaseB) }) }
	f := dnsPerfStart(t, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) {
		event := dnsRecoveryArrival{r.Context().Value(dnsPerfConnKey{}).(int), r.ProtoMajor, time.Now()}
		switch q.Question[0].Name[:1] {
		case "a":
			defer close(aEnded)
			aEntered <- event
			<-r.Context().Done()
		case "b":
			defer close(bEnded)
			bEntered <- event
			select {
			case <-releaseB:
				dnsPerfWrite(w, unifiedDNSAnswer(q, false))
			case <-r.Context().Done():
				close(bCanceled)
			}
		default:
			dnsPerfWrite(w, unifiedDNSAnswer(q, false))
		}
	})
	defer release()
	dnsPerfRun(t, f, f.query("warm", dns.TypeA), false)
	aDone, bDone := make(chan dnsRecoveryResult, 1), make(chan dnsRecoveryResult, 1)
	go func() { aDone <- dnsRecoveryExchange(f, f.query("a-timeout", dns.TypeA)) }()
	a := dnsRecoveryArrive(t, aEntered)
	// Leave B with a provably independent remaining budget after A's deadline.
	timer := time.NewTimer(time.Second)
	<-timer.C
	go func() { bDone <- dnsRecoveryExchange(f, f.query("b-healthy", dns.TypeAAAA)) }()
	b := dnsRecoveryArrive(t, bEntered)
	if a.conn != b.conn || a.proto != 2 || b.proto != 2 || f.accepted.Load() != 1 {
		t.Error("barriers did not share warmed TLS/h2 connection")
	}
	ar := dnsRecoveryReceive(t, aDone)
	dnsRecoveryFailure(t, ar)
	if ar.elapsed < 9*time.Second || ar.elapsed > 13*time.Second {
		t.Errorf("did not exercise default ten-second SDK deadline: %s", ar.elapsed)
	}
	select {
	case <-aEnded:
	case <-time.After(time.Second):
		t.Error("timed-out handler not joined")
	}
	remaining := 10*time.Second - time.Since(b.at)
	if remaining < 500*time.Millisecond {
		t.Errorf("B lacked independent remaining SDK budget: %s", remaining)
	}
	canceled := false
	select {
	case <-bCanceled:
		canceled = true
	default:
	}
	release()
	br := dnsRecoveryReceive(t, bDone)
	dnsPerfCheck(t, br.q, br.a, br.err, false)
	select {
	case <-bEnded:
	case <-time.After(time.Second):
		t.Error("healthy handler not joined")
	}
	dnsRecoveryAfter(t, f)
	f.shutdown()
	f.checkMetrics(t, 5)
	s := f.metrics.Snapshot()
	if s.UpstreamExchange.Outcomes[dnsmetrics.Timeout] != 1 {
		t.Errorf("A timeout callback count=%d want=1", s.UpstreamExchange.Outcomes[dnsmetrics.Timeout])
	}
	t.Logf("DNS_RECOVERY_DEADLINE shared_conn=%d a_us=%d b_us=%d b_budget_remaining_us=%d b_server_canceled_before_release=%t b_success=%t recovery_queries=2", a.conn, ar.elapsed.Microseconds(), br.elapsed.Microseconds(), remaining.Microseconds(), canceled, br.err == nil && br.a != nil && br.a.Rcode == dns.RcodeSuccess)
}

func TestDNSRecoveryAddressFamiliesIndependent(t *testing.T) {
	entered, ended := make(chan dnsRecoveryArrival, 1), make(chan struct{})
	f := dnsPerfStart(t, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) {
		if q.Question[0].Name[:1] == "x" && q.Question[0].Qtype == dns.TypeA {
			defer close(ended)
			entered <- dnsRecoveryArrival{r.Context().Value(dnsPerfConnKey{}).(int), r.ProtoMajor, time.Now()}
			<-r.Context().Done()
			return
		}
		dnsPerfWrite(w, unifiedDNSAnswer(q, false))
	})
	dnsPerfRun(t, f, f.query("warm", dns.TypeA), false)
	done := make(chan dnsRecoveryResult, 1)
	go func() { done <- dnsRecoveryExchange(f, f.query("x-family", dns.TypeA)) }()
	event := dnsRecoveryArrive(t, entered)
	start := time.Now()
	dnsPerfRun(t, f, f.query("x-family", dns.TypeAAAA), false)
	fast := time.Since(start)
	if fast > 2*time.Second || event.proto != 2 || f.accepted.Load() != 1 {
		t.Error("successful AAAA waited for blocked A or did not reuse h2")
	}
	ar := dnsRecoveryReceive(t, done)
	dnsRecoveryFailure(t, ar)
	if ar.elapsed < 9*time.Second {
		t.Error("default upstream timeout not reached")
	}
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Error("blocked A handler not joined")
	}
	dnsRecoveryAfter(t, f)
	f.shutdown()
	f.checkMetrics(t, 5)
	t.Logf("DNS_RECOVERY_FAMILIES shared_conn=%d successful_aaaa_us=%d blocked_a_us=%d recovery_queries=2", event.conn, fast.Microseconds(), ar.elapsed.Microseconds())
}
