//go:build embedded_core && with_utls

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
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
	case <-time.After(100 * time.Millisecond):
		// This window is observation only, below B's independent remaining budget.
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

// These are server-side faults on an actually active TLS/h2 connection, not
// cancellation of the engine root context. Two held streams share the connection.
func dnsRecoveryConnectionFault(t *testing.T, half bool) {
	entered := make(chan dnsRecoveryArrival, 2)
	ended := make(chan struct{}, 2)
	f := dnsPerfStart(t, func(w http.ResponseWriter, r *http.Request, q *dns.Msg) {
		if q.Question[0].Name[:1] == "x" {
			entered <- dnsRecoveryArrival{r.Context().Value(dnsPerfConnKey{}).(int), r.ProtoMajor, time.Now()}
			<-r.Context().Done()
			ended <- struct{}{}
			return
		}
		dnsPerfWrite(w, unifiedDNSAnswer(q, false))
	})
	dnsPerfRun(t, f, f.query("warm", dns.TypeA), false)
	done := make(chan dnsRecoveryResult, 2)
	for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
		go func(typ uint16) { done <- dnsRecoveryExchange(f, f.query("x-fault", typ)) }(typ)
	}
	a, b := dnsRecoveryArrive(t, entered), dnsRecoveryArrive(t, entered)
	if a.conn != b.conn || a.proto != 2 || b.proto != 2 || f.accepted.Load() != 1 {
		t.Error("fault streams did not share warmed TLS/h2 connection")
	}
	f.mu.Lock()
	var target net.Conn
	for c, id := range f.connections {
		if id == a.conn {
			target = c
		}
	}
	f.mu.Unlock()
	if target == nil {
		t.Fatal("missing exact server connection")
	}
	faultAt := time.Now()
	if half {
		tc, ok := target.(*tls.Conn)
		if !ok {
			t.Fatal("server connection is not TLS")
		}
		tcp, ok := tc.NetConn().(*net.TCPConn)
		if !ok {
			t.Fatal("TLS connection does not own TCP")
		}
		// Abrupt server->client FIN without TLS close_notify. The server read half
		// remains open; the real client must notice EOF and close/reset its side.
		if err := tcp.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	} else if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	var samples []int64
	for i := 0; i < 2; i++ {
		result := dnsRecoveryReceive(t, done)
		dnsRecoveryFailure(t, result)
		samples = append(samples, result.elapsed.Microseconds())
	}
	for i := 0; i < 2; i++ {
		select {
		case <-ended:
		case <-time.After(time.Second):
			t.Error("fault handler not joined before cleanup")
		}
	}
	if time.Since(faultAt) > 3*time.Second {
		t.Error("connection fault waited for default query deadline")
	}
	dnsRecoveryAfter(t, f)
	if f.accepted.Load() != 2 {
		t.Errorf("same-engine recovery TLS accepted=%d want=2", f.accepted.Load())
	}
	f.shutdown()
	f.checkMetrics(t, 5)
	s := f.metrics.Snapshot()
	if s.UpstreamExchange.Outcomes[dnsmetrics.Timeout] != 0 || s.UpstreamExchange.Outcomes[dnsmetrics.OtherError] != 2 || s.UpstreamExchange.Outcomes[dnsmetrics.NoError] != 3 {
		t.Errorf("connection-fault SDK callbacks=%+v", s.UpstreamExchange)
	}
	t.Logf("DNS_RECOVERY_CONNECTION_FAULT half_close_write=%t shared_conn=%d failed_streams=2 samples_us=%v recovery_queries=2", half, a.conn, samples)
}
func TestDNSRecoveryActiveEOF(t *testing.T)       { dnsRecoveryConnectionFault(t, false) }
func TestDNSRecoveryActiveHalfClose(t *testing.T) { dnsRecoveryConnectionFault(t, true) }

// Cache hits, warm-connection cache misses and fresh-engine cold misses are
// separate distributions. These are local protocol costs, not a WAN speed claim.
func TestDNSRecoveryTimingBaselines(t *testing.T) {
	var cold, hit, miss []int64
	for i := 0; i < 5; i++ {
		f := dnsPerfStart(t, nil)
		cold = append(cold, dnsPerfRun(t, f, f.query("cold", dns.TypeA), false).Microseconds())
		if i == 0 {
			for j := 0; j < 20; j++ {
				hit = append(hit, dnsPerfRun(t, f, f.query("cold", dns.TypeA), false).Microseconds())
			}
			if f.count(f.query("cold", dns.TypeA)) != 1 {
				t.Error("warm-hit control reached upstream")
			}
			for j := 0; j < 20; j++ {
				miss = append(miss, dnsPerfRun(t, f, f.query(fmt.Sprintf("unique-%d", j), dns.TypeAAAA), false).Microseconds())
			}
			if f.accepted.Load() != 1 {
				t.Error("warm misses did not retain same TLS connection")
			}
			f.checkMetrics(t, 21)
		} else {
			f.checkMetrics(t, 1)
		}
		f.shutdown()
	}
	t.Logf("DNS_RECOVERY_TIMINGS cold_us=%v cache_hit_us=%v warm_conn_miss_us=%v", cold, hit, miss)
}
