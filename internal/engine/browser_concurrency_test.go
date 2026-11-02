package engine

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/session"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func browserConcurrencyFixture(t *testing.T) (*browserProvenance, browserReceipt, M.Socksaddr) {
	t.Helper()
	s := newBrowserProvenance()
	scope := browserClientScope{inbound: "test", source: netip.MustParseAddr("127.0.0.1")}
	q, a := browserAnswer("a.test", 28, "2001:db8::1", 30)
	s.observe(scope, "secure", q, a)
	dst := M.Socksaddr{Addr: netip.MustParseAddr("2001:db8::1"), Port: 443}
	r, ok := s.receipt(scope, dst.Addr)
	if !ok {
		t.Fatal("receipt")
	}
	return s, r, dst
}
func browserAwait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("bounded join failed")
	}
}
func browserActive(s *browserProvenance) int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.active) }

type browserCloseBarrier struct {
	net.Conn
	entered, proceed chan struct{}
	once             sync.Once
	closes           atomic.Int32
}

func (c *browserCloseBarrier) Close() error {
	c.closes.Add(1)
	c.once.Do(func() { close(c.entered) })
	<-c.proceed
	return c.Conn.Close()
}

func TestBrowserRejectedAttachClosesOutsideMutex(t *testing.T) {
	s, r, _ := browserConcurrencyFixture(t)
	ctx, l, ok := s.reserve(context.Background(), r)
	if !ok {
		t.Fatal("reserve")
	}
	l.cancel()
	a, b := net.Pipe()
	defer b.Close()
	c := &browserCloseBarrier{Conn: a, entered: make(chan struct{}), proceed: make(chan struct{})}
	done := make(chan struct{})
	go func() { s.attach(ctx, l, c); close(done) }()
	browserAwait(t, c.entered)
	unlocked := make(chan struct{})
	go func() { s.mu.Lock(); s.mu.Unlock(); close(unlocked) }()
	// Always release the artificial Close barrier, even on the pre-fix failure.
	select {
	case <-unlocked:
		close(c.proceed)
		browserAwait(t, done)
	case <-time.After(100 * time.Millisecond):
		close(c.proceed)
		browserAwait(t, done)
		t.Fatal("rejected stream Close held provenance mutex")
	}
	s.release(l)
}

func TestBrowserInvalidationDrainsDeliveredReservation(t *testing.T) {
	s, r, dst := browserConcurrencyFixture(t)
	out := &browserTestOutbound{}
	d := &browserDialer{Outbound: out, prepared: browserPrepared{owner: s, receipt: r, metadata: adapter.InboundContext{Destination: dst}}}
	c, err := d.DialContext(context.Background(), "tcp", dst)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer out.held[0].Close()
	s.InvalidateBrowserDNS()
	if n := browserActive(s); n != 0 {
		t.Fatalf("invalidated delivered reservation leaked: %d", n)
	}
	if _, err := c.Write([]byte("must not escape")); err == nil {
		t.Fatal("application bytes after invalidation")
	}
}

type browserControlledOutbound struct {
	adapter.Outbound
	dial  func(context.Context, M.Socksaddr) (net.Conn, error)
	calls atomic.Int32
}

func (*browserControlledOutbound) Type() string { return "anytls" }
func (d *browserControlledOutbound) DialContext(ctx context.Context, _ string, dst M.Socksaddr) (net.Conn, error) {
	d.calls.Add(1)
	return d.dial(ctx, dst)
}

func TestBrowserInflightCancellationJoins(t *testing.T) {
	for _, kind := range []string{"epoch", "conflict", "capacity", "caller"} {
		t.Run(kind, func(t *testing.T) {
			s, r, dst := browserConcurrencyFixture(t)
			entered, done := make(chan struct{}), make(chan struct{})
			out := &browserControlledOutbound{dial: func(ctx context.Context, _ M.Socksaddr) (net.Conn, error) {
				close(entered)
				<-ctx.Done()
				return nil, ctx.Err()
			}}
			d := &browserDialer{Outbound: out, prepared: browserPrepared{owner: s, receipt: r, metadata: adapter.InboundContext{Destination: dst}}}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			var err error
			go func() { _, err = d.DialContext(ctx, "tcp", dst); close(done) }()
			browserAwait(t, entered)
			switch kind {
			case "epoch":
				s.InvalidateBrowserDNS()
			case "caller":
				cancel()
			default:
				q, a := browserAnswer("conflict.test", 28, dst.Addr.String(), 30)
				if kind == "capacity" {
					s.mu.Lock()
					s.limit = 1
					s.mu.Unlock()
					q, a = browserAnswer("other.test", 28, "2001:db8::2", 30)
				}
				s.observe(r.scope, "secure", q, a)
			}
			browserAwait(t, done)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
			if out.calls.Load() != 1 || browserActive(s) != 0 {
				t.Fatal("alternate launched or active reservation leaked")
			}
		})
	}
}

func TestBrowserExpiredPreparedReceiptKeepsOriginalPath(t *testing.T) {
	s, r, dst := browserConcurrencyFixture(t)
	s.now = func() time.Time { return r.expires }
	out := &browserTestOutbound{}
	d := &browserDialer{Outbound: out, prepared: browserPrepared{owner: s, receipt: r, metadata: adapter.InboundContext{Destination: dst}}}
	c, err := d.DialContext(context.Background(), "tcp", dst)
	if err != nil {
		t.Fatalf("UNKNOWN receipt changed legacy original into cancellation: %v", err)
	}
	c.Close()
	for _, p := range out.held {
		p.Close()
	}
	if len(out.addresses) != 1 || out.addresses[0] != dst {
		t.Fatal("original path not preserved")
	}
}

func TestBrowserLaunchBarrierInvalidation(t *testing.T) {
	for _, kind := range []string{"epoch", "ttl", "conflict", "capacity", "caller"} {
		t.Run(kind, func(t *testing.T) {
			s, r, dst := browserConcurrencyFixture(t)
			var clock atomic.Int64
			clock.Store(time.Now().UnixNano())
			s.now = func() time.Time { return time.Unix(0, clock.Load()) }
			entered, proceed, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			out := &browserControlledOutbound{dial: func(context.Context, M.Socksaddr) (net.Conn, error) {
				return nil, errors.New("unexpected actual launch")
			}}
			d := &browserDialer{Outbound: out, prepared: browserPrepared{owner: s, receipt: r, metadata: adapter.InboundContext{Destination: dst}}, beforeLaunch: func() { close(entered); <-proceed }}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var err error
			go func() { _, err = d.DialContext(ctx, "tcp", dst); close(done) }()
			browserAwait(t, entered)
			switch kind {
			case "epoch":
				s.InvalidateBrowserDNS()
			case "ttl":
				clock.Store(r.expires.UnixNano())
			case "caller":
				cancel()
			default:
				q, a := browserAnswer("conflict.test", 28, dst.Addr.String(), 30)
				if kind == "capacity" {
					s.mu.Lock()
					s.limit = 1
					s.mu.Unlock()
					q, a = browserAnswer("other.test", 28, "2001:db8::2", 30)
				}
				s.observe(r.scope, "secure", q, a)
			}
			close(proceed)
			browserAwait(t, done)
			if !errors.Is(err, context.Canceled) || out.calls.Load() != 0 || browserActive(s) != 0 {
				t.Fatalf("invalid-before-reservation launched: calls=%d err=%v active=%d", out.calls.Load(), err, browserActive(s))
			}
		})
	}
}

func TestBrowserDialErrorQualification(t *testing.T) {
	for _, err := range []error{syscall.EACCES, syscall.EPERM, context.Canceled, context.DeadlineExceeded, x509.UnknownAuthorityError{}, errors.New("auth failed"), &net.DNSError{IsNotFound: true}} {
		if browserNetworkFailure(&net.OpError{Op: "dial", Err: err}) {
			t.Fatalf("unsafe error qualified: %T", err)
		}
	}
	for _, err := range []error{syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ECONNREFUSED, syscall.ETIMEDOUT, syscall.EAFNOSUPPORT} {
		if !browserNetworkFailure(&net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connect", Err: err}}) {
			t.Fatalf("network error not qualified: %v", err)
		}
	}
}
func TestBrowserReservationInheritsAbsoluteDeadline(t *testing.T) {
	s, r, _ := browserConcurrencyFixture(t)
	deadline := time.Now().Add(100 * time.Millisecond)
	parent, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	ctx, l, ok := s.reserve(parent, r)
	if !ok {
		t.Fatal("reserve")
	}
	defer s.release(l)
	got, ok := ctx.Deadline()
	if !ok || !got.Equal(deadline) {
		t.Fatal("caller deadline reset")
	}
}

func TestBrowserAlternateLaunchInvalidation(t *testing.T) {
	for _, kind := range []string{"epoch", "ttl", "conflict", "capacity", "caller"} {
		t.Run(kind, func(t *testing.T) {
			s, r, dst := browserConcurrencyFixture(t)
			s.static = true
			var clock atomic.Int64
			clock.Store(time.Now().UnixNano())
			s.now = func() time.Time { return time.Unix(0, clock.Load()) }
			box := recordsBox(t, []byte(`{"outbounds":[{"type":"direct","tag":"P"}],"route":{"final":"P"}}`))
			out := &browserControlledOutbound{dial: func(context.Context, M.Socksaddr) (net.Conn, error) {
				return nil, &session.RemoteConnectError{Cause: syscall.ENETUNREACH}
			}}
			ctx := service.ContextWithRegistry(context.Background(), service.NewRegistry())
			resolver := &browserFixtureResolver{}
			ctx = service.ContextWith[adapter.DNSRouter](ctx, resolver)
			ctx = service.ContextWith[adapter.OutboundManager](ctx, &browserControlledManager{OutboundManager: box.Outbound(), out: out})
			s.trust(&browserFixtureTransport{})
			entered, proceed, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			launches := 0
			m := adapter.InboundContext{Network: "tcp", Inbound: r.scope.inbound, Source: M.Socksaddr{Addr: r.scope.source}, Destination: dst, IPVersion: 6}
			d := &browserDialer{Outbound: out, prepared: browserPrepared{owner: s, receipt: r, metadata: m, router: box.Router(), index: -1, outbound: out}, beforeLaunch: func() {
				launches++
				if launches == 2 {
					close(entered)
					<-proceed
				}
			}}
			parent, cancel := context.WithCancel(ctx)
			defer cancel()
			var err error
			go func() { _, err = d.DialContext(parent, "tcp", dst); close(done) }()
			browserAwait(t, entered)
			switch kind {
			case "epoch":
				s.InvalidateBrowserDNS()
			case "ttl":
				clock.Store(r.expires.UnixNano())
			case "caller":
				cancel()
			default:
				q, a := browserAnswer("conflict.test", 28, dst.Addr.String(), 30)
				if kind == "capacity" {
					s.mu.Lock()
					s.limit = 1
					s.mu.Unlock()
					q, a = browserAnswer("other.test", 28, "2001:db8::2", 30)
				}
				s.observe(r.scope, "secure", q, a)
			}
			close(proceed)
			browserAwait(t, done)
			if !errors.Is(err, context.Canceled) || out.calls.Load() != 1 || browserActive(s) != 0 || resolver.calls != 2 {
				t.Fatalf("alternate escaped final reservation: calls=%d dns=%d err=%v", out.calls.Load(), resolver.calls, err)
			}
		})
	}
}

type browserControlledManager struct {
	adapter.OutboundManager
	out adapter.Outbound
}

func (m *browserControlledManager) Default() adapter.Outbound { return m.out }

func TestBrowserOwnedCloseOnce(t *testing.T) {
	s, r, _ := browserConcurrencyFixture(t)
	_, l, ok := s.reserve(context.Background(), r)
	if !ok {
		t.Fatal("reserve")
	}
	a, b := net.Pipe()
	defer b.Close()
	gate := make(chan struct{})
	close(gate)
	raw := &browserCloseBarrier{Conn: a, entered: make(chan struct{}), proceed: gate}
	c := &browserOwnedConn{Conn: raw, owner: s, launch: l}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.Close() }()
	}
	wg.Wait()
	if raw.closes.Load() != 1 {
		t.Fatalf("underlying closed %d times", raw.closes.Load())
	}
}
