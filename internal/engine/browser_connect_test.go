package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/session"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type browserTestOutbound struct {
	adapter.Outbound
	addresses []M.Socksaddr
	mode      error
	held      []net.Conn
}

func (*browserTestOutbound) Type() string { return "anytls" }
func (d *browserTestOutbound) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	d.addresses = append(d.addresses, dest)
	a, b := net.Pipe()
	d.held = append(d.held, b)
	return &browserTestStream{Conn: a, result: d.mode}, nil
}

type browserTestStream struct {
	net.Conn
	result error
}

func (c *browserTestStream) WaitConnect(context.Context) error { return c.result }
func TestBrowserCoordinatorHealthyUnknownAndCancellation(t *testing.T) {
	for _, mode := range []error{nil, session.ErrConnectACKUnsupported, session.ErrConnectACKUnconfirmed, context.Canceled, context.DeadlineExceeded, &session.RemoteConnectError{Cause: errors.New("refused")}} {
		t.Run(func() string {
			if mode == nil {
				return "healthy"
			}
			return mode.Error()
		}(), func(t *testing.T) {
			raw := []byte(`{"outbounds":[{"type":"direct","tag":"P"}],"route":{"final":"P"}}`)
			box := recordsBox(t, raw)
			s := newBrowserProvenance()
			s.static = true
			scope := browserClientScope{inbound: "test", source: netip.MustParseAddr("127.0.0.1")}
			q, a := browserAnswer("a.test", 28, "2001:db8::1", 30)
			s.observe(scope, "secure", q, a)
			original := M.Socksaddr{Addr: netip.MustParseAddr("2001:db8::1"), Port: 443}
			out := &browserTestOutbound{mode: mode}
			receipt, _ := s.receipt(scope, original.Addr)
			d := &browserDialer{Outbound: out, prepared: browserPrepared{owner: s, router: box.Router(), metadata: adapter.InboundContext{Network: "tcp", Inbound: "test", Source: M.Socksaddr{Addr: scope.source}, Destination: original}, index: -1, outbound: out, receipt: receipt}}
			c, e := d.DialContext(context.Background(), "tcp", original)
			if c != nil {
				c.Close()
			}
			for _, c := range out.held {
				c.Close()
			}
			if len(out.addresses) != 1 || out.addresses[0] != original {
				t.Fatal("unexpected alternate")
			}
			if mode == nil || errors.Is(mode, session.ErrConnectACKUnsupported) || errors.Is(mode, session.ErrConnectACKUnconfirmed) {
				if e != nil {
					t.Fatal(e)
				}
			} else if e == nil {
				t.Fatal("failure swallowed")
			}
			if len(s.active) != 0 {
				t.Fatal("reservation leaked")
			}
		})
	}
}
func TestBrowserAtomicReservationInvalidateAndClose(t *testing.T) {
	s := newBrowserProvenance()
	scope := browserClientScope{inbound: "test", source: netip.MustParseAddr("127.0.0.1")}
	q, a := browserAnswer("a.test", 28, "2001:db8::1", 30)
	s.observe(scope, "secure", q, a)
	receipt, _ := s.receipt(scope, netip.MustParseAddr("2001:db8::1"))
	ctx, l, ok := s.reserve(context.Background(), receipt)
	if !ok {
		t.Fatal("reserve")
	}
	aConn, b := net.Pipe()
	defer b.Close()
	if !s.attach(ctx, l, aConn) {
		t.Fatal("attach")
	}
	serviceCtx := service.ContextWithRegistry(context.Background(), service.NewRegistry())
	serviceCtx = service.ContextWith[browserDNSObserver](serviceCtx, s)
	closeBrowserProvenance(serviceCtx)
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("reservation not canceled")
	}
	b.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := b.Read(make([]byte, 1)); e == nil {
		t.Fatal("stream not closed")
	} else if timeout, ok := e.(net.Error); ok && timeout.Timeout() {
		t.Fatal("timeout is not close")
	}
	if _, _, ok := s.reserve(context.Background(), receipt); ok {
		t.Fatal("old epoch launched")
	}
	s.release(l)
	if len(s.active) != 0 {
		t.Fatal("reservation leaked")
	}
}
