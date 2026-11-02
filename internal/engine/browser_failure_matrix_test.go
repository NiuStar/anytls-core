package engine

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/anytls/sing-anytls/session"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type browserFailureOutbound struct {
	adapter.Outbound
	kind    string
	failure error
	calls   int
	ack     bool
	peers   []net.Conn
}

func (o *browserFailureOutbound) Type() string { return o.kind }
func (o *browserFailureOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	o.calls++
	if !o.ack {
		return nil, o.failure
	}
	a, b := net.Pipe()
	o.peers = append(o.peers, b)
	return &browserTestStream{Conn: a, result: o.failure}, nil
}

func TestBrowserCoordinatorFailureMatrixNoRefresh(t *testing.T) {
	network := &os.SyscallError{Syscall: "connect", Err: syscall.ENETUNREACH}
	for _, tc := range []struct {
		name, kind string
		err        error
		ack        bool
	}{
		{"direct-certificate-join", "direct", &net.OpError{Op: "dial", Net: "tcp", Err: errors.Join(network, x509.UnknownAuthorityError{})}, false},
		{"direct-auth-join", "direct", &net.OpError{Op: "dial", Net: "tcp", Err: errors.Join(network, os.ErrPermission)}, false},
		{"direct-caller-join", "direct", &net.OpError{Op: "dial", Net: "tcp", Err: errors.Join(network, context.Canceled)}, false},
		{"direct-deadline-join", "direct", &net.OpError{Op: "dial", Net: "tcp", Err: errors.Join(network, context.DeadlineExceeded)}, false},
		{"node-certificate", "anytls", x509.UnknownAuthorityError{}, false},
		{"node-auth", "anytls", os.ErrPermission, false},
		{"caller", "anytls", context.Canceled, false},
		{"unsupported-ack", "anytls", session.ErrConnectACKUnsupported, true},
		{"no-ack", "anytls", session.ErrConnectACKUnconfirmed, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, r, dst := browserConcurrencyFixture(t)
			s.static = true
			s.trust(&browserFixtureTransport{})
			instance := recordsBox(t, []byte(`{"outbounds":[{"type":"direct","tag":"P"}],"route":{"final":"P"}}`))
			out := &browserFailureOutbound{kind: tc.kind, failure: tc.err, ack: tc.ack}
			defer func() {
				for _, c := range out.peers {
					c.Close()
				}
			}()
			resolver := &browserFixtureResolver{}
			ctx := service.ContextWithRegistry(context.Background(), service.NewRegistry())
			ctx = service.ContextWith[adapter.DNSRouter](ctx, resolver)
			ctx = service.ContextWith[adapter.OutboundManager](ctx, &browserControlledManager{out: out})
			metadata := adapter.InboundContext{Inbound: r.scope.inbound, Source: M.Socksaddr{Addr: r.scope.source}, Network: "tcp", Destination: dst}
			d := &browserDialer{Outbound: out, prepared: browserPrepared{owner: s, receipt: r, router: instance.Router(), metadata: metadata, index: -1, outbound: out}}
			c, err := d.DialContext(ctx, "tcp", dst)
			if c != nil {
				c.Close()
			}
			if !tc.ack && !errors.Is(err, tc.err) {
				t.Fatal("original failure identity lost")
			}
			if out.calls != 1 || resolver.calls != 0 || browserActive(s) != 0 {
				t.Fatalf("failure launched extra work: connect=%d DNS=%d active=%d", out.calls, resolver.calls, browserActive(s))
			}
			t.Logf("FAILURE_MATRIX %s CONNECT=1 alternate=0 DNS_refresh=0 joined=true", tc.name)
		})
	}
}
