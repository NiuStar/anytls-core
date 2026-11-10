//go:build embedded_core && with_utls

package engine

import (
	"context"
	"github.com/anytls/sing-anytls"
	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

type liveACKLeaf struct {
	adapter.Outbound
	client *anytls.Client
	tag    string
}

func (l *liveACKLeaf) Tag() string  { return l.tag }
func (l *liveACKLeaf) Type() string { return "anytls" }
func (l *liveACKLeaf) DialContext(ctx context.Context, _ string, d M.Socksaddr) (net.Conn, error) {
	return l.client.CreateProxy(ctx, d)
}

type liveCaptureManager struct {
	adapter.ConnectionManager
	ctx  context.Context
	dial N.Dialer
	got  chan net.Conn
}

func (m *liveCaptureManager) NewConnection(ctx context.Context, d N.Dialer, c net.Conn, md adapter.InboundContext, _ N.CloseHandlerFunc) {
	m.ctx, m.dial = ctx, d
	stream, err := d.DialContext(ctx, "tcp", md.Destination)
	if err != nil {
		m.got <- nil
		return
	}
	m.got <- stream
}
func TestLiveBrowserIPv4AlternatePinnedLeaf(t *testing.T) {
	// The unchanged strict-TLS AnyTLS ACK fixture forwards through tcp4 only.
	client, peer, _ := fixture(t)
	peer.forward = true
	peer.gate = make(chan struct{})
	close(peer.gate)
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		c, e := echo.Accept()
		if e == nil {
			defer c.Close()
			io.Copy(c, c)
		}
	}()
	port := uint16(echo.Addr().(*net.TCPAddr).Port)
	s, receipt, dst := browserConcurrencyFixture(t)
	s.static = true
	dst.Port = port
	// Existing independent DNS/rule matrix is reused; only its A answer is
	// mapped to literal loopback by a bounded resolver below.
	transport := &browserFixtureTransport{}
	s.trust(transport)
	raw := []byte(`{"outbounds":[{"type":"direct","tag":"P"}],"route":{"final":"P"}}`)
	instance := recordsBox(t, raw)
	leaf := &liveACKLeaf{client: client, tag: "a"}
	other := &liveACKLeaf{client: client, tag: "b"}
	manager := &liveCaptureManager{got: make(chan net.Conn, 1)}
	selector := &selectionOutbound{Adapter: outbound.NewAdapter(LiveSelectionType, "live", []string{"tcp"}, nil), connections: manager, leaves: map[string]adapter.Outbound{"a": leaf, "b": other}}
	selector.selected.Store(&selectedLeaf{leaf})
	ctx := service.ContextWithRegistry(context.Background(), service.NewRegistry())
	ctx = service.ContextWith[browserDialGuard](ctx, s)
	ctx = service.ContextWith[adapter.DNSRouter](ctx, &liveBrowserResolver{browserFixtureResolver: browserFixtureResolver{}, port: port})
	ctx = service.ContextWith[adapter.OutboundManager](ctx, &browserControlledManager{out: selector})
	metadata := adapter.InboundContext{Inbound: receipt.scope.inbound, Source: M.Socksaddr{Addr: receipt.scope.source}, Network: "tcp", Destination: dst, IPVersion: 6}
	ctx = context.WithValue(ctx, browserCandidateKey{}, browserPrepared{s, instance.Router(), metadata, nil, -1, selector, receipt})
	down, up := net.Pipe()
	defer down.Close()
	defer up.Close()
	selector.NewConnection(ctx, bufio.NewCounterConn(up, nil, nil), metadata, nil)
	c := <-manager.got
	if c == nil {
		t.Fatal("IPv4-only exit failed alternate")
	}
	defer c.Close()
	selector.selected.Store(&selectedLeaf{other})
	c.SetDeadline(time.Now().Add(time.Second))
	if _, err = c.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 2)
	if _, err = io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
	if d, ok := manager.dial.(*browserDialer); !ok || d.Outbound != leaf {
		t.Fatal("attempts not pinned to actual initial leaf")
	}
	first, second := <-peer.calls, <-peer.calls
	if !first.dest.Addr.Is6() || !second.dest.Addr.Is4() || second.dest.Addr != netip.MustParseAddr("127.0.0.1") {
		t.Fatal("wrong real CONNECT family sequence")
	}
}

type liveBrowserResolver struct {
	browserFixtureResolver
	port uint16
}

func (r *liveBrowserResolver) Exchange(ctx context.Context, q *dns.Msg, o adapter.DNSQueryOptions) (*dns.Msg, error) {
	value := "127.0.0.1"
	if q.Question[0].Qtype == dns.TypeAAAA {
		value = "2001:db8::1"
	}
	_, answer := browserAnswer(q.Question[0].Name, q.Question[0].Qtype, value, 30)
	answer.Id = q.Id
	operation := ctx.Value(browserRefreshKey{}).(*browserRefresh)
	operation.owner.ObserveBrowserDNS(ctx, q, answer, o.Transport)
	return answer, nil
}
