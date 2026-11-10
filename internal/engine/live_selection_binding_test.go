package engine

import (
	"context"
	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"net"
	"testing"
	"time"
)

type liveHeldManager struct {
	adapter.ConnectionManager
	reached, release chan struct{}
	leaf             adapter.Outbound
}

func (m *liveHeldManager) NewConnection(_ context.Context, d N.Dialer, _ net.Conn, _ adapter.InboundContext, _ N.CloseHandlerFunc) {
	close(m.reached)
	<-m.release
	m.leaf = d.(adapter.Outbound)
}
func TestLiveRecordsHeldDialUsesPinnedLeaf(t *testing.T) {
	a := &liveIdentityOutbound{tag: "a"}
	b := &liveIdentityOutbound{tag: "b"}
	manager := &liveHeldManager{reached: make(chan struct{}), release: make(chan struct{})}
	selector := &selectionOutbound{Adapter: outbound.NewAdapter(LiveSelectionType, "live", []string{"tcp"}, nil), connections: manager, leaves: map[string]adapter.Outbound{"a": a, "b": b}}
	selector.selected.Store(&selectedLeaf{a})
	m := recordsTestManifest(t, []byte("captured"), "a", "anytls")
	origin := m.Outbounds[0]
	sink := &recordsTestSink{}
	tracker := &recordsTracker{verified: true, sink: sink, final: m.FinalOrigin, outbounds: map[string]adapter.Outbound{"live": selector, "a": a, "b": b}, origins: map[string]cr.OutboundOrigin{"a": origin}}
	tracker.final.OutboundTag, tracker.final.OutboundType = "live", LiveSelectionType
	down, up := net.Pipe()
	defer down.Close()
	defer up.Close()
	md := adapter.InboundContext{Network: "tcp", Destination: M.ParseSocksaddr("127.0.0.1:1")}
	tracked := tracker.RoutedConnection(context.Background(), up, md, nil, selector)
	done := make(chan struct{})
	go func() {
		defer close(done)
		selector.NewConnection(context.Background(), bufio.NewCounterConn(tracked, nil, nil), md, nil)
	}()
	<-manager.reached
	selector.selected.Store(&selectedLeaf{b})
	close(manager.release)
	<-done
	rows, status := sink.snapshot()
	_ = status
	if manager.leaf != a || len(rows) != 1 || rows[0].Route.OutboundTag != "a" || rows[0].Route.Evidence != cr.ProvenanceVerified {
		t.Fatalf("held dial relabeled: leaf=%v rows=%+v", manager.leaf, rows)
	}
	// Wrong actual object with same tag cannot acquire VERIFIED leaf authority.
	if r := tracker.liveRoute(tracker.final, selector, &liveIdentityOutbound{tag: "a"}); r.Evidence != cr.ProvenanceUnknown {
		t.Fatal("forged leaf verified")
	}
	if cr.Validate(rows[0].Route) != nil {
		t.Fatal("invalid route schema")
	}
}

type liveIdentityOutbound struct {
	adapter.Outbound
	tag string
}

func (o *liveIdentityOutbound) Tag() string  { return o.tag }
func (o *liveIdentityOutbound) Type() string { return "anytls" }
func TestLiveBrowserDNSGenerationRejectsHeldAndAcceptsCacheClone(t *testing.T) {
	live := NewLiveSelection()
	transport := &observedHTTPS{live: live}
	_, reply := browserAnswer("held.test", 28, "2001:db8::1", 30)
	transport.certifyReply(reply, 0)
	cached := reply.Copy()
	cached.Id++
	cached.Answer[0].Header().Ttl = 20
	if !transport.currentReply(cached) {
		t.Fatal("cache clone lost browser authority")
	}
	live.dnsEpoch.Add(2)
	if transport.currentReply(reply) {
		t.Fatal("old response reacquired authority")
	}
	transport.certifyReply(reply, 0)
	if transport.currentReply(reply) {
		t.Fatal("held old completion reacquired authority")
	}
	transport.certifyReply(reply, 2)
	if !transport.currentReply(cached) {
		t.Fatal("current stable reply unavailable")
	}
	mutated := cached.Copy()
	mutated.Question[0].Name = "other.test."
	if transport.currentReply(mutated) {
		t.Fatal("mutated response verified")
	}
	for k, r := range transport.replies {
		r.expires = time.Now().Add(-time.Second)
		transport.replies[k] = r
	}
	if transport.currentReply(cached) {
		t.Fatal("expired certificate verified")
	}
}
