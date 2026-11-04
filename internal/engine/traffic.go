package engine

import (
	"context"
	"net"

	ts "github.com/NiuStar/anytls-core/internal/trafficstats"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

// Native counters retain the SDK's unwrap/copy/vectorised/batch/read-waiter
// behavior. No manager, connection metadata, event bus or Clash API is enabled.
type trafficTracker struct{ counter *ts.Counter }

var _ adapter.ConnectionTracker = (*trafficTracker)(nil)

func (t *trafficTracker) RoutedConnection(_ context.Context, c net.Conn, _ adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	return bufio.NewCounterConn(c, []N.CountFunc{t.counter.Upload}, []N.CountFunc{t.counter.Download})
}
func (t *trafficTracker) RoutedPacketConnection(_ context.Context, c N.PacketConn, _ adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	return bufio.NewCounterPacketConn(c, []N.CountFunc{t.counter.Upload}, []N.CountFunc{t.counter.Download})
}
func (t *trafficTracker) RoutedFlow(_ context.Context, _ adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) tun.FlowTracker {
	// Flow counters receive raw IP packets (including ICMP and headers), not
	// transport payload. The SDK permits nil trackers without disabling dispatch.
	return nil
}

type trafficLifecycle struct {
	adapter.SimpleLifecycle
	loaded func()
}

func (l trafficLifecycle) Start() error {
	if e := l.SimpleLifecycle.Start(); e != nil {
		return e
	}
	if l.loaded != nil {
		l.loaded()
	}
	return nil
}
