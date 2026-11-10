package engine

import (
	"context"
	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"net"
)

// The SDK tracker runs BEFORE Dial. Delay only live attribution until the
// handler has pinned the very leaf used by this connection's dialer.
// Static records retain their original route-time behavior.
type liveRecordConn struct {
	net.Conn
	record func(adapter.Outbound)
}

func (c *liveRecordConn) Upstream() any                   { return c.Conn }
func (c *liveRecordConn) liveRecord(out adapter.Outbound) { c.record(out) }

type liveRecordPacketConn struct {
	N.PacketConn
	record func(adapter.Outbound)
}

func (c *liveRecordPacketConn) Upstream() any                   { return c.PacketConn }
func (c *liveRecordPacketConn) liveRecord(out adapter.Outbound) { c.record(out) }
func (p *selectionOutbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	leaf := p.selected.Load().outbound
	if witness, ok := common.Cast[interface{ liveRecord(adapter.Outbound) }](conn); ok {
		witness.liveRecord(leaf)
	}
	dial := N.Dialer(leaf)
	if guard := service.FromContext[browserDialGuard](ctx); guard != nil {
		if browser, ok := guard.BrowserDialer(ctx, p).(*browserDialer); ok {
			browser.Outbound = leaf
			dial = browser
		}
	}
	p.connections.NewConnection(ctx, dial, conn, metadata, onClose)
}
func (p *selectionOutbound) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	leaf := p.selected.Load().outbound
	if witness, ok := common.Cast[interface{ liveRecord(adapter.Outbound) }](conn); ok {
		witness.liveRecord(leaf)
	}
	p.connections.NewPacketConnection(ctx, leaf, conn, metadata, onClose)
}
func (t *recordsTracker) liveRoute(base cr.RouteProjection, selector *selectionOutbound, leaf adapter.Outbound) cr.RouteProjection {
	origin, ok := t.origins[leaf.Tag()]
	if !t.verified || base.Evidence != cr.ProvenanceVerified || selector.leaves[leaf.Tag()] != leaf || t.outbounds[leaf.Tag()] != leaf || !ok || origin.Type != "anytls" {
		return unknownRecordsRoute(cr.ProvenanceUnknown, leaf.Tag(), leaf.Type())
	}
	base.OutboundTag, base.OutboundType = origin.Tag, origin.Type
	base.TerminalKind, base.FinalNodeID, base.FinalNodeLabel = origin.TerminalKind, origin.NodeID, origin.NodeLabel
	base.GroupPath = append([]cr.GroupEdge{}, base.GroupPath...)
	if len(base.GroupPath) > 0 {
		base.GroupPath[0].Selected = *origin.NodeLabel
	}
	return base
}

func browserLiveOutbound(out adapter.Outbound) bool { _, ok := out.(*selectionOutbound); return ok }
