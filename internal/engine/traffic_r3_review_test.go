package engine

import (
	"context"
	"encoding/binary"
	ts "github.com/NiuStar/anytls-core/internal/trafficstats"
	"github.com/sagernet/sing-box/adapter"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	"net/netip"
	"testing"
)

type reviewFlowHandler struct {
	tun.Handler
	tracker tun.FlowTracker
	port    tun.Port
}

func (h reviewFlowHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) tun.FlowVerdict {
	return tun.FlowVerdict{Action: tun.ActionFlow, Port: h.port, NewTracker: func() tun.FlowTracker { return h.tracker }}
}

type reviewFlowPort struct{ writes *int }

func (reviewFlowPort) PortAddresses() (netip.Addr, netip.Addr) {
	return netip.MustParseAddr("192.0.2.1"), netip.Addr{}
}
func (reviewFlowPort) PortMTU() uint32               { return 1500 }
func (reviewFlowPort) AttachReturn(tun.Return) error { return nil }
func (reviewFlowPort) DetachReturn(tun.Return) error { return nil }
func (p reviewFlowPort) WritePackets(packets [][]byte) error {
	*p.writes += len(packets)
	return nil
}

type reviewWriteback struct{}

func (reviewWriteback) ReturnHeadroom() int               { return 0 }
func (reviewWriteback) WriteReturnPackets([][]byte) error { return nil }
func TestReviewR2RealSDKFlowPayloadUnit(t *testing.T) {
	c := new(ts.Counter)
	tr := &trafficTracker{c}
	f := tr.RoutedFlow(context.Background(), adapter.InboundContext{}, nil, nil)
	writes := 0
	d := tun.NewForwardDispatcher(reviewFlowHandler{tracker: f, port: reviewFlowPort{writes: &writes}}, reviewWriteback{}, logger.NOP(), 0, 0)
	defer d.Close()
	raw := make([]byte, 31)
	raw[0] = 0x45
	binary.BigEndian.PutUint16(raw[2:4], 31)
	raw[8] = 64
	raw[9] = 17
	copy(raw[12:16], []byte{10, 0, 0, 1})
	copy(raw[16:20], []byte{198, 51, 100, 1})
	binary.BigEndian.PutUint16(raw[20:22], 12345)
	binary.BigEndian.PutUint16(raw[22:24], 443)
	binary.BigEndian.PutUint16(raw[24:26], 11)
	copy(raw[28:], []byte("abc"))
	if !d.Dispatch(raw) {
		t.Fatal("SDK flow did not handle fixture")
	}
	// A direct ICMP-style raw Flow must still dispatch, but not enter payload totals.
	icmp := append([]byte(nil), raw[:28]...)
	binary.BigEndian.PutUint16(icmp[2:4], 28)
	icmp[9] = 1
	icmp[20] = 8
	icmp[21] = 0
	if !d.Dispatch(icmp) {
		t.Fatal("SDK ICMP flow did not handle fixture")
	}
	d.Flush()
	if writes != 2 {
		t.Fatalf("nil tracker changed dispatch: port received %d packets, want 2", writes)
	}
	u, down, _ := c.Totals()
	if u != 0 || down != 0 {
		t.Fatalf("excluded raw Flow counted upload=%d download=%d for 3-byte UDP payload / 31-byte IPv4 packet", u, down)
	}
}
