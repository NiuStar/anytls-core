package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const LiveSelectionType = "anytls-selection"

type liveKey struct{}
type LiveSnapshot struct {
	Generation string `json:"generation"`
	Revision   uint64 `json:"revision"`
	Selected   string `json:"selected"`
	Ready      bool   `json:"ready"`
}

// LiveSelection is per-Run, never process global. The finite leaf set is owned by
// the Box; no paths, credentials, arbitrary rules or external APIs enter Switch.
type LiveSelection struct {
	mu        sync.Mutex
	snapshot  LiveSnapshot
	outbound  *selectionOutbound
	reset     func()
	dnsEpoch  atomic.Uint64
	dnsRouter adapter.DNSRouter
}

func NewLiveSelection() *LiveSelection {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil
	}
	return &LiveSelection{snapshot: LiveSnapshot{Generation: hex.EncodeToString(id[:])}}
}
func (s *LiveSelection) Snapshot() LiveSnapshot { s.mu.Lock(); defer s.mu.Unlock(); return s.snapshot }
func (s *LiveSelection) Switch(g string, r uint64, tag string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.snapshot.Ready || g != s.snapshot.Generation || r != s.snapshot.Revision || s.snapshot.Revision == ^uint64(0) {
		return errors.New("selection stale or unavailable")
	}
	leaf := s.outbound.leaves[tag]
	if leaf == nil {
		return errors.New("selection not admitted")
	}
	if tag == s.snapshot.Selected {
		return nil
	}
	// DNS cache keys include this epoch; an old operation cannot populate the
	// new namespace. Reset replaces the DoH pool before returning the switch.
	s.outbound.selected.Store(&selectedLeaf{leaf})
	s.dnsEpoch.Add(1)
	s.reset()
	s.dnsEpoch.Add(1)
	s.snapshot.Selected = tag
	s.snapshot.Revision++
	return nil
}
func RunControlled(ctx context.Context, raw []byte, records *RecordsInput, s *LiveSelection) error {
	if s == nil {
		return errors.New("selection unavailable")
	}
	return RunWithRecords(context.WithValue(ctx, liveKey{}, s), raw, records)
}
func CheckControlled(ctx context.Context, raw []byte) error {
	s := NewLiveSelection()
	if s == nil {
		return errors.New("selection unavailable")
	}
	return Check(context.WithValue(ctx, liveKey{}, s), raw)
}
func (s *LiveSelection) dnsEnvironment() []string {
	return []string{"selection:" + s.snapshot.Generation + ":" + strconv.FormatUint(s.dnsEpoch.Load(), 10)}
}
func liveFrom(ctx context.Context) *LiveSelection {
	s, _ := ctx.Value(liveKey{}).(*LiveSelection)
	return s
}
func liveReady(ctx context.Context) {
	if s := liveFrom(ctx); s != nil {
		s.mu.Lock()
		s.snapshot.Ready = s.outbound != nil
		s.mu.Unlock()
	}
}
func liveClosed(ctx context.Context) {
	if s := liveFrom(ctx); s != nil {
		s.mu.Lock()
		s.snapshot.Ready = false
		s.mu.Unlock()
	}
}

type selectedLeaf struct{ outbound adapter.Outbound }
type selectionOutbound struct {
	outbound.Adapter
	owner       *LiveSelection
	manager     adapter.OutboundManager
	tags        []string
	connections adapter.ConnectionManager
	initial     string
	leaves      map[string]adapter.Outbound
	selected    atomic.Pointer[selectedLeaf]
}

func registerLive(registry *outbound.Registry) {
	outbound.Register[option.SelectorOutboundOptions](registry, LiveSelectionType, newSelectionOutbound)
}
func newSelectionOutbound(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, o option.SelectorOutboundOptions) (adapter.Outbound, error) {
	s := liveFrom(ctx)
	if s == nil || tag != "live" || len(o.Outbounds) < 1 || len(o.Outbounds) > 256 || o.InterruptExistConnections {
		return nil, errors.New("private selection unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.outbound != nil {
		return nil, errors.New("duplicate selection")
	}
	p := &selectionOutbound{Adapter: outbound.NewAdapter(LiveSelectionType, tag, []string{N.NetworkTCP, N.NetworkUDP}, o.Outbounds), owner: s, manager: service.FromContext[adapter.OutboundManager](ctx), tags: append([]string(nil), o.Outbounds...), initial: o.Default, leaves: make(map[string]adapter.Outbound)}
	p.connections = service.FromContext[adapter.ConnectionManager](ctx)
	s.outbound = p
	s.snapshot.Selected = o.Default
	return p, nil
}
func (p *selectionOutbound) Start(stage adapter.StartStage, _ *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	for _, tag := range p.tags {
		leaf, ok := p.manager.Outbound(tag)
		if !ok || leaf.Type() != "anytls" || p.leaves[tag] != nil {
			return errors.New("invalid selection leaf")
		}
		p.leaves[tag] = leaf
	}
	initial := p.leaves[p.initial]
	if initial == nil {
		return errors.New("invalid initial selection")
	}
	p.selected.Store(&selectedLeaf{initial})
	return nil
}
func (p *selectionOutbound) DialContext(ctx context.Context, network string, d M.Socksaddr) (net.Conn, error) {
	return p.selected.Load().outbound.DialContext(ctx, network, d)
}
func (p *selectionOutbound) ListenPacket(ctx context.Context, d M.Socksaddr) (net.PacketConn, error) {
	return p.selected.Load().outbound.ListenPacket(ctx, d)
}
