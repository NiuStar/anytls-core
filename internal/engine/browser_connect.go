package engine

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/anytls/sing-anytls/session"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type browserDialGuard = interface {
	BrowserDialer(context.Context, adapter.Outbound) N.Dialer
}

func (s *browserProvenance) BrowserDialer(ctx context.Context, outbound adapter.Outbound) N.Dialer {
	p, ok := ctx.Value(browserCandidateKey{}).(browserPrepared)
	if !ok || p.owner != s || p.outbound != outbound {
		return outbound
	}
	return &browserDialer{Outbound: outbound, prepared: p}
}

type browserDialer struct {
	adapter.Outbound
	prepared browserPrepared
}

func browserGeneratedRule(raw string) bool {
	return raw == `{"action":"sniff"}` || raw == `{"action":"hijack-dns","port":53}` || raw == `{"action":"hijack-dns","protocol":["dns"]}`
}
func (s *browserProvenance) validLocked(old browserReceipt) bool {
	now := s.now()
	if old.epoch != s.epoch || !now.Before(old.expires) || now.Before(s.blockedUntil) {
		return false
	}
	found := false
	for _, c := range s.claims {
		if c.scope != old.scope || c.ip != old.ip || !now.Before(c.expires) {
			continue
		}
		if c.name != old.name || c.terminal != old.terminal || c.transport != old.transport {
			return false
		}
		found = true
	}
	return found
}
func (s *browserProvenance) reserve(ctx context.Context, old browserReceipt) (context.Context, *browserLaunch, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil || !s.validLocked(old) {
		return ctx, nil, false
	}
	ctx, cancel := context.WithCancel(ctx)
	launch := &browserLaunch{cancel: cancel, receipt: old}
	if s.active == nil {
		s.active = make(map[*browserLaunch]struct{})
	}
	s.active[launch] = struct{}{}
	return ctx, launch, true
}
func (s *browserProvenance) attach(ctx context.Context, l *browserLaunch, c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		if c != nil {
			c.Close()
		}
		return false
	}
	l.conn = c
	return true
}
func (s *browserProvenance) release(l *browserLaunch) {
	s.mu.Lock()
	delete(s.active, l)
	s.mu.Unlock()
	l.cancel()
}

type browserOwnedConn struct {
	net.Conn
	once   sync.Once
	owner  *browserProvenance
	launch *browserLaunch
}

func (c *browserOwnedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.owner.release(c.launch) })
	return err
}
func (d *browserDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	p := d.prepared
	s := p.owner
	if network != "tcp" || destination != p.metadata.Destination {
		return d.Outbound.DialContext(ctx, network, destination)
	}
	launchCtx, l, ok := s.reserve(ctx, p.receipt)
	if !ok {
		return nil, context.Canceled
	}
	keep := false
	defer func() {
		if !keep {
			s.release(l)
		}
	}()
	attempt := func(dest M.Socksaddr) (net.Conn, error) {
		if err := launchCtx.Err(); err != nil {
			return nil, err
		}
		c, err := d.Outbound.DialContext(launchCtx, network, dest)
		if err != nil {
			return nil, err
		}
		if !s.attach(launchCtx, l, c) {
			return nil, launchCtx.Err()
		}
		if w, ok := c.(interface{ WaitConnect(context.Context) error }); ok {
			err = w.WaitConnect(launchCtx)
			// Unknown/old peers keep the original early stream; neither is family evidence.
			if errors.Is(err, session.ErrConnectACKUnsupported) || (errors.Is(err, session.ErrConnectACKUnconfirmed) && launchCtx.Err() == nil) {
				err = nil
			}
		}
		if err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}
	c, err := attempt(destination)
	if err != nil && launchCtx.Err() == nil {
		var remote *session.RemoteConnectError
		var connect *net.OpError
		eligible := errors.As(err, &remote) || (d.Outbound.Type() == "direct" && errors.As(err, &connect) && connect.Op == "dial")
		if eligible && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			ip, expires, certified := s.BrowserCandidate(launchCtx, p.router, p.metadata, p.selected, p.index, p.outbound)
			if certified {
				s.mu.Lock()
				allowed := s.validLocked(p.receipt) && s.now().Before(expires) && launchCtx.Err() == nil
				s.mu.Unlock()
				if allowed {
					candidate := destination
					candidate.Addr = ip
					c, err = attempt(candidate)
				}
			}
		}
	}
	if err != nil {
		return nil, err
	}
	if !s.attach(launchCtx, l, c) {
		return nil, launchCtx.Err()
	}
	keep = true
	return &browserOwnedConn{Conn: c, owner: s, launch: l}, nil
}
func closeBrowserProvenance(ctx context.Context) {
	if s, ok := service.FromContext[browserDNSObserver](ctx).(*browserProvenance); ok {
		s.InvalidateBrowserDNS()
	}
}
