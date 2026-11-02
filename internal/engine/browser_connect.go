package engine

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/anytls/sing-anytls/session"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"

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
	// Test-only synchronization seam, before the final launch reservation.
	beforeLaunch func()
}

func browserGeneratedRule(raw string) bool {
	return raw == `{"action":"sniff"}` || raw == `{"action":"hijack-dns","port":53}` || raw == `{"action":"hijack-dns","protocol":["dns"]}`
}
func browserNetworkFailure(err error) bool {
	// Accept only a single typed connect-error chain, not an errors.Join
	// containing a network sentinel alongside security/cancellation failures.
	for depth := 0; err != nil && depth < 8; depth++ {
		switch e := err.(type) {
		case *net.OpError:
			if e.Op != "dial" {
				return false
			}
			err = e.Err
		case *os.SyscallError:
			if e.Syscall != "connect" {
				return false
			}
			err = e.Err
		case syscall.Errno:
			return e == syscall.ENETUNREACH || e == syscall.EHOSTUNREACH || e == syscall.ECONNREFUSED || e == syscall.ETIMEDOUT || e == syscall.EAFNOSUPPORT
		default:
			return false
		}
	}
	return false
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
	// Reuse the SDK default and inherit any shorter caller deadline. All
	// CONNECT attempts and the refresh share this one absolute deadline.
	ctx, cancel := context.WithTimeout(ctx, C.TCPConnectTimeout)
	launch := &browserLaunch{cancel: cancel, receipt: old}
	if s.active == nil {
		s.active = make(map[*browserLaunch]struct{})
	}
	s.active[launch] = struct{}{}
	return ctx, launch, true
}
func (s *browserProvenance) attach(ctx context.Context, l *browserLaunch, c net.Conn) bool {
	s.mu.Lock()
	_, active := s.active[l]
	allowed := active && ctx.Err() == nil
	if allowed {
		l.conn = c
	}
	s.mu.Unlock()
	// Close may block or reenter the observer; never call it under s.mu.
	if !allowed && c != nil {
		c.Close()
	}
	return allowed
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
	err    error
	owner  *browserProvenance
	launch *browserLaunch
}

func (c *browserOwnedConn) closeStream() error {
	c.once.Do(func() { c.err = c.Conn.Close() })
	return c.err
}
func (c *browserOwnedConn) Close() error {
	c.owner.release(c.launch)
	return c.closeStream()
}
func (d *browserDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	p := d.prepared
	s := p.owner
	if network != "tcp" || destination != p.metadata.Destination {
		return d.Outbound.DialContext(ctx, network, destination)
	}

	launchCtx, l, ok := s.reserve(ctx, p.receipt)
	if !ok {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s.mu.Lock()
		invalidated := p.receipt.epoch != s.epoch
		s.mu.Unlock()
		if invalidated {
			return nil, context.Canceled
		}
		// Expiry/ambiguity is UNKNOWN, not caller cancellation. Preserve the
		// original outbound without enabling an alternate.
		return d.Outbound.DialContext(ctx, network, destination)
	}
	keep := false
	defer func() {
		if !keep {
			s.release(l)
		}
	}()
	var candidateExpires time.Time
	attempt := func(dest M.Socksaddr) (net.Conn, error) {
		// Preliminary eligibility is not the launch reservation. Invalidation
		// may win while control is outside the lock; revalidate at admission.
		s.mu.Lock()
		eligible := s.validLocked(p.receipt) && launchCtx.Err() == nil
		s.mu.Unlock()
		if !eligible {
			return nil, context.Canceled
		}
		if d.beforeLaunch != nil {
			d.beforeLaunch()
		}
		s.mu.Lock()
		allowed := s.validLocked(p.receipt) && launchCtx.Err() == nil && (dest == destination || s.now().Before(candidateExpires))
		if !allowed {
			l.cancel()
		}
		s.mu.Unlock()
		if !allowed {
			return nil, context.Canceled
		}
		if err := launchCtx.Err(); err != nil {
			return nil, err
		}
		c, err := d.Outbound.DialContext(launchCtx, network, dest)
		if err != nil {
			return nil, err
		}
		owned := &browserOwnedConn{Conn: c, owner: s, launch: l}
		if !s.attach(launchCtx, l, owned) {
			return nil, launchCtx.Err()
		}
		if w, ok := c.(interface{ WaitConnect(context.Context) error }); ok {
			err = w.WaitConnect(launchCtx)
			// Unknown/old peers keep the original early stream; neither is family evidence.
			if dest == destination && (errors.Is(err, session.ErrConnectACKUnsupported) || (errors.Is(err, session.ErrConnectACKUnconfirmed) && launchCtx.Err() == nil)) {
				err = nil
			}
		}
		if err != nil {
			// An unsuccessful original may still be followed by one alternate;
			// close its stream without releasing the shared launch reservation.
			owned.closeStream()
			s.mu.Lock()
			if l.conn == owned {
				l.conn = nil
			}
			s.mu.Unlock()
			return nil, err
		}
		return owned, nil
	}
	c, err := attempt(destination)
	if err != nil && launchCtx.Err() == nil {
		var remote *session.RemoteConnectError
		var connect *net.OpError
		eligible := errors.As(err, &remote) || (d.Outbound.Type() == "direct" && errors.As(err, &connect) && connect.Op == "dial" && browserNetworkFailure(connect.Err))
		if eligible && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			ip, expires, certified := s.BrowserCandidate(launchCtx, p.router, p.metadata, p.selected, p.index, p.outbound)
			if certified {
				s.mu.Lock()
				allowed := s.validLocked(p.receipt) && s.now().Before(expires) && launchCtx.Err() == nil
				s.mu.Unlock()
				if allowed {
					candidate := destination
					candidate.Addr = ip
					candidateExpires = expires
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
	return c, nil
}
func closeBrowserProvenance(ctx context.Context) {
	if s, ok := service.FromContext[browserDNSObserver](ctx).(*browserProvenance); ok {
		s.InvalidateBrowserDNS()
	}
}
