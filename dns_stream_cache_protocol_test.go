//go:build embedded_core

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	dnsOutbound "github.com/sagernet/sing-box/protocol/dns"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/service"
)

type dnsStreamOwnershipRouter struct {
	adapter.DNSRouter
	exchange func(context.Context, *dns.Msg, func(*dns.Msg, error))
}

func (r *dnsStreamOwnershipRouter) ExchangeAsync(ctx context.Context, q *dns.Msg, _ adapter.DNSQueryOptions, cb func(*dns.Msg, error)) {
	r.exchange(ctx, q, cb)
}

type dnsStreamCloseCount struct {
	net.Conn
	count   atomic.Int32
	entered chan struct{}
	once    atomic.Bool
}

func (c *dnsStreamCloseCount) Close() error { c.count.Add(1); return c.Conn.Close() }
func (c *dnsStreamCloseCount) Read(p []byte) (int, error) {
	if c.once.CompareAndSwap(false, true) {
		close(c.entered)
	}
	return c.Conn.Read(p)
}

// The async admission hook observes ownership synchronously before returning.
// Old SDK deterministically admits a callback while CachedConn still owns replay
// data; no timing or race-detector luck is needed for that business RED.
func TestDNSStreamCachedOwnershipBeforeAsyncClose(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	raw := &dnsStreamCloseCount{Conn: client, entered: make(chan struct{})}
	q := new(dns.Msg)
	q.SetQuestion("ownership.invalid.", dns.TypeA)
	q.Id = 3191
	wire, e := q.Pack()
	if e != nil {
		t.Fatal(e)
	}
	frame := append([]byte{byte(len(wire) >> 8), byte(len(wire))}, wire...)
	cached := bufio.NewCachedConn(raw, buf.As(frame))
	var ownerDetached atomic.Bool
	callbackDone := make(chan struct{})
	sentinel := errors.New("exchange sentinel")
	router := &dnsStreamOwnershipRouter{exchange: func(ctx context.Context, got *dns.Msg, cb func(*dns.Msg, error)) {
		if got.Id != q.Id || got.Question[0] != q.Question[0] {
			t.Error("query changed")
		}
		ownerDetached.Store(cached.ReaderReplaceable())
		go func() { <-raw.entered; cb(nil, sentinel); close(callbackDone) }()
	}}
	ctx := service.ContextWith[adapter.DNSRouter](context.Background(), router)
	out, e := dnsOutbound.NewOutbound(ctx, nil, nil, "dns", option.StubOptions{})
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go out.(*dnsOutbound.Outbound).NewConnection(ctx, cached, adapter.InboundContext{}, func(err error) { done <- err })
	select {
	case err := <-done:
		if !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
			t.Errorf("read close identity: %v", err)
		}
	case <-time.After(2 * time.Second):
		raw.Close()
		t.Fatal("async Close did not wake blocked raw Read")
	}
	select {
	case <-callbackDone:
	case <-time.After(time.Second):
		t.Fatal("callback not joined")
	}
	if !ownerDetached.Load() {
		t.Error("DNS async exchange admitted while CachedConn still owns replay buffer")
	}
	if n := raw.count.Load(); n != 1 {
		t.Errorf("underlying Close count=%d, want 1", n)
	}
}
