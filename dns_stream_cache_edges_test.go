//go:build embedded_core

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	dnsOutbound "github.com/sagernet/sing-box/protocol/dns"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
)

func TestDNSStreamReplayAndCloseIdentity(t *testing.T) {
	for _, parts := range [][][]byte{nil, {{}}, {{1}, {2, 3}}, {{1, 2}, {}, {3, 4, 5}}} {
		t.Run("replay", func(t *testing.T) {
			client, peer := net.Pipe()
			sentinel := errors.New("close identity")
			raw := &dnsStreamErrorClose{Conn: client, err: sentinel}
			var conn net.Conn = raw
			want := []byte{9, 8}
			for _, part := range parts {
				conn = bufio.NewCachedConn(conn, buf.As(part))
				want = append(append([]byte{}, part...), want...)
			}
			conn = dnsOutbound.NewStreamDNSConn(conn)
			if dnsOutbound.NewStreamDNSConn(conn) != conn {
				t.Fatal("not idempotent")
			}
			wrote := make(chan error, 1)
			go func() { _, e := peer.Write([]byte{9, 8}); peer.Close(); wrote <- e }()
			var got []byte
			one := make([]byte, 1)
			for {
				n, e := conn.Read(one)
				got = append(got, one[:n]...)
				if errors.Is(e, io.EOF) {
					break
				}
				if e != nil {
					t.Fatal(e)
				}
			}
			if string(got) != string(want) {
				t.Fatalf("replay %v, want %v", got, want)
			}
			if e := <-wrote; e != nil {
				t.Fatal(e)
			}
			for j := 0; j < 2; j++ {
				if e := conn.Close(); e != sentinel {
					t.Fatalf("close identity %v", e)
				}
			}
			if raw.count.Load() != 1 {
				t.Fatal("duplicate underlying Close")
			}
			if n, e := conn.Read(one); n != 0 || !errors.Is(e, net.ErrClosed) {
				t.Fatalf("read after close %d %v", n, e)
			}
		})
	}
}

type dnsStreamErrorClose struct {
	net.Conn
	err   error
	count atomic.Int32
}

func (c *dnsStreamErrorClose) Close() error { c.count.Add(1); c.Conn.Close(); return c.err }

func TestDNSStreamConcurrentCachedReadClose(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	raw := &dnsStreamErrorClose{Conn: client, err: errors.New("close sentinel")}
	buffer := buf.NewSize(65536)
	buffer.Truncate(65536)
	conn := dnsOutbound.NewStreamDNSConn(bufio.NewCachedConn(raw, buffer))
	start := make(chan struct{})
	var group sync.WaitGroup
	for i := 0; i < 3; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			one := make([]byte, 1)
			for {
				if _, err := conn.Read(one); err != nil {
					return
				}
			}
		}()
	}
	for i := 0; i < 2; i++ {
		group.Add(1)
		go func() { defer group.Done(); <-start; conn.Close() }()
	}
	close(start)
	done := make(chan struct{})
	go func() { group.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent cached read/close did not join")
	}
	if raw.count.Load() != 1 {
		t.Fatal("concurrent Close repeated underlying close")
	}
	if buffer.Cap() != 0 {
		t.Fatal("managed replay buffer not released")
	}
}

func TestDNSStreamPipelinedCachedQueries(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	var want []uint16
	var all []byte
	for _, id := range []uint16{71, 72, 73} {
		q := new(dns.Msg)
		q.SetQuestion("pipeline.invalid.", dns.TypeAAAA)
		q.Id = id
		b, e := q.Pack()
		if e != nil {
			t.Fatal(e)
		}
		all = append(all, byte(len(b)>>8), byte(len(b)))
		all = append(all, b...)
		want = append(want, id)
	}
	var conn net.Conn = bufio.NewCachedConn(client, buf.As(all[3:]))
	conn = bufio.NewCachedConn(conn, buf.As(all[:3]))
	conn = dnsOutbound.NewStreamDNSConn(conn)
	defer conn.Close()
	var got []uint16
	router := &dnsStreamOwnershipRouter{exchange: func(_ context.Context, q *dns.Msg, _ func(*dns.Msg, error)) { got = append(got, q.Id) }}
	for range want {
		if e := dnsOutbound.HandleStreamDNSRequest(context.Background(), router, conn, adapter.InboundContext{}); e != nil {
			t.Fatal(e)
		}
	}
	if len(got) != len(want) {
		t.Fatal(got)
	}
	for i, id := range got {
		if id != want[i] {
			t.Fatalf("pipeline %v", got)
		}
	}
}
