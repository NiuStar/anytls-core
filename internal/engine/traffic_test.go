package engine

import (
	"context"
	"errors"
	ts "github.com/NiuStar/anytls-core/internal/trafficstats"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"testing"
	"time"
)

func TestTrafficNativeLoopbackTCPUDPExact(t *testing.T) {
	counter := new(ts.Counter)
	tracker := &trafficTracker{counter}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	client, e := net.Dial("tcp", listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	original, e := listener.Accept()
	if e != nil {
		t.Fatal(e)
	}
	conn := tracker.RoutedConnection(context.Background(), original, adapter.InboundContext{}, nil, nil)
	defer conn.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, e = client.Write([]byte("upload-23")); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 9)
	if _, e = io.ReadFull(conn, b); e != nil {
		t.Fatal(e)
	}
	if _, e = conn.Write([]byte("download-31")); e != nil {
		t.Fatal(e)
	}
	if _, e = io.ReadFull(client, make([]byte, 11)); e != nil {
		t.Fatal(e)
	}
	if _, ok := conn.(interface {
		UnwrapReader() (io.Reader, []func(int64))
	}); ok {
		t.Fatal("unexpected raw function type")
	}
	native, ok := conn.(*bufio.CounterConn)
	if !ok {
		t.Fatal("not SDK native")
	}
	_, callbacks := native.UnwrapReader()
	if len(callbacks) != 1 {
		t.Fatal("lost unwrap")
	}
	udp, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	pc := tracker.RoutedPacketConnection(context.Background(), bufio.NewPacketConn(udp), adapter.InboundContext{}, nil, nil)
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(time.Second))
	sender, e := net.Dial("udp", udp.LocalAddr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer sender.Close()
	_ = sender.SetDeadline(time.Now().Add(time.Second))
	if _, e = sender.Write([]byte("packet-up")); e != nil {
		t.Fatal(e)
	}
	packet := buf.NewPacket()
	dest, e := pc.ReadPacket(packet)
	if e != nil {
		t.Fatal(e)
	}
	if string(packet.Bytes()) != "packet-up" {
		t.Fatal("payload changed")
	}
	packet.Release()
	if e = pc.WritePacket(buf.As([]byte("packet-download")), dest); e != nil {
		t.Fatal(e)
	}
	if n, e := sender.Read(make([]byte, 99)); e != nil || n != 15 {
		t.Fatal(n, e)
	}
	u, d, s := counter.Totals()
	if u != 18 || d != 26 || s {
		t.Fatal("exact fixture bytes differ", u, d, s)
	}
	flow := tracker.RoutedFlow(context.Background(), adapter.InboundContext{Destination: M.Socksaddr{}}, nil, nil)
	if flow != nil {
		t.Fatal("raw Flow must not count as TCP/UDP transport payload")
	}
	u, d, _ = counter.Totals()
	if u != 18 || d != 26 {
		t.Fatal("Flow changed transport payload totals", u, d)
	}
	conn.Close()
	pc.Close()
	u, d, _ = counter.Totals()
	if u != 18 || d != 26 {
		t.Fatal("close fabricated bytes")
	}
}
func TestTrafficEngineRunCancelLoaded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loaded := make(chan struct{})
	raw := loopbackConfig()
	counter := new(ts.Counter)
	done := make(chan error, 1)
	go func() {
		done <- RunWithRecords(ctx, raw, &RecordsInput{Manifest: recordsTestManifest(t, raw, "direct", "direct"), Sink: &recordsTestSink{}, Traffic: counter, TrafficLoaded: func() { close(loaded) }})
	}()
	select {
	case <-loaded:
	case <-time.After(5 * time.Second):
		t.Fatal("not loaded")
	}
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancel blocked")
	}
	u, d, _ := counter.Totals()
	if u != 0 || d != 0 {
		t.Fatal("idle side effects", u, d)
	}
}
