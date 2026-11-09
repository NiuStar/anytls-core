package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"runtime"
	"testing"
	"time"
)

func TestDirectProbePolicy(t *testing.T) {
	for _, host := range []string{"localhost", "example.invalid", "127.0.0.1", "::1", "0.0.0.0", "fe80::1%en0", "fe80::1", "224.0.0.1", "::"} {
		if _, err := directProbeIP(host); !errors.Is(err, errNodeProbeDirectUnavailable) {
			t.Fatalf("unsafe host accepted: %s", host)
		}
	}
	for _, host := range []string{"192.0.2.1", "2001:db8::1", "192.168.1.2"} {
		if _, err := directProbeIP(host); err != nil {
			t.Fatal(err)
		}
	}
	physical := func(name string, index int) net.Interface {
		return net.Interface{Name: name, Index: index, Flags: net.FlagUp | net.FlagBroadcast, HardwareAddr: net.HardwareAddr{0, 1, 2, 3, 4, 5}}
	}
	a, b := physical("en0", 2), physical("en7", 8)
	for _, name := range []string{"utun0", "lo0", "bridge0", "feth0", "awdl0", "en", "en0x"} {
		if directPhysicalInterface(physical(name, 3)) {
			t.Fatal("nonphysical accepted", name)
		}
	}
	for _, flags := range []net.Flags{0, net.FlagUp | net.FlagLoopback, net.FlagUp | net.FlagPointToPoint} {
		i := a
		i.Flags = flags
		if directPhysicalInterface(i) {
			t.Fatal("unsafe flags accepted")
		}
	}
	if i, e := directSelectInterface("en7", []net.Interface{a, b}); e != nil || i.Index != b.Index {
		t.Fatal("primary lost")
	}
	if _, e := directSelectInterface("utun9", []net.Interface{a, b}); !errors.Is(e, errNodeProbeDirectUnavailable) {
		t.Fatal("ambiguous selection")
	}
	if i, e := directSelectInterface("utun9", []net.Interface{b}); e != nil || i.Index != b.Index {
		t.Fatal("unique physical route rejected")
	}
	if _, e := directSelectInterface("utun9", nil); e == nil {
		t.Fatal("missing route accepted")
	}
	for _, s := range []string{"interface: utun0\n flags: <UP,GATEWAY>", "interface: en0\n flags: <UP,REJECT>", "interface: en0\n flags: <UP,BLACKHOLE>", "interface: en0\ninterface: en0\n flags: <UP>"} {
		if directScopedRoute(s, "en0") {
			t.Fatal("unsafe route accepted")
		}
	}
	if !directScopedRoute("interface: en0\n flags: <UP,GATEWAY,DONE>", "en0") {
		t.Fatal("valid scoped route rejected")
	}
}

func TestWebNodeProbeDirectFailures(t *testing.T) {
	for _, tc := range []struct {
		err          error
		status, code string
	}{
		{errNodeProbeDirectUnavailable, "UNAVAILABLE", "PROBE_DIRECT_UNAVAILABLE"},
		{errors.New("refused secret"), "FAILED", "PROBE_FAILED"},
		{context.DeadlineExceeded, "TIMEOUT", "PROBE_TIMEOUT"},
	} {
		w, cookie, csrf, etag := probeWebFixture(t)
		w.nodeProbe = func(context.Context, node, string) (float64, error) { return 99, tc.err }
		r := probeWebRequest(w, cookie, csrf, etag, `{"name":"first","mode":"tcp_direct"}`)
		var v webNodeProbeResult
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &v) != nil || v.Status != tc.status || v.Error != tc.code || v.LatencyMS != nil {
			t.Fatalf("bad failure: %d %s", r.Code, r.Body.String())
		}
	}
}

func TestWebNodeProbeDirectNoDefaultFallback(t *testing.T) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	n := node{Type: "anytls", Server: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port}
	if _, e := webNodeProbe(context.Background(), n, "tcp_direct"); !errors.Is(e, errNodeProbeDirectUnavailable) {
		t.Fatal("default route fallback", e)
	}
	l.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Millisecond))
	if c, e := l.Accept(); e == nil {
		c.Close()
		t.Fatal("unbound socket connected")
	}
	if runtime.GOOS != "darwin" {
		n.Server = "192.0.2.1"
		if _, e := webNodeProbe(context.Background(), n, "tcp_direct"); !errors.Is(e, errNodeProbeDirectUnavailable) {
			t.Fatal("unsupported platform dialed", e)
		}
	}
}

func TestWebNodeProbeDirectSharedCapacity(t *testing.T) {
	f := newParallelProbeFixture(t)
	var active []*parallelProbeRequest
	for i := 0; i < 8; i++ {
		mode := "tcp_direct"
		if i == 7 {
			mode = "tcp"
		}
		p := f.start(mode)
		active = append(active, p)
		if !f.awaitEntry(t, p) {
			return
		}
	}
	requireParallelError(t, awaitParallelProbe(t, f.start("tcp_direct")), 429, "PROBE_BUSY")
	f.unblock()
	for _, p := range active {
		r := awaitParallelProbe(t, p)
		if r == nil {
			continue
		}
		var v webNodeProbeResult
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &v) != nil || v.Status != "OK" {
			t.Fatalf("direct parallel failed: %d %s", r.Code, r.Body.String())
		}
	}
	if r := awaitParallelProbe(t, f.start("tcp_direct")); r != nil && r.Code != 200 {
		t.Fatal("slot not recovered")
	}
}

func TestWebNodeProbeDirectContract(t *testing.T) {
	w, cookie, csrf, etag := probeWebFixture(t)
	calls := 0
	w.nodeProbe = func(ctx context.Context, n node, mode string) (float64, error) {
		calls++
		if mode != "tcp_direct" || n.Name != "first" {
			t.Fatal("wrong identity or mode")
		}
		return 3.25, nil
	}
	r := probeWebRequest(w, cookie, csrf, etag, `{"name":"first","mode":"tcp_direct"}`)
	var v map[string]any
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &v) != nil || len(v) != 8 || v["status"] != "OK" || v["mode"] != "tcp_direct" || v["latency_ms"] != 3.25 || calls != 1 {
		t.Fatalf("direct contract: %d %s calls=%d", r.Code, r.Body.String(), calls)
	}
}
