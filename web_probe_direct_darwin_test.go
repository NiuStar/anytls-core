//go:build darwin

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// No connect, listener, packets or production configuration: real kernel sockets
// prove rootless binding and readback for both address families independently.
func TestDirectDarwinReadOnlyDiscovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	i, e := directDiscoverInterface(ctx, netip.MustParseAddr("192.0.2.1"))
	if errors.Is(e, errNodeProbeDirectUnavailable) {
		t.Log("read-only discovery UNAVAILABLE: no unambiguous scoped physical route; no connect")
		return
	}
	if e != nil || !directPhysicalInterface(i) {
		t.Fatal("invalid discovered interface", e)
	}
	t.Logf("read-only discovery physical=%s index=%d destination=192.0.2.1 no_connect=true", i.Name, i.Index)
}

func TestDirectDarwinKernelBinding(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var physical *net.Interface
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if i, err := directDiscoverInterface(ctx, netip.MustParseAddr("192.0.2.1")); err == nil {
		physical = &i
	}
	for _, i := range interfaces {
		if physical == nil && directPhysicalInterface(i) {
			v := i
			physical = &v
			break
		}
	}
	if physical == nil {
		t.Skip("no physical Ethernet/Wi-Fi interface")
	}
	for _, tc := range []struct {
		family, level, option int
		network               string
	}{
		{unix.AF_INET, unix.IPPROTO_IP, unix.IP_BOUND_IF, "tcp4"},
		{unix.AF_INET6, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, "tcp6"},
	} {
		t.Run(tc.network, func(t *testing.T) {
			fd, e := unix.Socket(tc.family, unix.SOCK_STREAM, unix.IPPROTO_TCP)
			if e != nil {
				t.Fatal(e)
			}
			f := os.NewFile(uintptr(fd), "owned-direct-probe-socket")
			defer f.Close()
			raw, e := f.SyscallConn()
			if e != nil {
				t.Fatal(e)
			}
			if e := directBindSocket(raw, tc.network, "198.51.100.1:443", *physical); e != nil {
				t.Fatal(e)
			}
			value, e := unix.GetsockoptInt(fd, tc.level, tc.option)
			if e != nil || value != physical.Index {
				t.Fatalf("kernel readback=%d expected=%d err=%v", value, physical.Index, e)
			}
			t.Logf("uid=%d family=%s physical=%s index=%d kernel_BOUND_IF=%d no_connect=true", os.Getuid(), tc.network, physical.Name, physical.Index, value)
			bad := *physical
			bad.Name = "utun0"
			if e := directBindSocket(raw, tc.network, "198.51.100.1:443", bad); !errors.Is(e, errNodeProbeDirectUnavailable) {
				t.Fatal("tunnel admitted")
			}
			bad = *physical
			bad.Index = 2147483647
			if e := directBindSocket(raw, tc.network, "198.51.100.1:443", bad); !errors.Is(e, errNodeProbeDirectUnavailable) {
				t.Fatal("bad binding did not fail closed")
			}
		})
	}
}

func TestDirectDarwinControlFailureNeverConnects(t *testing.T) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	calls := 0
	d := net.Dialer{ControlContext: func(_ context.Context, network, address string, raw syscall.RawConn) error {
		calls++
		// Invoke the product binding path with an impossible interface index,
		// not a fabricated transport failure. The kernel rejects setsockopt.
		bad := net.Interface{Name: "en0", Index: 2147483647, Flags: net.FlagUp | net.FlagBroadcast, HardwareAddr: net.HardwareAddr{0, 1, 2, 3, 4, 5}}
		return directBindSocket(raw, network, "198.51.100.1:443", bad)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if c, e := d.DialContext(ctx, "tcp4", l.Addr().String()); !errors.Is(e, errNodeProbeDirectUnavailable) {
		if c != nil {
			c.Close()
		}
		t.Fatal("control failure ignored", e)
	}
	if calls != 1 {
		t.Fatal("unexpected control count", calls)
	}
	l.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Millisecond))
	if c, e := l.Accept(); e == nil {
		c.Close()
		t.Fatal("connection after control failure")
	}
}
