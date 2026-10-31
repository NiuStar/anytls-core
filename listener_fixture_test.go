//go:build embedded_core && with_utls

package main

import (
	"errors"
	"net"
	"syscall"
	"testing"
)

func TestUnifiedDNSListenPair(t *testing.T) {
	t.Run("occupied_udp_selects_another_pair", func(t *testing.T) {
		var foreign *net.UDPConn
		var first string
		calls := 0
		listen := func(network, addr string) (net.Listener, error) {
			if calls > 0 {
				unifiedDNSRebind(t, "tcp", first)
			}
			calls++
			l, err := net.Listen(network, addr)
			if err == nil && calls == 1 {
				first = l.Addr().String()
				a, e := net.ResolveUDPAddr("udp", first)
				if e != nil {
					l.Close()
					t.Fatal(e)
				}
				foreign, e = net.ListenUDP("udp", a)
				if e != nil {
					l.Close()
					t.Fatal(e)
				}
				t.Cleanup(func() { foreign.Close(); unifiedDNSRebind(t, "udp", first) })
			}
			return l, err
		}
		tcp, udp, err := unifiedDNSListenPair(0, listen, net.ListenUDP)
		if err != nil {
			t.Fatalf("mandatory pair must survive occupied UDP: %v", err)
		}
		addr := tcp.Addr().String()
		t.Cleanup(func() { udp.Close(); tcp.Close(); unifiedDNSRebind(t, "tcp", addr); unifiedDNSRebind(t, "udp", addr) })
		if calls != 2 || addr == first || udp.LocalAddr().String() != addr {
			t.Fatalf("pair selection calls=%d first=%s pair=%s/%s", calls, first, addr, udp.LocalAddr())
		}
		a, err := net.ResolveUDPAddr("udp", first)
		if err != nil {
			t.Fatal(err)
		}
		c, err := net.ListenUDP("udp", a)
		if c != nil {
			c.Close()
		}
		if !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatalf("foreign owner must remain held: %v", err)
		}
		t.Logf("PAIRED_RESERVATION foreign_udp=%s selected_tcp=%s selected_udp=%s attempts=%d", first, addr, udp.LocalAddr(), calls)
	})
	for _, tc := range []struct {
		name  string
		port  int
		cause error
		want  int
	}{
		{"explicit_port_never_retries", 53, syscall.EADDRINUSE, 1},
		{"other_error_never_retries", 0, syscall.EACCES, 1},
		{"bounded_exhaustion", 0, syscall.EADDRINUSE, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var addresses []string
			calls := 0
			listen := func(network, addr string) (net.Listener, error) {
				// Use real test-owned high ports even for the explicit-port policy control.
				calls++
				l, err := net.Listen(network, "127.0.0.1:0")
				if err == nil {
					addresses = append(addresses, l.Addr().String())
				}
				return l, err
			}
			failUDP := func(network string, addr *net.UDPAddr) (*net.UDPConn, error) {
				return nil, &net.OpError{Op: "listen", Net: network, Addr: addr, Err: tc.cause}
			}
			tcp, udp, err := unifiedDNSListenPair(tc.port, listen, failUDP)
			if tcp != nil {
				tcp.Close()
			}
			if udp != nil {
				udp.Close()
			}
			if !errors.Is(err, tc.cause) || calls != tc.want || tcp != nil || udp != nil {
				t.Fatalf("calls=%d want=%d tcp=%v udp=%v error=%v", calls, tc.want, tcp, udp, err)
			}
			for _, addr := range addresses {
				unifiedDNSRebind(t, "tcp", addr)
			}
		})
	}
	t.Run("tcp_error_never_retries", func(t *testing.T) {
		calls := 0
		listen := func(string, string) (net.Listener, error) { calls++; return nil, syscall.EADDRINUSE }
		tcp, udp, err := unifiedDNSListenPair(0, listen, net.ListenUDP)
		if tcp != nil || udp != nil || !errors.Is(err, syscall.EADDRINUSE) || calls != 1 {
			t.Fatalf("TCP allocation failure: calls=%d error=%v", calls, err)
		}
	})
}
