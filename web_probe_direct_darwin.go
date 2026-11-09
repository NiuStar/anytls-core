//go:build darwin

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sagernet/sing/common/control"
	"golang.org/x/sys/unix"
)

type directMetadataBuffer struct{ bytes.Buffer }

func (b *directMetadataBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 16384 {
		return 0, errors.New("direct metadata exceeds limit")
	}
	return b.Buffer.Write(p)
}

// Only fixed read-only OS metadata commands, bounded in time and output. Never
// query or modify DNS, routes, VPN lifecycle or privileged helper state.
func directMetadata(ctx context.Context, name, input string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	var out directMetadataBuffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return "", errNodeProbeDirectUnavailable
	}
	return out.String(), nil
}

func directDiscoverInterface(ctx context.Context, ip netip.Addr) (net.Interface, error) {
	family := "-inet"
	if ip.Is6() {
		family = "-inet6"
	}
	state := "IPv4"
	if ip.Is6() {
		state = "IPv6"
	}
	metadata, err := directMetadata(ctx, "/usr/sbin/scutil", "show State:/Network/Global/"+state+"\nquit\n")
	if err != nil {
		return net.Interface{}, err
	}
	primary := directMetadataField(metadata, "PrimaryInterface")
	interfaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, errNodeProbeDirectUnavailable
	}
	var eligible []net.Interface
	for _, i := range interfaces {
		if !directPhysicalInterface(i) {
			continue
		}
		addrs, e := i.Addrs()
		if e != nil {
			continue
		}
		hasSource := false
		for _, a := range addrs {
			p, e := netip.ParsePrefix(a.String())
			if e != nil {
				continue
			}
			src := p.Addr().Unmap()
			if src.Is4() == ip.Is4() && src.IsGlobalUnicast() && !src.IsLoopback() && !src.IsLinkLocalUnicast() {
				hasSource = true
			}
		}
		if !hasSource {
			continue
		}
		// Require both a scoped default and a scoped destination on the physical
		// interface. A plain default route may be utun and is never authoritative.
		def, e := directMetadata(ctx, "/sbin/route", "", "-n", "get", family, "-ifscope", i.Name, "default")
		if e != nil || !directScopedRoute(def, i.Name) {
			continue
		}
		dst, e := directMetadata(ctx, "/sbin/route", "", "-n", "get", family, "-ifscope", i.Name, ip.String())
		if e != nil || !directScopedRoute(dst, i.Name) {
			continue
		}
		eligible = append(eligible, i)
	}
	return directSelectInterface(primary, eligible)
}

// BindToInterface uses Darwin IP_BOUND_IF/IPV6_BOUND_IF. Read back the actual
// kernel socket value before connect; a source LocalAddr alone is insufficient.
func directBindSocket(raw syscall.RawConn, network, address string, i net.Interface) error {
	if !directPhysicalInterface(i) || (network != "tcp4" && network != "tcp6") {
		return errNodeProbeDirectUnavailable
	}
	if err := control.BindToInterface(nil, i.Name, i.Index)(network, address, raw); err != nil {
		return errNodeProbeDirectUnavailable
	}
	var checkErr error
	err := raw.Control(func(fd uintptr) {
		level, option := unix.IPPROTO_IP, unix.IP_BOUND_IF
		if network == "tcp6" {
			level, option = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
		}
		value, e := unix.GetsockoptInt(int(fd), level, option)
		if e != nil || value != i.Index {
			checkErr = errNodeProbeDirectUnavailable
		}
	})
	if err != nil || checkErr != nil {
		return errNodeProbeDirectUnavailable
	}
	return nil
}

func webDirectNodeProbe(ctx context.Context, n node) (float64, error) {
	ip, err := directProbeIP(n.Server)
	if err != nil {
		return 0, err
	}
	i, err := directDiscoverInterface(ctx, ip)
	if err != nil {
		return 0, err
	}
	network := "tcp4"
	if ip.Is6() {
		network = "tcp6"
	}
	dialer := net.Dialer{FallbackDelay: -1, ControlContext: func(ctx context.Context, network, address string, raw syscall.RawConn) error {
		current, e := net.InterfaceByName(i.Name)
		if e != nil || current.Index != i.Index || !directPhysicalInterface(*current) {
			return errNodeProbeDirectUnavailable
		}
		return directBindSocket(raw, network, address, *current)
	}}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), strconv.Itoa(n.Port)))
	if err != nil {
		if errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH) || errors.Is(err, unix.ENXIO) || errors.Is(err, unix.ENETDOWN) || errors.Is(err, unix.EADDRNOTAVAIL) {
			return 0, errNodeProbeDirectUnavailable
		}
		return 0, err
	}
	elapsed := float64(time.Since(start)) / float64(time.Millisecond)
	if err := conn.Close(); err != nil {
		return 0, errors.New("node probe close failed")
	}
	return elapsed, ctx.Err()
}
