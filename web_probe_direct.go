package main

import (
	"errors"
	"net"
	"net/netip"
	"strings"
)

var errNodeProbeDirectUnavailable = errors.New("physical direct probe unavailable")

// Direct probes deliberately accept IP literals only: using the process resolver
// could send DNS through the running VPN. Never silently fall back to that path.
func directProbeIP(server string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(server)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, errNodeProbeDirectUnavailable
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return netip.Addr{}, errNodeProbeDirectUnavailable
	}
	return ip, nil
}

func directPhysicalInterface(i net.Interface) bool {
	if i.Index <= 0 || i.Flags&net.FlagUp == 0 || i.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 || len(i.HardwareAddr) != 6 || !strings.HasPrefix(i.Name, "en") || len(i.Name) < 3 {
		return false
	}
	for _, c := range i.Name[2:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// A physical SystemConfiguration primary wins. If VPN replaces that primary,
// only an unambiguous scoped physical route is admissible; enumeration order is
// never a routing policy and neither is an arbitrary non-utun interface.
func directSelectInterface(primary string, eligible []net.Interface) (net.Interface, error) {
	for _, i := range eligible {
		if directPhysicalInterface(i) && i.Name == primary {
			return i, nil
		}
	}
	if len(eligible) == 1 && directPhysicalInterface(eligible[0]) {
		return eligible[0], nil
	}
	return net.Interface{}, errNodeProbeDirectUnavailable
}

func directMetadataField(text, key string) string {
	value := ""
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == key {
			if value != "" {
				return ""
			}
			value = fields[len(fields)-1]
		}
	}
	return value
}

func directScopedRoute(text, name string) bool {
	if directMetadataField(text, "interface:") != name {
		return false
	}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "flags:" {
			flags := "," + strings.Trim(fields[1], "<>") + ","
			return strings.Contains(flags, ",UP,") && !strings.Contains(flags, ",REJECT,") && !strings.Contains(flags, ",BLACKHOLE,")
		}
	}
	return false
}
