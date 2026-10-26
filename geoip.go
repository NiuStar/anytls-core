package main

import (
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Pinned complete upstream China lists, not a runtime geolocation service.
// See assets/geoip/SOURCE.json and the MIT attribution in THIRD_PARTY_NOTICES.md.
//
//go:embed assets/geoip/china.txt
var geoIPCN4 string

//go:embed assets/geoip/china6.txt
var geoIPCN6 string

func geoIPCNCIDRs() ([]string, error) {
	out := make([]string, 0, 10014)
	for _, src := range []struct {
		data, sha string
		count     int
	}{{geoIPCN4, "cd9c414cb1c6d3818cf4434e12d3e32c95aaac57afd0b4faac44ee46cb5bb33f", 6525}, {geoIPCN6, "a2f14c3d600dc7612638c51fd741d3d4cf4f115519436e05d4558d49e50664c9", 3489}} {
		if len(src.data) > 32<<20 || fmt.Sprintf("%x", sha256.Sum256([]byte(src.data))) != src.sha {
			return nil, errors.New("embedded GEOIP CN integrity failure")
		}
		lines := strings.Split(strings.TrimSuffix(src.data, "\n"), "\n")
		if len(lines) != src.count {
			return nil, errors.New("embedded GEOIP CN count failure")
		}
		for _, s := range lines {
			p, e := netip.ParsePrefix(s)
			if e != nil || p.Masked().String() != s {
				return nil, errors.New("embedded GEOIP CN prefix failure")
			}
		}
		out = append(out, lines...)
	}
	return out, nil
}

func supportedGeoIPRule(p []string) bool {
	return (len(p) == 3 || len(p) == 4 && p[3] == "no-resolve") && p[0] == "GEOIP" && p[1] == "CN"
}
