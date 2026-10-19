package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildSecureConfig(t *testing.T) {
	cert := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(cert, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := build(options{Server: "203.0.113.9:443", SNI: "vpn.example.com", Password: "secret", CA: cert})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	ins := v["inbounds"].([]any)[0].(map[string]any)
	if ins["type"] != "tun" || ins["auto_route"] != true || ins["dns_mode"] != "hijack" {
		t.Fatalf("bad tun: %s", b)
	}
	out := v["outbounds"].([]any)[0].(map[string]any)
	tls := out["tls"].(map[string]any)
	if tls["insecure"] != nil || tls["certificate_path"] != cert {
		t.Fatalf("bad tls: %s", b)
	}
	if v["route"].(map[string]any)["auto_detect_interface"] != true {
		t.Fatalf("route loop risk: %s", b)
	}
	if strings.Contains(string(b), "secret") == false {
		t.Fatal("password missing")
	}
}

func TestRejectUnsafeInput(t *testing.T) {
	cases := []options{
		{Server: "vpn.example.com:443", Password: "x"},
		{Server: "203.0.113.1:443", Password: "x"},
		{Server: "203.0.113.1:443", SNI: "vpn.example.com"},
		{Server: "203.0.113.1:443", SNI: "vpn.example.com", Password: "x", CA: "/nonexistent"},
		{Server: "example.com:443", SNI: "vpn.example.com", Password: "x", CA: "/nonexistent"},
	}
	for _, tc := range cases {
		if _, err := build(tc); err == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
}

func TestRejectNonRegularCA(t *testing.T) {
	_, err := build(options{Server: "203.0.113.1:443", SNI: "vpn.example.com", Password: "x", CA: t.TempDir()})
	if err == nil {
		t.Fatal("directory accepted as CA")
	}
}

func TestEndpointParsing(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:443", "[::1]:8443"} {
		host, port, err := splitEndpoint(addr)
		if err != nil || net.ParseIP(host) == nil || port < 1 {
			t.Fatalf("%s: %v", addr, err)
		}
	}
	for _, addr := range []string{"example.org:443", "127.0.0.1:0", "::1:443", "127.0.0.1:99999", "127.0.0.1"} {
		if _, _, err := splitEndpoint(addr); err == nil {
			t.Fatalf("accepted %s", addr)
		}
	}
}
