package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSelectConfigNodeAndProxy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := "proxies:\n  - name: a\n    type: anytls\n    server: 203.0.113.7\n    port: 8443\n    password: testonly\n    udp: true\n    client-fingerprint: chrome\n    idle-session-check-interval: 30\n    idle-session-timeout: 30\n    min-idle-session: 0\n    skip-cert-verify: true\n    egress-ip: 203.0.113.8\n  - name: b\n    type: ss\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	nodes, err := loadNodes(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("got %d", len(nodes))
	}
	n, err := choose(nodes, "a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := choose(nodes, "b"); err == nil {
		t.Fatal("non-AnyTLS accepted")
	}
	if _, err := choose(nodes, "missing"); err == nil {
		t.Fatal("missing node accepted")
	}
	if _, err := buildNode(n, "proxy", 11080, false); err == nil {
		t.Fatal("silent insecure TLS")
	}
	cfg, err := buildNode(n, "proxy", 11080, true)
	if err != nil {
		t.Fatal(err)
	}
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	if in["type"] != "mixed" || in["listen"] != "127.0.0.1" {
		t.Fatalf("inbound: %v", in)
	}
	out := cfg["outbounds"].([]any)[0].(map[string]any)
	if out["server_port"] != 8443 || out["idle_session_timeout"] != "30s" {
		t.Fatalf("out: %v", out)
	}
	tls := out["tls"].(map[string]any)
	if tls["insecure"] != true || tls["utls"].(map[string]any)["fingerprint"] != "chrome" {
		t.Fatalf("tls: %v", tls)
	}
	if _, ok := out["egress-ip"]; ok {
		t.Fatal("unsupported egress field leaked into protocol")
	}
}

func TestConfigPermissionsAndDuplicateNames(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("proxies:\n - {name: x, type: anytls}\n - {name: x, type: anytls}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadNodes(p); err == nil {
		t.Fatal("duplicate names accepted")
	}
}

func TestRefuseUnsafeNodeAndTunMode(t *testing.T) {
	n := node{Name: "x", Type: "anytls", Server: "example.com", Port: 443, Password: "test", SkipVerify: true}
	if _, err := buildNode(n, "tun", 0, true); err == nil {
		t.Fatal("domain dial accepted")
	}
	n.Server = "203.0.113.7"
	n.SkipVerify = false
	if _, err := buildNode(n, "tun", 0, false); err == nil {
		t.Fatal("missing trust rejected")
	}
	n.CA = "/missing"
	if _, err := buildNode(n, "tun", 0, false); err == nil {
		t.Fatal("missing CA accepted")
	}
	n.CA = ""
	n.SkipVerify = true
	if _, err := buildNode(n, "proxy", 11080, true); err != nil {
		t.Fatalf("domain should work in proxy mode: %v", err)
	}
}

func TestTunExcludesAnyTLSServerRoute(t *testing.T) {
	n := node{Name: "vpn", Type: "anytls", Server: "23.141.52.113", Port: 10087, Password: "test", SkipVerify: true}
	cfg, err := buildNode(n, "tun", 0, true)
	if err != nil {
		t.Fatal(err)
	}
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	excludes, ok := in["route_exclude_address"].([]string)
	if !ok || len(excludes) != 1 || excludes[0] != "23.141.52.113/32" {
		t.Fatalf("server route not excluded: %v", in)
	}
	n.Server = "2400:c620:2b:74::a"
	cfg, err = buildNode(n, "tun", 0, true)
	if err != nil {
		t.Fatal(err)
	}
	in = cfg["inbounds"].([]any)[0].(map[string]any)
	excludes = in["route_exclude_address"].([]string)
	if len(excludes) != 1 || excludes[0] != "2400:c620:2b:74::a/128" {
		t.Fatalf("IPv6 server route not excluded: %v", in)
	}
}

func TestRejectDisabledUDP(t *testing.T) {
	no := false
	n := node{Name: "x", Type: "anytls", Server: "203.0.113.7", Port: 443, Password: "test", SkipVerify: true, UDP: &no}
	if _, err := buildNode(n, "proxy", 11080, true); err == nil {
		t.Fatal("udp: false silently ignored")
	}
}
