package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestLocalStartPreservesWarmAndRuleIPv6Exclusions(t *testing.T) {
	d, b, c, k, _, _ := lifecycleFixture(t)
	ca, _ := runtimeCertificate(t)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, ca, 0600); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`proxies:
 - {name: primary, type: anytls, server: 203.0.113.1, port: 443, password: fixture, sni: example.com, ca: CAPATH}
 - {name: warm, type: anytls, server: '2001:db8::2', port: 443, password: fixture, sni: example.com, ca: CAPATH}
 - {name: dedicated, type: anytls, server: '2001:db8::3', port: 443, password: fixture, sni: example.com, ca: CAPATH}
proxy-groups:
 - {name: Default, type: select, proxies: [primary, warm], selected: primary}
rules: ["DOMAIN,example.org,dedicated", "MATCH,Default"]
`)
	raw = []byte(strings.ReplaceAll(string(raw), "CAPATH", caPath))
	if err := os.WriteFile(c, raw, 0600); err != nil {
		t.Fatal(err)
	}
	route := d.route
	d.route = func(ip string) (string, error) {
		if ip != "1.1.1.1" {
			t.Fatal("node route inspected")
		}
		return route(ip)
	}
	if err := d.start(b, c, k, false); err != nil {
		t.Fatal(err)
	}
	captured, err := captureServiceConfig(filepath.Join(d.root, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := captured.compile(false)
	if err != nil {
		t.Fatal(err)
	}
	// Non-root CI cannot opt into root-owned liveSnapshotEnabled. Exercise the
	// same warm producer explicitly on actual captured private staged bytes.
	nodes, err := loadNodesBytes(captured.config)
	if err != nil {
		t.Fatal(err)
	}
	addWarmCandidates(captured.config, nodes, nodes[0], cfg, false, nil)
	if cfg["route"].(map[string]any)["auto_detect_interface"] != true {
		t.Fatal("automatic interface policy removed")
	}
	excluded := cfg["inbounds"].([]any)[0].(map[string]any)["route_exclude_address"].([]string)
	for _, host := range []string{"203.0.113.1/32", "2001:db8::2/128", "2001:db8::3/128"} {
		if !slices.Contains(excluded, host) {
			t.Fatalf("missing actual staged exclusion %s: %v", host, excluded)
		}
	}
	var servers []string
	for _, entry := range cfg["outbounds"].([]any) {
		out := entry.(map[string]any)
		if out["type"] == "anytls" {
			servers = append(servers, out["server"].(string))
		}
	}
	for _, ip := range []string{"203.0.113.1", "2001:db8::2", "2001:db8::3"} {
		if !slices.Contains(servers, ip) {
			t.Fatalf("compiled node removed %s: %v", ip, servers)
		}
	}
	after, err := os.ReadFile(c)
	if err != nil || !bytes.Equal(after, raw) {
		t.Fatal("source nodes/config changed")
	}
	selected, err := os.ReadFile(selectedPath(c))
	if err != nil || string(selected) != "primary" {
		t.Fatal("selection changed")
	}
	encoded, err := json.Marshal(cfg)
	if err != nil || !bytes.Contains(encoded, []byte("2001:db8::2/128")) {
		t.Fatal("encoded staged guards missing", err)
	}
	if err = d.stop(); err != nil {
		t.Fatal(err)
	}
}
