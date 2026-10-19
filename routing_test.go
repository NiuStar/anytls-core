package main

import (
	"os"
	"path/filepath"
	"testing"
)

func routingFixture(t *testing.T, rules string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	data := "proxies:\n - {name: main, type: anytls, server: 203.0.113.10, port: 443, password: test, skip-cert-verify: true}\n - {name: backup, type: anytls, server: 203.0.113.11, port: 443, password: test, skip-cert-verify: true}\nrules:\n" + rules
	if err := os.WriteFile(p, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestClashRoutingOrderedAndServerBypass(t *testing.T) {
	p := routingFixture(t, " - DOMAIN,www.example.org,backup\n - DOMAIN-SUFFIX,example.org,DIRECT\n - IP-CIDR,10.0.0.0/8,DIRECT\n - DOMAIN,ads.example.org,REJECT\n - MATCH,main\n")
	nodes, err := loadNodes(p)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := buildNode(nodes[0], "tun", 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyRouting(p, nodes, nodes[0], cfg, true); err != nil {
		t.Fatal(err)
	}
	routes := cfg["route"].(map[string]any)
	rr := routes["rules"].([]any)
	if len(rr) != 5 {
		t.Fatalf("expected sniff plus 4 rules, got %#v", rr)
	}
	if rr[0].(map[string]any)["action"] != "sniff" {
		t.Fatalf("sniff must be first: %v", rr)
	}
	if rr[1].(map[string]any)["domain"].([]string)[0] != "www.example.org" || rr[1].(map[string]any)["outbound"] != "node-1" {
		t.Fatalf("ordered rule lost: %v", rr[1])
	}
	if rr[2].(map[string]any)["outbound"] != "direct" || rr[3].(map[string]any)["ip_cidr"].([]string)[0] != "10.0.0.0/8" {
		t.Fatalf("direct or CIDR lost: %v", rr)
	}
	if rr[4].(map[string]any)["action"] != "reject" {
		t.Fatalf("reject lost: %v", rr[4])
	}
	if routes["final"] != "anytls-out" {
		t.Fatalf("MATCH default lost: %v", routes)
	}
	out := cfg["outbounds"].([]any)
	if len(out) != 3 {
		t.Fatalf("expected 2 anytls and direct: %v", out)
	}
	excludes := cfg["inbounds"].([]any)[0].(map[string]any)["route_exclude_address"].([]string)
	if len(excludes) != 2 || excludes[0] != "203.0.113.10/32" || excludes[1] != "203.0.113.11/32" {
		t.Fatalf("bypass: %v", excludes)
	}
}
func TestRoutingRejectsUnknownOrUnsafeRules(t *testing.T) {
	for _, rule := range []string{" - GEOIP,CN,DIRECT\n", " - DOMAIN,example.org,missing\n", " - DOMAIN,example.org,DIRECT\n - MATCH,main\n - DOMAIN,late.org,DIRECT\n", " - IP-CIDR,not-a-cidr,DIRECT\n", " - MATCH,main\n - MATCH,backup\n", " - IP-CIDR,192.168.0.0/16,DIRECT\n"} {
		p := routingFixture(t, rule)
		nodes, _ := loadNodes(p)
		cfg, _ := buildNode(nodes[0], "tun", 0, true)
		if err := applyRouting(p, nodes, nodes[0], cfg, true); err == nil {
			t.Fatalf("accepted unsafe rule %q", rule)
		}
	}
}
func TestRoutingNoRulesKeepsExistingBehavior(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("proxies: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := map[string]any{"route": map[string]any{"final": "anytls-out"}}
	if err := applyRouting(p, nil, node{}, cfg, true); err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg["route"].(map[string]any)["rules"]; ok {
		t.Fatal("changed ruleless config")
	}
}
