package main

import (
	"encoding/json"
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

// Assert the complete, fixed TUN capture prefix before inspecting ordered
// business slots. Do not filter synthetics: resolve placement remains observable.
func tunBusinessRules(t *testing.T, cfg map[string]any) []any {
	t.Helper()
	rules, ok := cfg["route"].(map[string]any)["rules"].([]any)
	if !ok || len(rules) < 3 {
		t.Fatalf("missing TUN DNS capture prefix: %#v", cfg["route"])
	}
	prefix, err := json.Marshal(rules[:3])
	if err != nil {
		t.Fatal(err)
	}
	const want = `[{"action":"hijack-dns","port":53},{"action":"sniff"},{"action":"hijack-dns","protocol":["dns"]}]`
	if string(prefix) != want {
		t.Fatalf("TUN DNS capture prefix: %s != %s", prefix, want)
	}
	return rules[3:]
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
	rr := tunBusinessRules(t, cfg)
	if len(rr) != 4 {
		t.Fatalf("expected DNS prefix plus 4 business rules, got %#v", routes)
	}
	if rr[0].(map[string]any)["domain"].([]string)[0] != "www.example.org" || rr[0].(map[string]any)["outbound"] != "node-1" {
		t.Fatalf("ordered rule lost: %v", rr[0])
	}
	if rr[1].(map[string]any)["domain_suffix"].([]string)[0] != "example.org" || rr[1].(map[string]any)["outbound"] != "direct" || rr[2].(map[string]any)["ip_cidr"].([]string)[0] != "10.0.0.0/8" || rr[2].(map[string]any)["outbound"] != "direct" {
		t.Fatalf("direct or CIDR lost: %v", rr)
	}
	if rr[3].(map[string]any)["domain"].([]string)[0] != "ads.example.org" || rr[3].(map[string]any)["action"] != "reject" {
		t.Fatalf("reject lost: %v", rr[3])
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
	cfg := map[string]any{
		"inbounds":  []any{map[string]any{"type": "mixed"}},
		"outbounds": []any{},
		"route":     map[string]any{"final": "anytls-out"},
	}
	if err := applyRouting(p, nil, node{}, cfg, true); err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg["route"].(map[string]any)["rules"]; ok {
		t.Fatal("changed ruleless config")
	}
	if cfg["route"].(map[string]any)["final"] != "anytls-out" {
		t.Fatal("changed ruleless final outbound")
	}
	if _, ok := cfg["dns"]; ok {
		t.Fatal("added DNS to ruleless mixed config")
	}
}
