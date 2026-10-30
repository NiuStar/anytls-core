package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveGroupChoicePreservesRoutingAndRejectsSS(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	data := []byte("proxies:\n - {name: a, type: anytls, server: 203.0.113.1, port: 443, password: test}\n - {name: b, type: ss}\nproxy-groups:\n - {name: hk, type: select, proxies: [DIRECT, a, b], selected: a}\nrules: [MATCH,hk]\n")
	if err := os.WriteFile(p, data, 0644); err != nil {
		t.Fatal(err)
	}
	if err := saveGroupChoice(p, "hk", "b"); err == nil {
		t.Fatal("SS accepted")
	}
	if err := saveGroupChoice(p, "hk", "DIRECT"); err != nil {
		t.Fatal(err)
	}
	groups, err := groupChoices(p)
	if err != nil || groups[0].Selected != "DIRECT" {
		t.Fatalf("save: %v %v", groups, err)
	}
	var d struct {
		Rules []string `yaml:"rules"`
		Nodes []node   `yaml:"proxies"`
	}
	if err := readYAML(p, &d); err != nil {
		t.Fatal(err)
	}
	if len(d.Nodes) != 2 || d.Nodes[0].Password != "test" || len(d.Rules) != 2 {
		t.Fatalf("configuration altered: %#v", d)
	}
}

func TestSelectGroupsResolveExplicitSelection(t *testing.T) {
	nodes := []node{{Name: "a", Type: "anytls"}, {Name: "b", Type: "ss"}}
	groups := []proxyGroup{{Name: "节点选择", Type: "select", Proxies: []string{"DIRECT", "a", "b"}, Selected: "a"}, {Name: "openai", Type: "select", Proxies: []string{"DIRECT", "a"}, Selected: "DIRECT"}}
	for name, want := range map[string]string{"节点选择": "a", "openai": "DIRECT", "a": "a", "REJECT": "REJECT"} {
		got, err := resolveGroup(name, nodes, groups)
		if err != nil || got != want {
			t.Fatalf("%s -> %s, %v", name, got, err)
		}
	}
	groups[0].Selected = "not-listed"
	if _, err := resolveGroup("节点选择", nodes, groups); err == nil {
		t.Fatal("unlisted selection accepted")
	}
	groups[0].Selected = ""
	if _, err := resolveGroup("节点选择", nodes, groups); err == nil {
		t.Fatal("implicit first group member accepted")
	}
	groups[0].Selected = "b"
	if _, err := resolveGroup("节点选择", nodes, groups); err == nil {
		t.Fatal("unsupported selected protocol accepted")
	}
}

func TestFileRuleSetSHAAndOrderedReference(t *testing.T) {
	p := routingFixture(t, " - RULE-SET,private_ip,DIRECT,no-resolve\n - MATCH,main\n")
	// Missing provider MUST fail, never become an empty rule silently.
	nodes, _ := loadNodes(p)
	cfg, _ := buildNode(nodes[0], "tun", 0, true)
	if err := applyRouting(p, nodes, nodes[0], cfg, true); err == nil {
		t.Fatal("missing rule set accepted")
	}
	dir := filepath.Dir(p)
	b := []byte(`{"version":3,"rules":[{"ip_cidr":["192.168.0.0/16"]}]}`)
	if err := os.WriteFile(filepath.Join(dir, "private.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("rule-sets:\n  private_ip:\n    path: private.json\n    sha256: " + shaHex(b) + "\n")
	f.Close()
	cfg, _ = buildNode(nodes[0], "tun", 0, true)
	if err := applyRouting(p, nodes, nodes[0], cfg, true); err != nil {
		t.Fatal(err)
	}
	route := cfg["route"].(map[string]any)
	if len(route["rule_set"].([]any)) != 1 {
		t.Fatal(route)
	}
	rules := tunBusinessRules(t, cfg)
	if len(rules) != 1 {
		t.Fatalf("expected only the no-resolve rule after DNS capture: %#v", rules)
	}
	rule := rules[0].(map[string]any)
	if rule["rule_set"].([]string)[0] != "private_ip" || rule["outbound"] != "direct" || rule["action"] != "route" || route["final"] != "anytls-out" {
		t.Fatal(rule)
	}
	if err := os.WriteFile(filepath.Join(dir, "private.json"), []byte(`{"version":3,"rules":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, _ = buildNode(nodes[0], "tun", 0, true)
	if err := applyRouting(p, nodes, nodes[0], cfg, true); err == nil {
		t.Fatal("modified provider accepted")
	}
}
