package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveOccursOnlyAtNonNoResolveIPRule(t *testing.T) {
	p := routingFixture(t, " - RULE-SET,private,DIRECT,no-resolve\n - RULE-SET,proxy,main\n - RULE-SET,telegram,main\n - MATCH,main\n")
	dir := filepath.Dir(p)
	ip := []byte(`{"version":3,"rules":[{"ip_cidr":["91.108.4.0/22"]}]}`)
	domain := []byte(`{"version":3,"rules":[{"domain_suffix":["example.org"]}]}`)
	os.WriteFile(filepath.Join(dir, "ip.json"), ip, 0600)
	os.WriteFile(filepath.Join(dir, "domain.json"), domain, 0600)
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString("rule-sets:\n  private: {path: ip.json, sha256: " + shaHex(ip) + ", resolve-ip: true}\n  proxy: {path: domain.json, sha256: " + shaHex(domain) + "}\n  telegram: {path: ip.json, sha256: " + shaHex(ip) + ", resolve-ip: true}\n")
	f.Close()
	nodes, _ := loadNodes(p)
	cfg, _ := buildNode(nodes[0], "tun", 0, true)
	if err := applyRouting(p, nodes, nodes[0], cfg, true); err != nil {
		t.Fatal(err)
	}
	rules := cfg["route"].(map[string]any)["rules"].([]any)
	lastSet := ""
	resolved := false
	for _, v := range rules {
		r := v.(map[string]any)
		if r["action"] == "resolve" {
			if lastSet != "proxy" {
				t.Fatalf("DNS resolution too early: %v", rules)
			}
			resolved = true
		}
		if set, ok := r["rule_set"]; ok {
			lastSet = set.([]string)[0]
			if lastSet == "telegram" && !resolved {
				t.Fatal("missing before-match resolve")
			}
		}
	}
	if !resolved {
		t.Fatal("missing resolve action")
	}
}

func TestStageRuleSetsSurviveOriginalFileRemoval(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "config.yaml")
	dest := filepath.Join(root, "service")
	os.Mkdir(dest, 0700)
	b := []byte(`{"version":3,"rules":[{"domain_suffix":["example.org"]}]}`)
	source := filepath.Join(root, "source.json")
	os.WriteFile(source, b, 0600)
	data := []byte("proxies: []\nrule-sets:\n  domains: {path: source.json, sha256: " + shaHex(b) + "}\n")
	os.WriteFile(config, data, 0644)
	os.WriteFile(filepath.Join(dest, "config.yaml"), data, 0600)
	if err := stageRuleSets(config, dest); err != nil {
		t.Fatal(err)
	}
	os.Remove(source)
	var doc struct {
		Sets map[string]fileRuleSet `yaml:"rule-sets"`
	}
	if err := readYAML(filepath.Join(dest, "config.yaml"), &doc); err != nil {
		t.Fatal(err)
	}
	set, err := loadRuleSet(filepath.Join(dest, "config.yaml"), "domains", doc.Sets["domains"])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(set); err != nil {
		t.Fatal(err)
	}
}
