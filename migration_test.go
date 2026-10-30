package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
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
	rules := tunBusinessRules(t, cfg)
	if len(rules) != 4 || rules[0].(map[string]any)["rule_set"].([]string)[0] != "private" || rules[1].(map[string]any)["rule_set"].([]string)[0] != "proxy" || rules[2].(map[string]any)["action"] != "resolve" || rules[3].(map[string]any)["rule_set"].([]string)[0] != "telegram" {
		t.Fatalf("expected private/no-resolve, proxy/domain, resolve, telegram/IP order: %#v", rules)
	}
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
	// Both real rule-set files keep their own capture identity. Shared IP
	// references are deduplicated as sources, not as user rule slots.
	for _, mode := range []string{"proxy", "tun"} {
		compiled, err := prepareRuntimeWithRecords(&runtimeOptions{Config: p, NodeName: "main", Mode: mode, LocalPort: 11080, AllowInsecure: true})
		if err != nil || compiled.Manifest == nil {
			t.Fatalf("%s records compile: %v", mode, err)
		}
		m := compiled.Manifest
		prefix := 2 // mixed: sniff + conditional protocol DNS capture
		if mode == "tun" {
			prefix = 3
		}
		if len(m.Rules) != prefix+4 || m.Rules[prefix+2].ActionType != "resolve" {
			t.Fatalf("%s resolve/SDK slot order: %#v", mode, m.Rules)
		}
		for i, slot := range []int{prefix, prefix + 1, prefix + 3} {
			r := m.Rules[slot].Route
			wantSHA := shaHex(ip)
			if i == 1 {
				wantSHA = shaHex(domain)
			}
			if r.Evidence != cr.ProvenanceVerified || r.SourceIndex == nil || *r.SourceIndex != i || r.SourceID == nil || *r.SourceID != m.Generation+":rule:"+fmt.Sprint(i) || r.RuleSet == nil || r.RuleSet.Label != []string{"private", "proxy", "telegram"}[i] || r.RuleSet.SHA256 != wantSHA {
				t.Fatalf("%s rule-set source identity at SDK slot %d: %#v", mode, slot, r)
			}
		}
		if len(m.CapturedSources) != 4 || m.CapturedSources[2].Kind != cr.SourceRuleSet || !m.CapturedSources[2].Present || m.CapturedSources[2].Ordinal != 0 || m.CapturedSources[2].SHA256 == nil || *m.CapturedSources[2].SHA256 != shaHex(ip) || m.CapturedSources[3].Kind != cr.SourceRuleSet || !m.CapturedSources[3].Present || m.CapturedSources[3].Ordinal != 1 || m.CapturedSources[3].SHA256 == nil || *m.CapturedSources[3].SHA256 != shaHex(domain) {
			t.Fatalf("%s ordered rule-set captures: %#v", mode, m.CapturedSources)
		}
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
