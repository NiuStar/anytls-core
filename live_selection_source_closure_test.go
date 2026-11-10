package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLiveHelperStagedSourceClosure(t *testing.T) {
	for _, mode := range []string{"unchanged", "staged_rule_rehashed", "different_original", "cn_builtin"} {
		t.Run(mode, func(t *testing.T) {
			f := newLiveEntryFixture(t)
			config := f.s.registration.Config
			root := filepath.Join(filepath.Dir(config), "service")
			b, e := os.ReadFile(config)
			if e != nil {
				t.Fatal(e)
			}
			rules := []byte(`{"version":3,"rules":[{"domain_suffix":["example.test"]}]}`)
			if mode == "cn_builtin" {
				b = []byte(strings.Replace(string(b), "rules: [", "rules: ['GEOIP,CN,DIRECT', ", 1))
			} else {
				b = []byte(strings.Replace(string(b), "rules:", "rule-sets:\n  audited: {path: audited.json, sha256: "+shaHex(rules)+"}\nrules:", 1))
				b = []byte(strings.Replace(string(b), "rules: [", "rules: ['RULE-SET,audited,DIRECT', ", 1))
				if e = os.WriteFile(filepath.Join(filepath.Dir(config), "audited.json"), rules, 0600); e != nil {
					t.Fatal(e)
				}
			}
			for _, p := range []string{config, filepath.Join(root, "config.yaml")} {
				if e = os.WriteFile(p, b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if e = os.WriteFile(selectedPath(filepath.Join(root, "config.yaml")), []byte("b\n"), 0600); e != nil {
				t.Fatal(e)
			}
			if e = os.Remove(filepath.Join(root, liveSourceName)); e != nil {
				t.Fatal(e)
			}
			if mode == "different_original" {
				if e = os.WriteFile(config, append(b, []byte("\n# concurrent edit\n")...), 0600); e != nil {
					t.Fatal(e)
				}
				if e = stageLiveSource(config, root); e == nil {
					t.Fatal("captured unrelated source instead of staged bytes")
				}
				return
			}
			if e = stageLiveSource(config, root); e != nil {
				t.Fatal(e)
			}
			if e = stageRuleSets(config, root); e != nil {
				t.Fatal(e)
			}
			if e = stageCAs(root); e != nil {
				t.Fatal(e)
			}
			if mode == "staged_rule_rehashed" {
				poison := []byte(`{"version":3,"rules":[{"domain_suffix":["poison.test"]}]}`)
				if e = os.WriteFile(filepath.Join(root, "rules/audited.json"), poison, 0600); e != nil {
					t.Fatal(e)
				}
				p := filepath.Join(root, "config.yaml")
				next, e := os.ReadFile(p)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(p, []byte(strings.ReplaceAll(string(next), shaHex(rules), shaHex(poison))), 0600); e != nil {
					t.Fatal(e)
				}
				if e = finalizeLiveSource(root); e == nil {
					t.Fatal("accepted newly self-reported staged digest")
				}
				return
			}
			if e = finalizeLiveSource(root); e != nil {
				t.Fatal(e)
			}
			raw, e := os.ReadFile(filepath.Join(root, liveSourceName))
			if e != nil {
				t.Fatal(e)
			}
			var source map[string]json.RawMessage
			if e = json.Unmarshal(raw, &source); e != nil {
				t.Fatal(e)
			}
			if mode == "cn_builtin" && string(source["rules"]) != "{}" {
				t.Fatal("builtin CN falsely depends on a local file")
			}
			if r := f.call("select"); !r.OK || f.switches.Load() != 1 {
				t.Fatalf("staged positive %+v switches=%d", r, f.switches.Load())
			}
		})
	}
}
