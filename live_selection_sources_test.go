package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Real executeContext -> UDS, with mutable user sources and private staged rules.
func TestLiveHelperRuleSourceLease(t *testing.T) {
	for _, mode := range []string{"unchanged", "same_bytes_inode", "changed_contents", "rehash_config", "changed_path", "missing_pins", "schema_alias", "post_same_bytes_inode", "post_changed_contents", "post_rehash_config", "post_changed_path"} {
		t.Run(mode, func(t *testing.T) {
			f := newLiveEntryFixture(t)
			config := f.s.registration.Config
			root := filepath.Join(filepath.Dir(config), "service")
			raw := []byte(`{"version":3,"rules":[{"domain_suffix":["example.com"]}]}`)
			path := filepath.Join(filepath.Dir(config), "audited.json")
			if e := os.WriteFile(path, raw, 0600); e != nil {
				t.Fatal(e)
			}
			staged := filepath.Join(root, "config.yaml")
			base, e := os.ReadFile(config)
			if e != nil {
				t.Fatal(e)
			}
			base = []byte(strings.Replace(string(base), "rules:", "rule-sets:\n  audited: {path: audited.json, sha256: "+shaHex(raw)+"}\nrules:", 1))
			base = []byte(strings.Replace(string(base), "rules: [", "rules: ['RULE-SET,audited,DIRECT', ", 1))
			// Both pre-selection source and snapshot start at the same selected node.
			if e = os.WriteFile(config, base, 0600); e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(staged, base, 0600); e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(selectedPath(staged), []byte("b\n"), 0600); e != nil {
				t.Fatal(e)
			}
			if e = os.Remove(filepath.Join(root, liveSourceName)); e != nil {
				t.Fatal(e)
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
			if e = finalizeLiveSource(root); e != nil {
				t.Fatal(e)
			}
			mutate := func() {
				switch strings.TrimPrefix(mode, "post_") {
				case "same_bytes_inode":
					if e := os.Rename(path, path+".old"); e != nil {
						t.Error(e)
					}
					if e := os.WriteFile(path, raw, 0600); e != nil {
						t.Error(e)
					}
				case "changed_contents", "rehash_config":
					next := []byte(`{"version":3,"rules":[{"domain_suffix":["changed.test"]}]}`)
					if e := os.WriteFile(path, next, 0600); e != nil {
						t.Error(e)
					}
					if strings.HasSuffix(mode, "rehash_config") {
						if e := os.WriteFile(config, []byte(strings.ReplaceAll(string(base), shaHex(raw), shaHex(next))), 0600); e != nil {
							t.Error(e)
						}
					}
				case "changed_path":
					if e := os.WriteFile(config, []byte(strings.ReplaceAll(string(base), "audited.json", "other.json")), 0600); e != nil {
						t.Error(e)
					}
					if e := os.WriteFile(filepath.Join(filepath.Dir(config), "other.json"), raw, 0600); e != nil {
						t.Error(e)
					}
				case "missing_pins", "schema_alias":
					sourcePath := filepath.Join(root, liveSourceName)
					b, _ := os.ReadFile(sourcePath)
					var doc map[string]json.RawMessage
					if e := json.Unmarshal(b, &doc); e != nil {
						t.Error(e)
					}
					if mode == "missing_pins" {
						delete(doc, "rules")
					} else {
						doc["Rules"] = doc["rules"]
					}
					b, _ = json.Marshal(doc)
					if e := os.WriteFile(sourcePath, b, 0600); e != nil {
						t.Error(e)
					}
				}
			}
			late := strings.HasPrefix(mode, "post_")
			if late {
				f.onRead = func(n int32, _ *liveResponse) string {
					if n == 2 {
						mutate()
					}
					return ""
				}
			} else if mode != "unchanged" {
				mutate()
			}
			r := f.call("select")
			if mode == "unchanged" {
				if !r.OK || r.Code != "HOT_APPLIED" || f.switches.Load() != 1 {
					t.Fatalf("positive %+v switches=%d", r, f.switches.Load())
				}
				return
			}
			want, count := "RELOAD_REQUIRED", int32(0)
			if late {
				want, count = "SWITCH_UNKNOWN", 1
			}
			if r.OK || r.Code != want || f.switches.Load() != count {
				t.Fatalf("%s: %+v switches=%d expected=%s/%d", mode, r, f.switches.Load(), want, count)
			}
		})
	}
}
