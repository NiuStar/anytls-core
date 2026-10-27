package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/NiuStar/anytls-core/internal/engine"
)

func TestWebSingleRuleNativeRuleSetGate(t *testing.T) {
	for _, tc := range []struct {
		name, rule string
		valid      bool
	}{
		{"valid", `{"domain":["allowed.example"]}`, true},
		{"cidr", `{"ip_cidr":["not-a-cidr"]}`, false},
		{"regex", `{"domain_regex":["["]}`, false},
		{"unknown", `{"SECRET_UNKNOWN_FIELD":true}`, false},
	} {
		for _, method := range []string{"GET", "POST", "ACTIVE"} {
			t.Run(tc.name+"/"+method, func(t *testing.T) {
				w, p := webFixture(t)
				c, csrf := webLogin(t, w, p)
				set := []byte(`{"version":3,"rules":[` + tc.rule + `]}`)
				path := filepath.Join(filepath.Dir(w.configPath), "fixture.json")
				if err := os.WriteFile(path, set, 0600); err != nil {
					t.Fatal(err)
				}
				raw := []byte("nodes: []\nrule-sets:\n  audited:\n    path: fixture.json\n    sha256: " + shaHex(set) + "\nrules:\n - 'MATCH,DIRECT'\n")
				if method == "ACTIVE" {
					raw = bytes.Replace(raw, []byte("rules:\n"), []byte("rules:\n - 'RULE-SET,audited,DIRECT'\n"), 1)
				}
				if err := os.WriteFile(w.configPath, raw, 0600); err != nil {
					t.Fatal(err)
				}
				// Independent actual decoder/constructor check, never Start or a test seam.
				loaded, err := loadRuleSet(w.configPath, "audited", fileRuleSet{Path: "fixture.json", SHA256: shaHex(set)})
				if err != nil {
					t.Fatal(err)
				}
				cfg := map[string]any{"log": map[string]any{"disabled": true}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}, "route": map[string]any{"rule_set": []any{loaded}, "rules": []any{map[string]any{"rule_set": []string{"audited"}, "outbound": "direct"}}, "final": "direct"}}
				encoded, _ := json.Marshal(cfg)
				if err = engine.Check(context.Background(), encoded); (err == nil) != tc.valid {
					t.Fatalf("native fixture acceptance mismatch valid=%v error=%v", tc.valid, err)
				}
				before, _ := os.Stat(w.configPath)
				calls := 0
				w.state = func() (bool, bool, error) { calls++; return false, false, nil }
				w.serviceAction = func(context.Context, string, bool) error { calls++; return nil }
				if method == "GET" {
					result := webRequest(w, "GET", "/api/v1/rules", "", c, "")
					var got struct {
						RuleSets []string `json:"rule_sets"`
					}
					if err := json.Unmarshal(result.Body.Bytes(), &got); err != nil {
						t.Fatal(err)
					}
					want := []string{}
					if tc.valid {
						want = []string{"audited"}
					}
					if result.Code != 200 || !reflect.DeepEqual(got.RuleSets, want) {
						t.Fatalf("inventory must exclude native-invalid set: %d %s", result.Code, result.Body.String())
					}
				} else {
					body := `{"type":"RULE-SET","value":"audited","target":"DIRECT","no_resolve":false,"position":"before_match"}`
					if method == "ACTIVE" {
						body = `{"type":"DOMAIN","value":"new.example","target":"DIRECT","no_resolve":false,"position":"before_match"}`
					}
					result := groupETagRequest(w, c, csrf, "/api/v1/rules", body, `"`+shaHex(raw)+`"`)
					after, _ := os.Stat(w.configPath)
					got, _ := os.ReadFile(w.configPath)
					if tc.valid {
						if result.Code != 200 || !bytes.Contains(got, []byte("RULE-SET,audited,DIRECT")) {
							t.Fatalf("valid native set rejected: %d %s", result.Code, result.Body.String())
						}
					} else if result.Code != 422 || !strings.Contains(result.Body.String(), "RULE_VALUE_INVALID") || strings.Contains(result.Body.String(), "SECRET") || !bytes.Equal(raw, got) || !os.SameFile(before, after) || before.Mode() != after.Mode() || calls != 0 {
						t.Fatalf("native-invalid set persisted or action called: %d %s calls=%d", result.Code, result.Body.String(), calls)
					}
				}
			})
		}
	}
}
