package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestWebSingleRulePublicInventoryAndNativeTargets(t *testing.T) {
	raw := strings.Replace(singleRuleConfig, "nodes: []", "nodes:\n - {name: node1, type: anytls, server: 127.0.0.1, port: 443, password: 00123, skip-cert-verify: true}\n - {name: incomplete, type: anytls, server: 127.0.0.1, port: 443}\n", 1)
	raw = strings.Replace(raw, "rules:\n", "rule-sets:\n  audited:\n    path: audited.json\n    sha256: SETSHA\nrules:\n", 1)
	w, p := webFixture(t)
	set := []byte(`{"version":3,"rules":[{"domain":["audit.test"]}]}`)
	os.WriteFile(filepath.Join(filepath.Dir(w.configPath), "audited.json"), set, 0600)
	raw = strings.Replace(raw, "SETSHA", shaHex(set), 1)
	os.WriteFile(w.configPath, []byte(raw), 0600)
	c, csrf := webLogin(t, w, p)
	out := webRequest(w, "GET", "/api/v1/rules", "", c, "")
	var got map[string]any
	json.Unmarshal(out.Body.Bytes(), &got)
	var want map[string]any
	encoded, _ := json.Marshal(map[string]any{"rules": []string{"DOMAIN,old.example,DIRECT", "MATCH,DIRECT"}, "etag": `"` + shaHex([]byte(raw)) + `"`, "targets": []string{"DIRECT", "REJECT", "node1", "local"}, "rule_sets": []string{"audited"}, "editable": true, "edit_error": ""})
	json.Unmarshal(encoded, &want)
	if out.Code != 200 || !reflect.DeepEqual(got, want) {
		t.Fatalf("public projection mismatch %s", out.Body.String())
	}
	for _, kind := range []string{"DOMAIN-SUFFIX", "IP-CIDR", "GEOIP", "RULE-SET"} {
		value := map[string]string{"DOMAIN-SUFFIX": "例子.example", "IP-CIDR": "2001:db8::/32", "GEOIP": "CN", "RULE-SET": "audited"}[kind]
		body, _ := json.Marshal(map[string]any{"type": kind, "value": value, "target": "node1", "no_resolve": kind == "RULE-SET", "position": "first", "confirm_insecure": true})
		old, _ := os.ReadFile(w.configPath)
		out = groupETagRequest(w, c, csrf, "/api/v1/rules", string(body), `"`+shaHex(old)+`"`)
		if out.Code != 200 {
			t.Fatalf("native target %s: %d %s", kind, out.Code, out.Body.String())
		}
		after, _ := os.ReadFile(w.configPath)
		if !bytes.Contains(after, []byte("password: 00123")) {
			t.Fatal("numeric password changed")
		}
	}
	// An existing rule with whitespace is idempotent across insertion choices.
	old, _ := os.ReadFile(w.configPath)
	old = bytes.Replace(old, []byte("DOMAIN-SUFFIX,例子.example,node1"), []byte("DOMAIN-SUFFIX, 例子.example, node1"), 1)
	os.WriteFile(w.configPath, old, 0600)
	before, _ := os.Stat(w.configPath)
	out = groupETagRequest(w, c, csrf, "/api/v1/rules", `{"type":"DOMAIN-SUFFIX","value":"例子.example","target":"node1","no_resolve":false,"position":"before_match"}`, `"`+shaHex(old)+`"`)
	after, _ := os.Stat(w.configPath)
	if out.Code != 200 || !strings.Contains(out.Body.String(), `"inserted":false`) || !os.SameFile(before, after) {
		t.Fatal(out.Body.String())
	}
}
func TestWebSingleRuleMatchOnlyNoFinalNewline(t *testing.T) {
	w, p := webFixture(t)
	c, csrf := webLogin(t, w, p)
	raw := []byte("nodes: []\r\nrules:\r\n - 'MATCH,DIRECT'")
	os.WriteFile(w.configPath, raw, 0600)
	out := groupETagRequest(w, c, csrf, "/api/v1/rules", `{"type":"DOMAIN","value":"x.test","target":"DIRECT","no_resolve":false,"position":"before_match"}`, `"`+shaHex(raw)+`"`)
	after, _ := os.ReadFile(w.configPath)
	want := bytes.Replace(raw, []byte(" - 'MATCH"), []byte(" - 'DOMAIN,x.test,DIRECT'\r\n - 'MATCH"), 1)
	if out.Code != 200 || !bytes.Equal(want, after) {
		t.Fatalf("match-only CRLF insertion: %d %s", out.Code, after)
	}
}
