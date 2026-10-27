package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

const singleRuleConfig = "# 中文 source\nnodes: []\nx-password: 00123\nx-unknown: &keep {a: b}\nproxy-groups:\n  - {name: local, type: select, proxies: [DIRECT], selected: DIRECT}\nrules:\n  - 'DOMAIN,old.example,DIRECT' # keep\n  - \"MATCH,DIRECT\" # final\nx-tail: *keep\n"

func TestWebSingleRuleSnapshot(t *testing.T) {
	w, p := webFixture(t)
	c, _ := webLogin(t, w, p)
	raw, _ := os.ReadFile(w.configPath)
	r := webRequest(w, "GET", "/api/v1/rules", "", c, "")
	var result map[string]any
	if json.Unmarshal(r.Body.Bytes(), &result) != nil || result["etag"] != `"`+shaHex(raw)+`"` || r.Header().Get("ETag") != result["etag"] {
		t.Fatalf("rules snapshot must carry same-byte ETag: %d %s", r.Code, r.Body.String())
	}
}
func TestWebSingleRuleAdd(t *testing.T) {
	for _, tc := range []struct {
		position string
		index    string
		before   string
	}{
		{"before_match", "", "  - \"MATCH"}, {"first", "", "  - 'DOMAIN"}, {"index", `,"index":1`, "  - \"MATCH"},
	} {
		t.Run(tc.position, func(t *testing.T) {
			w, p := webFixture(t)
			c, csrf := webLogin(t, w, p)
			old := []byte(singleRuleConfig)
			if err := os.WriteFile(w.configPath, old, 0600); err != nil {
				t.Fatal(err)
			}
			body := `{"type":"DOMAIN","value":"例子.example","target":"local","no_resolve":false,"position":"` + tc.position + `"` + tc.index + `,"confirm_insecure":true}`
			r := groupETagRequest(w, c, csrf, "/api/v1/rules", body, `"`+shaHex(old)+`"`)
			if r.Code != 200 {
				t.Fatalf("authenticated add should save: %d %s", r.Code, r.Body.String())
			}
			got, _ := os.ReadFile(w.configPath)
			at := bytes.Index(old, []byte(tc.before))
			want := append(bytes.Clone(old[:at]), []byte("  - 'DOMAIN,例子.example,local'\n")...)
			want = append(want, old[at:]...)
			if !bytes.Equal(got, want) {
				t.Fatalf("must insert exactly one line without reserializing: %s", got)
			}
			r = groupETagRequest(w, c, csrf, "/api/v1/rules", body, `"`+shaHex(got)+`"`)
			if r.Code != 200 || !bytes.Contains(r.Body.Bytes(), []byte(`"apply_status":"NO_CHANGE"`)) {
				t.Fatalf("duplicate must be no-op: %d %s", r.Code, r.Body.String())
			}
		})
	}
}
