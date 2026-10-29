package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestWebRulesListOnlyProjection(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		editable  bool
	}{
		{"block", singleRuleConfig, true},
		{"flow", "nodes: []\nrules: ['MATCH,DIRECT']\n", false},
		{"empty", "nodes: []\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, password := webFixture(t)
			cookie, _ := webLogin(t, w, password)
			raw := []byte(tc.raw)
			if err := os.WriteFile(w.configPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(w.configPath)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			w.state = func() (bool, bool, error) { calls++; return false, false, nil }
			w.serviceAction = func(context.Context, string, bool) error { calls++; return nil }
			full := webRequest(w, "GET", "/api/v1/rules", "", cookie, "")
			list := webRequest(w, "GET", "/api/v1/rules?view=list", "", cookie, "")
			var want, got map[string]any
			if full.Code != 200 || list.Code != 200 || json.Unmarshal(full.Body.Bytes(), &want) != nil || json.Unmarshal(list.Body.Bytes(), &got) != nil {
				t.Fatalf("inventory responses: full=%d %s list=%d %s", full.Code, full.Body.String(), list.Code, list.Body.String())
			}
			// Legacy full projection stays exact (including no new mode metadata).
			for _, key := range []string{"targets", "rule_sets"} {
				if _, ok := want[key]; !ok {
					t.Fatalf("legacy response lost %s", key)
				}
				delete(want, key)
			}
			if len(want) != 4 || want["editable"] != tc.editable {
				t.Fatalf("legacy response contract changed: %s", full.Body.String())
			}
			want["view"], want["options_loaded"] = "list", false
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("list must omit options and preserve the complete snapshot projection: got=%s want=%v", list.Body.String(), want)
			}
			if got["etag"] != `"`+shaHex(raw)+`"` || list.Header().Get("ETag") != got["etag"] || full.Header().Get("ETag") != got["etag"] {
				t.Fatal("list/full/header ETags must bind identical captured bytes")
			}
			after, err := os.Stat(w.configPath)
			if err != nil {
				t.Fatal(err)
			}
			readback, err := os.ReadFile(w.configPath)
			if err != nil || !bytes.Equal(readback, raw) || !os.SameFile(before, after) || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) || calls != 0 {
				t.Fatalf("read-only inventories changed config or invoked service: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestWebRulesListOnlyRejectsInvalidQuery(t *testing.T) {
	w, password := webFixture(t)
	cookie, _ := webLogin(t, w, password)
	for _, query := range []string{"view=", "view=full", "view=LIST", "view=list&view=list", "view=list&view=", "view=list&unknown=1", "unknown=1", "view=%ZZ", "view=list;unknown=1"} {
		t.Run(query, func(t *testing.T) {
			out := webRequest(w, "GET", "/api/v1/rules?"+query, "", cookie, "")
			if out.Code != http.StatusBadRequest || strings.TrimSpace(out.Body.String()) != `{"error":"INVALID_INPUT"}` || out.Header().Get("ETag") != "" {
				t.Fatalf("invalid query must not silently load full options: %d %s", out.Code, out.Body.String())
			}
		})
	}
	out := webRequest(w, "GET", "/api/v1/rules?view=list", "", nil, "")
	if out.Code != http.StatusUnauthorized {
		t.Fatalf("list mode bypassed authentication: %d %s", out.Code, out.Body.String())
	}
}

func TestWebRulesListOnlyExternalSetUnavailable(t *testing.T) {
	w, password := webFixture(t)
	cookie, _ := webLogin(t, w, password)
	set := []byte(`{"version":3,"rules":[{"domain":["audit.test"]}]}`)
	path := filepath.Join(filepath.Dir(w.configPath), "audited.json")
	if err := os.WriteFile(path, set, 0600); err != nil {
		t.Fatal(err)
	}
	raw := strings.Replace(singleRuleConfig, "rules:\n", "rule-sets:\n  audited:\n    path: audited.json\n    sha256: "+shaHex(set)+"\nrules:\n", 1)
	if err := os.WriteFile(w.configPath, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	full := webRequest(w, "GET", "/api/v1/rules", "", cookie, "")
	var before map[string]any
	if full.Code != 200 || json.Unmarshal(full.Body.Bytes(), &before) != nil || !reflect.DeepEqual(before["rule_sets"], []any{"audited"}) {
		t.Fatalf("valid set fixture was not advertised: %d %s", full.Code, full.Body.String())
	}
	listBefore := webRequest(w, "GET", "/api/v1/rules?view=list", "", cookie, "")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	listAfter := webRequest(w, "GET", "/api/v1/rules?view=list", "", cookie, "")
	if listBefore.Code != 200 || listAfter.Code != 200 || !bytes.Equal(listBefore.Body.Bytes(), listAfter.Body.Bytes()) {
		t.Fatalf("list depends on external option availability: before=%s after=%s", listBefore.Body.String(), listAfter.Body.String())
	}
	var list map[string]any
	if json.Unmarshal(listAfter.Body.Bytes(), &list) != nil || list["options_loaded"] != false {
		t.Fatalf("list did not declare unloaded options: %s", listAfter.Body.String())
	}
	full = webRequest(w, "GET", "/api/v1/rules", "", cookie, "")
	var after map[string]any
	if full.Code != 200 || json.Unmarshal(full.Body.Bytes(), &after) != nil || !reflect.DeepEqual(after["rule_sets"], []any{}) || after["etag"] != before["etag"] {
		t.Fatalf("legacy options must still exclude missing sets without changing config identity: %s", full.Body.String())
	}
	// This is functional independence, not a source-read/SDK-construction counter.
}

func TestWebRulesListOnlyETagUsesOriginalSaveChain(t *testing.T) {
	for _, action := range []string{"add", "delete", "stale-add", "stale-delete"} {
		t.Run(action, func(t *testing.T) {
			w, password := webFixture(t)
			cookie, csrf := webLogin(t, w, password)
			raw := []byte(singleRuleConfig)
			if err := os.WriteFile(w.configPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			list := webRequest(w, "GET", "/api/v1/rules?view=list", "", cookie, "")
			if list.Code != 200 || list.Header().Get("ETag") == "" {
				t.Fatalf("cannot capture list snapshot: %d %s", list.Code, list.Body.String())
			}
			path, body := "/api/v1/rules", `{"type":"DOMAIN","value":"new.test","target":"DIRECT","no_resolve":false,"position":"first"}`
			want := bytes.Replace(raw, []byte("  - 'DOMAIN"), []byte("  - 'DOMAIN,new.test,DIRECT'\n  - 'DOMAIN"), 1)
			if strings.HasSuffix(action, "delete") {
				path, body = "/api/v1/rules/delete", `{"index":0,"rule":"DOMAIN,old.example,DIRECT"}`
				want = bytes.Replace(raw, []byte("  - 'DOMAIN,old.example,DIRECT' # keep\n"), nil, 1)
			}
			wantStatus := 200
			if strings.HasPrefix(action, "stale-") {
				want, wantStatus = append(bytes.Clone(raw), []byte("# external edit\n")...), 412
				if err := os.WriteFile(w.configPath, want, 0600); err != nil {
					t.Fatal(err)
				}
			}
			out := groupETagRequest(w, cookie, csrf, path, body, list.Header().Get("ETag"))
			got, err := os.ReadFile(w.configPath)
			if out.Code != wantStatus || err != nil || !bytes.Equal(got, want) {
				t.Fatalf("list ETag must preserve conditional byte-safe save: %d %s err=%v got=%q", out.Code, out.Body.String(), err, got)
			}
		})
	}
}
