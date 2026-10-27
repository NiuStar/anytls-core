package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestWebSingleRuleRejections(t *testing.T) {
	for _, tc := range []struct {
		name, body, config, etag string
		code                     int
	}{
		{"missing-etag", `{"type":"DOMAIN","value":"x.test","target":"DIRECT","no_resolve":false,"position":"first"}`, "", "", 428},
		{"stale", `{"type":"DOMAIN","value":"x.test","target":"DIRECT","no_resolve":false,"position":"first"}`, "", `"stale"`, 412},
		{"null-flag", `{"type":"DOMAIN","value":"x.test","target":"DIRECT","no_resolve":null,"position":"first"}`, "", "auto", 422},
		{"null-type", `{"type":null,"value":"x.test","target":"DIRECT","no_resolve":false,"position":"first"}`, "", "auto", 422},
		{"comma", `{"type":"DOMAIN","value":"x,secret","target":"DIRECT","no_resolve":false,"position":"first"}`, "", "auto", 422},
		{"newline", `{"type":"DOMAIN","value":"x\nsecret","target":"DIRECT","no_resolve":false,"position":"first"}`, "", "auto", 422},
		{"nul", `{"type":"DOMAIN","value":"x\u0000secret","target":"DIRECT","no_resolve":false,"position":"first"}`, "", "auto", 422},
		{"cidr", `{"type":"IP-CIDR","value":"not-cidr","target":"DIRECT","no_resolve":false,"position":"first"}`, "", "auto", 422},
		{"country", `{"type":"GEOIP","value":"gcn","target":"DIRECT","no_resolve":false,"position":"first"}`, "", "auto", 422},
		{"match", `{"type":"MATCH","value":"x","target":"DIRECT","no_resolve":false,"position":"first"}`, "", "auto", 422},
		{"flag", `{"type":"DOMAIN","value":"x.test","target":"DIRECT","no_resolve":true,"position":"first"}`, "", "auto", 422},
		{"target", `{"type":"DOMAIN","value":"x.test","target":"SECRET_TARGET","no_resolve":false,"position":"first"}`, "", "auto", 422},
		{"set", `{"type":"RULE-SET","value":"SECRET_PATH","target":"DIRECT","no_resolve":false,"position":"first"}`, "", "auto", 422},
		{"position", `{"type":"DOMAIN","value":"x.test","target":"DIRECT","no_resolve":false,"position":"index","index":2}`, "", "auto", 422},
		{"contradiction", `{"type":"DOMAIN","value":"x.test","target":"DIRECT","no_resolve":false,"position":"first","index":0}`, "", "auto", 422},
		{"negative-index", `{"type":"DOMAIN","value":"x.test","target":"DIRECT","no_resolve":false,"position":"index","index":-1}`, "", "auto", 422},
		{"fraction-index", `{"type":"DOMAIN","value":"x.test","target":"DIRECT","no_resolve":false,"position":"index","index":0.5}`, "", "auto", 422},
		{"missing-index", `{"type":"DOMAIN","value":"x.test","target":"DIRECT","no_resolve":false,"position":"index"}`, "", "auto", 422},
		{"unknown-field", `{"type":"DOMAIN","value":"x.test","target":"DIRECT","no_resolve":false,"position":"first","path":"SECRET_PATH"}`, "", "auto", 422},
		{"case-country", `{"type":"GEOIP","value":"cn","target":"DIRECT","no_resolve":false,"position":"first"}`, "", "auto", 422},
		{"space-country", `{"type":"GEOIP","value":" CN","target":"DIRECT","no_resolve":false,"position":"first"}`, "", "auto", 422},
		{"weak-etag", `{"type":"DOMAIN","value":"x.test","target":"DIRECT","no_resolve":false,"position":"first"}`, "", `W/"stale"`, 412},
		{"wildcard-etag", `{"type":"DOMAIN","value":"x.test","target":"DIRECT","no_resolve":false,"position":"first"}`, "", "*", 412},
		{"flow", `{"type":"DOMAIN","value":"x.test","target":"DIRECT","no_resolve":false,"position":"first"}`, "nodes: []\nrules: ['MATCH,DIRECT']\n", "auto", 422},
		{"alias", `{"type":"DOMAIN","value":"x.test","target":"DIRECT","no_resolve":false,"position":"first"}`, "nodes: []\nx: &r ['MATCH,DIRECT']\nrules: *r\n", "auto", 422},
		{"alias-key", `{"type":"DOMAIN","value":"x.test","target":"DIRECT","no_resolve":false,"position":"first"}`, "nodes: []\nx: &k rules\n*k :\n - 'MATCH,DIRECT'\n", "auto", 422},
		{"missing-match", `{"type":"DOMAIN","value":"x.test","target":"DIRECT","no_resolve":false,"position":"first"}`, "nodes: []\nrules:\n - 'DOMAIN,x.test,DIRECT'\n", "auto", 422},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, p := webFixture(t)
			c, csrf := webLogin(t, w, p)
			raw := []byte(tc.config)
			if tc.config == "" {
				raw = []byte(singleRuleConfig)
			}
			if e := os.WriteFile(w.configPath, raw, 0600); e != nil {
				t.Fatal(e)
			}
			before, _ := os.Stat(w.configPath)
			calls := 0
			w.state = func() (bool, bool, error) { calls++; return true, true, nil }
			w.serviceAction = func(context.Context, string, bool) error { calls++; return nil }
			etag := tc.etag
			if etag == "auto" {
				etag = `"` + shaHex(raw) + `"`
			}
			r := groupETagRequest(w, c, csrf, "/api/v1/rules", tc.body, etag)
			got, _ := os.ReadFile(w.configPath)
			after, _ := os.Stat(w.configPath)
			if r.Code != tc.code || !bytes.Equal(got, raw) || !os.SameFile(before, after) || calls != 0 || strings.Contains(r.Body.String(), "SECRET") {
				t.Fatalf("rejection changed state or leaked: %d %s calls=%d", r.Code, r.Body.String(), calls)
			}
			if tc.name == "flow" || strings.HasPrefix(tc.name, "alias") || tc.name == "missing-match" {
				if !strings.Contains(r.Body.String(), "RULE_EDIT_UNSUPPORTED") {
					t.Fatal(r.Body.String())
				}
			}
		})
	}
}
func TestWebSingleRuleApplyModes(t *testing.T) {
	for _, mode := range []string{"APPLIED", "APPLY_FAILED", "SAVED_STOPPED", "STATE_UNAVAILABLE"} {
		t.Run(mode, func(t *testing.T) {
			w, p := webFixture(t)
			c, csrf := webLogin(t, w, p)
			raw := []byte(singleRuleConfig)
			os.WriteFile(w.configPath, raw, 0600)
			calls := 0
			w.state = func() (bool, bool, error) {
				if mode == "STATE_UNAVAILABLE" {
					return false, false, errors.New("SECRET")
				}
				return mode != "SAVED_STOPPED", mode != "SAVED_STOPPED", nil
			}
			w.serviceAction = func(ctx context.Context, action string, insecure bool) error {
				calls++
				if action != "reload" || !insecure {
					t.Error("bad action")
				}
				if w.actionMu.TryLock() {
					w.actionMu.Unlock()
					t.Error("lock not held")
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Error("no deadline")
				}
				if mode == "APPLY_FAILED" {
					return errors.New("SECRET")
				}
				return nil
			}
			body := `{"type":"GEOIP","value":"CN","target":"REJECT","no_resolve":true,"position":"before_match","confirm_insecure":true}`
			r := groupETagRequest(w, c, csrf, "/api/v1/rules", body, `"`+shaHex(raw)+`"`)
			var result map[string]any
			json.Unmarshal(r.Body.Bytes(), &result)
			if r.Code != 200 || result["apply_status"] != mode || result["inserted"] != true || result["rule"] != "GEOIP,CN,REJECT,no-resolve" || strings.Contains(r.Body.String(), "SECRET") {
				t.Fatalf("bad result: %d %s", r.Code, r.Body.String())
			}
			expected := 0
			if mode == "APPLIED" || mode == "APPLY_FAILED" {
				expected = 1
			}
			if calls != expected {
				t.Fatal(calls)
			}
			got, _ := os.ReadFile(w.configPath)
			calls = 0
			r = groupETagRequest(w, c, csrf, "/api/v1/rules", body, `"`+shaHex(got)+`"`)
			if r.Code != 200 || !strings.Contains(r.Body.String(), `"apply_status":"NO_CHANGE"`) || calls != 0 {
				t.Fatal(r.Body.String(), calls)
			}
		})
	}
}
func TestWebSingleRuleAuthBusy(t *testing.T) {
	w, p := webFixture(t)
	c, csrf := webLogin(t, w, p)
	raw := []byte(singleRuleConfig)
	os.WriteFile(w.configPath, raw, 0600)
	body := `{"type":"DOMAIN","value":"x.test","target":"DIRECT","no_resolve":false,"position":"first"}`
	for _, mode := range []string{"auth", "origin", "csrf", "busy"} {
		t.Run(mode, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://127.0.0.1:18089/api/v1/rules", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", "http://127.0.0.1:18089")
			r.Header.Set("X-CSRF-Token", csrf)
			r.Header.Set("If-Match", `"`+shaHex(raw)+`"`)
			if mode != "auth" {
				r.AddCookie(c)
			}
			if mode == "origin" {
				r.Header.Del("Origin")
			}
			if mode == "csrf" {
				r.Header.Del("X-CSRF-Token")
			}
			want := 403
			if mode == "auth" {
				want = 401
			}
			if mode == "busy" {
				w.actionMu.Lock()
				defer w.actionMu.Unlock()
				want = 409
			}
			out := httptest.NewRecorder()
			w.ServeHTTP(out, r)
			if out.Code != want {
				t.Fatal(out.Code, out.Body.String())
			}
			got, _ := os.ReadFile(w.configPath)
			if !bytes.Equal(got, raw) {
				t.Fatal("mutated")
			}
		})
	}
}
func TestWebSingleRuleCRLF(t *testing.T) {
	w, p := webFixture(t)
	c, csrf := webLogin(t, w, p)
	raw := []byte(strings.ReplaceAll(strings.TrimSuffix(singleRuleConfig, "\n"), "\n", "\r\n"))
	os.WriteFile(w.configPath, raw, 0600)
	r := groupETagRequest(w, c, csrf, "/api/v1/rules", `{"type":"IP-CIDR","value":"10.0.0.0/8","target":"DIRECT","no_resolve":false,"position":"first"}`, `"`+shaHex(raw)+`"`)
	got, _ := os.ReadFile(w.configPath)
	insert := []byte("  - 'IP-CIDR,10.0.0.0/8,DIRECT'\r\n")
	if r.Code != 200 || !bytes.Equal(bytes.Replace(got, insert, nil, 1), raw) {
		t.Fatalf("CRLF damaged: %d %s", r.Code, r.Body.String())
	}
}
