package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
)

const deleteRulePath = "/api/v1/rules/delete"

func deleteRuleBody(index int, rule string) string {
	b, _ := json.Marshal(map[string]any{"index": index, "rule": rule, "confirm_insecure": true})
	return string(b)
}

func TestWebRuleDeleteExactPhysicalRow(t *testing.T) {
	for _, tc := range []struct {
		name, rows, remove, rule string
		index                    int
	}{
		{"first", "  - 'DOMAIN,old.example,DIRECT' # inline\n  # standalone next\n  - DOMAIN,next.example,DIRECT\n", "  - 'DOMAIN,old.example,DIRECT' # inline\n", "DOMAIN,old.example,DIRECT", 0},
		{"middle-unicode", "  - DOMAIN,first.example,DIRECT\n  # standalone before\n  - 'DOMAIN,例子.example,DIRECT' # inline\n  # standalone after\n  - DOMAIN,last.example,DIRECT\n", "  - 'DOMAIN,例子.example,DIRECT' # inline\n", "DOMAIN,例子.example,DIRECT", 1},
		{"duplicate-second", "  - 'DOMAIN,dup.example,DIRECT' # first stays\n  - 'DOMAIN,dup.example,DIRECT' # selected\n", "  - 'DOMAIN,dup.example,DIRECT' # selected\n", "DOMAIN,dup.example,DIRECT", 1},
		{"quoted-escape", "  - \"DOMAIN,old\\u002eexample,DIRECT\" # escape\n", "  - \"DOMAIN,old\\u002eexample,DIRECT\" # escape\n", "DOMAIN,old.example,DIRECT", 0},
		{"single-quote-escape", "  - 'DOMAIN,it''s.example,DIRECT' # escape\n", "  - 'DOMAIN,it''s.example,DIRECT' # escape\n", "DOMAIN,it's.example,DIRECT", 0},
		{"exact-whitespace", "  - ' DOMAIN , old.example , DIRECT ' # exact\n", "  - ' DOMAIN , old.example , DIRECT ' # exact\n", " DOMAIN , old.example , DIRECT ", 0},
	} {
		for _, newline := range []string{"\n", "\r\n"} {
			t.Run(tc.name+fmt.Sprintf("/%q", newline), func(t *testing.T) {
				w, p := webFixture(t)
				c, csrf := webLogin(t, w, p)
				raw := []byte(strings.ReplaceAll("# 中文\nnodes: []\nx-unknown: &keep {a: b}\nx-password: 00123\nrules:\n"+tc.rows+"  - 'MATCH,DIRECT' # final\nx-tail: *keep", "\n", newline))
				if err := os.WriteFile(w.configPath, raw, 0600); err != nil {
					t.Fatal(err)
				}
				// All sidecars must remain byte- and inode-identical, not merely equivalent.
				paths := []string{selectedPath(w.configPath), w.subscriptionPath(), w.passwordPath}
				for _, path := range paths[:2] {
					if err := os.WriteFile(path, []byte("SECRET_SIDECAR"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				beforeBytes := map[string][]byte{}
				beforeInfo := map[string]os.FileInfo{}
				for _, path := range paths {
					var err error
					beforeBytes[path], err = os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					beforeInfo[path], err = os.Stat(path)
					if err != nil {
						t.Fatal(err)
					}
				}
				calls := 0
				w.serviceAction = func(context.Context, string, bool) error { calls++; return nil }
				out := groupETagRequest(w, c, csrf, deleteRulePath, deleteRuleBody(tc.index, tc.rule), `"`+shaHex(raw)+`"`)
				want := bytes.Replace(raw, []byte(strings.ReplaceAll(tc.remove, "\n", newline)), nil, 1)
				got, err := os.ReadFile(w.configPath)
				var result map[string]any
				if err != nil || out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &result) != nil || !bytes.Equal(got, want) || result["saved"] != true || result["changed"] != true || result["deleted"] != true || result["index"] != float64(tc.index) || result["rule"] != tc.rule || result["apply_status"] != "SAVED_STOPPED" || result["etag"] != `"`+shaHex(want)+`"` || out.Header().Get("ETag") != result["etag"] || calls != 0 || strings.Contains(out.Body.String(), "SECRET") {
					t.Fatalf("wrong delete: %d %s err=%v got=%q want=%q calls=%d", out.Code, out.Body.String(), err, got, want, calls)
				}
				for _, path := range paths {
					got, err := os.ReadFile(path)
					after, statErr := os.Stat(path)
					if err != nil || statErr != nil || !bytes.Equal(got, beforeBytes[path]) || !os.SameFile(beforeInfo[path], after) {
						t.Fatalf("sidecar changed: %s", path)
					}
				}
				inventory := webRequest(w, "GET", "/api/v1/rules", "", c, "")
				var list struct {
					Rules []string `json:"rules"`
				}
				if inventory.Code != 200 || json.Unmarshal(inventory.Body.Bytes(), &list) != nil || len(list.Rules) == 0 || list.Rules[len(list.Rules)-1] != "MATCH,DIRECT" {
					t.Fatal(inventory.Code, inventory.Body.String())
				}
			})
		}
	}
}

func TestWebRuleDeleteInvalidRequests(t *testing.T) {
	valid := `{"index":0,"rule":"DOMAIN,old.example,DIRECT"}`
	for _, tc := range []struct {
		name, body, etag, code string
		status                 int
	}{
		{"empty-object", `{}`, "auto", "RULE_DELETE_INVALID", 422},
		{"null-body", `null`, "auto", "RULE_DELETE_INVALID", 422},
		{"array", `[]`, "auto", "RULE_DELETE_INVALID", 422},
		{"malformed", `{"index":`, "auto", "RULE_DELETE_INVALID", 422},
		{"two-values", valid + valid, "auto", "RULE_DELETE_INVALID", 422},
		{"missing-rule", `{"index":0}`, "auto", "RULE_DELETE_INVALID", 422},
		{"missing-index", `{"rule":"DOMAIN,old.example,DIRECT"}`, "auto", "RULE_DELETE_INVALID", 422},
		{"null-index", `{"index":null,"rule":"DOMAIN,old.example,DIRECT"}`, "auto", "RULE_DELETE_INVALID", 422},
		{"null-rule", `{"index":0,"rule":null}`, "auto", "RULE_DELETE_INVALID", 422},
		{"null-consent", `{"index":0,"rule":"DOMAIN,old.example,DIRECT","confirm_insecure":null}`, "auto", "RULE_DELETE_INVALID", 422},
		{"string-consent", `{"index":0,"rule":"DOMAIN,old.example,DIRECT","confirm_insecure":"true"}`, "auto", "RULE_DELETE_INVALID", 422},
		{"negative", deleteRuleBody(-1, "DOMAIN,old.example,DIRECT"), "auto", "RULE_DELETE_INVALID", 422},
		{"bounds", deleteRuleBody(2, "DOMAIN,old.example,DIRECT"), "auto", "RULE_DELETE_INVALID", 422},
		{"fraction", `{"index":0.1,"rule":"DOMAIN,old.example,DIRECT"}`, "auto", "RULE_DELETE_INVALID", 422},
		{"exponent", `{"index":0e0,"rule":"DOMAIN,old.example,DIRECT"}`, "auto", "RULE_DELETE_INVALID", 422},
		{"string-index", `{"index":"0","rule":"DOMAIN,old.example,DIRECT"}`, "auto", "RULE_DELETE_INVALID", 422},
		{"bool-index", `{"index":false,"rule":"DOMAIN,old.example,DIRECT"}`, "auto", "RULE_DELETE_INVALID", 422},
		{"overflow", `{"index":99999999999999999999999999,"rule":"DOMAIN,old.example,DIRECT"}`, "auto", "RULE_DELETE_INVALID", 422},
		{"wrong-rule-type", `{"index":0,"rule":[]}`, "auto", "RULE_DELETE_INVALID", 422},
		{"empty-rule", deleteRuleBody(0, ""), "auto", "RULE_DELETE_INVALID", 422},
		{"mismatch", deleteRuleBody(0, "DOMAIN,SECRET,DIRECT"), "auto", "RULE_DELETE_INVALID", 422},
		{"no-trim", deleteRuleBody(0, " DOMAIN,old.example,DIRECT"), "auto", "RULE_DELETE_INVALID", 422},
		{"unknown", `{"index":0,"rule":"DOMAIN,old.example,DIRECT","SECRET":true}`, "auto", "RULE_DELETE_INVALID", 422},
		{"duplicate-index", `{"index":1,"index":0,"rule":"DOMAIN,old.example,DIRECT"}`, "auto", "RULE_DELETE_INVALID", 422},
		{"duplicate-rule", `{"index":0,"rule":"SECRET","rule":"DOMAIN,old.example,DIRECT"}`, "auto", "RULE_DELETE_INVALID", 422},
		{"escaped-duplicate", `{"index":0,"ind\u0065x":0,"rule":"DOMAIN,old.example,DIRECT"}`, "auto", "RULE_DELETE_INVALID", 422},
		{"duplicate-consent", `{"index":0,"rule":"DOMAIN,old.example,DIRECT","confirm_insecure":false,"confirm_insecure":true}`, "auto", "RULE_DELETE_INVALID", 422},
		{"missing-etag", valid, "", "IF_MATCH_REQUIRED", 428},
		{"stale", valid, `"stale"`, "CONFIG_CONFLICT", 412},
		{"weak", valid, `W/"stale"`, "CONFIG_CONFLICT", 412},
		{"wildcard", valid, `*`, "CONFIG_CONFLICT", 412},
		{"list-etag", valid, `"one", "two"`, "CONFIG_CONFLICT", 412},
		{"protected", deleteRuleBody(1, "MATCH,DIRECT"), "auto", "RULE_DELETE_PROTECTED", 422},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, p := webFixture(t)
			c, csrf := webLogin(t, w, p)
			raw := []byte(singleRuleConfig)
			if err := os.WriteFile(w.configPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(w.configPath)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			w.state = func() (bool, bool, error) { calls++; return true, true, nil }
			w.serviceAction = func(context.Context, string, bool) error { calls++; return nil }
			etag := tc.etag
			if etag == "auto" {
				etag = `"` + shaHex(raw) + `"`
			}
			out := groupETagRequest(w, c, csrf, deleteRulePath, tc.body, etag)
			got, err := os.ReadFile(w.configPath)
			after, statErr := os.Stat(w.configPath)
			if out.Code != tc.status || !strings.Contains(out.Body.String(), `"error":"`+tc.code+`"`) || strings.Contains(out.Body.String(), "SECRET") || !strings.Contains(out.Body.String(), `"startup_operation":null`) || err != nil || statErr != nil || !bytes.Equal(got, raw) || !os.SameFile(before, after) || calls != 0 {
				t.Fatalf("bad rejection: %d %s calls=%d", out.Code, out.Body.String(), calls)
			}
		})
	}
}

func TestWebRuleDeleteLayoutRejections(t *testing.T) {
	for _, tc := range []struct{ name, config, rule, code string }{
		{"flow", "nodes: []\nrules: ['DOMAIN,x.test,DIRECT', 'MATCH,DIRECT']\n", "DOMAIN,x.test,DIRECT", "RULE_EDIT_UNSUPPORTED"},
		{"sequence-alias", "nodes: []\nx: &r ['DOMAIN,x.test,DIRECT', 'MATCH,DIRECT']\nrules: *r\n", "DOMAIN,x.test,DIRECT", "RULE_EDIT_UNSUPPORTED"},
		{"item-alias", "nodes: []\nx: &r DOMAIN,x.test,DIRECT\nrules:\n - *r\n - MATCH,DIRECT\n", "DOMAIN,x.test,DIRECT", "RULE_EDIT_UNSUPPORTED"},
		{"item-anchor", "nodes: []\nrules:\n - &r DOMAIN,x.test,DIRECT\n - MATCH,DIRECT\n", "DOMAIN,x.test,DIRECT", "RULE_EDIT_UNSUPPORTED"},
		{"sequence-anchor", "nodes: []\nrules: &r\n - DOMAIN,x.test,DIRECT\n - MATCH,DIRECT\n", "DOMAIN,x.test,DIRECT", "RULE_EDIT_UNSUPPORTED"},
		{"merge", "nodes: []\nx: &r {a: b}\n<<: *r\nrules:\n - DOMAIN,x.test,DIRECT\n - MATCH,DIRECT\n", "DOMAIN,x.test,DIRECT", "RULE_EDIT_UNSUPPORTED"},
		{"literal", "nodes: []\nrules:\n - |-\n   DOMAIN,x.test,DIRECT\n - MATCH,DIRECT\n", "DOMAIN,x.test,DIRECT", "RULE_EDIT_UNSUPPORTED"},
		{"folded", "nodes: []\nrules:\n - >-\n   DOMAIN,x.test,DIRECT\n - MATCH,DIRECT\n", "DOMAIN,x.test,DIRECT", "RULE_EDIT_UNSUPPORTED"},
		{"double-quoted-continuation", "nodes: []\nrules:\n - \"DOMAIN,x.\\\n   test,DIRECT\"\n - MATCH,DIRECT\n", "DOMAIN,x.test,DIRECT", "RULE_EDIT_UNSUPPORTED"},
		{"single-quoted-continuation", "nodes: []\nrules:\n - 'DOMAIN,x.test,\n   DIRECT'\n - MATCH,DIRECT\n", "DOMAIN,x.test, DIRECT", "RULE_EDIT_UNSUPPORTED"},
		{"plain-continuation", "nodes: []\nrules:\n - DOMAIN,x.test,\n   DIRECT\n - MATCH,DIRECT\n", "DOMAIN,x.test, DIRECT", "RULE_EDIT_UNSUPPORTED"},
		{"unselected-continuation", "nodes: []\nrules:\n - DOMAIN,x.test,DIRECT\n - \"DOMAIN,y.\\\n   test,DIRECT\"\n - MATCH,DIRECT\n", "DOMAIN,x.test,DIRECT", "RULE_EDIT_UNSUPPORTED"},
		{"missing-match", "nodes: []\nrules:\n - DOMAIN,x.test,DIRECT\n", "DOMAIN,x.test,DIRECT", "RULE_EDIT_UNSUPPORTED"},
		{"multiple-match", "nodes: []\nrules:\n - DOMAIN,x.test,DIRECT\n - MATCH,DIRECT\n - MATCH,DIRECT\n", "DOMAIN,x.test,DIRECT", "RULE_EDIT_UNSUPPORTED"},
		{"empty", "nodes: []\nrules: []\n", "", "RULE_EDIT_UNSUPPORTED"},
		{"match-only", "nodes: []\nrules:\n - MATCH,DIRECT\n", "MATCH,DIRECT", "RULE_DELETE_PROTECTED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, p := webFixture(t)
			c, csrf := webLogin(t, w, p)
			raw := []byte(tc.config)
			if err := os.WriteFile(w.configPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			out := groupETagRequest(w, c, csrf, deleteRulePath, deleteRuleBody(0, tc.rule), `"`+shaHex(raw)+`"`)
			got, err := os.ReadFile(w.configPath)
			if out.Code != 422 || !strings.Contains(out.Body.String(), tc.code) || err != nil || !bytes.Equal(got, raw) {
				t.Fatal(out.Code, out.Body.String(), err)
			}
		})
	}
}

func TestWebRuleDeleteSecurityAndMethod(t *testing.T) {
	for _, mode := range []string{"auth", "origin", "csrf", "host", "busy", "content-type", "large-body", "multiple-if-match", "get", "put", "delete"} {
		t.Run(mode, func(t *testing.T) {
			w, p := webFixture(t)
			c, csrf := webLogin(t, w, p)
			raw := []byte(singleRuleConfig)
			if err := os.WriteFile(w.configPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			method := "POST"
			if mode == "get" || mode == "put" || mode == "delete" {
				method = strings.ToUpper(mode)
			}
			body := deleteRuleBody(0, "DOMAIN,old.example,DIRECT")
			if mode == "large-body" {
				body += strings.Repeat(" ", 16<<10)
			}
			r := httptest.NewRequest(method, "http://127.0.0.1:18089"+deleteRulePath, strings.NewReader(body))
			r.Header.Set("Origin", "http://127.0.0.1:18089")
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-CSRF-Token", csrf)
			r.Header.Set("If-Match", `"`+shaHex(raw)+`"`)
			if mode != "auth" {
				r.AddCookie(c)
			}
			want := 403
			switch mode {
			case "auth":
				want = 401
			case "origin":
				r.Header.Del("Origin")
			case "csrf":
				r.Header.Del("X-CSRF-Token")
			case "host":
				r.Host = "evil.example:18089"
			case "busy":
				w.actionMu.Lock()
				defer w.actionMu.Unlock()
				want = 409
			case "content-type":
				r.Header.Set("Content-Type", "text/plain")
				want = 422
			case "large-body":
				want = 422
			case "multiple-if-match":
				r.Header.Add("If-Match", `"`+shaHex(raw)+`"`)
				want = 428
			case "get":
				want = 404
			case "put", "delete":
				want = 405
			}
			calls := 0
			w.state = func() (bool, bool, error) { calls++; return true, true, nil }
			out := httptest.NewRecorder()
			w.ServeHTTP(out, r)
			got, err := os.ReadFile(w.configPath)
			if out.Code != want || err != nil || !bytes.Equal(got, raw) || calls != 0 {
				t.Fatal(out.Code, out.Body.String(), calls, err)
			}
		})
	}
}

func TestWebRuleDeleteRemainingValidation(t *testing.T) {
	for _, tc := range []struct {
		name, setRule    string
		removeSet, valid bool
	}{
		{"valid-remaining", `{"domain":["ok.example"]}`, false, true},
		{"invalid-remaining-cidr", `{"ip_cidr":["SECRET_BAD_CIDR"]}`, false, false},
		{"invalid-remaining-regex", `{"domain_regex":["["]}`, false, false},
		{"invalid-remaining-field", `{"SECRET_UNKNOWN":true}`, false, false},
		{"removed-invalid", `{"ip_cidr":["SECRET_BAD_CIDR"]}`, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, p := webFixture(t)
			c, csrf := webLogin(t, w, p)
			set := []byte(`{"version":3,"rules":[` + tc.setRule + `]}`)
			if err := os.WriteFile(filepath.Join(filepath.Dir(w.configPath), "fixture.json"), set, 0600); err != nil {
				t.Fatal(err)
			}
			raw := []byte("nodes: []\nrule-sets:\n  audited:\n    path: fixture.json\n    sha256: " + shaHex(set) + "\nrules:\n - DOMAIN,old.example,DIRECT\n - RULE-SET,audited,DIRECT\n - MATCH,DIRECT\n")
			if err := os.WriteFile(w.configPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			index, rule := 0, "DOMAIN,old.example,DIRECT"
			if tc.removeSet {
				index, rule = 1, "RULE-SET,audited,DIRECT"
			}
			calls := 0
			w.state = func() (bool, bool, error) { calls++; return false, false, nil }
			out := groupETagRequest(w, c, csrf, deleteRulePath, deleteRuleBody(index, rule), `"`+shaHex(raw)+`"`)
			got, err := os.ReadFile(w.configPath)
			wantStatus := 422
			if tc.valid {
				wantStatus = 200
			}
			want := raw
			if tc.valid {
				want = bytes.Replace(raw, []byte(" - "+rule+"\n"), nil, 1)
			}
			if out.Code != wantStatus || err != nil || !bytes.Equal(got, want) || strings.Contains(out.Body.String(), "SECRET") || !tc.valid && (calls != 0 || !strings.Contains(out.Body.String(), "CONFIG_VALIDATION_FAILED")) {
				t.Fatal(out.Code, out.Body.String(), calls, err)
			}
		})
	}
	for _, remaining := range []string{"IP-CIDR,SECRET_BAD,DIRECT", "DOMAIN,x.test,SECRET_TARGET"} {
		t.Run(remaining, func(t *testing.T) {
			w, p := webFixture(t)
			c, csrf := webLogin(t, w, p)
			raw := []byte("nodes: []\nrules:\n - DOMAIN,old.example,DIRECT\n - " + remaining + "\n - MATCH,DIRECT\n")
			if err := os.WriteFile(w.configPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			out := groupETagRequest(w, c, csrf, deleteRulePath, deleteRuleBody(0, "DOMAIN,old.example,DIRECT"), `"`+shaHex(raw)+`"`)
			got, err := os.ReadFile(w.configPath)
			if out.Code != 422 || err != nil || !bytes.Equal(got, raw) || strings.Contains(out.Body.String(), "SECRET") || !strings.Contains(out.Body.String(), "CONFIG_VALIDATION_FAILED") {
				t.Fatal(out.Code, out.Body.String(), err)
			}
		})
	}
}

// Inject an external editor at the real SDK's first context error check. This
// exercises the fresh-source read deterministically, without a production seam,
// timing races, or replacing the real RULE-SET constructor.
type deleteRuleEditorContext struct {
	context.Context
	once sync.Once
	edit func()
}

func (c *deleteRuleEditorContext) Err() error { c.once.Do(c.edit); return c.Context.Err() }

func TestWebRuleDeleteFreshSourceRecheck(t *testing.T) {
	w, p := webFixture(t)
	c, csrf := webLogin(t, w, p)
	set := []byte(`{"version":3,"rules":[{"domain":["ok.example"]}]}`)
	if err := os.WriteFile(filepath.Join(filepath.Dir(w.configPath), "fixture.json"), set, 0600); err != nil {
		t.Fatal(err)
	}
	raw := []byte("nodes: []\nrule-sets:\n  audited:\n    path: fixture.json\n    sha256: " + shaHex(set) + "\nrules:\n - DOMAIN,old.example,DIRECT\n - RULE-SET,audited,DIRECT\n - MATCH,DIRECT\n")
	if err := os.WriteFile(w.configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	changed := append(bytes.Clone(raw), []byte("# external editor\n")...)
	edited := false
	ctx := &deleteRuleEditorContext{Context: context.Background(), edit: func() {
		edited = true
		if err := os.WriteFile(w.configPath, changed, 0600); err != nil {
			t.Fatal(err)
		}
	}}
	r := httptest.NewRequest("POST", "http://127.0.0.1:18089"+deleteRulePath, strings.NewReader(deleteRuleBody(0, "DOMAIN,old.example,DIRECT"))).WithContext(ctx)
	r.AddCookie(c)
	r.Header.Set("Origin", "http://127.0.0.1:18089")
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("If-Match", `"`+shaHex(raw)+`"`)
	calls := 0
	w.state = func() (bool, bool, error) { calls++; return true, true, nil }
	out := httptest.NewRecorder()
	w.ServeHTTP(out, r)
	got, err := os.ReadFile(w.configPath)
	if out.Code != 412 || !strings.Contains(out.Body.String(), "CONFIG_CONFLICT") || !edited || calls != 0 || err != nil || !bytes.Equal(got, changed) {
		t.Fatal(out.Code, out.Body.String(), edited, calls, err)
	}
}

func TestWebRuleDeleteStartupRealRouteIPC(t *testing.T) {
	for _, mode := range []string{"success", "failure", "stopped"} {
		t.Run(mode, func(t *testing.T) {
			w, p := webFixture(t)
			c, csrf := webLogin(t, w, p)
			raw := []byte(singleRuleConfig)
			if err := os.WriteFile(w.configPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			old := w.beginStartup("start", "MANUAL_START")
			calls, mutation := webStartupRouteIPC(t, w, "reload", mode == "failure")
			w.state = func() (bool, bool, error) { return mode != "stopped", mode != "stopped", nil }
			out := groupETagRequest(w, c, csrf, deleteRulePath, deleteRuleBody(0, "DOMAIN,old.example,DIRECT"), `"`+shaHex(raw)+`"`)
			var result struct {
				Saved, Applied, Deleted bool
				ApplyStatus             string `json:"apply_status"`
			}
			if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &result) != nil || !result.Saved || !result.Deleted || result.Applied != (mode == "success") || result.ApplyStatus != map[string]string{"success": "APPLIED", "failure": "APPLY_FAILED", "stopped": "SAVED_STOPPED"}[mode] {
				t.Fatal(out.Code, out.Body.String())
			}
			got, err := os.ReadFile(w.configPath)
			want := bytes.Replace(raw, []byte("  - 'DOMAIN,old.example,DIRECT' # keep\n"), nil, 1)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("save lost", err)
			}
			if mode == "stopped" {
				if len(*calls) != 0 || w.startupLatest != old || !strings.Contains(out.Body.String(), `"startup_operation":null`) {
					t.Fatal(*calls, out.Body.String())
				}
				return
			}
			if !reflect.DeepEqual(*calls, []string{"status", "startup.read", "reload"}) {
				t.Fatal(*calls)
			}
			webStartupAssertRouteReference(t, w, out.Body.Bytes(), "SAVE_RULE", "reload", mutation)
			trace := webStartupHTTPRequest(w, c, "?operation_id="+*mutation.OperationID, nil)
			var read st.ReadResponse
			if trace.Code != 200 || st.Decode(bytes.NewReader(trace.Body.Bytes()), &read) != nil || read.Trace == nil || read.Trace.Source != "SAVE_RULE" || read.Trace.Operation != "RELOAD" {
				t.Fatal(trace.Code, trace.Body.String())
			}
		})
	}
}

func TestWebRuleDeleteApplyOwnsDisconnectAndLock(t *testing.T) {
	w, p := webFixture(t)
	c, csrf := webLogin(t, w, p)
	raw := []byte(singleRuleConfig)
	if err := os.WriteFile(w.configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	w.state = func() (bool, bool, error) { return true, true, nil }
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	w.serviceAction = func(applyCtx context.Context, action string, consent bool) error {
		calls++
		cancel()
		if action != "reload" || !consent || applyCtx.Err() != nil {
			t.Error("apply detached/cancelled/wrong action")
		}
		if _, ok := applyCtx.Deadline(); !ok {
			t.Error("unbounded apply")
		}
		if w.actionMu.TryLock() {
			w.actionMu.Unlock()
			t.Error("mutation lock released early")
		}
		return errors.New("SECRET_NATIVE_FAILURE")
	}
	r := httptest.NewRequest("POST", "http://127.0.0.1:18089"+deleteRulePath, strings.NewReader(deleteRuleBody(0, "DOMAIN,old.example,DIRECT"))).WithContext(ctx)
	r.AddCookie(c)
	r.Header.Set("Origin", "http://127.0.0.1:18089")
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("If-Match", `"`+shaHex(raw)+`"`)
	out := httptest.NewRecorder()
	w.ServeHTTP(out, r)
	if out.Code != 200 || calls != 1 || ctx.Err() != context.Canceled || !strings.Contains(out.Body.String(), `"saved":true`) || !strings.Contains(out.Body.String(), `"apply_status":"APPLY_FAILED"`) || strings.Contains(out.Body.String(), "SECRET") {
		t.Fatal(out.Code, out.Body.String(), calls)
	}
	if !w.actionMu.TryLock() {
		t.Fatal("action lock not released after joined apply")
	}
	w.actionMu.Unlock()
}
