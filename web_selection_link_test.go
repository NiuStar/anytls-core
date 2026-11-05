package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const selectionLinkConfig = `nodes:
 - {name: a, type: anytls, server: 127.0.0.1, port: 443, password: secret, skip-cert-verify: true}
 - {name: b, type: anytls, server: 127.0.0.2, port: 443, password: secret, skip-cert-verify: true}
proxy-groups:
 - {name: dedicated, type: select, proxies: [a, b, DIRECT], selected: a}
 - {name: default, type: select, proxies: [a, b, DIRECT], selected: DIRECT}
rules: ['DOMAIN,example.test,dedicated', 'MATCH,default']
`

func linkFixture(t *testing.T, config, selection string) (*webConsole, *http.Cookie, string) {
	t.Helper()
	w, password := webFixture(t)
	if err := os.WriteFile(w.configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if selection != "" {
		if err := os.WriteFile(selectedPath(w.configPath), []byte(selection+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := webValidateConfig(w.configPath, []byte(config)); err != nil {
		t.Fatalf("fixture validation: %v", err)
	}
	cookie, csrf := webLogin(t, w, password)
	return w, cookie, csrf
}

func linkPost(t *testing.T, w *webConsole, cookie *http.Cookie, csrf, path, body string) int {
	t.Helper()
	b, err := os.ReadFile(w.configPath)
	if err != nil {
		t.Fatal(err)
	}
	out := groupETagRequest(w, cookie, csrf, path, body, `"`+shaHex(b)+`"`)
	if out.Code != 200 {
		t.Fatalf("POST %s: %d %s", path, out.Code, out.Body.String())
	}
	return out.Code
}

func linkAssert(t *testing.T, w *webConsole, selected, group, finalServer string) {
	t.Helper()
	b, err := os.ReadFile(w.configPath)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := loadNodesBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	got, err := selectedNode(w.configPath, nodes)
	if err != nil || got != selected {
		t.Fatalf("selection=%q want=%q err=%v", got, selected, err)
	}
	var doc struct {
		Groups []proxyGroup `yaml:"proxy-groups"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, g := range doc.Groups {
		if g.Name == "default" && g.Selected != group {
			t.Fatalf("default=%q want=%q", g.Selected, group)
		}
		if g.Name == "dedicated" && g.Selected != "a" {
			t.Fatalf("dedicated changed: %+v", g)
		}
	}
	n, err := choose(nodes, selected)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := buildNode(n, "proxy", 11080, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyRoutingBytes(w.configPath, b, nodes, n, cfg, true); err != nil {
		t.Fatal(err)
	}
	final := cfg["route"].(map[string]any)["final"]
	for _, out := range cfg["outbounds"].([]any) {
		v := out.(map[string]any)
		if v["tag"] == final {
			if v["server"] != finalServer {
				t.Fatalf("final outbound=%v want server=%s", v, finalServer)
			}
			return
		}
	}
	t.Fatalf("missing final outbound %v", final)
}

func TestWebSelectionLinkNodeAndSameNodeRepair(t *testing.T) {
	for _, saved := range []string{"a", "b"} {
		t.Run(saved, func(t *testing.T) {
			w, cookie, csrf := linkFixture(t, selectionLinkConfig, saved)
			calls := 0
			w.state = func() (bool, bool, error) { calls++; return true, true, nil }
			w.serviceAction = func(context.Context, string, bool) error { calls++; return nil }
			linkPost(t, w, cookie, csrf, "/api/v1/nodes/selection", `{"name":"b","confirm_insecure":true}`)
			linkAssert(t, w, "b", "b", "127.0.0.2")
			if calls != 3 {
				t.Fatalf("expected one reload and two state reads, got %d", calls)
			}
			calls = 0
			linkPost(t, w, cookie, csrf, "/api/v1/nodes/selection", `{"name":"b","confirm_insecure":true}`)
			if calls != 0 {
				t.Fatalf("no-op touched service: %d", calls)
			}
		})
	}
}

func TestWebSelectionLinkReverseAndDedicated(t *testing.T) {
	w, cookie, csrf := linkFixture(t, selectionLinkConfig, "a")
	linkPost(t, w, cookie, csrf, "/api/v1/groups/selection", `{"group":"default","choice":"b"}`)
	linkAssert(t, w, "b", "b", "127.0.0.2")
	linkPost(t, w, cookie, csrf, "/api/v1/groups/selection", `{"group":"dedicated","choice":"a"}`)
	nodes, _ := loadNodes(w.configPath)
	got, _ := selectedNode(w.configPath, nodes)
	if got != "b" {
		t.Fatal("dedicated rewrote selection")
	}
	// Same group/choice request repairs a stale startup selection too.
	if err := webAtomicWrite(selectedPath(w.configPath), []byte("a\n")); err != nil {
		t.Fatal(err)
	}
	linkPost(t, w, cookie, csrf, "/api/v1/groups/selection", `{"group":"default","choice":"b"}`)
	linkAssert(t, w, "b", "b", "127.0.0.2")
}

func TestWebSelectionLinkEffectiveDTO(t *testing.T) {
	for _, tc := range []struct{ name, config, want string }{
		{"direct", selectionLinkConfig, "a"},
		{"concrete", strings.Replace(selectionLinkConfig, "selected: DIRECT}", "selected: b}", 1), "a"},
		{"nested", strings.Replace(selectionLinkConfig, "proxies: [a, b, DIRECT], selected: DIRECT}", "proxies: [a, b, DIRECT, dedicated], selected: dedicated}", 1), "a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, cookie, _ := linkFixture(t, tc.config, "a")
			before, _ := os.ReadFile(w.configPath)
			out := webRequest(w, "GET", "/api/v1/nodes", "", cookie, "")
			var dto struct {
				Nodes []struct {
					Name     string `json:"name"`
					Selected bool   `json:"selected"`
				} `json:"nodes"`
			}
			if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &dto) != nil {
				t.Fatalf("GET: %d %s", out.Code, out.Body.String())
			}
			got := ""
			for _, n := range dto.Nodes {
				if n.Selected {
					if got != "" {
						t.Fatal("multiple selected")
					}
					got = n.Name
				}
			}
			if got != tc.want {
				t.Fatalf("effective selected=%q want=%q", got, tc.want)
			}
			after, _ := os.ReadFile(w.configPath)
			if !bytes.Equal(before, after) {
				t.Fatal("GET wrote config")
			}
		})
	}
}

func TestWebSelectionLinkRejectsStaleAndInvalid(t *testing.T) {
	for _, tc := range []struct {
		name, body, etag string
		status           int
	}{
		{"stale", `{"name":"b"}`, `"stale"`, 412},
		{"unknown", `{"name":"missing"}`, "", 422},
		{"direct", `{"name":"DIRECT"}`, "", 422},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, cookie, csrf := linkFixture(t, selectionLinkConfig, "a")
			before, _ := os.ReadFile(w.configPath)
			sel, _ := os.ReadFile(selectedPath(w.configPath))
			etag := tc.etag
			if etag == "" {
				etag = `"` + shaHex(before) + `"`
			}
			calls := 0
			w.state = func() (bool, bool, error) { calls++; return true, true, nil }
			w.serviceAction = func(context.Context, string, bool) error { calls++; return nil }
			out := groupETagRequest(w, cookie, csrf, "/api/v1/nodes/selection", tc.body, etag)
			after, _ := os.ReadFile(w.configPath)
			next, _ := os.ReadFile(selectedPath(w.configPath))
			if out.Code != tc.status || !bytes.Equal(before, after) || !bytes.Equal(sel, next) || calls != 0 {
				t.Fatalf("rejection status=%d calls=%d body=%s", out.Code, calls, out.Body.String())
			}
		})
	}
}
