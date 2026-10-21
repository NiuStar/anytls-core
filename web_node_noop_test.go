package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// Exercise the real authenticated PUT, including optimistic concurrency and
// filesystem no-write semantics, rather than only the pure YAML helper.
func webNodePut(t *testing.T, w *webConsole, cookie *http.Cookie, csrf string, in webNodeEdit) *httptest.ResponseRecorder {
	t.Helper()
	get := webRequest(w, "GET", "/api/v1/config", "", cookie, "")
	if get.Code != http.StatusOK {
		t.Fatalf("config GET: %d %s", get.Code, get.Body.String())
	}
	body, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("PUT", "http://127.0.0.1:18089/api/v1/nodes", bytes.NewReader(body))
	r.Header.Set("Origin", "http://127.0.0.1:18089")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("If-Match", get.Header().Get("ETag"))
	r.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, r)
	return rec
}

func webNodeFile(t *testing.T, w *webConsole, original string) os.FileInfo {
	t.Helper()
	if err := os.WriteFile(w.configPath, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	// Distinct from both creation time and current time; no timing sleeps.
	stamp := time.Unix(1600000000, 0)
	if err := os.Chtimes(w.configPath, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(w.configPath)
	if err != nil {
		t.Fatal(err)
	}
	w.metaMu.Lock()
	w.pending = false
	w.metaMu.Unlock()
	w.baseline = w.fingerprint()
	return st
}

func webNodeUnwritten(t *testing.T, w *webConsole, before os.FileInfo, original string) {
	t.Helper()
	after, err := os.Stat(w.configPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(w.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original || !os.SameFile(before, after) || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("node PUT rewrote bytes, inode, mode, or mtime")
	}
}

func TestWebNodeSameValueHTTPNoWrite(t *testing.T) {
	for _, tc := range []struct{ name, config, sni, password string }{
		{"absent-sni", "nodes:\n - {name: example, type: anytls, server: 127.0.0.1, port: 443, password: secret} # compact\n", "", ""},
		{"explicit-empty-sni", "nodes: [{name: example, type: anytls, server: 127.0.0.1, port: 443, password: secret, sni: ''}] # empty\n", "", ""},
		{"explicit-sni", "nodes: [{name: example, type: anytls, server: 127.0.0.1, port: 443, password: secret, sni: vpn.test}] # preserve\n", "vpn.test", ""},
		{"scalar-tags-and-unrelated-alias", "x-value: &other '00123'\nnodes:\n - name: example\n   type: anytls\n   server: !!str 127.0.0.1 # server comment\n   port: !!int 0x1bb # nondecimal\n   password: !!str '00123' # secret comment\n   x-custom: *other\n", "", "00123"},
		// The actual typed loader reads top-level sni, not tls.server_name.
		{"nested-tls-is-unknown", "nodes: [{name: example, type: anytls, server: 127.0.0.1, port: 443, password: secret, tls: {server_name: ignored.test}}]\n", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, password := webFixture(t)
			before := webNodeFile(t, w, tc.config)
			cookie, csrf := webLogin(t, w, password)
			rec := webNodePut(t, w, cookie, csrf, webNodeEdit{Name: "example", Server: "127.0.0.1", Port: 443, Password: tc.password, SNI: tc.sni})
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"changed":false`) || !strings.Contains(rec.Body.String(), `"pendingReload":false`) {
				t.Fatalf("PUT: %d %s", rec.Code, rec.Body.String())
			}
			webNodeUnwritten(t, w, before, tc.config)
		})
	}
}

func TestWebNodeSingleFieldHTTPChange(t *testing.T) {
	const original = "x-value: &other '00123'\nnodes:\n - name: example\n   type: anytls\n   server: !!str 127.0.0.1 # server comment\n   port: !!int 0x1bb # port comment\n   password: !!str '00123' # secret comment\n   tls: {server_name: ignored.test}\n   x-custom: *other\n"
	for _, field := range []string{"server", "port", "password", "sni"} {
		t.Run(field, func(t *testing.T) {
			w, password := webFixture(t)
			webNodeFile(t, w, original)
			cookie, csrf := webLogin(t, w, password)
			in := webNodeEdit{Name: "example", Server: "127.0.0.1", Port: 443}
			want := node{Name: "example", Type: "anytls", Server: in.Server, Port: in.Port, Password: "00123"}
			switch field {
			case "server":
				in.Server, want.Server = "127.0.0.2", "127.0.0.2"
			case "port":
				in.Port, want.Port = 8443, 8443
			case "password":
				in.Password, want.Password = "replacement", "replacement"
			case "sni":
				in.SNI, want.SNI = "vpn.test", "vpn.test"
			}
			rec := webNodePut(t, w, cookie, csrf, in)
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"changed":true`) || !strings.Contains(rec.Body.String(), `"pendingReload":true`) {
				t.Fatalf("PUT: %d %s", rec.Code, rec.Body.String())
			}
			out, err := os.ReadFile(w.configPath)
			if err != nil {
				t.Fatal(err)
			}
			nodes, err := loadNodesBytes(out)
			if err != nil || len(nodes) != 1 || nodes[0] != want {
				t.Fatalf("typed loader did not read expected edit: %v", err)
			}
			var before, after yaml.Node
			if yaml.Unmarshal([]byte(original), &before) != nil || yaml.Unmarshal(out, &after) != nil {
				t.Fatal("invalid YAML")
			}
			oldTarget := snapshotYAMLField(before.Content[0], "nodes").Content[0]
			newTarget := snapshotYAMLField(after.Content[0], "nodes").Content[0]
			for i := 0; i < len(oldTarget.Content); i += 2 {
				key := oldTarget.Content[i].Value
				if key == field {
					continue
				}
				// Re-encoding just the leaf ignores whole-document indentation
				// but checks tags, spelling, comments, and unrelated aliases.
				a, e1 := yaml.Marshal(oldTarget.Content[i+1])
				b, e2 := yaml.Marshal(snapshotYAMLField(newTarget, key))
				if e1 != nil || e2 != nil || !bytes.Equal(a, b) {
					t.Fatalf("unrelated leaf %s changed", key)
				}
			}
			if field != "sni" && snapshotYAMLField(newTarget, "sni") != nil {
				t.Fatal("materialized absent empty sni")
			}
			// An identical resubmission after a real change must also not write.
			st, err := os.Stat(w.configPath)
			if err != nil {
				t.Fatal(err)
			}
			rec = webNodePut(t, w, cookie, csrf, in)
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"changed":false`) {
				t.Fatalf("repeat PUT: %d %s", rec.Code, rec.Body.String())
			}
			webNodeUnwritten(t, w, st, string(out))
		})
	}
}

func TestWebNodeSameValueRejectsIndirectTargets(t *testing.T) {
	for _, tc := range []struct{ name, config string }{
		{"alias-key", "x-key: &key server\nnodes:\n - name: example\n   type: anytls\n   *key : 127.0.0.1\n   port: 443\n   password: secret\n"},
		{"merge-key", "base: &base {server: 127.0.0.1}\nnodes: [{name: example, type: anytls, <<: *base, port: 443, password: secret}]\n"},
		{"alias-leaf", "x-server: &server 127.0.0.1\nnodes: [{name: example, type: anytls, server: *server, port: 443, password: secret}]\n"},
		{"shared-server-leaf", "nodes: [{name: example, type: anytls, server: &server 127.0.0.1, port: 443, password: secret}]\nx-server: *server\n"},
		{"shared-password-blank-preserve", "nodes: [{name: example, type: anytls, server: 127.0.0.1, port: 443, password: &pw secret}]\nx-password: *pw\n"},
		{"alias-password-blank-preserve", "x-password: &pw secret\nnodes: [{name: example, type: anytls, server: 127.0.0.1, port: 443, password: *pw}]\n"},
		{"shared-empty-sni", "nodes: [{name: example, type: anytls, server: 127.0.0.1, port: 443, password: secret, sni: &sni ''}]\nx-sni: *sni\n"},
		{"shared-mapping", "nodes: [&node {name: example, type: anytls, server: 127.0.0.1, port: 443, password: secret}]\nx-node: *node\n"},
		{"shared-sequence", "nodes: &nodes [{name: example, type: anytls, server: 127.0.0.1, port: 443, password: secret}]\nx-nodes: *nodes\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Prove the fixture reaches editing policy, not a typed decode error.
			nodes, err := loadNodesBytes([]byte(tc.config))
			if err != nil || len(nodes) != 1 || nodes[0].Server != "127.0.0.1" || nodes[0].Password != "secret" {
				t.Fatalf("invalid typed fixture: %v", err)
			}
			w, password := webFixture(t)
			before := webNodeFile(t, w, tc.config)
			cookie, csrf := webLogin(t, w, password)
			rec := webNodePut(t, w, cookie, csrf, webNodeEdit{Name: "example", Server: "127.0.0.1", Port: 443})
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("indirect no-op accepted: %d %s", rec.Code, rec.Body.String())
			}
			webNodeUnwritten(t, w, before, tc.config)
		})
	}
}
