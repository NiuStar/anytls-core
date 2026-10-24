package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

func TestWebImportPinnedURLAndTLS(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Fragment != "" || r.URL.Path != "/subscribe/"+token {
			t.Error("credential route")
		}
		w.Write([]byte(webImportYAML))
	}))
	defer server.Close()
	sum := sha256.Sum256(server.Certificate().Raw)
	raw := "https://8.8.8.8:9443/subscribe/" + token + "#anytls-cert-sha256=" + hex.EncodeToString(sum[:])
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "8.8.8.8:9443" {
			t.Error(address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	b, e := webImportPinnedFetch(context.Background(), raw, dial)
	if e != nil || string(b) != webImportYAML || requests.Load() != 1 {
		t.Fatal(e, requests.Load())
	}
	wrong := strings.Replace(raw, hex.EncodeToString(sum[:]), strings.Repeat("0", 64), 1)
	if _, e = webImportPinnedFetch(context.Background(), wrong, dial); e == nil || requests.Load() != 1 {
		t.Fatal("wrong pin reached HTTP", e, requests.Load())
	}
	for _, bad := range []string{strings.Replace(raw, "8.8.8.8", "127.0.0.1", 1), strings.Replace(raw, "8.8.8.8", "sub.example", 1), strings.Replace(raw, "/subscribe/", "/other/", 1), raw + "&x=y", strings.Replace(raw, "#", "?secret=x#", 1), strings.Replace(raw, token, token+"=", 1), strings.Replace(raw, "9443", "0", 1), strings.Replace(raw, "#anytls", "#%61nytls", 1)} {
		if _, _, e := webImportPinnedURL(bad); e == nil {
			t.Fatal("accepted unsafe link")
		}
	}
	if _, e := webImportURL(raw); e == nil {
		t.Fatal("replace accepted bootstrap pin")
	}
}

func TestWebImportAppendAuthenticatedPreservesState(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "present"}[existing], func(t *testing.T) {
			w, password := webFixture(t)
			c, csrf := webLogin(t, w, password)
			original, _ := os.ReadFile(w.configPath)
			selected := []byte("stale-node\n")
			sub := []byte("{\"url\":\"https://sub.example/private?x=secret\"}\n")
			if existing {
				os.WriteFile(selectedPath(w.configPath), selected, 0600)
				os.WriteFile(w.subscriptionPath(), sub, 0600)
			}
			p := importPreview(t, w, c, csrf, map[string]any{"yaml": webImportYAML, "mode": "append_nodes"})
			if p["mode"] != "append_nodes" {
				t.Fatal(p)
			}
			before, _ := os.ReadFile(w.configPath)
			if !bytes.Equal(before, original) {
				t.Fatal("preview wrote")
			}
			r := importCommit(t, w, c, csrf, p)
			if r.Code != 400 {
				t.Fatal("replace consent authorized append", r.Code)
			}
			r = importRequest(t, w, c, csrf, "import/commit", map[string]any{"token": p["token"], "confirm_append": true, "confirm_insecure": true}, p["etag"].(string))
			if r.Code != 200 {
				t.Fatal(r.Code, r.Body.String())
			}
			after, _ := os.ReadFile(w.configPath)
			if !bytes.Contains(after, []byte("MATCH,DIRECT")) || !bytes.Contains(after, []byte("name: local")) {
				t.Fatal("routing lost")
			}
			for path, want := range map[string][]byte{selectedPath(w.configPath): selected, w.subscriptionPath(): sub} {
				got, e := os.ReadFile(path)
				if existing {
					if e != nil || !bytes.Equal(got, want) {
						t.Fatal("sidecar changed")
					}
				} else if !os.IsNotExist(e) {
					t.Fatal("sidecar created")
				}
			}
			w.state = func() (bool, bool, error) { return true, true, nil }
			p = importPreview(t, w, c, csrf, map[string]any{"yaml": webImportYAML, "mode": "append_nodes"})
			r = importRequest(t, w, c, csrf, "import/commit", map[string]any{"token": p["token"], "confirm_append": true, "confirm_insecure": true}, p["etag"].(string))
			if r.Code != 200 || !strings.Contains(r.Body.String(), `"changed":false`) {
				t.Fatal(r.Body.String())
			}
			got, _ := os.ReadFile(w.configPath)
			if !bytes.Equal(after, got) {
				t.Fatal("identical append not no-op")
			}
			bad := strings.Replace(webImportYAML, "password: secret", "password: changed", 1)
			r = importRequest(t, w, c, csrf, "import/preview", map[string]any{"yaml": bad, "mode": "append_nodes"}, "")
			if r.Code != 422 || !strings.Contains(r.Body.String(), "IMPORT_NODE_CONFLICT") {
				t.Fatal(r.Code, r.Body.String())
			}
		})
	}
}

func TestWebImportAppendRejectsAmbiguityAndInactiveBadNode(t *testing.T) {
	for _, dest := range []string{"nodes: []\nproxies: []\n", "x: &n []\nnodes: *n\n", "nodes: []\nnodes: []\n", "x: &n {nodes: []}\n<<: *n\n"} {
		if _, _, e := webImportAppend([]byte(dest), []byte(webImportYAML)); e == nil {
			t.Fatal("ambiguous destination accepted")
		}
	}
	bad := webImportYAML + ""
	bad = strings.Replace(bad, "port: 443", "port: 0", 1)
	if _, _, e := webImportAppend([]byte("nodes: []\n"), []byte(bad)); e == nil {
		t.Fatal("invalid inactive node accepted")
	}
}
