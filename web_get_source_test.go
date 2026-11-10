package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func getSourceFixture(t testing.TB, count int) (*webConsole, *http.Cookie) {
	t.Helper()
	dir := t.TempDir()
	var s strings.Builder
	s.WriteString("proxies:\n")
	for i := 0; i < count; i++ {
		fmt.Fprintf(&s, " - {name: n%d, type: anytls, server: 192.0.2.1, port: 443, password: secret, sni: example.invalid}\n", i)
	}
	s.WriteString("proxy-groups:\n - {name: main, type: select, proxies: [n0, n1], selected: n0}\nrules: ['MATCH,main']\n")
	config := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(config, []byte(s.String()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(selectedPath(config), []byte("n0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	passwordPath := filepath.Join(dir, "webui.password")
	password, err := webPassword(passwordPath, false)
	if err != nil {
		t.Fatal(err)
	}
	w := newWebConsole(config, passwordPath, 18089)
	w.state = func() (bool, bool, error) { return false, false, nil }
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": password})
	out := webRequest(w, "POST", "/api/v1/login", string(body), nil, "")
	if out.Code != 200 || len(out.Result().Cookies()) != 1 {
		t.Fatalf("login: %d %s", out.Code, out.Body.String())
	}
	return w, out.Result().Cookies()[0]
}

func TestWebGETSourceCountsAndParity(t *testing.T) {
	for _, size := range []int{20, 200} {
		for _, route := range []string{"nodes", "groups"} {
			t.Run(fmt.Sprintf("%s/%d", route, size), func(t *testing.T) {
				w, cookie := getSourceFixture(t, size)
				reads, parses := 0, 0
				w.getSourceRead = func(path string, limit int64, follow bool) ([]byte, error) {
					reads++
					return readSnapshotSource(path, limit, follow)
				}
				w.getYAMLParse = func(b []byte, doc *yaml.Node) error { parses++; return yaml.Unmarshal(b, doc) }
				out := webRequest(w, "GET", "/api/v1/"+route, "", cookie, "")
				if out.Code != 200 {
					t.Fatalf("not accepted: %d %s", out.Code, out.Body.String())
				}
				oracle := httptest.NewRecorder()
				w.getSourceBaselineOracle(oracle, httptest.NewRequest("GET", "http://127.0.0.1:18089/api/v1/"+route, nil), webSession{})
				if oracle.Code != out.Code || !bytes.Equal(oracle.Body.Bytes(), out.Body.Bytes()) {
					t.Fatalf("frozen baseline complete response mismatch: %d %s", oracle.Code, oracle.Body.String())
				}
				var public any
				if err := json.Unmarshal(out.Body.Bytes(), &public); err != nil {
					t.Fatal(err)
				}
				canonical, _ := json.Marshal(public)
				if root := os.Getenv("ANYTLS_GET_ORACLE"); root != "" {
					path := filepath.Join(root, fmt.Sprintf("%s-%d.json", route, size))
					if os.Getenv("ANYTLS_GET_RECORD") == "1" {
						if err := os.WriteFile(path, canonical, 0600); err != nil {
							t.Fatal(err)
						}
					} else {
						want, err := os.ReadFile(path)
						if err != nil || !bytes.Equal(want, canonical) {
							t.Fatalf("complete public JSON parity failed: %v\nwant %s\ngot %s", err, want, canonical)
						}
					}
				}
				wantReads := 1
				if route == "nodes" {
					wantReads = 2
				}
				t.Logf("HTTP 200 size=%d reads=%d YAML parses=%d responseSHA=%s", size, reads, parses, shaHex(canonical))
				if reads != wantReads || parses != 1 {
					t.Errorf("GET work: reads=%d want=%d parses=%d want=1", reads, wantReads, parses)
				}
				reads, parses = 0, 0
				next := webRequest(w, "GET", "/api/v1/"+route, "", cookie, "")
				if next.Code != 200 || !bytes.Equal(next.Body.Bytes(), out.Body.Bytes()) || reads != wantReads || parses != 1 {
					t.Errorf("independent GET not reconstructed: reads=%d parses=%d", reads, parses)
				}
				reads, parses = 0, 0
				denied := webRequest(w, "GET", "/api/v1/"+route, "", nil, "")
				if denied.Code != 401 || reads != 0 || parses != 0 {
					t.Fatal("anonymous GET touched source")
				}
			})
		}
	}
}

func TestWebGETSourceFreshness(t *testing.T) {
	for _, kind := range []string{"config", "selected", "rules", "ca", "missing-config", "invalid-config", "missing-selected", "invalid-selected", "config-symlink", "selected-symlink", "metadata-error"} {
		t.Run(kind, func(t *testing.T) {
			w, cookie := getSourceFixture(t, 20)
			original := webRequest(w, "GET", "/api/v1/nodes", "", cookie, "")
			if original.Code != 200 {
				t.Fatal(original.Code)
			}
			raw, err := os.ReadFile(w.configPath)
			if err != nil {
				t.Fatal(err)
			}
			wantChange := true
			wantStatus := 200
			switch kind {
			case "config":
				raw = bytes.ReplaceAll(raw, []byte("192.0.2.1"), []byte("192.0.2.2"))
			case "selected":
				err = os.WriteFile(selectedPath(w.configPath), []byte("n1\n"), 0600)
			case "rules":
				raw = bytes.ReplaceAll(raw, []byte("MATCH,main"), []byte("MATCH,DIRECT"))
			case "ca":
				raw = append(raw, []byte("# changed CA configuration\n")...)
				raw = bytes.Replace(raw, []byte("sni: example.invalid"), []byte("ca: /nonexistent/ca.pem, sni: example.invalid"), 1)
			case "missing-config":
				err = os.Remove(w.configPath)
				wantStatus = 500
			case "invalid-config":
				raw = []byte("proxies: [")
				wantStatus = 422
			case "missing-selected":
				err = os.Remove(selectedPath(w.configPath))
			case "invalid-selected":
				err = os.WriteFile(selectedPath(w.configPath), []byte("not-a-node\n"), 0600)
			case "config-symlink":
				target := w.configPath + ".target"
				if err = os.WriteFile(target, raw, 0600); err == nil {
					err = os.Rename(w.configPath, w.configPath+".old")
				}
				if err == nil {
					err = os.Symlink(target, w.configPath)
				}
				wantStatus = 500
			case "selected-symlink":
				target := w.configPath + ".target"
				if err = os.WriteFile(target, []byte("n1\n"), 0600); err == nil {
					err = os.Rename(selectedPath(w.configPath), selectedPath(w.configPath)+".old")
				}
				if err == nil {
					err = os.Symlink(target, selectedPath(w.configPath))
				}
			case "metadata-error":
				w.getSourceRead = func(path string, limit int64, follow bool) ([]byte, error) {
					if path == w.configPath {
						return nil, fmt.Errorf("snapshot source changed during acquisition")
					}
					return readSnapshotSource(path, limit, follow)
				}
				wantStatus = 500
			}
			if err != nil {
				t.Fatal(err)
			}
			if kind == "config" || kind == "rules" || kind == "ca" || kind == "invalid-config" {
				if err = os.WriteFile(w.configPath, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			next := webRequest(w, "GET", "/api/v1/nodes", "", cookie, "")
			if next.Code != wantStatus || wantChange && bytes.Equal(next.Body.Bytes(), original.Body.Bytes()) {
				t.Fatalf("stale GET: %d %s", next.Code, next.Body.String())
			}
			if kind != "metadata-error" {
				oracle := httptest.NewRecorder()
				w.getSourceBaselineOracle(oracle, httptest.NewRequest("GET", "http://127.0.0.1:18089/api/v1/nodes", nil), webSession{})
				if next.Code != oracle.Code || !bytes.Equal(next.Body.Bytes(), oracle.Body.Bytes()) {
					t.Fatal("changed-source complete baseline parity failed")
				}
			}
			// CA files/rule-set files are not read by these DTO routes, just as before;
			// changing config references must still change its complete ETag response.
		})
	}
}

func BenchmarkWebGETSource(b *testing.B) {
	for _, size := range []int{20, 200} {
		for _, route := range []string{"nodes", "groups"} {
			b.Run(fmt.Sprintf("%s/%d", route, size), func(b *testing.B) {
				w, cookie := getSourceFixture(b, size)
				reads, parses := 0, 0
				w.getSourceRead = func(path string, limit int64, follow bool) ([]byte, error) {
					reads++
					return readSnapshotSource(path, limit, follow)
				}
				w.getYAMLParse = func(raw []byte, doc *yaml.Node) error { parses++; return yaml.Unmarshal(raw, doc) }
				b.ReportAllocs()
				b.ResetTimer()
				start := time.Now()
				for i := 0; i < b.N; i++ {
					out := webRequest(w, "GET", "/api/v1/"+route, "", cookie, "")
					if out.Code != 200 {
						b.Fatal(out.Code)
					}
				}
				elapsed := time.Since(start)
				b.StopTimer()
				b.ReportMetric(float64(reads)/float64(b.N), "reads/op")
				b.ReportMetric(float64(parses)/float64(b.N), "yaml-parses/op")
				b.ReportMetric(float64(elapsed.Nanoseconds())/float64(b.N), "wall-ns/op")
			})
		}
	}
}
