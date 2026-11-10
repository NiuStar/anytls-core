package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestWebGETSourceFrozenCompatibility(t *testing.T) {
	samples := []string{
		"", "null\n", "[]\n", "{}\n", "proxies: [\n", "proxies: []\nproxies: []\n",
		"ipv6: maybe\nproxies: []\n", "ipv6: true\nproxies: []\n",
		"proxies: [{name: a}, {name: a}]\n", "proxies: [{name: 123, password: 00123}]\n",
		"base: &base {name: a, type: anytls, password: secret, server: 192.0.2.1, port: 443}\nproxies: [*base]\nrules: ['MATCH,DIRECT']\n",
		"proxies: []\nproxy-groups: not-a-sequence\n", "proxies: []\nrules: not-a-sequence\n",
		"proxies: []\n---\nproxies: [{name: ignored}]\n",
	}
	for i, s := range samples {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			w, cookie := getSourceFixture(t, 20)
			if err := os.WriteFile(w.configPath, []byte(s), 0600); err != nil {
				t.Fatal(err)
			}
			for _, route := range []string{"nodes", "groups"} {
				got := webRequest(w, "GET", "/api/v1/"+route, "", cookie, "")
				oracle := httptest.NewRecorder()
				w.getSourceBaselineOracle(oracle, httptest.NewRequest("GET", "http://127.0.0.1:18089/api/v1/"+route, nil), webSession{})
				if got.Code != oracle.Code || !bytes.Equal(got.Body.Bytes(), oracle.Body.Bytes()) {
					t.Fatalf("%s complete baseline parity: got %d %s want %d %s", route, got.Code, got.Body.String(), oracle.Code, oracle.Body.String())
				}
			}
		})
	}
}

func TestWebGETSourceDoesNotLeasePOST(t *testing.T) {
	w, password := webFixture(t)
	cookie, csrf := webLogin(t, w, password)
	snapshot := webRequest(w, "GET", "/api/v1/groups", "", cookie, "")
	var public struct {
		ETag string `json:"etag"`
	}
	if snapshot.Code != 200 || json.Unmarshal(snapshot.Body.Bytes(), &public) != nil {
		t.Fatal(snapshot.Code)
	}
	raw, err := os.ReadFile(w.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(w.configPath, append(raw, []byte("# external mutation\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	w.getSourceRead = func(string, int64, bool) ([]byte, error) {
		t.Error("POST used GET reader")
		return nil, errors.New("GET reader not allowed")
	}
	w.getYAMLParse = func([]byte, *yaml.Node) error {
		t.Error("POST used GET document")
		return errors.New("GET document not allowed")
	}
	out := groupETagRequest(w, cookie, csrf, "/api/v1/groups/selection", `{"group":"local","choice":"DIRECT"}`, public.ETag)
	if out.Code != 412 {
		t.Fatalf("POST did not fresh-CAS reject stale GET: %d %s", out.Code, out.Body.String())
	}
}

func TestWebGETSourceExternalFilesRemainFresh(t *testing.T) {
	for _, kind := range []string{"ca", "rules"} {
		t.Run(kind, func(t *testing.T) {
			w, cookie := getSourceFixture(t, 20)
			ca, _ := runtimeCertificate(t)
			caPath := filepath.Join(filepath.Dir(w.configPath), "ca.pem")
			rulesPath := filepath.Join(filepath.Dir(w.configPath), "rules.json")
			rule := []byte(`{"version":3,"rules":[{"domain_suffix":["example.invalid"]}]}`)
			runtimeWrite(t, caPath, ca, 0600)
			runtimeWrite(t, rulesPath, rule, 0600)
			raw, err := os.ReadFile(w.configPath)
			if err != nil {
				t.Fatal(err)
			}
			raw = bytes.ReplaceAll(raw, []byte("sni: example.invalid"), []byte(fmt.Sprintf("sni: example.invalid, ca: %q", caPath)))
			raw = append(raw, []byte(fmt.Sprintf("rule-sets:\n test: {path: %q, sha256: %s}\n", rulesPath, shaHex(rule)))...)
			runtimeWrite(t, w.configPath, raw, 0600)
			before := webRequest(w, "GET", "/api/v1/nodes", "", cookie, "")
			if before.Code != 200 {
				t.Fatal(before.Code)
			}
			check := func() error {
				if kind == "ca" {
					_, err := readSnapshotCA(caPath)
					return err
				}
				return webCheckRuleSet(t.Context(), w.configPath, "test", fileRuleSet{Path: rulesPath, SHA256: shaHex(rule)})
			}
			if err := check(); err != nil {
				t.Fatalf("external source positive: %v", err)
			}
			path := rulesPath
			if kind == "ca" {
				path = caPath
			}
			runtimeWrite(t, path, []byte("tampered external bytes"), 0600)
			after := webRequest(w, "GET", "/api/v1/nodes", "", cookie, "")
			// DTOs never attested these external files. Preserve that exact scope,
			// while their independent original validators must reject the change.
			if after.Code != 200 || !bytes.Equal(before.Body.Bytes(), after.Body.Bytes()) {
				t.Fatal("DTO external-source policy changed")
			}
			if err := check(); err == nil {
				t.Fatal("independent external source validation reused GET state")
			}
		})
	}
}

func TestWebGETSourceDecodeFailureNotRetained(t *testing.T) {
	w := &webConsole{}
	calls := 0
	w.getYAMLParse = func(b []byte, doc *yaml.Node) error {
		calls++
		if calls == 1 {
			return errors.New("acquisition parse error")
		}
		return yaml.Unmarshal(b, doc)
	}
	decode := w.getConfigDecode([]byte("proxies: []\n"))
	var v any
	if decode(&v) == nil || decode(&v) != nil || calls != 2 || decode(&v) != nil || calls != 2 {
		t.Fatalf("only success may be retained: calls=%d", calls)
	}
}
