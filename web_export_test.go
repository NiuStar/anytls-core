package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

const clashExportFixture = "x-template: &base {type: anytls, server: 1.1.1.1, port: 443, password: '00123', skip-cert-verify: true}\nproxies:\n - {<<: *base, name: converted}\nproxy-groups:\n - {name: 出口, type: select, proxies: [converted, DIRECT]}\nrules: ['MATCH,出口']\n"

func TestWebConversionExportPreviewIsSideEffectFree(t *testing.T) {
	w, password := webFixture(t)
	cookie, csrf := webLogin(t, w, password)
	old, _ := os.ReadFile(w.configPath)
	p := importPreview(t, w, cookie, csrf, map[string]any{"yaml": clashExportFixture})
	rec := importRequest(t, w, cookie, csrf, "import/export", map[string]any{"token": p["token"]}, p["etag"].(string))
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	var result struct {
		YAML   string `json:"yaml"`
		Format string `json:"format"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &result) != nil {
		t.Fatal("json")
	}
	if result.Format != "anytls-native" || !strings.Contains(result.YAML, "nodes:") || strings.Contains(result.YAML, "proxies:\n  - {") {
		t.Fatal(result.Format)
	}
	nodes, err := loadNodesBytes([]byte(result.YAML))
	if err != nil || len(nodes) != 1 || nodes[0].Password != "00123" {
		t.Fatal("converted password type", err)
	}
	got, _ := os.ReadFile(w.configPath)
	if !bytes.Equal(old, got) {
		t.Fatal("export wrote config")
	}
	if w.importPending == nil {
		t.Fatal("export consumed token")
	}
	bad := importRequest(t, w, cookie, csrf, "import/export", map[string]any{"token": p["token"]}, "wrong")
	if bad.Code != 412 {
		t.Fatal(bad.Code)
	}
	rec = importRequest(t, w, cookie, csrf, "import/commit", map[string]any{"token": p["token"], "confirm_replace": true, "confirm_insecure": true, "accept_conversion": true}, p["etag"].(string))
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	saved, _ := os.ReadFile(w.configPath)
	if string(saved) != result.YAML {
		t.Fatal("export differs from saved converted configuration")
	}
}

func TestWebExportCurrentAuthAndExactNativeBytes(t *testing.T) {
	w, password := webFixture(t)
	c, _ := webLogin(t, w, password)
	if err := os.WriteFile(w.configPath, []byte(webImportYAML), 0600); err != nil {
		t.Fatal(err)
	}
	rec := webRequest(w, http.MethodGet, "/api/v1/config/export", "", nil, "")
	if rec.Code != 401 {
		t.Fatal(rec.Code)
	}
	rec = webRequest(w, http.MethodGet, "/api/v1/config/export", "", c, "")
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	var result map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &result)
	if result["yaml"] != webImportYAML {
		t.Fatal("native export bytes changed")
	}
	w.actionMu.Lock()
	rec = webRequest(w, http.MethodGet, "/api/v1/config/export", "", c, "")
	w.actionMu.Unlock()
	if rec.Code != 409 {
		t.Fatal("export during import", rec.Code)
	}
}

func TestWebClashRemoteTemplatesConvertBeforeNativeValidation(t *testing.T) {
	w, password := webFixture(t)
	c, csrf := webLogin(t, w, password)
	w.importFetch = func(context.Context, string) ([]byte, error) { return []byte(clashExportFixture), nil }
	p := importPreview(t, w, c, csrf, map[string]any{"url": "https://sub.example/profile?token=PRIVATE"})
	conversion, ok := p["conversion"].(map[string]any)
	if !ok || conversion["format"] != "clash" || conversion["converted"] != true {
		t.Fatal("conversion report")
	}
	b, _ := json.Marshal(p)
	if bytes.Contains(b, []byte("PRIVATE")) || bytes.Contains(b, []byte("00123")) {
		t.Fatal("preview leaked credentials")
	}
}
