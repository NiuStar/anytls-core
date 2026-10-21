package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestWebMixedSubscriptionRetainsSupportedPreviewExport(t *testing.T) {
	w, password := webFixture(t)
	c, csrf := webLogin(t, w, password)
	original, _ := os.ReadFile(w.configPath)
	mixed := strings.Replace(clashExportFixture, "proxy-groups:", " - {name: ignored, type: ss, server: 1.1.1.2, port: 443, password: SECRET}\nproxy-groups:", 1)
	w.importFetch = func(context.Context, string) ([]byte, error) { return []byte(mixed), nil }
	p := importPreview(t, w, c, csrf, map[string]any{"url": "https://sub.example/profile?token=SECRET"})
	conversion := p["conversion"].(map[string]any)
	if len(conversion["skipped"].([]any)) == 0 || len(conversion["issues"].([]any)) != 0 {
		t.Fatal("mixed not usable", conversion)
	}
	if p["nodes"].(float64) != 1 {
		t.Fatal("supported node count", p["nodes"])
	}
	rec := importRequest(t, w, c, csrf, "import/export", map[string]any{"token": p["token"]}, p["etag"].(string))
	var out struct {
		YAML string `json:"yaml"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 200 || strings.Contains(out.YAML, "SECRET") {
		t.Fatal(rec.Code, "export includes skipped credentials")
	}
	after, _ := os.ReadFile(w.configPath)
	if !bytes.Equal(original, after) {
		t.Fatal("preview/export wrote config")
	}
	rec = importRequest(t, w, c, csrf, "import/commit", map[string]any{"token": p["token"], "confirm_replace": true, "confirm_insecure": true}, p["etag"].(string))
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "CONVERSION_CONFIRMATION_REQUIRED") {
		t.Fatal(rec.Code, rec.Body.String())
	}
	rec = importRequest(t, w, c, csrf, "import/commit", map[string]any{"token": p["token"], "confirm_replace": true, "confirm_insecure": true, "accept_conversion": true}, p["etag"].(string))
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	saved, _ := os.ReadFile(w.configPath)
	if string(saved) != out.YAML {
		t.Fatal("export differs from saved bytes")
	}
}
