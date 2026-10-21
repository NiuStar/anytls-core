package main

import (
	"bytes"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestWebConversionWarningsRequireExplicitAcceptance(t *testing.T) {
	w, password := webFixture(t)
	c, csrf := webLogin(t, w, password)
	old, _ := os.ReadFile(w.configPath)
	candidate := strings.Replace(clashExportFixture, "type: select", "type: url-test", 1)
	p := importPreview(t, w, c, csrf, map[string]any{"yaml": candidate})
	conversion := p["conversion"].(map[string]any)
	if len(conversion["warnings"].([]any)) == 0 {
		t.Fatal("no automatic-to-manual warning")
	}
	rec := importRequest(t, w, c, csrf, "import/commit", map[string]any{"token": p["token"], "confirm_replace": true, "confirm_insecure": true}, p["etag"].(string))
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "CONVERSION_CONFIRMATION_REQUIRED") {
		t.Fatal(rec.Code, rec.Body.String())
	}
	saved, _ := os.ReadFile(w.configPath)
	if !bytes.Equal(saved, old) || w.importPending == nil {
		t.Fatal("unconfirmed conversion altered state")
	}
	rec = importRequest(t, w, c, csrf, "import/commit", map[string]any{"token": p["token"], "confirm_replace": true, "confirm_insecure": true, "accept_conversion": true}, p["etag"].(string))
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
}

func TestWebConversionUnsupportedBlocksTokenAndState(t *testing.T) {
	w, password := webFixture(t)
	c, csrf := webLogin(t, w, password)
	old, _ := os.ReadFile(w.configPath)
	candidate := strings.Replace(clashExportFixture, "type: anytls", "type: ss", 1)
	rec := importRequest(t, w, c, csrf, "import/preview", map[string]any{"yaml": candidate}, "")
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), "CONFIG_CONVERSION_UNSUPPORTED") || !strings.Contains(rec.Body.String(), "issues") {
		t.Fatal(rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "00123") || w.importPending != nil {
		t.Fatal("unsafe conversion result")
	}
	saved, _ := os.ReadFile(w.configPath)
	if !bytes.Equal(saved, old) {
		t.Fatal("blocked conversion wrote configuration")
	}
}

func TestWebExportConvertedRetainsPreviewBindings(t *testing.T) {
	for _, kind := range []string{"auth", "csrf", "ttl", "session", "config", "selection", "subscription"} {
		t.Run(kind, func(t *testing.T) {
			w, password := webFixture(t)
			c, csrf := webLogin(t, w, password)
			p := importPreview(t, w, c, csrf, map[string]any{"yaml": clashExportFixture})
			etag := p["etag"].(string)
			want := 409
			switch kind {
			case "auth":
				c = nil
				want = 401
			case "csrf":
				csrf = "invalid"
				want = 403
			case "ttl":
				w.now = func() time.Time { return w.importPending.expires.Add(time.Second) }
			case "session":
				c, csrf = webLogin(t, w, password)
			case "config":
				_ = os.WriteFile(w.configPath, []byte(webImportYAML), 0600)
				want = 412
			case "selection":
				_ = os.WriteFile(w.configPath+".selected", []byte("changed\n"), 0600)
				want = 412
			case "subscription":
				_ = os.WriteFile(w.subscriptionPath(), []byte("changed\n"), 0600)
				want = 412
			}
			rec := importRequest(t, w, c, csrf, "import/export", map[string]any{"token": p["token"]}, etag)
			if rec.Code != want {
				t.Fatal(kind, rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "00123") {
				t.Fatal("bound export leaked candidate")
			}
		})
	}
	w, password := webFixture(t)
	c, _ := webLogin(t, w, password)
	if rec := webRequest(w, http.MethodGet, "/api/v1/import/export", "", c, ""); rec.Code == 200 {
		t.Fatal("export POST bypass")
	}
}
