package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func profileRouterFixture(t *testing.T) (*webConsole, *http.Cookie, string) {
	t.Helper()
	w, password := webFixture(t)
	if err := os.WriteFile(w.configPath, []byte(webImportYAML), 0600); err != nil {
		t.Fatal(err)
	}
	cookie, csrf := webLogin(t, w, password)
	return w, cookie, csrf
}

func profileRouterList(t *testing.T, w *webConsole, cookie *http.Cookie) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	out := webRequest(w, "GET", "/api/v1/profiles", "", cookie, "")
	var body map[string]any
	if err := json.Unmarshal(out.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return out, body
}

func TestWebProfilesListRouterAuthenticatedPublicProjection(t *testing.T) {
	w, cookie, csrf := profileRouterFixture(t)
	nodes, err := loadNodes(w.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = saveSelection(w.configPath, nodes[0].Name, nodes); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(w.subscriptionPath(), []byte(`{"url":"https://example.com/private-list-token"}`), 0600); err != nil {
		t.Fatal(err)
	}
	saved := webRequest(w, "POST", "/api/v1/profiles", `{"name":"router snapshot"}`, cookie, csrf)
	if saved.Code != 200 {
		t.Fatalf("save route: %d %s", saved.Code, saved.Body.String())
	}
	var result struct {
		ID string `json:"id"`
	}
	if err = json.Unmarshal(saved.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	p, _, err := w.readProfile(result.ID)
	if err != nil || !webProfileID.MatchString(p.ID) || p.Selected == nil || p.Subscription == nil {
		t.Fatal("saved fixture missing private payload", err)
	}
	raw, err := os.ReadFile(w.configPath)
	if err != nil {
		t.Fatal(err)
	}
	etag := `"` + shaHex(raw) + `"`
	for i := 0; i < 4; i++ {
		out, body := profileRouterList(t, w, cookie)
		if out.Code != 200 {
			t.Fatalf("authenticated profiles route: got %d, want 200: %s", out.Code, out.Body.String())
		}
		want := map[string]any{"etag": etag, "profiles": []any{map[string]any{"id": p.ID, "name": p.Name, "created_at": p.CreatedAt, "current": true}}}
		if out.Header().Get("ETag") != etag || !reflect.DeepEqual(body, want) {
			t.Fatal("list must contain exactly public metadata and matching ETag", body)
		}
	}
	// Current describes all three stored files, not just config equality.
	if err = os.WriteFile(w.subscriptionPath(), []byte(`{"url":"https://example.com/changed"}`), 0600); err != nil {
		t.Fatal(err)
	}
	out, body := profileRouterList(t, w, cookie)
	if out.Code != 200 || body["profiles"].([]any)[0].(map[string]any)["current"] != false {
		t.Fatal("subscription change must clear current", out.Code, body)
	}
}

func TestWebProfilesListRouterEmptyAndBusyRecovery(t *testing.T) {
	w, cookie, _ := profileRouterFixture(t)
	for i := 0; i < 3; i++ {
		w.actionMu.Lock()
		out, body := profileRouterList(t, w, cookie)
		w.actionMu.Unlock()
		if out.Code != 409 || body["error"] != "ACTION_BUSY" {
			t.Fatal("held action lock must reject list", out.Code, body)
		}
		out, body = profileRouterList(t, w, cookie)
		profiles, ok := body["profiles"].([]any)
		if out.Code != 200 || !ok || len(profiles) != 0 || body["etag"] != out.Header().Get("ETag") {
			t.Fatal("empty store must recover with empty array and ETag", out.Code, body)
		}
		if !w.actionMu.TryLock() {
			t.Fatal("list leaked action lock")
		}
		w.actionMu.Unlock()
	}
}

func TestWebProfilesListRouterCorruptionFailClosed(t *testing.T) {
	w, cookie, csrf := profileRouterFixture(t)
	out := webRequest(w, "POST", "/api/v1/profiles", `{"name":"valid"}`, cookie, csrf)
	if out.Code != 200 {
		t.Fatal(out.Code, out.Body.String())
	}
	path := filepath.Join(filepath.Dir(w.configPath), "profiles", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json")
	if err := os.WriteFile(path, []byte(`{"private-corruption":"must-not-escape"`), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		out, body := profileRouterList(t, w, cookie)
		if out.Code != 503 || !reflect.DeepEqual(body, map[string]any{"error": "PROFILE_STORE_UNAVAILABLE"}) {
			t.Fatal("corruption must fail closed without partial list or private bytes", out.Code, body)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	out, _ = profileRouterList(t, w, cookie)
	if out.Code != 200 {
		t.Fatal("failed list leaked action lock", out.Code)
	}
}
