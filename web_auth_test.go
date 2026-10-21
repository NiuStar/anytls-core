package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func webFixture(t *testing.T) (*webConsole, string) {
	t.Helper()
	dir := t.TempDir()
	config := filepath.Join(dir, "config.yaml")
	// Rules are supplied as one YAML scalar, not two sequence entries.
	if err := os.WriteFile(config, []byte("nodes: []\nproxy-groups:\n  - name: local\n    type: select\n    proxies: [DIRECT]\n    selected: DIRECT\nrules: ['MATCH,DIRECT']\n"), 0600); err != nil {
		t.Fatal(err)
	}
	password, err := webPassword(filepath.Join(dir, "webui.password"), false)
	if err != nil {
		t.Fatal(err)
	}
	w := newWebConsole(config, filepath.Join(dir, "webui.password"), 18089)
	w.state = func() (bool, bool, error) { return false, false, nil }
	return w, password
}
func webRequest(w *webConsole, method, path, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:18089"+path, strings.NewReader(body))
	r.Host = "127.0.0.1:18089"
	r.Header.Set("Origin", "http://127.0.0.1:18089")
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, r)
	return rec
}
func TestWebWrongPassword(t *testing.T) {
	w, _ := webFixture(t)
	r := webRequest(w, "POST", "/api/v1/login", `{"username":"admin","password":"wrong"}`, nil, "")
	if r.Code != 401 {
		t.Fatal(r.Code)
	}
}
func webLogin(t *testing.T, w *webConsole, p string) (*http.Cookie, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": p})
	rec := webRequest(w, "POST", "/api/v1/login", string(body), nil, "")
	if rec.Code != 200 {
		t.Fatalf("login %d %s", rec.Code, rec.Body.String())
	}
	var result struct {
		CSRF string `json:"csrf"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &result) != nil || result.CSRF == "" {
		t.Fatal("missing csrf")
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("missing cookie")
	}
	return cookies[0], result.CSRF
}
func TestWebCookieFlags(t *testing.T) {
	w, p := webFixture(t)
	c, _ := webLogin(t, w, p)
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.MaxAge != 28800 || c.Secure {
		t.Fatalf("bad loopback cookie: %+v", c)
	}
}
func TestWebSessionRequired(t *testing.T) {
	w, _ := webFixture(t)
	for _, path := range []string{"status", "nodes", "groups", "config", "version", "update-check"} {
		if r := webRequest(w, "GET", "/api/v1/"+path, "", nil, ""); r.Code != 401 {
			t.Fatal(path, r.Code)
		}
	}
}
func TestWebCSRFRequired(t *testing.T) {
	w, p := webFixture(t)
	c, _ := webLogin(t, w, p)
	if r := webRequest(w, "POST", "/api/v1/logout", `{}`, c, ""); r.Code != 403 {
		t.Fatal(r.Code)
	}
}
func TestWebLogoutRevokes(t *testing.T) {
	w, p := webFixture(t)
	c, csrf := webLogin(t, w, p)
	if r := webRequest(w, "POST", "/api/v1/logout", `{}`, c, csrf); r.Code != 200 {
		t.Fatal(r.Code)
	}
	if r := webRequest(w, "GET", "/api/v1/status", "", c, ""); r.Code != 401 {
		t.Fatal(r.Code)
	}
}
func TestWebSessionExpiry(t *testing.T) {
	w, p := webFixture(t)
	now := time.Now()
	w.now = func() time.Time { return now }
	c, _ := webLogin(t, w, p)
	now = now.Add(webSessionTTL)
	if r := webRequest(w, "GET", "/api/v1/status", "", c, ""); r.Code != 401 {
		t.Fatal(r.Code)
	}
}
func TestWebResetInvalidatesSessions(t *testing.T) {
	w, p := webFixture(t)
	c, _ := webLogin(t, w, p)
	if _, e := webPassword(w.passwordPath, true); e != nil {
		t.Fatal(e)
	}
	if r := webRequest(w, "GET", "/api/v1/status", "", c, ""); r.Code != 401 {
		t.Fatal(r.Code)
	}
}
func TestWebHostAllowlist(t *testing.T) {
	w, _ := webFixture(t)
	for _, host := range []string{"evil.test:18089", "127.0.0.1:80", "127.0.0.2:18089", "localhost.evil:18089", "127.0.0.1", "[::1]:18090"} {
		r := httptest.NewRequest("GET", "http://"+host+"/", nil)
		r.Host = host
		rec := httptest.NewRecorder()
		w.ServeHTTP(rec, r)
		if rec.Code != 403 {
			t.Fatal(host, rec.Code)
		}
	}
}
func TestWebOriginRequired(t *testing.T) {
	w, _ := webFixture(t)
	for _, origin := range []string{"", "null", "http://evil.test:18089", "http://localhost:18089", "https://127.0.0.1:18089", "http://127.0.0.1:18089/"} {
		r := httptest.NewRequest("POST", "http://127.0.0.1:18089/api/v1/login", strings.NewReader(`{}`))
		r.Header.Set("Origin", origin)
		rec := httptest.NewRecorder()
		w.ServeHTTP(rec, r)
		if rec.Code != 403 {
			t.Fatal(origin, rec.Code)
		}
	}
}
func TestWebThrottle(t *testing.T) {
	w, _ := webFixture(t)
	for i := 0; i < 5; i++ {
		webRequest(w, "POST", "/api/v1/login", `{"username":"admin","password":"wrong"}`, nil, "")
	}
	if r := webRequest(w, "POST", "/api/v1/login", `{"username":"admin","password":"wrong"}`, nil, ""); r.Code != 429 {
		t.Fatal(r.Code)
	}
}
func TestWebConfigConflict(t *testing.T) {
	w, p := webFixture(t)
	c, csrf := webLogin(t, w, p)
	r := httptest.NewRequest("PUT", "http://127.0.0.1:18089/api/v1/config", strings.NewReader(`{"yaml":"nodes: []"}`))
	r.AddCookie(c)
	r.Header.Set("Origin", "http://127.0.0.1:18089")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("If-Match", `"stale"`)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, r)
	if rec.Code != 412 {
		t.Fatal(rec.Code)
	}
}
func TestWebNoPublicCredentials(t *testing.T) {
	w, p := webFixture(t)
	secret := "NODE_SECRET_DO_NOT_EXPOSE"
	b := []byte("nodes:\n - name: example\n   type: anytls\n   server: 127.0.0.1\n   port: 443\n   password: " + secret + "\n")
	if e := os.WriteFile(w.configPath, b, 0600); e != nil {
		t.Fatal(e)
	}
	c, _ := webLogin(t, w, p)
	for _, path := range []string{"/", "/app.js", "/style.css", "/api/v1/nodes", "/api/v1/groups", "/api/v1/status", "/api/v1/version"} {
		r := webRequest(w, "GET", path, "", c, "")
		if r.Code != 200 || strings.Contains(r.Body.String(), secret) || strings.Contains(r.Body.String(), p) {
			t.Fatal(path, r.Code, "credential exposure or read failure")
		}
	}
}
func TestWebGroupNoop(t *testing.T) {
	w, p := webFixture(t)
	c, csrf := webLogin(t, w, p)
	before, _ := os.Stat(w.configPath)
	b, _ := os.ReadFile(w.configPath)
	r := webRequest(w, "POST", "/api/v1/groups/selection", `{"group":"local","choice":"DIRECT"}`, c, csrf)
	after, _ := os.Stat(w.configPath)
	got, _ := os.ReadFile(w.configPath)
	if r.Code != 200 || !os.SameFile(before, after) || string(got) != string(b) || !strings.Contains(r.Body.String(), `"changed":false`) {
		t.Fatal(r.Code, r.Body.String())
	}
}
func TestWebRejectInvalidInput(t *testing.T) {
	w, p := webFixture(t)
	c, csrf := webLogin(t, w, p)
	for _, body := range []string{`{"group":"local","choice":"not-a-member"}`, `{"group":"local","choice":"DIRECT","command":"id"}`, `{}`, `{} {}`} {
		r := webRequest(w, "POST", "/api/v1/groups/selection", body, c, csrf)
		if r.Code < 400 {
			t.Fatal(body, r.Code)
		}
	}
}
func TestWebConfigValidation(t *testing.T) {
	w, _ := webFixture(t)
	for _, b := range []string{"[]", "nodes: []\n---\nnodes: []", "nodes: []\nrules: ['UNKNOWN,value,DIRECT','MATCH,DIRECT']", "nodes: []\nproxy-groups: [{name: loop, type: select, proxies: [loop], selected: loop}]", "nodes: []\nnodes: []"} {
		if webValidateConfig(w.configPath, []byte(b)) == nil {
			t.Fatal("accepted invalid config", b)
		}
	}
	if e := webValidateConfig(w.configPath, []byte("nodes: []\nx-unknown: '00123'\nrules: ['MATCH,DIRECT']\n")); e != nil {
		t.Fatal(e)
	}
}
func TestWebConfigSaveAtomicReadback(t *testing.T) {
	w, p := webFixture(t)
	c, csrf := webLogin(t, w, p)
	get := webRequest(w, "GET", "/api/v1/config", "", c, "")
	candidate := "nodes: []\nx-custom: '00123' # preserve\nrules: ['MATCH,DIRECT']\n"
	body, _ := json.Marshal(map[string]string{"yaml": candidate})
	r := httptest.NewRequest("PUT", "http://127.0.0.1:18089/api/v1/config", strings.NewReader(string(body)))
	r.AddCookie(c)
	r.Header.Set("Origin", "http://127.0.0.1:18089")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("If-Match", get.Header().Get("ETag"))
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, r)
	b, _ := os.ReadFile(w.configPath)
	st, _ := os.Stat(w.configPath)
	if rec.Code != 200 || string(b) != candidate || st.Mode().Perm() != 0600 {
		t.Fatal(rec.Code, rec.Body.String())
	}
}
func TestWebActionsDontBlockAuthentication(t *testing.T) {
	w, p := webFixture(t)
	c, _ := webLogin(t, w, p)
	w.actionMu.Lock()
	defer w.actionMu.Unlock()
	if r := webRequest(w, "GET", "/api/v1/status", "", c, ""); r.Code != 200 {
		t.Fatal(r.Code)
	}
}
func TestWebNodeFormPreservesUnknownAndPassword(t *testing.T) {
	original := []byte("nodes:\n - name: example\n   type: anytls\n   server: 127.0.0.1\n   port: 443\n   password: '00123' # preserve\n   x-custom: '00123'\n")
	out, e := webEditNode(original, webNodeEdit{Name: "example", Server: "127.0.0.2", Port: 8443, SNI: "example.test"})
	if e != nil {
		t.Fatal(e)
	}
	nodes, e := loadNodesBytes(out)
	if e != nil || len(nodes) != 1 || nodes[0].Password != "00123" || nodes[0].Server != "127.0.0.2" || !strings.Contains(string(out), "# preserve") || !strings.Contains(string(out), "x-custom: '00123'") {
		t.Fatal("node edit lost fields")
	}
}
func TestWebNodeFormRejectsSharedSecret(t *testing.T) {
	original := []byte("secret: &pw '00123'\nnodes:\n - name: example\n   type: anytls\n   server: 127.0.0.1\n   port: 443\n   password: *pw\n")
	if _, e := webEditNode(original, webNodeEdit{Name: "example", Server: "127.0.0.2", Port: 8443, Password: "replacement"}); e == nil {
		t.Fatal("accepted alias password edit")
	}
}
func TestWebServiceSeamAndReadback(t *testing.T) {
	w, p := webFixture(t)
	c, csrf := webLogin(t, w, p)
	called := false
	w.serviceAction = func(_ context.Context, action string, insecure bool) error {
		called = action == "start" && insecure
		return nil
	}
	w.state = func() (bool, bool, error) { return true, true, nil }
	r := webRequest(w, "POST", "/api/v1/service/start", `{"confirm_insecure":true}`, c, csrf)
	if r.Code != 200 || !called {
		t.Fatal(r.Code, r.Body.String())
	}
	w.serviceAction = func(context.Context, string, bool) error { return errors.New("SENSITIVE_INTERNAL_OUTPUT") }
	r = webRequest(w, "POST", "/api/v1/service/start", `{}`, c, csrf)
	if r.Code != 503 || strings.Contains(r.Body.String(), "SENSITIVE_INTERNAL_OUTPUT") {
		t.Fatal(r.Code, "unsafe error")
	}
}
func TestWebBusyMutationRejected(t *testing.T) {
	w, p := webFixture(t)
	c, csrf := webLogin(t, w, p)
	w.actionMu.Lock()
	defer w.actionMu.Unlock()
	r := webRequest(w, "POST", "/api/v1/service/start", `{}`, c, csrf)
	if r.Code != 409 {
		t.Fatal(r.Code)
	}
}
func TestWebUpdateUnavailableNotFake(t *testing.T) {
	w, p := webFixture(t)
	c, _ := webLogin(t, w, p)
	w.updateAction = func(context.Context, bool) (json.RawMessage, error) { return nil, errors.New("UPSTREAM_SECRET") }
	r := webRequest(w, "GET", "/api/v1/update-check", "", c, "")
	if r.Code != 503 || strings.Contains(r.Body.String(), "UPSTREAM_SECRET") {
		t.Fatal(r.Code)
	}
}
func TestWebPasswordPrivateAndRotation(t *testing.T) {
	w, p := webFixture(t)
	st, e := os.Stat(w.passwordPath)
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatal(st, e)
	}
	p2, e := webPassword(w.passwordPath, true)
	if e != nil || p == p2 || len(p2) != 32 {
		t.Fatal("rotation failed")
	}
	p3, e := webPassword(w.passwordPath, false)
	if e != nil || p3 != p2 {
		t.Fatal("readback failed")
	}
}
