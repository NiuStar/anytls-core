package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func r10Call(t *testing.T, w *webConsole, c *http.Cookie, csrf, method, path string, body any, etag string) *httptest.ResponseRecorder {
	t.Helper()
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	r.Host = "127.0.0.1:18089"
	r.Header.Set("Origin", "http://"+r.Host)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("If-Match", etag)
	if c != nil {
		r.AddCookie(c)
	}
	out := httptest.NewRecorder()
	w.ServeHTTP(out, r)
	return out
}
func r10Body(t *testing.T, r *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if r.Code != 200 {
		t.Fatalf("HTTP %d %s", r.Code, r.Body.String())
	}
	var b map[string]any
	if e := json.Unmarshal(r.Body.Bytes(), &b); e != nil {
		t.Fatal(e)
	}
	return b
}
func r10Sub(t *testing.T, w *webConsole, c *http.Cookie) map[string]any {
	t.Helper()
	b := r10Body(t, r10Call(t, w, c, "", "GET", "/api/v1/subscriptions", nil, ""))
	return b["subscriptions"].([]any)[0].(map[string]any)
}
func r10Import(t *testing.T, w *webConsole, c *http.Cookie, csrf, name string) string {
	t.Helper()
	p := r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/subscriptions/preview", map[string]any{"url": "https://example.com/private/path?token=SECRET", "name": name}, ""))
	v := r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/subscriptions/import", map[string]any{"token": p["token"], "name": name, "confirm": true, "confirm_insecure": true, "accept_conversion": true}, ""))
	return v["id"].(string)
}
func TestR10StableActiveAndExactEditSync(t *testing.T) {
	w, c, csrf := profileRouterFixture(t)
	w.state = func() (bool, bool, error) { return false, false, nil }
	a := r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/profiles", map[string]any{"name": "A"}, ""))["id"].(string)
	b := r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/profiles/copy", map[string]any{"id": a, "name": "B"}, ""))["id"].(string)
	raw, _ := os.ReadFile(w.configPath)
	edit := string(raw) + "# edit A\n"
	r10Body(t, r10Call(t, w, c, csrf, "PUT", "/api/v1/config", map[string]any{"yaml": edit, "confirm_insecure": true}, `"`+shaHex(raw)+`"`))
	pa, _, _ := w.readProfile(a)
	pb, _, _ := w.readProfile(b)
	if pa.YAML != edit || pb.YAML == edit {
		t.Fatal("edit did not bind to one stable active ID")
	}
	r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/profiles/switch", map[string]any{"id": b, "confirm_replace": true, "confirm_insecure": true}, `"`+shaHex([]byte(edit))+`"`))
	now, _ := os.ReadFile(w.configPath)
	r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/profiles/switch", map[string]any{"id": a, "confirm_replace": true, "confirm_insecure": true}, `"`+shaHex(now)+`"`))
	got, _ := os.ReadFile(w.configPath)
	if string(got) != edit {
		t.Fatal("switch-back lost edits")
	}
	detail := r10Body(t, r10Call(t, w, c, "", "GET", "/api/v1/profiles?detail=1", nil, ""))
	if detail["active_id"] != a {
		t.Fatal(detail)
	}
}
func TestR10SubscriptionPersistenceCandidateRestoreAndRedaction(t *testing.T) {
	w, c, csrf := profileRouterFixture(t)
	w.state = func() (bool, bool, error) { return false, false, nil }
	fetchData := webImportYAML
	w.importFetch = func(context.Context, string) ([]byte, error) { return []byte(fetchData), nil }
	before, _ := os.ReadFile(w.configPath)
	id := r10Import(t, w, c, csrf, "Provider")
	after, _ := os.ReadFile(w.configPath)
	if !bytes.Equal(before, after) {
		t.Fatal("import activated")
	}
	s := r10Sub(t, w, c)
	if s["source_host"] != "example.com" || s["auto_check"] != true || s["profile_id"] != id {
		t.Fatal(s)
	}
	encoded, _ := json.Marshal(s)
	if strings.Contains(string(encoded), "SECRET") || strings.Contains(string(encoded), "private/path") {
		t.Fatal("token leak")
	}
	fetchData += "# new\n"
	r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/subscriptions/check", map[string]any{"id": id}, ""))
	p, _, _ := w.readProfile(id)
	if p.YAML != fetchData {
		t.Fatal("inactive safe update not saved")
	}
	s = r10Sub(t, w, c)
	r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/subscriptions/restore", map[string]any{"id": id, "version": s["version"], "confirm": true}, ""))
	s = r10Sub(t, w, c)
	oldTarget := s["target_version"]
	oldCandidate := s["candidate_version"]
	r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/profiles/rename", map[string]any{"id": id, "name": "Renamed", "version": oldTarget}, ""))
	out := r10Call(t, w, c, csrf, "POST", "/api/v1/subscriptions/apply", map[string]any{"id": id, "target_version": oldTarget, "candidate_version": oldCandidate, "confirm": true, "confirm_insecure": true, "accept_conversion": true}, "")
	if out.Code != 412 {
		t.Fatal("stale consent accepted", out.Code, out.Body.String())
	}
	s = r10Sub(t, w, c)
	r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/subscriptions/apply", map[string]any{"id": id, "target_version": s["target_version"], "candidate_version": s["candidate_version"], "confirm": true, "confirm_insecure": true, "accept_conversion": true}, ""))
	p, _, _ = w.readProfile(id)
	if p.YAML != webImportYAML || p.Name != "Renamed" {
		t.Fatal("restore or rename lost")
	}
	restarted := newWebConsole(w.configPath, w.passwordPath, w.port)
	if _, _, e := restarted.readProfile(id); e != nil {
		t.Fatal("not persisted", e)
	}
	s = r10Sub(t, w, c)
	r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/subscriptions/unlink", map[string]any{"id": id, "version": s["version"], "confirm": true}, ""))
	p, _, _ = w.readProfile(id)
	if p.Subscription != nil {
		t.Fatal("unlink retained credential")
	}
}
func TestR10NetworkCheckDoesNotHoldActionAndRejectsDrift(t *testing.T) {
	w, c, csrf := profileRouterFixture(t)
	w.importFetch = func(context.Context, string) ([]byte, error) { return []byte(webImportYAML), nil }
	id := r10Import(t, w, c, csrf, "Provider")
	started := make(chan struct{})
	release := make(chan struct{})
	w.importFetch = func(context.Context, string) ([]byte, error) {
		close(started)
		<-release
		return []byte(webImportYAML + "# update\n"), nil
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- r10Call(t, w, c, csrf, "POST", "/api/v1/subscriptions/check", map[string]any{"id": id}, "")
	}()
	<-started
	if !w.actionMu.TryLock() {
		close(release)
		t.Fatal("network holds action lock")
	}
	w.actionMu.Unlock()
	s := r10Sub(t, w, c)
	r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/profiles/rename", map[string]any{"id": id, "name": "During check", "version": s["target_version"]}, ""))
	close(release)
	r10Body(t, <-done)
	p, _, _ := w.readProfile(id)
	if p.YAML != webImportYAML || p.Name != "During check" {
		t.Fatal("late network overwrote manual change")
	}
	if r10Sub(t, w, c)["candidate_version"] == "" {
		t.Fatal("missing conflict candidate")
	}
}
func TestR10HourlyWorkerWithoutBrowser(t *testing.T) {
	w, c, csrf := profileRouterFixture(t)
	w.importFetch = func(context.Context, string) ([]byte, error) { return []byte(webImportYAML), nil }
	r10Import(t, w, c, csrf, "Provider")
	w.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	checkedNetwork := make(chan struct{}, 1)
	w.importFetch = func(context.Context, string) ([]byte, error) {
		checkedNetwork <- struct{}{}
		return []byte(webImportYAML), nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); w.runSubscriptionWorker(ctx) }()
	select {
	case <-checkedNetwork:
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Fatal("worker made no due network check")
	}
	deadline := time.Now().Add(time.Second)
	for {
		w.actionMu.Lock()
		ps, _ := w.allProfiles()
		checked := false
		for _, p := range ps {
			if p.Link != nil && p.Link.Last != "" {
				checked = true
			}
		}
		w.actionMu.Unlock()
		if checked || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	s := r10Sub(t, w, c)
	if s["last_check"] == "" || s["result"] != "NO_CHANGE" {
		t.Fatal(s)
	}
}
func TestR10NewRoutesAuthBoundary(t *testing.T) {
	w, c, csrf := profileRouterFixture(t)
	paths := []string{"/api/v1/profiles/rename", "/api/v1/profiles/delete", "/api/v1/subscriptions/preview", "/api/v1/subscriptions/import", "/api/v1/subscriptions/check", "/api/v1/subscriptions/options", "/api/v1/subscriptions/apply", "/api/v1/subscriptions/restore", "/api/v1/subscriptions/unlink"}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			if out := r10Call(t, w, nil, "", "POST", path, map[string]any{}, ""); out.Code != 401 {
				t.Fatal(out.Code)
			}
			if out := r10Call(t, w, c, "", "POST", path, map[string]any{}, ""); out.Code != 403 {
				t.Fatal(out.Code)
			}
			if out := r10Call(t, w, c, csrf, "POST", path, map[string]any{"unknown": "SECRET"}, ""); out.Code != 400 {
				t.Fatal(out.Code, out.Body.String())
			}
		})
	}
	if out := r10Call(t, w, nil, "", "GET", "/api/v1/subscriptions", nil, ""); out.Code != 401 {
		t.Fatal(out.Code)
	}
}
