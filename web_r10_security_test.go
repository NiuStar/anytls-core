package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestR10OptionsDeleteAndFailurePreserve(t *testing.T) {
	w, c, csrf := profileRouterFixture(t)
	w.importFetch = func(context.Context, string) ([]byte, error) { return []byte(webImportYAML), nil }
	id := r10Import(t, w, c, csrf, "Provider")
	p, _, _ := w.readProfile(id)
	original := p.YAML
	s := r10Sub(t, w, c)
	r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/subscriptions/options", map[string]any{"id": id, "version": s["version"], "auto_check": false}, ""))
	if r10Sub(t, w, c)["auto_check"] != false {
		t.Fatal("pause not persisted")
	}
	w.importFetch = func(context.Context, string) ([]byte, error) { return nil, errors.New("https://example.com/SECRET") }
	r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/subscriptions/check", map[string]any{"id": id}, ""))
	s = r10Sub(t, w, c)
	p, _, _ = w.readProfile(id)
	if p.YAML != original || s["result"] != "CHECK_FAILED" {
		t.Fatal("failed check lost snapshot")
	}
	r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/profiles/delete", map[string]any{"id": id, "version": s["target_version"], "confirm": true}, ""))
	if _, _, e := w.readProfile(id); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("delete did not remove exact profile")
	}
	b := r10Body(t, r10Call(t, w, c, "", "GET", "/api/v1/subscriptions", nil, ""))
	if len(b["subscriptions"].([]any)) != 0 {
		t.Fatal("delete retained link")
	}
}
func TestR10ActiveCandidateApplyOnceAndInvalidSelection(t *testing.T) {
	w, c, csrf := profileRouterFixture(t)
	value := webImportYAML
	w.importFetch = func(context.Context, string) ([]byte, error) { return []byte(value), nil }
	id := r10Import(t, w, c, csrf, "Provider")
	before, _ := os.ReadFile(w.configPath)
	w.state = func() (bool, bool, error) { return false, false, nil }
	r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/profiles/switch", map[string]any{"id": id, "confirm_replace": true, "confirm_insecure": true}, `"`+shaHex(before)+`"`))
	p, _, _ := w.readProfile(id)
	nodes, _ := loadNodesBytes([]byte(p.YAML))
	value = strings.Replace(value, nodes[0].Server, "new.example.com", 1)
	value += "# updated target\n"
	calls := 0
	w.state = func() (bool, bool, error) { return true, true, nil }
	w.serviceAction = func(context.Context, string, bool) error { calls++; return nil }
	r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/subscriptions/check", map[string]any{"id": id}, ""))
	if calls != 0 {
		t.Fatal("check controlled service")
	}
	s := r10Sub(t, w, c)
	if s["selection_invalid"] != true || s["candidate_version"] == "" {
		t.Fatal(s)
	}
	payload := map[string]any{"id": id, "target_version": s["target_version"], "candidate_version": s["candidate_version"], "confirm": true, "confirm_insecure": true, "accept_conversion": true}
	out := r10Call(t, w, c, csrf, "POST", "/api/v1/subscriptions/apply", payload, "")
	if out.Code != 422 || calls != 0 {
		t.Fatal("implicit stale selection", out.Code, calls)
	}
	payload["selected"] = s["candidate_choices"].([]any)[0]
	r10Body(t, r10Call(t, w, c, csrf, "POST", "/api/v1/subscriptions/apply", payload, ""))
	if calls != 1 {
		t.Fatal("apply did not use one existing service action", calls)
	}
	p, _, _ = w.readProfile(id)
	got, _ := os.ReadFile(w.configPath)
	if !bytes.Equal(got, []byte(p.YAML)) {
		t.Fatal("active snapshot drift")
	}
}
func TestR10NewMutationOriginHostMethodMatrix(t *testing.T) {
	w, c, csrf := profileRouterFixture(t)
	paths := []string{"profiles/rename", "profiles/delete", "subscriptions/preview", "subscriptions/import", "subscriptions/check", "subscriptions/options", "subscriptions/apply", "subscriptions/restore", "subscriptions/unlink"}
	for _, path := range paths {
		for _, kind := range []string{"host", "origin", "duplicate-origin", "method"} {
			t.Run(path+"/"+kind, func(t *testing.T) {
				r := httptest.NewRequest("POST", "http://127.0.0.1:18089/api/v1/"+path, strings.NewReader(`{}`))
				r.Header.Set("Origin", "http://127.0.0.1:18089")
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("X-CSRF-Token", csrf)
				r.AddCookie(c)
				want := 403
				switch kind {
				case "host":
					r.Host = "evil.example:18089"
				case "origin":
					r.Header.Set("Origin", "http://evil.example")
				case "duplicate-origin":
					r.Header.Add("Origin", "http://127.0.0.1:18089")
				case "method":
					r.Method = http.MethodDelete
					want = 405
				}
				out := httptest.NewRecorder()
				w.ServeHTTP(out, r)
				if out.Code != want {
					t.Fatal(out.Code, out.Body.String())
				}
			})
		}
	}
}
func TestR10CancelledCheckAndDuplicateSource(t *testing.T) {
	w, c, csrf := profileRouterFixture(t)
	w.importFetch = func(context.Context, string) ([]byte, error) { return []byte(webImportYAML), nil }
	id := r10Import(t, w, c, csrf, "Provider")
	before, _, _ := w.readProfile(id)
	started := make(chan struct{})
	release := make(chan struct{})
	w.importFetch = func(context.Context, string) ([]byte, error) {
		close(started)
		<-release
		return []byte(webImportYAML + "# candidate\n"), nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan string, 1)
	go func() { _, code := w.checkSubscription(ctx, id); done <- code }()
	<-started
	out := r10Call(t, w, c, csrf, "POST", "/api/v1/subscriptions/check", map[string]any{"id": id}, "")
	if out.Code != 409 {
		t.Fatal(out.Code)
	}
	cancel()
	close(release)
	if code := <-done; code != "CONFIG_CONVERSION_CANCELED" {
		t.Fatal(code)
	}
	after, _, _ := w.readProfile(id)
	if profileVersion(before) != profileVersion(after) {
		t.Fatal("cancel committed metadata or candidate")
	}
}
func TestR10GroupChoicesRetainIdentity(t *testing.T) {
	base := webImportYAML + "\nproxy-groups:\n  - name: pick\n    type: select\n    proxies: [imported, DIRECT]\n    selected: imported\n"
	old := webProfile{YAML: base}
	incoming := strings.Replace(base, "selected: imported", "selected: DIRECT", 1)
	b, invalid := subscriptionGroupSelections(old, []byte(incoming))
	if invalid || !strings.Contains(string(b), "selected: imported") {
		t.Fatal("valid identity not retained", invalid, string(b))
	}
	nodes, _ := loadNodesBytes([]byte(base))
	incoming = strings.Replace(incoming, nodes[0].Server, "different.example.com", 1)
	_, invalid = subscriptionGroupSelections(old, []byte(incoming))
	if !invalid {
		t.Fatal("same-name changed target retained group choice")
	}
}
