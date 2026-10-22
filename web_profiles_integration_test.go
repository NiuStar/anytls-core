package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWebProfilesSwitchApplyIntegration(t *testing.T) {
	for _, mode := range []string{"stopped", "reload-failure"} {
		t.Run(mode, func(t *testing.T) {
			w := profileFixture(t)
			password, err := webReadPassword(w.passwordPath)
			if err != nil {
				t.Fatal(err)
			}
			cookie, csrf := webLogin(t, w, password)
			original, err := os.ReadFile(w.configPath)
			if err != nil {
				t.Fatal(err)
			}
			out := webRequest(w, "POST", "/api/v1/profiles", `{"name":"saved"}`, cookie, csrf)
			var profile struct {
				ID string `json:"id"`
			}
			if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &profile) != nil || profile.ID == "" {
				t.Fatal(out.Code, out.Body.String())
			}
			changed := append(bytes.Clone(original), []byte("# current disk differs\n")...)
			if err := os.WriteFile(w.configPath, changed, 0600); err != nil {
				t.Fatal(err)
			}
			calls := 0
			w.state = func() (bool, bool, error) { return mode == "reload-failure", mode == "reload-failure", nil }
			w.serviceAction = func(_ context.Context, action string, consent bool) error {
				calls++
				if action != "reload" || !consent {
					t.Errorf("unexpected action %q consent=%v", action, consent)
				}
				return errors.New("synthetic reload failure, secret must not leak")
			}
			out = groupETagRequest(w, cookie, csrf, "/api/v1/profiles/switch", `{"id":"`+profile.ID+`","confirm_replace":true,"confirm_insecure":true}`, `"`+shaHex(changed)+`"`)
			var result struct {
				Saved   bool   `json:"saved"`
				Changed bool   `json:"changed"`
				Applied bool   `json:"applied"`
				Pending bool   `json:"pendingReload"`
				Status  string `json:"apply_status"`
			}
			got, err := os.ReadFile(w.configPath)
			if err != nil || out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &result) != nil || !result.Saved || !result.Changed || result.Applied || !result.Pending || !bytes.Equal(got, original) || strings.Contains(out.Body.String(), "secret") {
				t.Fatalf("save/apply contract: %d %s", out.Code, out.Body.String())
			}
			if mode == "stopped" && (calls != 0 || result.Status != "SAVED_STOPPED") {
				t.Fatalf("stopped service touched: calls=%d status=%s", calls, result.Status)
			}
			if mode == "reload-failure" && (calls != 1 || result.Status != "APPLY_FAILED") {
				t.Fatalf("reload failure lost: calls=%d status=%s", calls, result.Status)
			}
		})
	}
}

func TestWebProfilesProbeFinalRouterSecurity(t *testing.T) {
	for _, endpoint := range []struct{ method, path string }{
		{"GET", "/api/v1/profiles"}, {"POST", "/api/v1/profiles"}, {"POST", "/api/v1/profiles/copy"}, {"POST", "/api/v1/profiles/switch"}, {"POST", "/api/v1/nodes/probe"}, {"POST", "/api/v1/groups/selection"},
	} {
		for _, boundary := range []string{"host", "session", "origin-missing", "origin-multiple", "origin-mismatch", "csrf"} {
			if endpoint.method == "GET" && boundary != "host" && boundary != "session" {
				continue
			}
			t.Run(endpoint.method+endpoint.path+"/"+boundary, func(t *testing.T) {
				w, password := webFixture(t)
				cookie, csrf := webLogin(t, w, password)
				raw, err := os.ReadFile(w.configPath)
				if err != nil {
					t.Fatal(err)
				}
				before, err := os.Stat(w.configPath)
				if err != nil {
					t.Fatal(err)
				}
				calls := 0
				w.nodeProbe = func(context.Context, node, string) (float64, error) { calls++; return 1, nil }
				w.state = func() (bool, bool, error) { calls++; return false, false, nil }
				w.serviceAction = func(context.Context, string, bool) error { calls++; return nil }
				r := httptest.NewRequest(endpoint.method, "http://127.0.0.1:18089"+endpoint.path, strings.NewReader(`{"name":"test"}`))
				r.Header.Set("Origin", "http://127.0.0.1:18089")
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("X-CSRF-Token", csrf)
				r.Header.Set("If-Match", `"`+shaHex(raw)+`"`)
				if boundary != "session" {
					r.AddCookie(cookie)
				}
				switch boundary {
				case "host":
					r.Host = "evil.invalid:18089"
				case "origin-missing":
					r.Header.Del("Origin")
				case "origin-multiple":
					r.Header.Add("Origin", "http://127.0.0.1:18089")
				case "origin-mismatch":
					r.Header.Set("Origin", "http://evil.invalid:18089")
				case "csrf":
					r.Header.Set("X-CSRF-Token", "wrong")
				}
				out := httptest.NewRecorder()
				w.ServeHTTP(out, r)
				want := 403
				if boundary == "session" {
					want = 401
				}
				got, err := os.ReadFile(w.configPath)
				after, statErr := os.Stat(w.configPath)
				_, storeErr := os.Lstat(filepath.Join(filepath.Dir(w.configPath), "profiles"))
				_, selErr := os.Lstat(selectedPath(w.configPath))
				if out.Code != want || err != nil || statErr != nil || !bytes.Equal(got, raw) || !os.SameFile(before, after) || !os.IsNotExist(storeErr) || !os.IsNotExist(selErr) || calls != 0 {
					t.Fatalf("security boundary bypass/effect: %d want %d calls=%d", out.Code, want, calls)
				}
			})
		}
	}
}
