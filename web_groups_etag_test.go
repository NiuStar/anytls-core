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
)

func groupETagRequest(w *webConsole, cookie *http.Cookie, csrf, path, body, etag string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "http://127.0.0.1:18089"+path, strings.NewReader(body))
	r.Header.Set("Origin", "http://127.0.0.1:18089")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("If-Match", etag)
	r.AddCookie(cookie)
	out := httptest.NewRecorder()
	w.ServeHTTP(out, r)
	return out
}

func TestWebGroupsSnapshotETag(t *testing.T) {
	w, password := webFixture(t)
	cookie, _ := webLogin(t, w, password)
	raw, err := os.ReadFile(w.configPath)
	if err != nil {
		t.Fatal(err)
	}
	out := webRequest(w, "GET", "/api/v1/groups", "", cookie, "")
	var snapshot struct {
		ETag   string `json:"etag"`
		Groups []struct {
			Name string `json:"name"`
		} `json:"groups"`
	}
	if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &snapshot) != nil || snapshot.ETag != `"`+shaHex(raw)+`"` || len(snapshot.Groups) != 1 || snapshot.Groups[0].Name != "local" {
		t.Fatalf("groups snapshot lacks matching config etag: %d %s", out.Code, out.Body.String())
	}
}

func TestWebGroupsSelectionRejectsStaleSnapshot(t *testing.T) {
	for _, change := range []string{"external-mutation", "profile-switch"} {
		t.Run(change, func(t *testing.T) {
			w, password := webFixture(t)
			cookie, csrf := webLogin(t, w, password)
			original := []byte("nodes: []\nproxy-groups:\n  - name: local\n    type: select\n    proxies: [DIRECT, REJECT]\n    selected: DIRECT\nrules: ['MATCH,DIRECT']\n")
			updated := append(bytes.Clone(original), []byte("# different profile, same group and choice names\n")...)
			if err := os.WriteFile(w.configPath, updated, 0600); err != nil {
				t.Fatal(err)
			}
			id := ""
			if change == "profile-switch" {
				out := webRequest(w, "POST", "/api/v1/profiles", `{"name":"other"}`, cookie, csrf)
				var saved struct {
					ID string `json:"id"`
				}
				if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &saved) != nil || saved.ID == "" {
					t.Fatalf("save profile: %d %s", out.Code, out.Body.String())
				}
				id = saved.ID
			}
			if err := os.WriteFile(w.configPath, original, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(selectedPath(w.configPath), []byte("untouched-selection\n"), 0600); err != nil {
				t.Fatal(err)
			}
			out := webRequest(w, "GET", "/api/v1/groups", "", cookie, "")
			if out.Code != 200 {
				t.Fatal(out.Code)
			}
			var snapshot struct {
				ETag string `json:"etag"`
			}
			if err := json.Unmarshal(out.Body.Bytes(), &snapshot); err != nil {
				t.Fatal(err)
			}
			// Let the old implementation reach the stale-write assertion even when
			// its GET lacks etag; the separate snapshot test requires that field.
			if snapshot.ETag == "" {
				snapshot.ETag = `"` + shaHex(original) + `"`
			}
			if change == "profile-switch" {
				// Profile requires a valid captured optional selection; remove our
				// sentinel before switching to its absent-selection snapshot.
				if err := os.Remove(selectedPath(w.configPath)); err != nil {
					t.Fatal(err)
				}
				out = groupETagRequest(w, cookie, csrf, "/api/v1/profiles/switch", `{"id":"`+id+`","confirm_replace":true,"confirm_insecure":true}`, snapshot.ETag)
				if out.Code != 200 {
					t.Fatalf("switch profile: %d %s", out.Code, out.Body.String())
				}
			} else if err := os.WriteFile(w.configPath, updated, 0600); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(w.configPath)
			if err != nil {
				t.Fatal(err)
			}
			selection, selectionErr := os.ReadFile(selectedPath(w.configPath))
			serviceCalls := 0
			w.state = func() (bool, bool, error) { serviceCalls++; return true, true, nil }
			w.serviceAction = func(context.Context, string, bool) error { serviceCalls++; return nil }
			out = groupETagRequest(w, cookie, csrf, "/api/v1/groups/selection", `{"group":"local","choice":"REJECT"}`, snapshot.ETag)
			after, err := os.Stat(w.configPath)
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(w.configPath)
			if err != nil {
				t.Fatal(err)
			}
			sel, selErr := os.ReadFile(selectedPath(w.configPath))
			if out.Code != 412 || !strings.Contains(out.Body.String(), "CONFIG_CONFLICT") || !bytes.Equal(got, updated) || !os.SameFile(before, after) || !bytes.Equal(selection, sel) || os.IsNotExist(selectionErr) != os.IsNotExist(selErr) || serviceCalls != 0 {
				t.Fatalf("stale snapshot mutated config/selection or touched service: status=%d service=%d body=%s", out.Code, serviceCalls, out.Body.String())
			}
			out = webRequest(w, "GET", "/api/v1/groups", "", cookie, "")
			if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &snapshot) != nil || snapshot.ETag != `"`+shaHex(updated)+`"` {
				t.Fatal("fresh snapshot etag mismatch")
			}
			w.state = func() (bool, bool, error) { return false, false, nil }
			out = groupETagRequest(w, cookie, csrf, "/api/v1/groups/selection", `{"group":"local","choice":"REJECT"}`, snapshot.ETag)
			got, err = os.ReadFile(w.configPath)
			if err != nil || out.Code != 200 || !bytes.Contains(got, []byte("selected: REJECT")) || serviceCalls != 0 {
				t.Fatalf("matching snapshot rejected: %d %s", out.Code, out.Body.String())
			}
		})
	}
}
