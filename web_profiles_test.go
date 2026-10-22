package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func profileFixture(t *testing.T) *webConsole {
	t.Helper()
	w, _ := webFixture(t)
	if e := os.WriteFile(w.configPath, []byte(webImportYAML), 0600); e != nil {
		t.Fatal(e)
	}
	return w
}

func profileCall(t *testing.T, w *webConsole, action, body, etag string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/profiles", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("If-Match", etag)
	out := httptest.NewRecorder()
	switch action {
	case "save":
		w.saveProfile(out, r)
	case "copy":
		w.copyProfile(out, r)
	case "switch":
		w.switchProfile(out, r)
	case "list":
		w.getProfiles(out, r)
	}
	return out
}
func profileSavedID(t *testing.T, w *webConsole) string {
	t.Helper()
	out := profileCall(t, w, "save", `{"name":"snapshot"}`, "")
	if out.Code != 200 {
		t.Fatalf("save: %d %s", out.Code, out.Body.String())
	}
	var p struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(out.Body.Bytes(), &p) != nil || !webProfileID.MatchString(p.ID) {
		t.Fatal("missing profile ID")
	}
	return p.ID
}
func TestWebProfilesSnapshotCopyAndPrivateList(t *testing.T) {
	w := profileFixture(t)
	raw, _ := os.ReadFile(w.configPath)
	// Optional absence must be captured exactly, with no fabricated selection.
	id := profileSavedID(t, w)
	p, _, e := w.readProfile(id)
	if e != nil || p.YAML != string(raw) || p.Selected != nil {
		t.Fatal("snapshot capture", e)
	}
	out := profileCall(t, w, "copy", `{"id":"`+id+`","name":"copy"}`, "")
	if out.Code != 200 {
		t.Fatal(out.Code, out.Body.String())
	}
	var copied struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(out.Body.Bytes(), &copied)
	q, _, e := w.readProfile(copied.ID)
	if e != nil || q.ID == id || q.YAML != p.YAML || q.Selected != nil || q.Subscription != nil {
		t.Fatal("copy changed captured payload", e)
	}
	out = profileCall(t, w, "list", "", "")
	if out.Code != 200 || bytes.Contains(out.Body.Bytes(), []byte("password")) || bytes.Contains(out.Body.Bytes(), []byte("yaml")) || bytes.Contains(out.Body.Bytes(), []byte("url")) {
		t.Fatal("private list", out.Code, out.Body.String())
	}
	for _, path := range []string{filepath.Join(filepath.Dir(w.configPath), "profiles", id+".json"), filepath.Join(filepath.Dir(w.configPath), "profiles")} {
		st, e := os.Lstat(path)
		if e != nil {
			t.Fatal(e)
		}
		want := os.FileMode(0600)
		if st.IsDir() {
			want = 0700
		}
		if st.Mode().Perm() != want {
			t.Fatal("unsafe mode")
		}
	}
}
func TestWebProfilesSwitchExactStateAndNoop(t *testing.T) {
	w := profileFixture(t)
	nodes, _ := loadNodes(w.configPath)
	if e := saveSelection(w.configPath, nodes[0].Name, nodes); e != nil {
		t.Fatal(e)
	}
	id := profileSavedID(t, w)
	original, _ := os.ReadFile(w.configPath)
	selected, _ := os.ReadFile(selectedPath(w.configPath))
	if e := os.WriteFile(w.configPath, append(bytes.Clone(original), []byte("# changed\n")...), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(w.subscriptionPath(), []byte(`{"url":"https://example.com/private-token"}`), 0600); e != nil {
		t.Fatal(e)
	}
	reloads := 0
	w.state = func() (bool, bool, error) { return true, true, nil }
	w.serviceAction = func(context.Context, string, bool) error { reloads++; return nil }
	w.importPending = &webImportCandidate{}
	current, _ := os.ReadFile(w.configPath)
	body := `{"id":"` + id + `","confirm_insecure":true,"confirm_replace":true}`
	out := profileCall(t, w, "switch", body, `"`+shaHex(current)+`"`)
	if out.Code != 200 || reloads != 1 || w.importPending != nil {
		t.Fatal(out.Code, out.Body.String(), reloads)
	}
	got, _ := os.ReadFile(w.configPath)
	sel, _ := os.ReadFile(selectedPath(w.configPath))
	if !bytes.Equal(got, original) || !bytes.Equal(sel, selected) {
		t.Fatal("not exact restore")
	}
	if _, e := os.Lstat(w.subscriptionPath()); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("subscription not cleared", e)
	}
	out = profileCall(t, w, "switch", body, `"`+shaHex(original)+`"`)
	if out.Code != 200 || reloads != 1 {
		t.Fatal("no-op reloaded", out.Code, reloads)
	}
}
func TestWebProfilesRejectUnsafeSourcesAndPreconditions(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo", "stale-selection", "bad-id", "missing-etag", "stale-etag"} {
		t.Run(kind, func(t *testing.T) {
			w := profileFixture(t)
			if kind == "symlink" || kind == "fifo" {
				root := filepath.Join(filepath.Dir(w.configPath), "profiles")
				if e := os.Mkdir(root, 0700); e != nil {
					t.Fatal(e)
				}
				path := filepath.Join(root, strings.Repeat("a", 32)+".json")
				if kind == "symlink" {
					if e := os.Symlink(w.configPath, path); e != nil {
						t.Fatal(e)
					}
				} else {
					if e := unix.Mkfifo(path, 0600); e != nil {
						t.Fatal(e)
					}
				}
				if out := profileCall(t, w, "list", "", ""); out.Code != 503 {
					t.Fatal(out.Code)
				}
				return
			}
			if kind == "stale-selection" {
				if e := os.WriteFile(selectedPath(w.configPath), []byte("missing\n"), 0600); e != nil {
					t.Fatal(e)
				}
				if out := profileCall(t, w, "save", `{"name":"bad"}`, ""); out.Code != 422 {
					t.Fatal(out.Code)
				}
				return
			}
			id := profileSavedID(t, w)
			etag := ""
			want := 428
			if kind == "bad-id" {
				id = "../outside"
				want = 400
			}
			if kind == "stale-etag" {
				etag = `"stale"`
				want = 412
			}
			out := profileCall(t, w, "switch", `{"id":"`+id+`","confirm_insecure":true,"confirm_replace":true}`, etag)
			if out.Code != want {
				t.Fatal(out.Code, out.Body.String())
			}
		})
	}
}
func TestWebProfilesMissingSelectionAndMetadataOnlySwitch(t *testing.T) {
	w := profileFixture(t)
	// Both optional files are missing in the snapshot.
	id := profileSavedID(t, w)
	nodes, _ := loadNodes(w.configPath)
	if e := saveSelection(w.configPath, nodes[0].Name, nodes); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(w.subscriptionPath(), []byte(`{"url":"https://example.com/token"}`), 0600); e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(w.configPath)
	body := `{"id":"` + id + `","confirm_insecure":true,"confirm_replace":true}`
	out := profileCall(t, w, "switch", body, `"`+shaHex(raw)+`"`)
	if out.Code != 200 {
		t.Fatal(out.Code, out.Body.String())
	}
	for _, path := range []string{selectedPath(w.configPath), w.subscriptionPath()} {
		if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("optional absence lost", path, e)
		}
	}
	// Metadata-only restoration must not inspect/control the VPN.
	w.state = func() (bool, bool, error) { t.Fatal("metadata-only switch checked VPN"); return false, false, nil }
	if e := os.WriteFile(w.subscriptionPath(), []byte(`{"url":"https://example.com/token"}`), 0600); e != nil {
		t.Fatal(e)
	}
	out = profileCall(t, w, "list", "", "")
	if out.Code != 200 {
		t.Fatal(out.Code, out.Body.String())
	}
	var list struct {
		Profiles []webProfileSummary `json:"profiles"`
	}
	if json.Unmarshal(out.Body.Bytes(), &list) != nil || len(list.Profiles) != 1 || list.Profiles[0].Current {
		t.Fatal("subscription drift must clear current")
	}
	out = profileCall(t, w, "switch", body, `"`+shaHex(raw)+`"`)
	if out.Code != 200 {
		t.Fatal(out.Code, out.Body.String())
	}
	var result struct {
		Changed bool `json:"changed"`
		Saved   bool `json:"saved"`
		Applied bool `json:"applied"`
	}
	if json.Unmarshal(out.Body.Bytes(), &result) != nil || result.Changed || !result.Saved || result.Applied {
		t.Fatal("metadata-only save semantics", out.Body.String())
	}
}

func TestWebProfilesRouterSecurity(t *testing.T) {
	w := profileFixture(t)
	password, e := webReadPassword(w.passwordPath)
	if e != nil {
		t.Fatal(e)
	}
	cookie, csrf := webLogin(t, w, password)
	for _, path := range []string{"/api/v1/profiles", "/api/v1/profiles/copy", "/api/v1/profiles/switch"} {
		if out := webRequest(w, "POST", path, `{"name":"test"}`, nil, ""); out.Code != 401 {
			t.Fatal(path, out.Code)
		}
		if out := webRequest(w, "POST", path, `{"name":"test"}`, cookie, ""); out.Code != 403 {
			t.Fatal(path, out.Code)
		}
	}
	if out := webRequest(w, "GET", "/api/v1/profiles", "", nil, ""); out.Code != 401 {
		t.Fatal(out.Code)
	}
	w.actionMu.Lock()
	out := webRequest(w, "POST", "/api/v1/profiles", `{"name":"test"}`, cookie, csrf)
	w.actionMu.Unlock()
	if out.Code != 409 {
		t.Fatal("missing action lock", out.Code)
	}
}

func TestWebProfilesSourceIdentityAndUncertainRollback(t *testing.T) {
	w := profileFixture(t)
	id := profileSavedID(t, w)
	p, source, e := w.readProfile(id)
	if e != nil {
		t.Fatal(e)
	}
	old, e := w.profileFiles()
	if e != nil {
		t.Fatal(e)
	}
	// Same bytes at a new inode are still a conflicting source snapshot.
	if e := webAtomicWrite(source.path, source.data); e != nil {
		t.Fatal(e)
	}
	if code := w.commitProfile(p, source, old, webAtomicWrite); code != "PROFILE_CONFLICT" {
		t.Fatal(code)
	}
	_, source, e = w.readProfile(id)
	if e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(w.configPath, append(bytes.Clone(old[0].data), []byte("# changed\n")...), 0600); e != nil {
		t.Fatal(e)
	}
	old, e = w.profileFiles()
	if e != nil {
		t.Fatal(e)
	}
	w.importPending = &webImportCandidate{}
	code := w.commitProfile(p, source, old, func(string, []byte) error { return errors.New("persistent write fault") })
	if code != "PROFILE_STATE_UNCERTAIN" || w.importPending != nil {
		t.Fatal(code)
	}
}

func TestWebProfilesRollbackInjectedWriteFailure(t *testing.T) {
	w := profileFixture(t)
	nodes, _ := loadNodes(w.configPath)
	if e := saveSelection(w.configPath, nodes[0].Name, nodes); e != nil {
		t.Fatal(e)
	}
	id := profileSavedID(t, w)
	if e := os.Remove(selectedPath(w.configPath)); e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(w.configPath)
	changed := append(bytes.Clone(raw), []byte("# live\n")...)
	if e := os.WriteFile(w.configPath, changed, 0600); e != nil {
		t.Fatal(e)
	}
	old, e := w.profileFiles()
	if e != nil {
		t.Fatal(e)
	}
	p, source, e := w.readProfile(id)
	if e != nil {
		t.Fatal(e)
	}
	writes := 0
	write := func(path string, b []byte) error {
		writes++
		if writes == 2 {
			return errors.New("injected")
		}
		return webAtomicWrite(path, b)
	}
	// Force two changed leaves, then fail after the config publication.
	code := w.commitProfile(p, source, old, write)
	if code != "PROFILE_SWITCH_FAILED_ROLLED_BACK" {
		t.Fatal(code)
	}
	for _, f := range old {
		f.info = nil
		if !webProfileSame(f) {
			t.Fatal("rollback lost original existence or bytes")
		}
	}
}
