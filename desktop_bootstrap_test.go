package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func desktopFixture(t *testing.T) (string, string) {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(home, "AnyTLSMenuBar.app", "Contents", "Resources", "runtime", "anytls-macos")
	if err = os.MkdirAll(filepath.Dir(source), 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(source, []byte("owned synthetic executable fixture\n"), 0755); err != nil {
		t.Fatal(err)
	}
	return home, source
}
func TestDesktopPrepareFreshAndPreserve(t *testing.T) {
	home, source := desktopFixture(t)
	m, err := desktopPrepare(home, source, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	if !m.Installed || m.Binary != filepath.Join(home, ".anytls", "anytls-macos") || m.Listen != "0.0.0.0" || m.Endpoint != "http://127.0.0.1:18089" {
		t.Fatal(m)
	}
	nodes, err := loadNodes(m.Config)
	if err != nil || len(nodes) != 0 {
		t.Fatalf("empty starter: %v %v", nodes, err)
	}
	if _, err = preflightServiceNode(m.Config); err == nil {
		t.Fatal("empty starter must not start VPN")
	}
	preserved := map[string][]byte{"config.yaml": []byte("proxies: []\n# preserve verbatim\n"), "config.yaml.selected": []byte("existing selection"), "CA.pem": []byte("private fixture CA"), "rules.json": []byte("private fixture rules")}
	root := filepath.Dir(m.Binary)
	secret, err := os.ReadFile(filepath.Join(root, "webui.password"))
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range preserved {
		if err = os.WriteFile(filepath.Join(root, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	again, err := desktopPrepare(home, source, os.Getuid())
	if err != nil || again.Installed {
		t.Fatalf("idempotent: %+v %v", again, err)
	}
	for name, b := range preserved {
		got, e := os.ReadFile(filepath.Join(root, name))
		if e != nil || !bytes.Equal(got, b) {
			t.Fatal("preservation", name, e)
		}
	}
	got, err := os.ReadFile(filepath.Join(root, "webui.password"))
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatal("secret changed")
	}
	for name, mode := range map[string]os.FileMode{"anytls-macos": 0755, "config.yaml": 0600, "webui.password": 0600} {
		s, e := os.Stat(filepath.Join(root, name))
		if e != nil || s.Mode().Perm() != mode {
			t.Fatal(name, e)
		}
	}
}
func TestDesktopPrepareRefusesExistingDifferentBeforeWrites(t *testing.T) {
	home, source := desktopFixture(t)
	root := filepath.Join(home, ".anytls")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "anytls-macos")
	before := []byte("old executable must remain")
	if err := os.WriteFile(target, before, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := desktopPrepare(home, source, os.Getuid()); err == nil || err.Error() != "UPDATE_REQUIRED" {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(target)
	if !bytes.Equal(got, before) {
		t.Fatal("old image replaced")
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 1 {
		t.Fatal("refusal wrote files", entries)
	}
}
func TestDesktopRejectsUnsafePaths(t *testing.T) {
	for _, kind := range []string{"source-layout", "source-link", "root-link", "root-writable", "target-link", "target-hardlink", "secret-mode", "secret-link"} {
		t.Run(kind, func(t *testing.T) {
			home, source := desktopFixture(t)
			root := filepath.Join(home, ".anytls")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "source-layout":
				source = filepath.Join(home, "other")
				os.WriteFile(source, []byte("x"), 0755)
			case "source-link":
				real := source + ".real"
				os.Rename(source, real)
				os.Symlink(real, source)
			case "root-link":
				os.Remove(root)
				real := root + ".real"
				os.Mkdir(real, 0700)
				os.Symlink(real, root)
			case "root-writable":
				os.Chmod(root, 0777)
			case "target-link":
				os.Symlink(source, filepath.Join(root, "anytls-macos"))
			case "target-hardlink":
				os.Link(source, filepath.Join(root, "anytls-macos"))
			case "secret-mode":
				os.WriteFile(filepath.Join(root, "webui.password"), []byte("unsafe"), 0644)
			case "secret-link":
				os.Symlink(source, filepath.Join(root, "webui.password"))
			}
			if _, err := desktopPrepare(home, source, os.Getuid()); err == nil {
				t.Fatal("unsafe path accepted")
			}
		})
	}
}
func TestDesktopHelperBinding(t *testing.T) {
	m := desktopMetadata{BinarySHA256: "sha", ConfigIdentity: "config"}
	good := controlHelperResponse{OK: true, HelperSHA256: "sha", ConfigIdentity: "config"}
	if desktopHelperState(m, good, nil) != "ready" {
		t.Fatal("binding")
	}
	for _, r := range []controlHelperResponse{{OK: false, HelperSHA256: "sha", ConfigIdentity: "config"}, {OK: true, HelperSHA256: "wrong", ConfigIdentity: "config"}, {OK: true, HelperSHA256: "sha", ConfigIdentity: "wrong"}} {
		if desktopHelperState(m, r, nil) != "mismatch" {
			t.Fatal("wrong helper accepted")
		}
	}
}
func TestDesktopCredentialFixture(t *testing.T) {
	home, source := desktopFixture(t)
	m, err := desktopPrepare(home, source, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	secret, err := desktopReadCredential(home, os.Getuid())
	if err != nil || len(secret) != 32 {
		t.Fatal("owned secret unavailable")
	}
	path := filepath.Join(filepath.Dir(m.Binary), "webui.password")
	if err = os.WriteFile(path, bytes.Repeat([]byte("x"), 129), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = desktopReadCredential(home, os.Getuid()); err == nil {
		t.Fatal("oversize secret accepted")
	}
	if err = os.WriteFile(path, []byte("not-base64\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = desktopReadCredential(home, os.Getuid()); err == nil {
		t.Fatal("malformed secret accepted")
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = desktopReadCredential(home, os.Getuid()); err == nil {
		t.Fatal("public secret accepted")
	}
}
func TestDesktopPublicationDirectoryFence(t *testing.T) {
	home, _ := desktopFixture(t)
	root := filepath.Join(home, ".anytls")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	anchor, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(root, root+".old"); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err = desktopPublish(root, "leaf", []byte("candidate"), 0600, anchor); err == nil {
		t.Fatal("replaced parent accepted")
	}
	if _, err = os.Lstat(filepath.Join(root, "leaf")); !os.IsNotExist(err) {
		t.Fatal("published into replacement root")
	}
}
func TestDesktopLegacyLayoutRefusesBeforeWrites(t *testing.T) {
	home, source := desktopFixture(t)
	root := filepath.Join(home, ".anytls")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "anytls"), []byte("legacy fixture"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := desktopPrepare(home, source, os.Getuid()); err == nil || err.Error() != "LEGACY_LAYOUT_REQUIRES_REVIEW" {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatal("legacy layout mutated")
	}
}
func TestDesktopStarterRealRouterLogin(t *testing.T) {
	home, source := desktopFixture(t)
	m, err := desktopPrepare(home, source, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	password, err := desktopReadCredential(home, os.Getuid())
	if err != nil {
		t.Fatal("credential fixture failed")
	}
	w := newWebConsole(m.Config, filepath.Join(filepath.Dir(m.Config), "webui.password"), 18089)
	w.state = func() (bool, bool, error) { return false, false, nil }
	w.serviceAction = func(context.Context, string, bool) error {
		t.Error("unexpected lifecycle mutation")
		return errors.New("fixture rejects lifecycle")
	}
	cookie, csrf := webLogin(t, w, password)
	rec := webRequest(w, "GET", "/api/v1/nodes", "", cookie, csrf)
	var response struct {
		Nodes []json.RawMessage `json:"nodes"`
		ETag  string            `json:"etag"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &response) != nil || response.Nodes == nil || len(response.Nodes) != 0 || response.ETag == "" {
		t.Fatal("starter not editable through existing authenticated router", rec.Code)
	}
}
func TestDesktopCredentialOutputRequiresPipe(t *testing.T) {
	var out bytes.Buffer
	if err := desktopDispatch([]string{"credentials"}, &out); err == nil {
		t.Fatal("credential output accepted without pipe")
	}
	var result struct {
		Schema int    `json:"schema"`
		Error  string `json:"error"`
	}
	if json.Unmarshal(out.Bytes(), &result) != nil || result.Schema != 1 || (result.Error != "PRIVATE_PIPE_REQUIRED" && result.Error != "EMBEDDED_CORE_REQUIRED") {
		t.Fatal("unsafe credential response")
	}
}
func TestDesktopDispatchRejectsArguments(t *testing.T) {
	for _, args := range [][]string{{}, {"prepare", "/arbitrary/source"}, {"credentials", "reset"}, {"console"}} {
		var out bytes.Buffer
		if err := desktopDispatch(args, &out); err == nil {
			t.Fatal(args)
		}
		if !bytes.Contains(out.Bytes(), []byte(`"schema":1`)) || bytes.Contains(out.Bytes(), []byte("password")) {
			t.Fatal("unsafe error", out.String())
		}
	}
}
