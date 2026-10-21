package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const webImportYAML = "# keep this comment\nnodes:\n - {name: imported, type: anytls, server: 1.1.1.1, port: 443, password: secret, skip-cert-verify: true}\nx-custom: '00123'\nrules: ['MATCH,DIRECT']\n"

func importRequest(t *testing.T, w *webConsole, c *http.Cookie, csrf, path string, body any, etag string) *httptest.ResponseRecorder {
	t.Helper()
	b, e := json.Marshal(body)
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("POST", "http://127.0.0.1:18089/api/v1/"+path, bytes.NewReader(b))
	r.Header.Set("Origin", "http://127.0.0.1:18089")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("If-Match", etag)
	if c != nil {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, r)
	return rec
}
func importPreview(t *testing.T, w *webConsole, c *http.Cookie, csrf string, body any) map[string]any {
	t.Helper()
	rec := importRequest(t, w, c, csrf, "import/preview", body, "")
	if rec.Code != 200 {
		t.Fatalf("preview: %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if json.Unmarshal(rec.Body.Bytes(), &out) != nil {
		t.Fatal("JSON")
	}
	return out
}
func importCommit(t *testing.T, w *webConsole, c *http.Cookie, csrf string, p map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	return importRequest(t, w, c, csrf, "import/commit", map[string]any{"token": p["token"], "confirm_replace": true, "confirm_insecure": true}, p["etag"].(string))
}
func TestWebImportInputExclusion(t *testing.T) {
	w, password := webFixture(t)
	c, csrf := webLogin(t, w, password)
	for _, body := range []any{map[string]any{}, map[string]any{"yaml": webImportYAML, "url": "https://sub.example/"}, map[string]any{"yaml": webImportYAML, "use_saved": false}, map[string]any{"yaml": webImportYAML, "url": nil}, map[string]any{"use_saved": false}} {
		rec := importRequest(t, w, c, csrf, "import/preview", body, "")
		if rec.Code != 400 {
			t.Fatal(rec.Code, rec.Body.String())
		}
	}
}
func TestWebImportRejectBoundaries(t *testing.T) {
	for _, mode := range []string{"auth", "csrf", "ttl", "session", "config", "selection", "ifmatch", "failed-preview", "busy"} {
		t.Run(mode, func(t *testing.T) {
			w, password := webFixture(t)
			c, csrf := webLogin(t, w, password)
			old, _ := os.ReadFile(w.configPath)
			if mode == "auth" || mode == "csrf" {
				cc, cs := c, csrf
				if mode == "auth" {
					cc = nil
				} else {
					cs = ""
				}
				rec := importRequest(t, w, cc, cs, "import/preview", map[string]any{"yaml": webImportYAML}, "")
				want := 403
				if mode == "auth" {
					want = 401
				}
				if rec.Code != want {
					t.Fatal(rec.Code)
				}
				return
			}
			p := importPreview(t, w, c, csrf, map[string]any{"yaml": webImportYAML})
			want := 409
			switch mode {
			case "ttl":
				now := w.now()
				w.now = func() time.Time { return now.Add(10 * time.Minute) }
			case "session":
				c, csrf = webLogin(t, w, password)
			case "config":
				if e := os.WriteFile(w.configPath, append(old, []byte("# external\n")...), 0600); e != nil {
					t.Fatal(e)
				}
				want = 412
			case "selection":
				if e := os.WriteFile(selectedPath(w.configPath), []byte("other\n"), 0600); e != nil {
					t.Fatal(e)
				}
				want = 412
			case "ifmatch":
				p["etag"] = ""
				want = 428
			case "failed-preview":
				r := importRequest(t, w, c, csrf, "import/preview", map[string]any{"yaml": "not YAML mapping"}, "")
				if r.Code != 422 {
					t.Fatal(r.Code)
				}
			case "busy":
				w.actionMu.Lock()
				defer w.actionMu.Unlock()
			}
			rec := importCommit(t, w, c, csrf, p)
			if rec.Code != want {
				t.Fatalf("%d %s", rec.Code, rec.Body.String())
			}
			if mode != "config" {
				got, _ := os.ReadFile(w.configPath)
				if !bytes.Equal(got, old) {
					t.Fatal("rejection changed config")
				}
			}
		})
	}
}
func TestWebImportSelectionApplyAndNoop(t *testing.T) {
	for _, mode := range []string{"stopped", "failed", "noop"} {
		t.Run(mode, func(t *testing.T) {
			w, password := webFixture(t)
			c, csrf := webLogin(t, w, password)
			calls := 0
			if e := os.WriteFile(w.configPath, []byte(webImportYAML), 0600); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(selectedPath(w.configPath), []byte("imported\n"), 0600); e != nil {
				t.Fatal(e)
			}
			w.baseline = w.fingerprint()
			w.state = func() (bool, bool, error) { return mode != "stopped", mode != "stopped", nil }
			w.serviceAction = func(_ context.Context, action string, consent bool) error {
				calls++
				if action != "reload" || !consent {
					t.Fatal("bad apply")
				}
				if w.actionMu.TryLock() {
					w.actionMu.Unlock()
					t.Fatal("lock released")
				}
				return errors.New("SECRET_APPLY")
			}
			candidate := webImportYAML
			if mode != "noop" {
				candidate += "# change\n"
			}
			p := importPreview(t, w, c, csrf, map[string]any{"yaml": candidate})
			if p["selected"] != "imported" {
				t.Fatal(p)
			}
			rec := importCommit(t, w, c, csrf, p)
			status := "SAVED_STOPPED"
			if mode == "failed" {
				status = "APPLY_FAILED"
			}
			if mode == "noop" {
				status = "NO_CHANGE"
			}
			webAutoResult(t, rec, status, mode != "noop", false, mode != "noop")
			want := 0
			if mode == "failed" {
				want = 1
			}
			if calls != want {
				t.Fatal(calls)
			}
			b, _ := os.ReadFile(w.configPath)
			if string(b) != candidate || strings.Contains(rec.Body.String(), "SECRET_APPLY") {
				t.Fatal("save semantics")
			}
		})
	}
}
func TestWebImportSubscriptionPrivacyAndLocalKeep(t *testing.T) {
	w, password := webFixture(t)
	c, csrf := webLogin(t, w, password)
	raw := "https://sub.example/feed?token=TOP_SECRET"
	calls := 0
	w.importFetch = func(ctx context.Context, u string) ([]byte, error) {
		calls++
		if u != raw {
			t.Fatal("wrong URL")
		}
		return []byte(webImportYAML), nil
	}
	p := importPreview(t, w, c, csrf, map[string]any{"url": raw})
	if p["source_host"] != "sub.example" {
		t.Fatal(p)
	}
	rec := importCommit(t, w, c, csrf, p)
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	f, e := webImportCapture(w.subscriptionPath(), snapshotConfigLimit, false)
	if e != nil {
		t.Fatal(e)
	}
	got, e := webImportSubscription(f)
	if e != nil || got != raw {
		t.Fatal("metadata", e)
	}
	rec = webRequest(w, "GET", "/api/v1/subscription", "", c, "")
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "TOP_SECRET") || !strings.Contains(rec.Body.String(), "sub.example") || calls != 1 {
		t.Fatal(rec.Body.String(), calls)
	}
	p = importPreview(t, w, c, csrf, map[string]any{"use_saved": true})
	if calls != 2 {
		t.Fatal(calls)
	}
	_ = p
	p = importPreview(t, w, c, csrf, map[string]any{"yaml": webImportYAML})
	if !strings.Contains(p["warning"].(string), "kept unchanged") {
		t.Fatal(p)
	}
	rec = importCommit(t, w, c, csrf, p)
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	b, _ := os.ReadFile(w.subscriptionPath())
	if !bytes.Equal(b, f.data) {
		t.Fatal("local import changed metadata")
	}
	if e = os.WriteFile(w.subscriptionPath(), []byte(`{"url":"https://sub.example/?x=SECRET","url":"https://sub.example/"}`), 0600); e != nil {
		t.Fatal(e)
	}
	rec = webRequest(w, "GET", "/api/v1/subscription", "", c, "")
	if rec.Code != 503 || strings.Contains(rec.Body.String(), "SECRET") {
		t.Fatal(rec.Body.String())
	}
}
func TestWebImportFormatsRemotePathsAndInvalidUntouched(t *testing.T) {
	for _, candidate := range []string{"anytls://secret@example", "cHJveGllcw==", "[Proxy]\na=anytls,example,443", "nodes: []\n", strings.Replace(webImportYAML, "type: anytls", "type: ss", 1), webImportYAML + "proxy-providers: {}\n"} {
		w, password := webFixture(t)
		c, csrf := webLogin(t, w, password)
		old, _ := os.ReadFile(w.configPath)
		r := importRequest(t, w, c, csrf, "import/preview", map[string]any{"yaml": candidate}, "")
		if r.Code != 422 {
			t.Fatal(r.Code, r.Body.String())
		}
		b, _ := os.ReadFile(w.configPath)
		if !bytes.Equal(b, old) {
			t.Fatal("invalid write")
		}
	}
	for _, suffix := range []string{"extra: {ca: /etc/passwd}\n", "extra: {path: /etc/passwd}\n", "x: &x {path: /etc/passwd}\ny: *x\n", "x: &x {foo: bar}\ny: {<<: *x}\n"} {
		converted, report, err := webConvertConfiguration(context.Background(), []byte(webImportYAML+suffix), true, nil)
		if err != nil || len(report.Issues) != 0 || webImportFormat(converted, false) != nil {
			t.Fatal("inert path metadata or template was blanket-rejected", err, report)
		}
	}
}
func TestWebImportNetworkGuards(t *testing.T) {
	for _, raw := range []string{"http://sub.example/", "https://user:pass@sub.example/", "https://sub.example:8443/", "https://sub.example/#x", "https://127.0.0.1/", "https://[::1]/", "https://169.254.169.254/latest/", "https://localhost/", "https://sub.example:/"} {
		if _, e := webImportURL(raw); e == nil {
			t.Fatal("URL accepted", raw)
		}
	}
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.100.100.200", "0.0.0.0", "224.0.0.1", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "2001:db8::1"} {
		if webImportPublic(net.ParseIP(ip)) {
			t.Fatal("private accepted", ip)
		}
	}
	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !webImportPublic(net.ParseIP(ip)) {
			t.Fatal("public rejected", ip)
		}
	}
	public := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
	}
	for _, mode := range []string{"ok", "mixed", "redirect", "large", "timeout", "error", "status", "redirect-limit"} {
		t.Run(mode, func(t *testing.T) {
			lookups, trips := 0, 0
			lookup := func(ctx context.Context, host string) ([]net.IPAddr, error) {
				lookups++
				if mode == "mixed" {
					return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}, {IP: net.ParseIP("127.0.0.1")}}, nil
				}
				return public(ctx, host)
			}
			round := func(r *http.Request, tr *http.Transport) (*http.Response, error) {
				trips++
				if tr.Proxy != nil || tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.ServerName != "sub.example" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
					t.Fatal("unsafe transport")
				}
				if _, ok := r.Context().Deadline(); !ok {
					t.Fatal("no timeout")
				}
				resp := &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(webImportYAML)), Header: make(http.Header), Request: r}
				switch mode {
				case "redirect":
					resp.StatusCode = 302
					resp.Header.Set("Location", "https://127.0.0.1/private?secret=LEAK")
				case "redirect-limit":
					resp.StatusCode = 302
					resp.Header.Set("Location", "https://sub.example/again")
				case "large":
					resp.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", snapshotConfigLimit+1)))
				case "timeout", "error":
					return nil, errors.New("https://sub.example/?secret=LEAK")
				case "status":
					resp.StatusCode = 500
				}
				return resp, nil
			}
			b, e := webImportFetchWith(context.Background(), "https://sub.example/?secret=LEAK", lookup, round)
			if mode == "ok" {
				if e != nil || string(b) != webImportYAML {
					t.Fatal(e)
				}
				return
			}
			if e == nil || strings.Contains(e.Error(), "LEAK") {
				t.Fatal("bad rejection", e)
			}
			if mode == "mixed" && trips != 0 {
				t.Fatal("private dialed")
			}
			if mode == "redirect-limit" && (trips != 4 || lookups != 4) {
				t.Fatal(trips, lookups)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e := webImportFetchWith(ctx, "https://sub.example/", func(ctx context.Context, _ string) ([]net.IPAddr, error) { return nil, ctx.Err() }, nil)
	if e == nil {
		t.Fatal("cancel accepted")
	}
}
func TestWebImportFetchTimeoutAndSanitizedHTTPError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
	}
	_, e := webImportFetchWith(ctx, "https://sub.example/?token=SECRET", lookup, func(r *http.Request, _ *http.Transport) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	if e == nil || e.Error() != "IMPORT_FETCH_FAILED" {
		t.Fatal(e)
	}
	w, password := webFixture(t)
	c, csrf := webLogin(t, w, password)
	w.importFetch = func(context.Context, string) ([]byte, error) {
		return nil, errors.New("https://sub.example/?token=SECRET")
	}
	rec := importRequest(t, w, c, csrf, "import/preview", map[string]any{"url": "https://sub.example/?token=SECRET"}, "")
	if rec.Code != 422 || strings.Contains(rec.Body.String(), "SECRET") || !strings.Contains(rec.Body.String(), "IMPORT_FETCH_FAILED") {
		t.Fatal(rec.Body.String())
	}
}
func TestWebImportPinsDNSAndRelativeRedirect(t *testing.T) {
	calls := 0
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		calls++
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
	}
	dials := 0
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		dials++
		if network != "tcp" || address != "1.1.1.1:443" {
			t.Fatal("unpinned", network, address)
		}
		return nil, errors.New("fake dial: no network")
	}
	trips := 0
	round := func(r *http.Request, tr *http.Transport) (*http.Response, error) {
		trips++
		_, _ = tr.DialContext(r.Context(), "tcp", "attacker.invalid:1")
		resp := &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(webImportYAML))}
		if trips == 1 {
			resp.StatusCode = 302
			resp.Header.Set("Location", "/next")
		} else if r.URL.Path != "/next" {
			t.Fatal("relative redirect", r.URL.Path)
		}
		return resp, nil
	}
	b, e := webImportFetchWith(context.Background(), "https://sub.example/first", lookup, round, dial)
	if e != nil || string(b) != webImportYAML || calls != 2 || dials != 2 {
		t.Fatal(e, calls, dials)
	}
}
func TestWebImportBacksUpExistingSelectionAndSubscription(t *testing.T) {
	w, password := webFixture(t)
	c, csrf := webLogin(t, w, password)
	oldSelection := []byte("retired-node\n")
	oldMetadata := []byte("{\n \"url\": \"https://sub.example/feed?token=OLD_SECRET\"\n}\n")
	if e := os.WriteFile(selectedPath(w.configPath), oldSelection, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(w.subscriptionPath(), oldMetadata, 0600); e != nil {
		t.Fatal(e)
	}
	p := importPreview(t, w, c, csrf, map[string]any{"yaml": webImportYAML})
	rec := importCommit(t, w, c, csrf, p)
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	dirs, e := os.ReadDir(filepath.Join(filepath.Dir(w.configPath), "import-backups"))
	if e != nil || len(dirs) != 1 {
		t.Fatal(e)
	}
	root := filepath.Join(filepath.Dir(w.configPath), "import-backups", dirs[0].Name())
	for _, f := range []struct {
		name string
		data []byte
	}{{"config.yaml.selected", oldSelection}, {"subscription.json", oldMetadata}} {
		b, e := os.ReadFile(filepath.Join(root, f.name))
		if e != nil || !bytes.Equal(b, f.data) {
			t.Fatal(f.name, e)
		}
		st, e := os.Stat(filepath.Join(root, f.name))
		if e != nil || st.Mode().Perm() != 0600 {
			t.Fatal("backup mode", e)
		}
	}
	b, _ := os.ReadFile(w.subscriptionPath())
	if !bytes.Equal(b, oldMetadata) {
		t.Fatal("metadata rewritten")
	}
}
func TestWebImportCommitReadbackFailureRollsBackWholeTransaction(t *testing.T) {
	w, password := webFixture(t)
	c, csrf := webLogin(t, w, password)
	old, _ := os.ReadFile(w.configPath)
	oldSelected := []byte("retired\n")
	if e := os.WriteFile(selectedPath(w.configPath), oldSelected, 0600); e != nil {
		t.Fatal(e)
	}
	// This name is accepted by the existing loader/saveSelection, but its saved
	// selection exceeds the existing selected-file reader limit. Exercise the
	// real post-write failure, not a fake transaction implementation.
	candidate := strings.Replace(webImportYAML, "name: imported", "name: "+strings.Repeat("n", snapshotSelectedLimit+1), 1)
	w.importFetch = func(context.Context, string) ([]byte, error) { return []byte(candidate), nil }
	p := importPreview(t, w, c, csrf, map[string]any{"url": "https://sub.example/?token=PRIVATE"})
	rec := importCommit(t, w, c, csrf, p)
	if rec.Code != 500 || !strings.Contains(rec.Body.String(), "IMPORT_WRITE_FAILED_ROLLED_BACK") {
		t.Fatal(rec.Code, rec.Body.String())
	}
	b, _ := os.ReadFile(w.configPath)
	s, _ := os.ReadFile(selectedPath(w.configPath))
	if !bytes.Equal(b, old) || !bytes.Equal(s, oldSelected) {
		t.Fatal("partial transaction survived")
	}
	if _, e := os.Stat(w.subscriptionPath()); !os.IsNotExist(e) {
		t.Fatal("new metadata survived rollback")
	}
}
func TestWebImportRollbackRestoresExactFiles(t *testing.T) {
	root := t.TempDir()
	old := []byte("# old config\n")
	files := []webImportFile{{path: filepath.Join(root, "config.yaml"), data: old, exists: true}, {path: filepath.Join(root, "selected")}, {path: filepath.Join(root, "subscription.json"), data: []byte(`{"url":"https://sub.example/"}`), exists: true}}
	for _, f := range files {
		if e := os.WriteFile(f.path, []byte("partial"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if !webImportRollback(files) {
		t.Fatal("rollback failed")
	}
	for _, f := range files {
		if !webImportSame(f) {
			t.Fatal("rollback readback")
		}
	}
	if e := os.Mkdir(files[0].path+".dir", 0700); e != nil {
		t.Fatal(e)
	}
	files[0].path += ".dir"
	if webImportRollback(files) {
		t.Fatal("unconfirmed rollback accepted")
	}
}
func TestWebImportPreviewCommitRawBackup(t *testing.T) {
	w, p := webFixture(t)
	c, csrf := webLogin(t, w, p)
	old, _ := os.ReadFile(w.configPath)
	preview := importPreview(t, w, c, csrf, map[string]any{"yaml": webImportYAML})
	if preview["selected"] != "imported" || preview["nodes"] != float64(1) {
		t.Fatal(preview)
	}
	got, _ := os.ReadFile(w.configPath)
	if !bytes.Equal(old, got) {
		t.Fatal("preview wrote config")
	}
	if _, e := os.Stat(filepath.Join(filepath.Dir(w.configPath), "import-backups")); !os.IsNotExist(e) {
		t.Fatal("preview wrote backup")
	}
	rec := importCommit(t, w, c, csrf, preview)
	webAutoResult(t, rec, "SAVED_STOPPED", true, false, true)
	got, _ = os.ReadFile(w.configPath)
	if string(got) != webImportYAML {
		t.Fatal("raw bytes lost")
	}
	s, e := selectedNode(w.configPath, []node{{Name: "imported", Type: "anytls", Server: "1.1.1.1", Port: 443, Password: "secret"}})
	if e != nil || s != "imported" {
		t.Fatal(s, e)
	}
	dirs, e := os.ReadDir(filepath.Join(filepath.Dir(w.configPath), "import-backups"))
	if e != nil || len(dirs) != 1 {
		t.Fatal(dirs, e)
	}
	root := filepath.Join(filepath.Dir(w.configPath), "import-backups", dirs[0].Name())
	b, e := os.ReadFile(filepath.Join(root, "config.yaml"))
	if e != nil || !bytes.Equal(b, old) {
		t.Fatal("backup", e)
	}
	if _, e = os.Stat(filepath.Join(root, "config.yaml.selected")); !os.IsNotExist(e) {
		t.Fatal("invented missing selection")
	}
}
