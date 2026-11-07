package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	ts "github.com/NiuStar/anytls-core/internal/trafficstats"
)

// Native contract: PROBE --integration reads {origin,password,evidence} from
// stdin and emits only {"ok":true,"checks":N} on stdout. The probe must use the
// shipped APIClient/URLSession, not a URLProtocol stub. No credentials in argv.
// Sequence: login, read status/nodes/traffic; authenticated traffic without
// X-AnyTLS-Origin => 403; select second while stopped => SAVED_STOPPED; start;
// select first while running => APPLIED (one reload); stop. Refresh nodes/ETag
// before each selection. Never request helper/status: its production handler
// bypasses the lifecycle seam. The allowlist below fences ALL other routes too.
func TestMenuBarNativeHTTP(t *testing.T) {
	if os.Getenv("ANYTLS_MENUBAR_HTTP_NATIVE") != "1" {
		t.Skip("opt in with ANYTLS_MENUBAR_HTTP_NATIVE=1")
	}
	if runtime.GOOS != "darwin" {
		t.Fatal("native HTTP integration requires Darwin; no simulated fallback")
	}
	probe := os.Getenv("ANYTLS_MENUBAR_NATIVE_PROBE")
	info, err := os.Stat(probe)
	if !filepath.IsAbs(probe) || err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		t.Fatal("ANYTLS_MENUBAR_NATIVE_PROBE must be an absolute executable file")
	}
	evidence := os.Getenv("ANYTLS_MENUBAR_HTTP_EVIDENCE")
	if !filepath.IsAbs(evidence) {
		t.Fatal("ANYTLS_MENUBAR_HTTP_EVIDENCE must be an absolute, nonexistent directory")
	}
	if err := os.Mkdir(evidence, 0700); err != nil {
		t.Fatalf("reserve exclusive evidence directory: %v", err)
	}
	f := newMenuBarHTTPFixture(t)
	input, err := json.Marshal(map[string]string{"origin": f.origin, "password": f.password, "evidence": evidence})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	// This is the ONLY child process: the explicitly authorized Swift probe.
	cmd := exec.CommandContext(ctx, probe, "--integration")
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	// Redact even a misbehaving probe before preserving diagnostics.
	for name, data := range map[string][]byte{"probe.stdout.json": stdout.Bytes(), "probe.stderr.log": stderr.Bytes()} {
		data = bytes.ReplaceAll(data, []byte(f.password), []byte("[REDACTED]"))
		if e := os.WriteFile(filepath.Join(evidence, name), data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if err != nil {
		t.Fatalf("native probe failed: %v (diagnostics in evidence directory)", err)
	}
	var result struct {
		OK     bool `json:"ok"`
		Checks int  `json:"checks"`
	}
	if json.Unmarshal(stdout.Bytes(), &result) != nil || !result.OK || result.Checks < 1 {
		t.Fatal("probe must emit a successful JSON check summary")
	}
	f.verify(t)
	summary, _ := json.MarshalIndent(map[string]any{"ok": true, "checks": result.Checks, "transport": "real-loopback-http", "lifecycle": "synthetic-only", "productionHelper": "blocked", "actions": f.actionsCopy()}, "", "  ")
	if err := os.WriteFile(filepath.Join(evidence, "harness-result.json"), summary, 0600); err != nil {
		t.Fatal(err)
	}
}

type menuBarHTTPFixture struct {
	w                                                                 *webConsole
	origin, password, fingerprint                                     string
	config                                                            []byte
	mu                                                                sync.Mutex
	loaded, running                                                   bool
	actions                                                           []string
	counts                                                            map[string]int
	savedStopped, applied, forbiddenTraffic, observedTraffic, blocked int
}

type menuBarHTTPRecorder struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (r *menuBarHTTPRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}
func (r *menuBarHTTPRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.WriteHeader(200)
	}
	r.body.Write(p)
	return r.ResponseWriter.Write(p)
}

func newMenuBarHTTPFixture(t *testing.T) *menuBarHTTPFixture {
	t.Helper()
	w, password := webFixture(t)
	// webImportYAML has one insecure node. The existing two-node auto-apply
	// fixture exercises both selection transitions without insecure consent.
	webNodeFile(t, w, webAutoConfig)
	if err := os.WriteFile(selectedPath(w.configPath), []byte("first\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f := &menuBarHTTPFixture{w: w, password: password, config: []byte(webAutoConfig), counts: make(map[string]int)}
	f.fingerprint = w.fingerprint()
	if f.fingerprint == "" {
		t.Fatal("missing fixture fingerprint")
	}
	w.state = func() (bool, bool, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.loaded, f.running, nil
	}
	w.serviceAction = func(_ context.Context, action string, insecure bool) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		if insecure {
			return fmt.Errorf("unexpected insecure consent")
		}
		switch action {
		case "start":
			f.loaded, f.running = true, true
		case "stop":
			f.loaded, f.running = false, false
		case "reload":
			if !f.loaded || !f.running {
				return fmt.Errorf("reload while stopped")
			}
		default:
			return fmt.Errorf("unexpected fixture action")
		}
		f.actions = append(f.actions, action)
		return nil
	}
	identity, err := controlHelperConfigIdentity(w.configPath)
	if err != nil {
		t.Fatal(err)
	}
	counter := new(ts.Counter)
	counter.Upload(9007199254740993)
	sampler := ts.New(counter, recordsTestPage(identity).Header)
	// Prime at a real timestamp: the first HTTP response already has a rate
	// interval rather than null, so the strict native DTO parser can consume it.
	_ = sampler.Sample(time.Now(), "RUNNING")
	w.trafficRequest = func(context.Context) (ts.Response, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		snapshot := sampler.Sample(time.Now(), "RUNNING")
		return ts.Response{TrafficSchema: 1, Availability: "OBSERVED", Snapshot: &snapshot}, nil
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	w.listenHost = "127.0.0.1"
	w.port = listener.Addr().(*net.TCPAddr).Port
	f.origin = "http://" + listener.Addr().String()
	server := &http.Server{Handler: http.HandlerFunc(f.serveHTTP), ReadHeaderTimeout: 5 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		if err := <-done; err != nil && err != http.ErrServerClosed {
			t.Errorf("fixture server: %v", err)
		}
	})
	return f
}

func (f *menuBarHTTPFixture) serveHTTP(rw http.ResponseWriter, r *http.Request) {
	// Buffer until observation is recorded. Otherwise a fast final response can
	// let the probe exit before the server has recorded its last request.
	buffer := httptest.NewRecorder()
	f.routeHTTP(buffer, r)
	for key, values := range buffer.Header() {
		rw.Header()[key] = values
	}
	rw.WriteHeader(buffer.Code)
	_, _ = rw.Write(buffer.Body.Bytes())
}

func (f *menuBarHTTPFixture) routeHTTP(rw http.ResponseWriter, r *http.Request) {
	key := r.Method + " " + r.URL.Path
	switch key {
	case "POST /api/v1/login", "GET /api/v1/status", "GET /api/v1/nodes", "GET /api/v1/traffic", "POST /api/v1/nodes/selection", "POST /api/v1/service/start", "POST /api/v1/service/stop":
	default:
		f.mu.Lock()
		f.blocked++
		f.mu.Unlock()
		// Includes helper/status, startup-trace, update, records and every
		// unmocked IPC/network/process route. Never pass these to production.
		webError(rw, 503, "NATIVE_FIXTURE_ROUTE_BLOCKED")
		return
	}
	rec := &menuBarHTTPRecorder{ResponseWriter: rw}
	f.w.ServeHTTP(rec, r) // Real Host, Origin, cookie, CSRF, If-Match and telemetry guards.
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counts[key]++
	if key == "GET /api/v1/traffic" {
		if rec.status == 403 && r.Header.Get("X-AnyTLS-Origin") == "" {
			f.forbiddenTraffic++
		}
		if rec.status == 200 {
			f.observedTraffic++
		}
	}
	if key == "POST /api/v1/nodes/selection" && rec.status == 200 {
		var body struct {
			Status string `json:"apply_status"`
		}
		_ = json.Unmarshal(rec.body.Bytes(), &body)
		if body.Status == "SAVED_STOPPED" && len(f.actions) == 0 {
			f.savedStopped++
		}
		if body.Status == "APPLIED" && reflect.DeepEqual(f.actions, []string{"start", "reload"}) {
			f.applied++
		}
	}
}
func (f *menuBarHTTPFixture) actionsCopy() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.actions...)
}
func (f *menuBarHTTPFixture) verify(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if !reflect.DeepEqual(f.actions, []string{"start", "reload", "stop"}) || f.loaded || f.running {
		t.Fatalf("synthetic lifecycle: actions=%v loaded=%v running=%v", f.actions, f.loaded, f.running)
	}
	if f.blocked != 0 || f.savedStopped != 1 || f.applied != 1 || f.forbiddenTraffic < 1 || f.observedTraffic < 1 {
		t.Fatalf("route evidence: blocked=%d stopped=%d applied=%d negative=%d traffic=%d", f.blocked, f.savedStopped, f.applied, f.forbiddenTraffic, f.observedTraffic)
	}
	for _, key := range []string{"POST /api/v1/login", "GET /api/v1/status", "GET /api/v1/nodes"} {
		if f.counts[key] < 1 {
			t.Errorf("missing route %s", key)
		}
	}
	for key, want := range map[string]int{"POST /api/v1/nodes/selection": 2, "POST /api/v1/service/start": 1, "POST /api/v1/service/stop": 1} {
		if f.counts[key] != want {
			t.Errorf("%s requests=%d want=%d", key, f.counts[key], want)
		}
	}
	config, err := os.ReadFile(f.w.configPath)
	if err != nil || !bytes.Equal(config, f.config) {
		t.Fatal("fixture config unexpectedly changed", err)
	}
	selected, err := os.ReadFile(selectedPath(f.w.configPath))
	if err != nil || strings.TrimSpace(string(selected)) != "first" || f.w.fingerprint() != f.fingerprint {
		t.Fatal("selection/fingerprint readback failed", err)
	}
}

// Portable real-HTTP check of the isolated fixture, NOT native-client evidence.
func TestMenuBarHTTPFixtureIsolation(t *testing.T) {
	f := newMenuBarHTTPFixture(t)
	jar, _ := cookiejar.New(nil)
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Jar: jar, Transport: transport, Timeout: 5 * time.Second}
	csrf := ""
	call := func(method, path string, body map[string]any, etag string, telemetry bool, want int) map[string]any {
		t.Helper()
		data, _ := json.Marshal(body)
		r, err := http.NewRequest(method, f.origin+"/api/v1/"+path, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Origin", f.origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		if telemetry {
			r.Header.Set("X-AnyTLS-Origin", f.origin)
		}
		if etag != "" {
			r.Header.Set("If-Match", etag)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err = io.ReadAll(response.Body)
		if err != nil || response.StatusCode != want {
			t.Fatalf("%s %s: status=%d want=%d err=%v body=%s", method, path, response.StatusCode, want, err, data)
		}
		var result map[string]any
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	call("GET", "status", nil, "", true, 401)
	login := call("POST", "login", map[string]any{"username": "admin", "password": f.password}, "", true, 200)
	csrf = login["csrf"].(string)
	call("GET", "status", nil, "", true, 200)
	call("GET", "traffic", nil, "", false, 403)
	traffic := call("GET", "traffic", nil, "", true, 200)
	snapshot, ok := traffic["snapshot"].(map[string]any)
	if !ok || snapshot["rate"] == nil || snapshot["upload_bytes"] != "9007199254740993" {
		t.Fatal("fixture must expose rate and lossless string counters")
	}
	selectNode := func(name string) {
		nodes := call("GET", "nodes", nil, "", true, 200)
		call("POST", "nodes/selection", map[string]any{"name": name, "confirm_insecure": false}, nodes["etag"].(string), true, 200)
	}
	selectNode("second")
	call("POST", "service/start", map[string]any{"confirm_insecure": false}, "", true, 200)
	selectNode("first")
	call("POST", "service/stop", map[string]any{"confirm_insecure": false}, "", true, 200)
	f.verify(t)
	// Explicitly exercise the unsafe global helper route fence after verification.
	call("GET", "helper/status", nil, "", true, 503)
}
