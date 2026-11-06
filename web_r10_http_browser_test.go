package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	ts "github.com/NiuStar/anytls-core/internal/trafficstats"
)

// Opt-in browser qualification uses the real router and private durable files.
// Only privileged lifecycle and the subscription provider are synthetic seams.
func TestR10RealHTTPBrowser(t *testing.T) {
	if os.Getenv("ANYTLS_R10_HTTP_BROWSER") != "1" {
		t.Skip("opt-in local browser qualification")
	}
	node := os.Getenv("ANYTLS_R10_NODE")
	if node == "" {
		t.Fatal("explicit Node path required")
	}
	evidence := os.Getenv("ANYTLS_R10_HTTP_EVIDENCE")
	if evidence == "" {
		t.Fatal("exclusive evidence path required")
	}
	if err := os.Mkdir(evidence, 0700); err != nil {
		t.Fatal(err)
	}
	w, password := webFixture(t)
	if err := os.WriteFile(w.configPath, []byte(webImportYAML), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	w.port = listener.Addr().(*net.TCPAddr).Port
	w.state = func() (bool, bool, error) { return false, false, nil }
	w.serviceAction = func(context.Context, string, bool) error { t.Error("browser invoked privileged action"); return nil }
	w.importFetch = func(context.Context, string) ([]byte, error) { return []byte(webImportYAML), nil }
	w.trafficRequest = func(context.Context) (ts.Response, error) { return ts.Unavailable(), nil }
	// Stable release lookup is synthetic; admission, auth and response are real HTTP.
	w.updateAction = func(_ context.Context, check bool) (json.RawMessage, error) {
		if !check {
			t.Error("browser attempted automatic installation")
		}
		return json.RawMessage(`{"current":"v2026-11-06-02","installed":"v2026-11-06-02","latest":"v2026-11-07-01","status":"UPDATE_AVAILABLE","available":true,"sourceOnly":false,"updated":false,"restartRequired":false}`), nil
	}
	// Create a genuine login session through the application's existing login handler.
	// The cookie stays in anonymous child stdin, not argv, disk or the evidence log.
	w.port = 18089
	cookie, _ := webLogin(t, w, password)
	w.port = listener.Addr().(*net.TCPAddr).Port
	server := &http.Server{Handler: w, ReadHeaderTimeout: 5 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() { server.Close(); <-done }()
	origin := "http://127.0.0.1:" + strconv.Itoa(w.port)
	payload, _ := json.Marshal(map[string]string{"origin": origin, "cookie_name": cookie.Name, "cookie_value": cookie.Value, "evidence": evidence})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "web_r10_http_browser_test.mjs")
	cmd.Stdin = strings.NewReader(string(payload))
	cmd.Env = os.Environ()
	log, err := os.OpenFile(filepath.Join(evidence, "browser.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = log
	cmd.Stderr = log
	err = cmd.Run()
	log.Close()
	if err != nil {
		t.Fatalf("browser failed: %v (see private evidence log)", err)
	}
	var result struct {
		Status string   `json:"status"`
		Errors []string `json:"errors"`
		Checks []any    `json:"checks"`
	}
	b, err := os.ReadFile(filepath.Join(evidence, "results.json"))
	if err != nil || json.Unmarshal(b, &result) != nil || result.Status != "PASS" || len(result.Errors) != 0 || len(result.Checks) < 60 {
		t.Fatal("missing complete browser result")
	}
	t.Logf("actual authenticated HTTP browser checks: %d; no privileged service action", len(result.Checks))
}
