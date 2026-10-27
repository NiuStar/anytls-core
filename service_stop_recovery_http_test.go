package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
)

// Same bytes compile on baseline. Authenticated HTTP -> private Unix IPC ->
// real lifecycle with simulated OS tools; no installed helper or live TUN.
func TestStopRecoveryHTTPWarning(t *testing.T) {
	for _, action := range []string{"stop", "reload", "save"} {
		t.Run(action, func(t *testing.T) {
			d, b, c, k, _, _ := lifecycleFixture(t)
			if err := d.start(b, c, k, true); err != nil { t.Fatal(err) }
			if err := os.Remove(filepath.Join(d.root, serviceBaselineName)); err != nil { t.Fatal(err) }
			w, password := webFixture(t)
			webNodeFile(t, w, webAutoConfig)
			s := unitControlServer()
			s.registration.Config = w.configPath
			s.state = d.state
			s.stop = func(ctx context.Context) error { return d.withStartup(ctx, s).stop() }
			s.start = func(ctx context.Context, allow bool) error { return d.withStartup(ctx, s).start(b, c, k, allow) }
			w.serviceAction = nil
			w.state = d.state
			w.startupReadRequest = func(context.Context, *string) (st.ReadResponse, error) { return st.ReadResponse{}, startupUnsupportedError{} }
			w.startupLegacyRequest = func(ctx context.Context, action string, allow bool) (controlHelperResponse, error) {
				conn, done := unitControlPair(t, s)
				defer conn.Close()
				r, err := controlHelperExchange(ctx, conn, controlHelperWireRequest{action, allow}, func(net.Conn) (uint32, error) { return 0, nil })
				<-done
				return r, err
			}
			cookie, csrf := webLogin(t, w, password)
			verb := action
			if verb == "save" { verb = "reload" }
			input := `{"confirm_insecure":true}`
			if action == "stop" { input = `{}` }
			var out *httptest.ResponseRecorder
			if action == "save" {
				out = httptest.NewRecorder()
				w.ServeHTTP(out, webAutoRequest(t, w, cookie, csrf, "config", true, true))
			} else {
				out = webRequest(w, "POST", "/api/v1/service/"+verb, input, cookie, csrf)
			}
			var body map[string]any
			if err := json.Unmarshal(out.Body.Bytes(), &body); err != nil { t.Fatal(err) }
			diag, ok := body["diagnostics"].(map[string]any)
			if out.Code != 200 || !ok || diag["outcome"] != "SUCCEEDED" || diag["restoration"] != "UNKNOWN" || diag["operation"] != strings.ToUpper(verb) { t.Fatalf("HTTP warning lost: %d %s", out.Code, out.Body.String()) }
			if action == "save" && (body["apply_status"] != "APPLIED" || body["saved"] != true) { t.Fatal("warning changed save semantics", body) }
			if strings.Contains(out.Body.String(), d.root) { t.Fatal("private archive path leaked") }
		})
	}
}
