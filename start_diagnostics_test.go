package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Same bytes compile on the old source: assertions use public JSON, not new fields.
func TestStartDiagnosticsTrace(t *testing.T) {
	for _, mode := range []string{"manual", "save"} {
		t.Run(mode, func(t *testing.T) {
			d, b, c, k, _, _ := lifecycleFixture(t)
			secret := errors.New("PRIVATE_PASSWORD_PROXY_SENTINEL")
			d.proxy = func() error { return secret }
			w, password := webFixture(t)
			webNodeFile(t, w, webAutoConfig)
			s := unitControlServer()
			s.registration.Config = w.configPath
			s.start = func(context.Context, bool) error { return d.start(b, c, k, true) }
			request := func(ctx context.Context, action string, allow bool) (controlHelperResponse, error) {
				conn, _ := unitControlPair(t, s)
				defer conn.Close()
				return controlHelperExchange(ctx, conn, controlHelperWireRequest{action, allow}, func(net.Conn) (uint32, error) { return 0, nil })
			}
			w.state = func() (bool, bool, error) { return true, true, nil }
			w.serviceAction = func(ctx context.Context, action string, allow bool) error {
				return webControlAction(ctx, w.configPath, action, allow, request)
			}
			cookie, csrf := webLogin(t, w, password)
			var rec *httptest.ResponseRecorder
			if mode == "save" {
				rec = httptest.NewRecorder()
				w.ServeHTTP(rec, webAutoRequest(t, w, cookie, csrf, "config", true, true))
			} else {
				rec = webRequest(w, "POST", "/api/v1/service/start", `{"confirm_insecure":true}`, cookie, csrf)
			}
			var body map[string]json.RawMessage
			if json.Unmarshal(rec.Body.Bytes(), &body) != nil {
				t.Fatal(rec.Body.String())
			}
			var diag map[string]any
			if json.Unmarshal(body["diagnostics"], &diag) != nil || diag["stage"] != "PROXY" || diag["reason"] != "PROXY_STATE_UNAVAILABLE" || diag["receipt"] != "WRITTEN" || len(diag) != 11 {
				t.Fatal("missing invocation diagnostics", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), secret.Error()) || strings.Contains(rec.Body.String(), d.root) {
				t.Fatal("private data leaked")
			}
			if mode == "save" && (!strings.Contains(rec.Body.String(), `"saved":true`) || !strings.Contains(rec.Body.String(), `"pendingReload":true`) || strings.Contains(rec.Body.String(), `"applied":true`)) {
				t.Fatal(rec.Body.String())
			}
		})
	}
}
func TestStartDiagnosticsIdentity(t *testing.T) {
	d, b, c, k, _, _ := lifecycleFixture(t)
	primary := errors.New("same text")
	secondary := errors.New("same text")
	d.proxy = func() error { return primary }
	d.remove = func(string) error { return secondary }
	err := d.start(b, c, k, true)
	if !errors.Is(err, primary) || !errors.Is(err, secondary) {
		t.Fatal("cause lost", err)
	}
}

func TestStartDiagnosticsProtocol(t *testing.T) {
	diag := `{"schema":1,"operation":"START","outcome":"FAILED","stage":"HTTPS","reason":"HTTPS_CERTIFICATE_FAILED","rollback":"VERIFIED","restoration":"VERIFIED","cleanup":"VERIFIED","receipt":"WRITTEN","job":"RUNNING","tun":"TUN"}`
	legacy := `{"ok":false,"code":"START_FAILED","message":"PRIVATE","loaded":false,"running":false,"helper_version":"unit","helper_sha256":"","config_identity":""}`
	frame := strings.TrimSuffix(legacy, "}") + `,"diagnostics":` + diag + `}`
	cases := []struct {
		name, raw string
		valid     bool
	}{{"legacy", legacy, true}, {"new", frame, true}, {"nestedduplicate", strings.Replace(frame, `"schema":1`, `"schema":1,"schema":1`, 1), false}, {"nestedunknown", strings.Replace(frame, `"schema":1`, `"extra":"PRIVATE","schema":1`, 1), false}, {"null", strings.Replace(frame, diag, "null", 1), false}, {"nestednull", strings.Replace(frame, `"receipt":"WRITTEN"`, `"receipt":null`, 1), false}, {"missingnested", strings.Replace(frame, `"schema":1,`, "", 1), false}, {"missinglegacy", strings.Replace(legacy, `"loaded":false,`, "", 1), false}, {"duplicateouter", strings.Replace(frame, `"ok":false`, `"ok":false,"ok":false`, 1), false}, {"unknownouter", strings.Replace(frame, `"ok":false`, `"extra":1,"ok":false`, 1), false}, {"badstage", strings.Replace(frame, `"stage":"HTTPS"`, `"stage":"PROXY"`, 1), false}, {"badoutcome", strings.Replace(frame, `"outcome":"FAILED"`, `"outcome":"SUCCEEDED"`, 1), false}, {"successcross", strings.Replace(frame, `"ok":false,"code":"START_FAILED"`, `"ok":true,"code":""`, 1), false}, {"trailing", frame + "{}", false}, {"schematype", strings.Replace(frame, `"schema":1`, `"schema":1.0`, 1), false}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(unitControlSocketDir(t), "d.sock"), Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, e := listener.AcceptUnix()
				if e == nil {
					defer c.Close()
					io.Copy(io.Discard, c)
					io.WriteString(c, tc.raw)
				}
			}()
			c, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_, err = controlHelperExchange(context.Background(), c, controlHelperWireRequest{"start", true}, func(net.Conn) (uint32, error) { return 0, nil })
			<-done
			if tc.valid {
				if err == nil || !strings.HasPrefix(err.Error(), "START_FAILED:") {
					t.Fatal("valid error response rejected", err)
				}
			} else if err == nil || strings.HasPrefix(err.Error(), "START_FAILED:") {
				t.Fatal("invalid protocol accepted", err)
			}
		})
	}
}
func TestStartDiagnosticsReceiptOnly(t *testing.T) {
	d, b, c, k, loaded, _ := lifecycleFixture(t)
	if err := os.Mkdir(filepath.Join(filepath.Dir(d.root), "service-diagnostic.json"), 0700); err != nil {
		t.Fatal(err)
	}
	err := d.start(b, c, k, true)
	if err == nil || !*loaded {
		t.Fatal("receipt failure changed business", err)
	}
	s := unitControlServer()
	s.start = func(context.Context, bool) error { return err }
	r := s.execute(controlHelperWireRequest{"start", true})
	raw, _ := json.Marshal(r)
	if !strings.Contains(string(raw), `"outcome":"SUCCEEDED"`) || !strings.Contains(string(raw), `"reason":"RECEIPT_WRITE_FAILED"`) {
		t.Fatal(string(raw))
	}
}
