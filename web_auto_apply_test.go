package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const webAutoConfig = "nodes:\n - {name: first, type: anytls, server: 127.0.0.1, port: 443, password: secret}\n - {name: second, type: anytls, server: 127.0.0.2, port: 443, password: secret}\nproxy-groups:\n - {name: local, type: select, proxies: [DIRECT, REJECT], selected: DIRECT}\nrules: ['MATCH,DIRECT']\n"

// All four public save routes use the real authenticated handler and readback.
func webAutoRequest(t *testing.T, w *webConsole, cookie *http.Cookie, csrf, route string, changed, consent bool) *http.Request {
	t.Helper()
	method, path := "POST", "/api/v1/"+route
	body := map[string]any{"confirm_insecure": consent}
	switch route {
	case "config":
		method = "PUT"
		b, err := os.ReadFile(w.configPath)
		if err != nil {
			t.Fatal(err)
		}
		if changed {
			b = append(b, []byte("x-auto: changed\n")...)
		}
		body["yaml"] = string(b)
	case "nodes":
		method = "PUT"
		body["name"], body["server"], body["port"] = "first", "127.0.0.1", 443
		if changed {
			body["port"] = 8443
		}
	case "nodes/selection":
		body["name"] = "first"
		if changed {
			body["name"] = "second"
		}
	case "groups/selection":
		body["group"], body["choice"] = "local", "DIRECT"
		if changed {
			body["choice"] = "REJECT"
		}
	default:
		t.Fatal("unknown route", route)
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(method, "http://127.0.0.1:18089"+path, strings.NewReader(string(b)))
	r.Header.Set("Origin", "http://127.0.0.1:18089")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	config, err := os.ReadFile(w.configPath)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("If-Match", `"`+shaHex(config)+`"`)
	r.AddCookie(cookie)
	return r
}

func webAutoResult(t *testing.T, rec *httptest.ResponseRecorder, status string, changed, applied, pending bool) {
	t.Helper()
	var got struct {
		OK      bool   `json:"ok"`
		Saved   bool   `json:"saved"`
		Changed bool   `json:"changed"`
		Applied bool   `json:"applied"`
		Status  string `json:"apply_status"`
		Pending bool   `json:"pendingReload"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || !got.OK || !got.Saved || got.Changed != changed || got.Applied != applied || got.Status != status || got.Pending != pending {
		t.Fatalf("save result: %d %s", rec.Code, rec.Body.String())
	}
}

func TestWebAutoApplyFourSaveRoutes(t *testing.T) {
	for _, route := range []string{"config", "nodes", "nodes/selection", "groups/selection"} {
		for _, mode := range []string{"running", "stopped", "loaded-stopped", "unavailable", "inconsistent", "noop", "failed", "unconfirmed", "concurrent", "selected-concurrent", "unknown-after", "inconsistent-after"} {
			t.Run(route+"/"+mode, func(t *testing.T) {
				w, password := webFixture(t)
				if err := os.WriteFile(selectedPath(w.configPath), []byte("first\n"), 0600); err != nil {
					t.Fatal(err)
				}
				webNodeFile(t, w, webAutoConfig)
				cookie, csrf := webLogin(t, w, password)
				baseline := w.baseline
				calls, stateCalls := 0, 0
				w.state = func() (bool, bool, error) {
					stateCalls++
					switch mode {
					case "stopped":
						return false, false, nil
					case "loaded-stopped":
						return true, false, nil
					case "unavailable":
						return false, false, errors.New("private state failure")
					case "inconsistent":
						return false, true, nil
					case "unconfirmed":
						if calls > 0 {
							return true, false, nil
						}
					case "unknown-after":
						if calls > 0 {
							return true, true, errors.New("private state failure")
						}
					case "inconsistent-after":
						if calls > 0 {
							return false, true, nil
						}
					}
					return true, true, nil
				}
				// Explicit consent is passed through on both false and true paths.
				consent := route == "nodes" || route == "groups/selection"
				w.serviceAction = func(ctx context.Context, action string, insecure bool) error {
					calls++
					if w.actionMu.TryLock() {
						w.actionMu.Unlock()
						t.Error("save released action lock before reload")
					}
					if action != "reload" || insecure != consent {
						t.Error("wrong reload/consent", action, insecure)
					}
					deadline, ok := ctx.Deadline()
					if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 3*time.Minute {
						t.Error("missing bounded independent context")
					}
					if mode == "failed" {
						return errors.New("SECRET_NATIVE_ERROR")
					}
					if mode == "concurrent" {
						f, err := os.OpenFile(w.configPath, os.O_APPEND|os.O_WRONLY, 0600)
						if err != nil {
							t.Fatal(err)
						}
						_, err = f.WriteString("x-concurrent: changed\n")
						closeErr := f.Close()
						if err != nil || closeErr != nil {
							t.Fatal(err, closeErr)
						}
					}
					if mode == "selected-concurrent" {
						if err := os.WriteFile(selectedPath(w.configPath), []byte("external\n"), 0600); err != nil {
							t.Fatal(err)
						}
					}
					return nil
				}
				r := webAutoRequest(t, w, cookie, csrf, route, mode != "noop", consent)
				rec := httptest.NewRecorder()
				w.ServeHTTP(rec, r)
				status, applied, pending, wantCalls := "APPLIED", true, false, 1
				switch mode {
				case "stopped", "loaded-stopped":
					status, applied, pending, wantCalls = "SAVED_STOPPED", false, true, 0
				case "unavailable", "inconsistent":
					status, applied, pending, wantCalls = "STATE_UNAVAILABLE", false, true, 0
				case "noop":
					status, applied, pending, wantCalls = "NO_CHANGE", false, false, 0
				case "failed", "unconfirmed", "concurrent", "selected-concurrent", "unknown-after", "inconsistent-after":
					status, applied, pending = "APPLY_FAILED", false, true
				}
				webAutoResult(t, rec, status, mode != "noop", applied, pending)
				if calls != wantCalls {
					t.Fatalf("reload calls: %d want %d", calls, wantCalls)
				}
				if mode == "noop" && stateCalls != 0 {
					t.Fatal("no-op touched service")
				}
				if applied {
					if w.baseline != w.fingerprint() || w.baseline == baseline || !w.pendingKnown {
						t.Fatal("new baseline not confirmed")
					}
				} else if w.baseline != baseline {
					t.Fatal("failed/stopped/no-op advanced baseline")
				}
				if strings.Contains(rec.Body.String(), "SECRET") || strings.Contains(rec.Body.String(), "private state failure") {
					t.Fatal("private error leaked")
				}
				statusRec := webRequest(w, "GET", "/api/v1/status", "", cookie, "")
				var statusGot struct {
					Pending bool `json:"pendingReload"`
				}
				if statusRec.Code != 200 || json.Unmarshal(statusRec.Body.Bytes(), &statusGot) != nil || statusGot.Pending != pending {
					t.Fatal("status lost pending apply state", statusRec.Body.String())
				}
			})
		}
	}
}

func TestWebAutoApplyRejectedSavesNeverAct(t *testing.T) {
	for _, route := range []string{"config", "nodes", "nodes/selection", "groups/selection"} {
		t.Run(route, func(t *testing.T) {
			w, password := webFixture(t)
			webNodeFile(t, w, webAutoConfig)
			cookie, csrf := webLogin(t, w, password)
			w.state = func() (bool, bool, error) { t.Error("rejected save touched service state"); return true, true, nil }
			w.serviceAction = func(context.Context, string, bool) error { t.Error("rejected save invoked helper"); return nil }
			r := webAutoRequest(t, w, cookie, csrf, route, true, false)
			body := `{"yaml":"[]"}`
			switch route {
			case "nodes":
				body = `{"name":"missing","server":"127.0.0.1","port":443}`
			case "nodes/selection":
				body = `{"name":"missing"}`
			case "groups/selection":
				body = `{"group":"local","choice":"missing"}`
			}
			r.Body = io.NopCloser(strings.NewReader(body))
			rec := httptest.NewRecorder()
			w.ServeHTTP(rec, r)
			if rec.Code != 422 || w.pending {
				t.Fatal("rejected save contract", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestWebAutoApplySelectionWriteFailureNeverActs(t *testing.T) {
	w, password := webFixture(t)
	webNodeFile(t, w, webAutoConfig)
	if err := os.Mkdir(selectedPath(w.configPath), 0700); err != nil {
		t.Fatal(err)
	}
	cookie, csrf := webLogin(t, w, password)
	w.state = func() (bool, bool, error) { t.Error("failed write queried service"); return true, true, nil }
	w.serviceAction = func(context.Context, string, bool) error { t.Error("failed write invoked service"); return nil }
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, webAutoRequest(t, w, cookie, csrf, "nodes/selection", true, false))
	if rec.Code != 422 || w.pending {
		t.Fatal("failed write contract", rec.Code, rec.Body.String())
	}
}

func TestWebAutoApplyInsecureSaveNeedsOnlyApplyConsent(t *testing.T) {
	for _, consent := range []bool{false, true} {
		t.Run(map[bool]string{false: "not-consented", true: "consented"}[consent], func(t *testing.T) {
			w, password := webFixture(t)
			webNodeFile(t, w, webAutoConfig)
			cookie, csrf := webLogin(t, w, password)
			candidate := strings.Replace(webAutoConfig, "password: secret", "password: secret, skip-cert-verify: true", 1)
			r := webAutoRequest(t, w, cookie, csrf, "config", true, consent)
			body, err := json.Marshal(map[string]any{"yaml": candidate, "confirm_insecure": consent})
			if err != nil {
				t.Fatal(err)
			}
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			w.state = func() (bool, bool, error) { return true, true, nil }
			calls := 0
			w.serviceAction = func(_ context.Context, action string, insecure bool) error {
				calls++
				if action != "reload" || insecure != consent {
					t.Error("implicit insecure authorization")
				}
				b, err := os.ReadFile(w.configPath)
				if err != nil || string(b) != candidate {
					t.Error("apply preceded disk save/readback")
				}
				if !insecure {
					return errors.New("simulated root TLS preflight rejection")
				}
				return nil
			}
			rec := httptest.NewRecorder()
			w.ServeHTTP(rec, r)
			status := "APPLY_FAILED"
			if consent {
				status = "APPLIED"
			}
			webAutoResult(t, rec, status, true, consent, !consent)
			if calls != 1 {
				t.Fatal("reload calls", calls)
			}
		})
	}
}

// No native authorization: exercise the actual osascript argv/Run seam with an
// owned test subprocess. Its release gate proves cancellation cannot release
// actionMu, while status/auth remain readable and update remains busy.
func TestWebAutoApplyCancellationOwnsHelperAndLock(t *testing.T) {
	w, password := webFixture(t)
	cookie, csrf := webLogin(t, w, password)
	ready, release := w.configPath+".ready", w.configPath+".release"
	t.Cleanup(func() { _ = os.WriteFile(release, nil, 0600) })
	w.state = func() (bool, bool, error) { return true, true, nil }
	w.serviceAction = func(ctx context.Context, action string, insecure bool) error {
		return webServiceWithCommand(ctx, action, insecure, "/synthetic/anytls", func(ctx context.Context, name string, args ...string) *exec.Cmd {
			if name != "/usr/bin/osascript" || len(args) != 6 || args[3] != "/synthetic/anytls" || args[4] != "service-reload" || args[5] != "false" {
				t.Error("unexpected native argv", name, args)
			}
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWebAutoApplyOwnedHelper$")
			cmd.Env = append(os.Environ(), "ANYTLS_WEB_AUTO_HELPER=1", "ANYTLS_WEB_AUTO_READY="+ready, "ANYTLS_WEB_AUTO_RELEASE="+release)
			return cmd
		})
	}
	r := webAutoRequest(t, w, cookie, csrf, "config", true, false)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	r = r.WithContext(ctx)
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = os.WriteFile(release, nil, 0600)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("owned helper did not join during cleanup")
		}
	})
	rec := httptest.NewRecorder()
	go func() { defer close(done); w.ServeHTTP(rec, r) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("helper did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
		t.Fatal("HTTP cancellation returned before helper exit")
	case <-time.After(50 * time.Millisecond):
	}
	if got := webRequest(w, "GET", "/api/v1/status", "", cookie, ""); got.Code != 200 {
		t.Fatal(got.Code)
	}
	for _, path := range []string{"/api/v1/update", "/api/v1/service/stop"} {
		if got := webRequest(w, "POST", path, `{"confirm":true}`, cookie, csrf); got.Code != 409 {
			t.Fatal("action lock released early", path, got.Code)
		}
	}
	if err := os.WriteFile(release, nil, 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("helper not joined")
	}
	webAutoResult(t, rec, "APPLIED", true, true, false)
	if !w.actionMu.TryLock() {
		t.Fatal("action lock leaked")
	}
	w.actionMu.Unlock()
}

func TestWebAutoApplyOwnedHelper(t *testing.T) {
	if os.Getenv("ANYTLS_WEB_AUTO_HELPER") != "1" {
		return
	}
	if err := os.WriteFile(os.Getenv("ANYTLS_WEB_AUTO_READY"), nil, 0600); err != nil {
		os.Exit(2)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(os.Getenv("ANYTLS_WEB_AUTO_RELEASE")); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	os.Exit(3)
}
