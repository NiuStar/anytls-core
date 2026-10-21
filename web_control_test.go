package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// UNIT: real authenticated HTTP save and Unix IPC; only UID/lifecycle injected.
func TestWebControlConfigBindingSave(t *testing.T) {
	for _, mode := range []string{"mismatch", "matching", "drift"} {
		t.Run(mode, func(t *testing.T) {
			w, password := webFixture(t)
			webNodeFile(t, w, webAutoConfig)
			configA := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(configA, []byte(webAutoConfig), 0600); err != nil {
				t.Fatal(err)
			}
			s := unitControlServer()
			s.registration.Config = configA
			if mode != "mismatch" {
				s.registration.Config = w.configPath
			}
			mutations := 0
			s.start = func(context.Context, bool) error { mutations++; return nil }
			request := func(ctx context.Context, action string, allow bool) (controlHelperResponse, error) {
				if mode == "drift" && action != "status" {
					s.registration.Config = configA
				}
				c, _ := unitControlPair(t, s)
				return controlHelperExchange(ctx, c, controlHelperWireRequest{action, allow}, func(net.Conn) (uint32, error) { return 0, nil })
			}
			w.state = func() (bool, bool, error) { return true, true, nil }
			w.serviceAction = func(ctx context.Context, action string, allow bool) error {
				return webControlAction(ctx, w.configPath, action, allow, request)
			}
			cookie, csrf := webLogin(t, w, password)
			rec := httptest.NewRecorder()
			w.ServeHTTP(rec, webAutoRequest(t, w, cookie, csrf, "config", true, false))
			var got struct {
				Saved   bool   `json:"saved"`
				Applied bool   `json:"applied"`
				Pending bool   `json:"pendingReload"`
				Error   string `json:"apply_error"`
			}
			if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || !got.Saved {
				t.Fatal(rec.Code, rec.Body.String())
			}
			if mode == "matching" {
				if !got.Applied || got.Pending || mutations != 1 {
					t.Fatal(rec.Body.String(), mutations)
				}
			} else if got.Applied || !got.Pending || got.Error != "HELPER_CONFIG_MISMATCH" || (mode == "mismatch" && mutations != 0) {
				t.Fatal(rec.Body.String(), mutations)
			}
		})
	}
}

func TestWebControlAllActionsRefuseOtherConfig(t *testing.T) {
	for _, action := range []string{"start", "stop", "reload"} {
		t.Run(action, func(t *testing.T) {
			config := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(config, []byte("unit"), 0600); err != nil {
				t.Fatal(err)
			}
			calls := 0
			err := webControlAction(context.Background(), config, action, false, func(_ context.Context, action string, allow bool) (controlHelperResponse, error) {
				calls++
				if action != "status" || allow {
					t.Fatal("mutation before binding", action)
				}
				return controlHelperResponse{OK: true, ConfigIdentity: strings.Repeat("a", 64)}, nil
			})
			if webControlFailureCode(err) != "HELPER_CONFIG_MISMATCH" || calls != 1 {
				t.Fatal(err, calls)
			}
		})
	}
}

func TestWebControlStatusConfigMismatch(t *testing.T) {
	config := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(config, []byte("unit"), 0600); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	webControlStatusForConfig(rec, httptest.NewRequest("GET", "/", nil), config, func(context.Context, string, bool) (controlHelperResponse, error) {
		return controlHelperResponse{OK: true, ConfigIdentity: strings.Repeat("a", 64)}, nil
	})
	if !strings.Contains(rec.Body.String(), `"available":false`) || !strings.Contains(rec.Body.String(), `"HELPER_CONFIG_MISMATCH"`) || strings.Contains(rec.Body.String(), config) {
		t.Fatal(rec.Body.String())
	}
}

func TestWebControlFailureStagesAreAllowlisted(t *testing.T) {
	for _, code := range []string{"HELPER_UNAVAILABLE", "HELPER_CONFIG_MISMATCH", "FORBIDDEN", "INVALID_REQUEST", "BUSY", "PREFLIGHT_FAILED", "STOP_FAILED", "START_FAILED", "STATE_FAILED"} {
		if got := webControlFailureCode(&webControlError{Code: code}); got != code {
			t.Fatal(code, got)
		}
	}
	for _, err := range []error{errors.New("PRIVATE_PASSWORD"), &webControlError{Code: "PRIVATE_PASSWORD"}} {
		if webControlFailureCode(err) != "SERVICE_ACTION_FAILED" {
			t.Fatal("untrusted message escaped")
		}
	}
}
func TestWebAutoApplyReturnsHelperFailureStage(t *testing.T) {
	w, password := webFixture(t)
	webNodeFile(t, w, webAutoConfig)
	cookie, csrf := webLogin(t, w, password)
	w.state = func() (bool, bool, error) { return true, true, nil }
	w.serviceAction = func(context.Context, string, bool) error { return &webControlError{Code: "HELPER_UNAVAILABLE"} }
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, webAutoRequest(t, w, cookie, csrf, "config", true, true))
	var got struct {
		Saved      bool   `json:"saved"`
		Applied    bool   `json:"applied"`
		ApplyError string `json:"apply_error"`
		Pending    bool   `json:"pendingReload"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || !got.Saved || got.Applied || !got.Pending || got.ApplyError != "HELPER_UNAVAILABLE" {
		t.Fatal(rec.Code, rec.Body.String())
	}
}
func TestWebHelperStatusRequiresAuthentication(t *testing.T) {
	w, _ := webFixture(t)
	rec := webRequest(w, "GET", "/api/v1/helper/status", "", nil, "")
	if rec.Code != 401 {
		t.Fatal(rec.Code)
	}
}
func TestWebHelperStatusDoesNotExposePaths(t *testing.T) {
	// Read-only: tolerate an existing helper on a developer's Mac. Never install
	// or control it from the test, and do not expose the private config path.
	w, password := webFixture(t)
	cookie, _ := webLogin(t, w, password)
	rec := webRequest(w, "GET", "/api/v1/helper/status", "", cookie, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"available":`) {
		t.Fatal(rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), w.configPath) {
		t.Fatal("private path leaked")
	}
}
