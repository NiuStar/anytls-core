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

// Same test bytes run on both frozen candidates; assertions use wire JSON.
func p2Projection(t *testing.T, err error, action string) map[string]any {
	t.Helper()
	s := unitControlServer()
	s.stop = func(context.Context) error { return err }
	s.start = func(context.Context, bool) error { return err }
	raw, e := json.Marshal(s.execute(controlHelperWireRequest{action, action != "stop"}))
	if e != nil {
		t.Fatal(e)
	}
	var body map[string]any
	if json.Unmarshal(raw, &body) != nil {
		t.Fatal(string(raw))
	}
	d, ok := body["diagnostics"].(map[string]any)
	if !ok {
		t.Fatal(string(raw))
	}
	t.Log(string(raw))
	return d
}
func TestDiagnosticsP2Recovery(t *testing.T) {
	for _, mode := range []string{"initial_state", "missing_baseline", "invalid_baseline", "public_read", "server_read", "dns_read", "public_mismatch", "server_mismatch", "dns_mismatch", "remove"} {
		t.Run(mode, func(t *testing.T) {
			d, b, c, k, _, _ := lifecycleFixture(t)
			if err := d.start(b, c, k, true); err != nil {
				t.Fatal(err)
			}
			secret := errors.New("PRIVATE_P2_RECOVERY")
			want := "UNKNOWN"
			cleanup := "UNKNOWN"
			route := d.route
			switch mode {
			case "initial_state":
				d.state = func() (bool, bool, error) { return false, false, secret }
				want = "NOT_ATTEMPTED"
				cleanup = "NOT_ATTEMPTED"
			case "missing_baseline":
				if err := os.Remove(filepath.Join(d.root, serviceBaselineName)); err != nil {
					t.Fatal(err)
				}
			case "invalid_baseline":
				if err := os.WriteFile(filepath.Join(d.root, serviceBaselineName), []byte("invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			case "public_read", "server_read", "public_mismatch", "server_mismatch":
				d.route = func(ip string) (string, error) {
					match := (strings.HasPrefix(mode, "public") && ip == "1.1.1.1") || (strings.HasPrefix(mode, "server") && ip != "1.1.1.1")
					if match {
						if strings.HasSuffix(mode, "read") {
							return "", secret
						}
						return "en9", nil
					}
					return route(ip)
				}
				if strings.HasSuffix(mode, "mismatch") {
					want = "FAILED"
				}
			case "dns_read":
				d.dns = func() ([]string, error) { return nil, secret }
			case "dns_mismatch":
				d.dns = func() ([]string, error) { return []string{"nameserver[0] : 192.0.2.99"}, nil }
				want = "FAILED"
			case "remove":
				d.remove = func(string) error { return secret }
				want = "VERIFIED"
				cleanup = "FAILED"
			}
			err := d.stop()
			if mode != "initial_state" && mode != "remove" {
				if err != nil {
					t.Fatal("network warning blocked stop", err)
				}
				v, _ := readDiagnostic(t, d.root)
				if v["restoration"] != want || v["snapshot"] != "ARCHIVED" || v["outcome"] != "SUCCEEDED" {
					t.Fatal("recovery warning lost", v)
				}
				return
			}
			if err == nil {
				t.Fatal("expected stop failure")
			}
			if mode == "initial_state" || strings.HasSuffix(mode, "read") || mode == "remove" {
				if !errors.Is(err, secret) {
					t.Fatal("identity lost", err)
				}
			}
			diag := p2Projection(t, err, "stop")
			if diag["restoration"] != want || diag["cleanup"] != cleanup || diag["rollback"] != "NOT_ATTEMPTED" || diag["reason"] != "STOP_FAILED" {
				t.Fatalf("recovery want %s/%s got %v", want, cleanup, diag)
			}
		})
	}
}
func TestDiagnosticsP2Retry(t *testing.T) {
	for _, mode := range []string{"unloaded", "not_running", "state_error", "physical_route", "route_error"} {
		t.Run(mode, func(t *testing.T) {
			d, b, c, k, loaded, _ := lifecycleFixture(t)
			state := d.state
			route := d.route
			tool := d.tool
			afterCurl := false
			curlCalls := 0
			primary := diagnosticCurlExit(6)
			secret := errors.New("PRIVATE_P2_RETRY")
			d.state = func() (bool, bool, error) {
				if afterCurl && *loaded {
					switch mode {
					case "unloaded":
						return false, false, nil
					case "not_running":
						return true, false, nil
					case "state_error":
						return false, false, secret
					}
				}
				return state()
			}
			d.route = func(ip string) (string, error) {
				if afterCurl && *loaded && ip == "1.1.1.1" {
					switch mode {
					case "physical_route":
						return "en0", nil
					case "route_error":
						return "", secret
					}
				}
				return route(ip)
			}
			d.tool = func(ctx context.Context, name string, args ...string) (string, error) {
				if name == "/usr/bin/curl" {
					afterCurl = true
					curlCalls++
					return "", primary
				}
				return tool(ctx, name, args...)
			}
			err := d.start(b, c, k, true)
			if err == nil || !errors.Is(err, primary) || curlCalls != 1 {
				t.Fatal("retry contract", err, curlCalls)
			}
			diag := p2Projection(t, err, "start")
			job, tun, reason := "RUNNING", "TUN", "READINESS_CHANGED"
			switch mode {
			case "unloaded":
				job = "UNLOADED"
			case "not_running":
				job = "NOT_RUNNING"
			case "state_error":
				job = "UNKNOWN"
				reason = "READINESS_JOB_UNAVAILABLE"
			case "physical_route":
				tun = "NOT_TUN"
			case "route_error":
				tun = "UNKNOWN"
				reason = "READINESS_ROUTE_UNAVAILABLE"
			}
			if diag["job"] != job || diag["tun"] != tun || diag["reason"] != reason || diag["stage"] != "READINESS" {
				t.Fatalf("current observations want %s/%s/%s got %v", job, tun, reason, diag)
			}
		})
	}
}
func TestDiagnosticsP2ReloadReceiptHTTP(t *testing.T) {
	for _, mode := range []string{"manual", "save"} {
		t.Run(mode, func(t *testing.T) {
			d, b, c, k, loaded, _ := lifecycleFixture(t)
			if err := d.start(b, c, k, true); err != nil {
				t.Fatal(err)
			}
			receipt := filepath.Join(filepath.Dir(d.root), "service-diagnostic.json")
			if err := os.Remove(receipt); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(receipt, 0700); err != nil {
				t.Fatal(err)
			}
			w, password := webFixture(t)
			webNodeFile(t, w, webAutoConfig)
			s := unitControlServer()
			s.registration.Config = w.configPath
			s.state = d.state
			startCalls, stopCalls := 0, 0
			s.start = func(context.Context, bool) error { startCalls++; return errors.New("must not start") }
			s.stop = func(context.Context) error { stopCalls++; return d.stop() }
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
				rec = webRequest(w, "POST", "/api/v1/service/reload", `{"confirm_insecure":true}`, cookie, csrf)
			}
			var body map[string]any
			if json.Unmarshal(rec.Body.Bytes(), &body) != nil {
				t.Fatal(rec.Body.String())
			}
			diag, ok := body["diagnostics"].(map[string]any)
			t.Log(rec.Code, rec.Body.String())
			if !ok || diag["operation"] != "RELOAD" || diag["outcome"] != "FAILED" || diag["stage"] != "STOP" || diag["reason"] != "STOP_FAILED" || diag["receipt"] != "FAILED" || diag["restoration"] != "VERIFIED" || diag["cleanup"] != "VERIFIED" || diag["rollback"] != "NOT_ATTEMPTED" || startCalls != 0 || stopCalls != 1 || *loaded {
				t.Fatalf("incomplete reload mislabeled: %v start=%d stop=%d loaded=%v", diag, startCalls, stopCalls, *loaded)
			}
			if mode == "save" && (rec.Code != 200 || body["saved"] != true || body["applied"] != false || body["pendingReload"] != true || body["apply_error"] != "STOP_FAILED") {
				t.Fatal(rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), d.root) {
				t.Fatal("private path leaked")
			}
		})
	}
}
