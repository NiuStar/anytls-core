package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWebAgentManagedUpdateSchedulesAfterFlush(t *testing.T) {
	w, p := webFixture(t)
	cookie, csrf := webLogin(t, w, p)
	var checks, requests atomic.Int32
	w.restartCheck = func() error { checks.Add(1); return nil }
	w.restartRequest = func() { requests.Add(1) }
	w.updateAction = func(context.Context, bool) (json.RawMessage, error) {
		return json.RawMessage(`{"updated":true,"status":"UPDATED","installed":"v1.0.1","latest":"v1.0.1","restartRequired":true}`), nil
	}
	r := webRequest(w, "POST", "/api/v1/update", `{"confirm":true}`, cookie, csrf)
	var got map[string]any
	json.Unmarshal(r.Body.Bytes(), &got)
	if got["restartScheduled"] != true || !r.Flushed || checks.Load() != 1 || requests.Load() != 1 {
		t.Fatalf("not safely scheduled: %s flushed=%v checks=%d requests=%d", r.Body.String(), r.Flushed, checks.Load(), requests.Load())
	}
	r = webRequest(w, "POST", "/api/v1/service/stop", `{}`, cookie, csrf)
	if r.Code != 409 {
		t.Fatalf("mutation accepted during restart: %d", r.Code)
	}
}

func TestWebAgentRealHTTPManagedGracefulExit(t *testing.T) {
	w, p := webFixture(t)
	cookie, csrf := webLogin(t, w, p)
	w.restartCheck = func() error { return nil }
	w.updateAction = func(context.Context, bool) (json.RawMessage, error) {
		return json.RawMessage(`{"updated":true,"status":"UPDATED","installed":"v1.0.1","latest":"v1.0.1","restartRequired":true}`), nil
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{}
	done := make(chan error, 1)
	go func() { done <- webAgentServe(server, listener, w, true) }()
	req, _ := http.NewRequest("POST", "http://"+listener.Addr().String()+"/api/v1/update", strings.NewReader(`{"confirm":true}`))
	req.Host = "127.0.0.1:18089"
	req.AddCookie(cookie)
	req.Header.Set("Origin", "http://127.0.0.1:18089")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || !strings.Contains(string(b), `"restartScheduled":true`) {
		t.Fatalf("response not complete: %s %v", b, err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("graceful shutdown deadlocked on own update handler")
	}
}

func TestWebAgentRestartEligibility(t *testing.T) {
	for _, raw := range []string{
		`{"updated":false,"status":"UPDATED","installed":"v1.0.1","latest":"v1.0.1","restartRequired":true}`,
		`{"updated":true,"status":"RESTART_REQUIRED","installed":"v1.0.1","latest":"v1.0.1","restartRequired":true}`,
		`{"updated":true,"status":"UPDATED","installed":"v1.0.1","latest":"v1.0.2","restartRequired":true}`,
		`{"updated":true,"status":"UPDATED","installed":"v1.0.1-rc1","latest":"v1.0.1-rc1","restartRequired":true}`,
		`{"updated":true,"status":"UPDATED","installed":"v1.0.1","latest":"v1.0.1","restartRequired":false}`,
	} {
		t.Run(raw, func(t *testing.T) {
			w, p := webFixture(t)
			cookie, csrf := webLogin(t, w, p)
			w.restartCheck = func() error { t.Error("ineligible result reached authority check"); return nil }
			w.restartRequest = func() { t.Error("ineligible shutdown") }
			w.updateAction = func(context.Context, bool) (json.RawMessage, error) { return json.RawMessage(raw), nil }
			r := webRequest(w, "POST", "/api/v1/update", `{"confirm":true}`, cookie, csrf)
			var got map[string]any
			json.Unmarshal(r.Body.Bytes(), &got)
			if r.Code != 200 || got["restartScheduled"] != false || w.restartPending {
				t.Fatalf("unsafe restart: %s", r.Body.String())
			}
		})
	}
}

type webAgentBrokenWriter struct {
	header    http.Header
	failWrite bool
	failFlush bool
}

func (b *webAgentBrokenWriter) Header() http.Header { return b.header }
func (b *webAgentBrokenWriter) WriteHeader(int)     {}
func (b *webAgentBrokenWriter) Write(p []byte) (int, error) {
	if b.failWrite {
		return 0, errors.New("broken write")
	}
	return len(p), nil
}
func (b *webAgentBrokenWriter) FlushError() error {
	if b.failFlush {
		return errors.New("broken flush")
	}
	return nil
}
func TestWebAgentWriteFailureNeverRequestsExit(t *testing.T) {
	for _, failure := range []string{"write", "flush"} {
		t.Run(failure, func(t *testing.T) {
			w, p := webFixture(t)
			cookie, csrf := webLogin(t, w, p)
			w.restartCheck = func() error { return nil }
			w.restartRequest = func() { t.Error("exit requested after failed response") }
			w.updateAction = func(context.Context, bool) (json.RawMessage, error) {
				return json.RawMessage(`{"updated":true,"status":"UPDATED","installed":"v1.0.1","latest":"v1.0.1","restartRequired":true}`), nil
			}
			req := httptest.NewRequest("POST", "http://127.0.0.1:18089/api/v1/update", strings.NewReader(`{"confirm":true}`))
			req.AddCookie(cookie)
			req.Header.Set("Origin", "http://127.0.0.1:18089")
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-CSRF-Token", csrf)
			rw := &webAgentBrokenWriter{header: make(http.Header), failWrite: failure == "write", failFlush: failure == "flush"}
			w.ServeHTTP(rw, req)
			if w.restartPending {
				t.Fatal("failed response latched pending restart")
			}
		})
	}
}

func TestWebAgentCheckRevalidatesAuthority(t *testing.T) {
	w, p := webFixture(t)
	cookie, _ := webLogin(t, w, p)
	w.updateAction = func(context.Context, bool) (json.RawMessage, error) {
		return json.RawMessage(`{"updated":false,"status":"UPDATE_AVAILABLE"}`), nil
	}
	checks := 0
	w.restartCheck = func() error {
		checks++
		if checks > 1 {
			return errors.New("job changed")
		}
		return nil
	}
	w.restartRequest = func() { t.Error("GET scheduled restart") }
	for i, want := range []bool{true, false} {
		r := webRequest(w, "GET", "/api/v1/update-check", "", cookie, "")
		var got map[string]any
		json.Unmarshal(r.Body.Bytes(), &got)
		if got["restartManaged"] != want || got["restartScheduled"] != false || checks != i+1 {
			t.Fatalf("stale managed authority: %s checks=%d", r.Body.String(), checks)
		}
	}
}

func TestWebAgentManagedGuardFailurePreservesInstall(t *testing.T) {
	w, p := webFixture(t)
	cookie, csrf := webLogin(t, w, p)
	w.restartCheck = func() error { return errors.New("job changed") }
	w.restartRequest = func() { t.Error("unsafe shutdown") }
	w.updateAction = func(context.Context, bool) (json.RawMessage, error) {
		return json.RawMessage(`{"updated":true,"status":"UPDATED","installed":"v1.0.1","latest":"v1.0.1","restartRequired":true}`), nil
	}
	r := webRequest(w, "POST", "/api/v1/update", `{"confirm":true}`, cookie, csrf)
	var got map[string]any
	json.Unmarshal(r.Body.Bytes(), &got)
	if r.Code != 200 || got["updated"] != true || got["restartScheduled"] != false || got["restartError"] != "RESTART_MANAGED_UNAVAILABLE" {
		t.Fatalf("install result lost: %d %s", r.Code, r.Body.String())
	}
}

// Real HTTP: default constructors must never acquire process-exit authority.
func TestWebAgentManualUpdateKeepsServing(t *testing.T) {
	w, p := webFixture(t)
	cookie, csrf := webLogin(t, w, p)
	w.updateAction = func(context.Context, bool) (json.RawMessage, error) {
		return json.RawMessage(`{"updated":true,"status":"UPDATED","installed":"v1.0.1","latest":"v1.0.1","restartRequired":true}`), nil
	}
	s := httptest.NewServer(w)
	defer s.Close()
	req, _ := http.NewRequest("POST", s.URL+"/api/v1/update", strings.NewReader(`{"confirm":true}`))
	req.Host = "127.0.0.1:18089"
	req.Header.Set("Origin", "http://127.0.0.1:18089")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(cookie)
	res, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	var got map[string]any
	if json.Unmarshal(b, &got) != nil || res.StatusCode != 200 || got["restartScheduled"] != false || got["updated"] != true {
		t.Fatalf("manual update contract: %d %s", res.StatusCode, b)
	}
	req, _ = http.NewRequest("GET", s.URL+"/api/v1/version", nil)
	req.Host = "127.0.0.1:18089"
	req.AddCookie(cookie)
	res, err = s.Client().Do(req)
	if err != nil {
		t.Fatal("manual console exited:", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
}
