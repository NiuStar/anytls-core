//go:build embedded_core

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	"github.com/NiuStar/anytls-core/internal/engine"
	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
)

// This is a test-owned helper, not the installed helper: UID/root/composite
// witnesses and launchd/route/DNS/curl are UNIT-SIMULATED. Real operations are
// private Unix IPC, strict codecs, config compilation/staging, embedded
// decode/New/OpenSink/Start/Close, and authenticated HTTP ServeHTTP. The core is
// loopback DIRECT only; no TUN, public network, production socket or root wrapper.
func TestStartupIntegrationIPCAuthenticatedHTTP(t *testing.T) {
	// This fixture deliberately uses the real helper engine preflight, whose
	// non-Darwin implementation rejects service operations before core startup.
	if runtime.GOOS != "darwin" {
		t.Skip("requires the Darwin control-helper engine preflight")
	}
	d, b, config, k, loaded, _ := lifecycleFixture(t)
	s := unitControlServer()
	s.registration.Config = config
	s.state = d.state
	s.startupInit()
	s.startupIdentity, _ = controlHelperConfigIdentity(config)
	s.startupRegistration = func() (controlHelperRegistration, error) { return s.registration, nil }
	entered, release := make(chan struct{}), make(chan struct{})
	var preOnce, releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	s.preflight = func(ctx context.Context, allow bool) error {
		return startupSpan(ctx, "PREFLIGHT", "HELPER_PREFLIGHT_CAPTURE", func() error {
			preOnce.Do(func() { close(entered) })
			<-release
			captured, e := captureServiceConfig(config)
			if e != nil {
				return e
			}
			return controlHelperConfigPreflight(ctx, captured, allow)
		})
	}
	// Each exchange owns a fresh real private socket; only kernel UID is injected.
	request := func(ctx context.Context, q, dst any, bound time.Duration) error {
		c, _ := unitControlPair(t, s)
		defer c.Close()
		return startupExchange(ctx, c, q, dst, bound, func(net.Conn) (uint32, error) { return 0, nil })
	}
	w, password := webFixture(t)
	w.configPath = config
	w.serviceAction = nil
	w.state = d.state
	w.startupReadRequest = func(ctx context.Context, id *string) (st.ReadResponse, error) {
		var r st.ReadResponse
		e := request(ctx, st.ReadRequest{TimelineSchema: 1, Action: "startup.read", OperationID: id}, &r, 2*time.Second)
		return r, e
	}
	w.startupControlRequest = func(ctx context.Context, action string, allow bool, id string) (st.MutationResponse, error) {
		return startupControlWithRequest(ctx, action, allow, id, request)
	}
	w.startupLegacyRequest = func(ctx context.Context, action string, allow bool) (controlHelperResponse, error) {
		// The only legacy request in this test is bound status over the real socket.
		if action != "status" {
			return controlHelperResponse{}, errors.New("unexpected legacy mutation")
		}
		c, _ := unitControlPair(t, s)
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		json.NewEncoder(c).Encode(controlHelperWireRequest{Action: action, AllowInsecure: allow})
		c.CloseWrite()
		var r controlHelperResponse
		e := controlHelperReadResponse(c, &r)
		return r, e
	}
	server := httptest.NewUnstartedServer(w)
	w.port = server.Listener.Addr().(*net.TCPAddr).Port
	server.Start()
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	call := func(method, path, body, csrf string) (int, []byte) {
		req, e := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Origin", server.URL)
		req.Header.Set("X-AnyTLS-Origin", server.URL)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Content-Type", "application/json")
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		r, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		raw, e := io.ReadAll(r.Body)
		if e != nil {
			t.Fatal(e)
		}
		return r.StatusCode, raw
	}
	login, _ := json.Marshal(map[string]string{"username": "admin", "password": password})
	code, raw := call("POST", "/api/v1/login", string(login), "")
	if code != 200 {
		t.Fatalf("login %d %s", code, raw)
	}
	var session struct {
		CSRF string `json:"csrf"`
	}
	if json.Unmarshal(raw, &session) != nil || session.CSRF == "" {
		t.Fatal("login token missing")
	}
	// Real Core recorder snapshots traverse the private root-handler socket. The
	// authentication seam is deliberately simulated; native primitive guard tests
	// remain separately named in the complete Darwin suite.
	core, _ := st.NewRecorder("CORE", startupProvenance(""))
	push := func() {
		s.startup.mu.Lock()
		o := s.startup.latest
		o.binding = &startupBinding{}
		id, epoch := o.trace.OperationID, *o.trace.HelperEpoch
		s.startup.mu.Unlock()
		listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(unitControlSocketDir(t), "push"), Net: "unix"})
		if e != nil {
			t.Fatal(e)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			p, e := listener.AcceptUnix()
			if e == nil {
				defer p.Close()
				s.startupRootHandle(p)
			}
		}()
		conn, e := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
		if e != nil {
			t.Fatal(e)
		}
		e = startupExchange(context.Background(), conn, st.PushRequest{TimelineSchema: 1, Action: "startup.push", OperationID: id, HelperEpoch: epoch, Snapshot: st.CoreSnapshot{Stream: core.Snapshot(), StartupResult: "IN_PROGRESS"}}, new(st.PushAck), time.Second, func(net.Conn) (uint32, error) { return 0, nil })
		conn.Close()
		listener.Close()
		<-done
		if e != nil {
			t.Fatal(e)
		}
	}
	s.startupAuthenticate = func(net.Conn, *startupBinding) bool { return true }
	sinkEntered, sinkRelease := make(chan struct{}), make(chan struct{})
	var sinkOnce sync.Once
	t.Cleanup(func() { sinkOnce.Do(func() { close(sinkRelease) }) })
	coreCtx, cancelCore := context.WithCancel(st.WithRecorder(context.Background(), core))
	defer cancelCore()
	coreDone := make(chan error, 1)
	coreStarted := false
	tool := d.tool
	d.tool = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "/bin/launchctl" && args[0] == "bootstrap" {
			// A real core with no TUN or DNS lookup, only a test-owned loopback listener.
			l, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				return "", e
			}
			port := l.Addr().(*net.TCPAddr).Port
			l.Close()
			cfg := []byte(`{"log":{"disabled":true},"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":` + strconv.Itoa(port) + `}],"outbounds":[{"type":"direct","tag":"direct"}],"dns":{"servers":[{"type":"https","server":"127.0.0.1","server_port":9}]}}`)
			coreStarted = true
			go func() {
				coreDone <- engine.RunWithRecords(coreCtx, cfg, &engine.RecordsInput{OpenSink: func() cr.Sink { close(sinkEntered); <-sinkRelease; return nil }})
			}()
			<-sinkEntered
			push()
			<-sinkRelease
			deadline := time.NewTimer(3 * time.Second)
			defer deadline.Stop()
			for {
				snap := core.Snapshot()
				for _, ev := range snap.Events {
					if ev.Stage == "CORE_WAIT" {
						push()
						return tool(ctx, name, args...)
					}
				}
				select {
				case <-core.Notifications():
				case e := <-coreDone:
					return "", e
				case <-deadline.C:
					return "", errors.New("core Start not observed")
				}
			}
		}
		if name == "/bin/launchctl" && args[0] == "bootout" && coreStarted {
			cancelCore()
			select {
			case e := <-coreDone:
				if !errors.Is(e, context.Canceled) {
					return "", e
				}
			case <-time.After(3 * time.Second):
				return "", errors.New("core Close timeout")
			}
			push()
		}
		if name == "/usr/bin/curl" {
			return "", errors.New("private fixture HTTPS failure")
		}
		return tool(ctx, name, args...)
	}
	s.start = func(ctx context.Context, allow bool) error { return d.withStartup(ctx, s).start(b, config, k, allow) }
	s.stop = func(ctx context.Context) error { return d.withStartup(ctx, s).stop() }
	result := make(chan struct {
		code int
		raw  []byte
	}, 1)
	go func() {
		c, r := call("POST", "/api/v1/service/start", `{"confirm_insecure":true}`, session.CSRF)
		result <- struct {
			code int
			raw  []byte
		}{c, r}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("mutation did not enter preflight")
	}
	traces := map[string][]byte{}
	read := func(name, current string) st.ReadResponse {
		t.Helper()
		code, raw := call("GET", "/api/v1/startup-trace", "", "")
		if code != 200 {
			t.Fatalf("%s HTTP %d %s", name, code, raw)
		}
		var r st.ReadResponse
		if e := st.Decode(bytes.NewReader(raw), &r); e != nil || r.Trace == nil {
			t.Fatalf("%s invalid actual trace %v %s", name, e, raw)
		}
		if current != "" {
			found := false
			for _, stream := range r.Trace.Streams {
				if stream.Current != nil && stream.Current.Stage == current {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s current %s missing", name, current)
			}
		}
		traces[name] = raw
		return r
	}
	held := read("preflight", "HELPER_PREFLIGHT_CAPTURE")
	releaseOnce.Do(func() { close(release) })
	select {
	case <-sinkEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("core OpenSink not reached")
	}
	// Wait for the push, not just the callback entrance.
	deadline := time.Now().Add(3 * time.Second)
	for {
		s.startup.mu.Lock()
		ready := s.startup.latest.core != nil
		s.startup.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("core snapshot not pushed")
		}
		time.Sleep(time.Millisecond)
	}
	sink := read("open-sink", "CORE_OPEN_SINK")
	if held.Trace.OperationID != sink.Trace.OperationID {
		t.Fatal("operation drift")
	}
	sinkOnce.Do(func() { close(sinkRelease) })
	var finish struct {
		code int
		raw  []byte
	}
	select {
	case finish = <-result:
	case <-time.After(5 * time.Second):
		t.Fatal("mutation not completed")
	}
	traces["mutation"] = finish.raw
	final := read("rollback", "")
	if *loaded {
		t.Fatal("fixture job still loaded")
	}
	if _, e := os.Stat(d.root); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("owned snapshot not removed")
	}
	if final.Trace.State != "FINISHED" || final.Trace.ReceiptResult != "WRITTEN" {
		t.Fatal("retained terminal receipt missing")
	}
	stages := map[string]bool{}
	for _, stream := range final.Trace.Streams {
		for _, event := range stream.Events {
			stages[event.Stage] = true
		}
	}
	for _, stage := range []string{"CORE_OPEN_SINK", "CORE_START", "CORE_CLOSE", "SNAPSHOT_REMOVE", "RECEIPT_WRITE", "HELPER_FINISH", "WEB_FINISH"} {
		if !stages[stage] {
			t.Errorf("missing actual stage %s", stage)
		}
	}
	// A validated helper failure is not a transport failure. Keep the lifecycle
	// code/diagnostics and failed web return; never report unknown or resend.
	var failure struct {
		Error       string          `json:"error"`
		Diagnostics json.RawMessage `json:"diagnostics"`
	}
	json.Unmarshal(finish.raw, &failure)
	if finish.code != 503 || failure.Error != "START_FAILED" || len(failure.Diagnostics) == 0 || final.Trace.WebReturn != "FAILED" {
		t.Errorf("validated helper business failure lost: HTTP=%d body=%s web_return=%s", finish.code, finish.raw, final.Trace.WebReturn)
	}
	if dir := os.Getenv("ST1_EXPORT"); dir != "" {
		if !filepath.IsAbs(dir) {
			t.Fatal("export must be absolute")
		}
		if e := os.MkdirAll(dir, 0700); e != nil {
			t.Fatal(e)
		}
		for name, b := range traces {
			if e := os.WriteFile(filepath.Join(dir, name+".json"), b, 0600); e != nil {
				t.Fatal(e)
			}
		}
		// All inputs are synthetic public documentation addresses, never user YAML.
		u, _ := url.Parse(server.URL)
		t.Logf("actual test HTTP %s, private IPC, retained operation %s", u.Host, final.Trace.OperationID)
	}
}
