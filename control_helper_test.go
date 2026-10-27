package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// UNIT: real Unix sockets and transport, injected kernel UID and lifecycle.
// No root, launchd, TUN, or real service operations are used.
func unitControlServer() *controlHelperServer {
	config, _ := os.Executable() // Existing regular path; UNIT never compiles it.
	return &controlHelperServer{registration: controlHelperRegistration{UID: 501, Config: config}, peer: func(net.Conn) (uint32, error) { return 501, nil },
		state: func() (bool, bool, error) { return true, true, nil }, preflight: func(context.Context, bool) error { return nil },
		start: func(context.Context, bool) error { return nil }, stop: func(context.Context) error { return nil }, version: "unit", sha: strings.Repeat("a", 64)}
}

// Socket paths must fit Darwin sockaddr_un even when the suite name is long.
func unitControlSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ch-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}
func unitControlPair(t *testing.T, s *controlHelperServer) (*net.UnixConn, <-chan struct{}) {
	t.Helper()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(unitControlSocketDir(t), "control.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := listener.AcceptUnix()
		listener.Close()
		if err == nil {
			s.handle(c)
		}
	}()
	c, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("UNIT handler did not finish")
		}
	})
	return c, done
}
func unitControlRaw(t *testing.T, s *controlHelperServer, raw string) controlHelperResponse {
	t.Helper()
	c, _ := unitControlPair(t, s)
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var r controlHelperResponse
	if err := json.NewDecoder(c).Decode(&r); err != nil {
		t.Fatal(err)
	}
	return r
}
func TestControlHelperUNITProtocol(t *testing.T) {
	cases := []struct {
		raw string
		ok  bool
	}{
		{`{"action":"status","allow_insecure":false}`, true},
		{`{"action":"start","allow_insecure":true}`, true},
		{`{"action":"reload","allow_insecure":true}`, true},
		{`{"action":"stop","allow_insecure":true}`, false},
		{`{"action":"status","allow_insecure":true}`, false},
		{`{"action":"exec","allow_insecure":false}`, false},
		{`{"action":"start","allow_insecure":false,"path":"/bin/sh"}`, false},
		{`{"Action":"status","allow_insecure":false}`, false},
		{`{"action":"status","action":"start","allow_insecure":false}`, false},
		{`{"action":"status","allow_insecure":null}`, false},
		{`{"action":"status","allow_insecure":"true"}`, false},
		{`{"action":"status","allow_insecure":false} {}`, false},
		{`{"action":"status","allow_insecure":false} garbage`, false},
		{`{"action":"status"}`, false}, {`null`, false}, {`[]`, false},
		{strings.Repeat(" ", controlHelperJSONLimit) + `{}`, false},
	}
	for _, tt := range cases {
		t.Run(tt.raw[:min(50, len(tt.raw))], func(t *testing.T) {
			r := unitControlRaw(t, unitControlServer(), tt.raw)
			if r.OK != tt.ok || (!tt.ok && r.Code != "INVALID_REQUEST") {
				t.Fatalf("response %+v", r)
			}
		})
	}
}
func TestControlHelperUNITAuthorizedUID(t *testing.T) {
	r := unitControlRaw(t, unitControlServer(), `{"action":"status","allow_insecure":false}`)
	if !r.OK || !r.Loaded || !r.Running || r.HelperVersion != "unit" || len(r.HelperSHA256) != 64 {
		t.Fatalf("%+v", r)
	}
}
func TestControlHelperUNITAuthRejects(t *testing.T) {
	for _, uid := range []uint32{0, 502} {
		t.Run(string(rune(uid)), func(t *testing.T) {
			s := unitControlServer()
			s.peer = func(net.Conn) (uint32, error) { return uid, nil }
			c, _ := unitControlPair(t, s)
			if uid == 0 {
				// Root's sole allowed request now uses separate EOF framing.
				_, _ = io.WriteString(c, `{"action":"status","allow_insecure":false}`)
				_ = c.CloseWrite()
			}
			var r controlHelperResponse
			if err := json.NewDecoder(c).Decode(&r); err != nil || r.Code != "FORBIDDEN" {
				t.Fatalf("%+v %v", r, err)
			}
		})
	}
}
func TestControlHelperUNITAuthError(t *testing.T) {
	s := unitControlServer()
	s.peer = func(net.Conn) (uint32, error) { return 501, errors.New("secret") }
	c, _ := unitControlPair(t, s)
	var r controlHelperResponse
	if err := json.NewDecoder(c).Decode(&r); err != nil || r.Code != "FORBIDDEN" || strings.Contains(r.Message, "secret") {
		t.Fatalf("%+v %v", r, err)
	}
}
func TestControlHelperUNITZeroRegistration(t *testing.T) {
	s := unitControlServer()
	s.registration.UID = 0
	c, _ := unitControlPair(t, s)
	var r controlHelperResponse
	if err := json.NewDecoder(c).Decode(&r); err != nil || r.Code != "FORBIDDEN" {
		t.Fatalf("%+v %v", r, err)
	}
}
func TestControlHelperUNITBusyStatusDisconnect(t *testing.T) {
	s := unitControlServer()
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	var calls atomic.Int32
	s.start = func(ctx context.Context, _ bool) error {
		calls.Add(1)
		close(entered)
		<-release
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}
	c, done := unitControlPair(t, s)
	io.WriteString(c, `{"action":"start","allow_insecure":false}`)
	c.CloseWrite()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("start not entered")
	}
	c.Close()
	if r := unitControlRaw(t, s, `{"action":"reload","allow_insecure":false}`); r.Code != "BUSY" {
		t.Fatalf("disconnect released mutation: %+v", r)
	}
	if r := unitControlRaw(t, s, `{"action":"status","allow_insecure":false}`); !r.OK {
		t.Fatalf("status blocked: %+v", r)
	}
	if calls.Load() != 1 {
		t.Fatal("queued mutation executed")
	}
	select {
	case <-done:
		t.Fatal("disconnect completed in-flight operation")
	default:
	}
}
func TestControlHelperUNITReloadOrderConsent(t *testing.T) {
	s := unitControlServer()
	var order []string
	s.preflight = func(_ context.Context, allow bool) error {
		if !allow {
			t.Error("consent lost")
		}
		order = append(order, "preflight")
		return nil
	}
	s.stop = func(context.Context) error { order = append(order, "stop"); return nil }
	s.start = func(_ context.Context, allow bool) error {
		if !allow {
			t.Error("consent lost")
		}
		order = append(order, "start")
		return nil
	}
	r := unitControlRaw(t, s, `{"action":"reload","allow_insecure":true}`)
	if !r.OK || strings.Join(order, ",") != "preflight,stop,start" {
		t.Fatalf("%+v %v", r, order)
	}
}
func TestControlHelperUNITPreflightPreservesService(t *testing.T) {
	s := unitControlServer()
	s.preflight = func(context.Context, bool) error { return errors.New("password=SENSITIVE") }
	s.stop = func(context.Context) error { t.Fatal("stop before successful preflight"); return nil }
	r := unitControlRaw(t, s, `{"action":"reload","allow_insecure":false}`)
	if r.Code != "PREFLIGHT_FAILED" || strings.Contains(r.Message, "SENSITIVE") {
		t.Fatalf("%+v", r)
	}
}
func TestControlHelperUNITStopFailurePreventsStart(t *testing.T) {
	s := unitControlServer()
	s.stop = func(context.Context) error { return errors.New("password=SENSITIVE") }
	s.start = func(context.Context, bool) error { t.Fatal("start after failed stop"); return nil }
	r := unitControlRaw(t, s, `{"action":"reload","allow_insecure":false}`)
	if r.Code != "STOP_FAILED" || strings.Contains(r.Message, "SENSITIVE") {
		t.Fatalf("%+v", r)
	}
}
func TestControlHelperUNITStartFailure(t *testing.T) {
	s := unitControlServer()
	s.start = func(context.Context, bool) error { return errors.New("password=SENSITIVE") }
	r := unitControlRaw(t, s, `{"action":"start","allow_insecure":false}`)
	if r.Code != "START_FAILED" || strings.Contains(r.Message, "SENSITIVE") {
		t.Fatalf("%+v", r)
	}
}
func TestControlHelperUNITStateFailure(t *testing.T) {
	s := unitControlServer()
	s.state = func() (bool, bool, error) { return false, false, errors.New("password=SENSITIVE") }
	r := unitControlRaw(t, s, `{"action":"status","allow_insecure":false}`)
	if r.Code != "STATE_FAILED" || strings.Contains(r.Message, "SENSITIVE") {
		t.Fatalf("%+v", r)
	}
}
func TestControlHelperUNITClientExchange(t *testing.T) {
	s := unitControlServer()
	c, _ := unitControlPair(t, s)
	r, err := controlHelperExchange(context.Background(), c, controlHelperWireRequest{"status", false}, func(net.Conn) (uint32, error) { return 0, nil })
	if err != nil || !r.OK {
		t.Fatalf("%+v %v", r, err)
	}
}
func TestControlHelperUNITClientRejectsNonRootBeforeWrite(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_, err := controlHelperExchange(context.Background(), a, controlHelperWireRequest{"start", false}, func(net.Conn) (uint32, error) { return 501, nil })
	if err == nil || !strings.Contains(err.Error(), "FORBIDDEN") {
		t.Fatal(err)
	}
	b.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	buf := make([]byte, 1)
	if n, _ := b.Read(buf); n != 0 {
		t.Fatal("sent request to non-root peer")
	}
}
func TestControlHelperUNITRegistrationAndResponseFields(t *testing.T) {
	var uid uint32
	var config, home string
	if err := controlHelperDecode(strings.NewReader(`{"uid":501,"config":"/Users/unit/config.yaml","home":"/Users/unit"}`), map[string]any{"uid": &uid, "config": &config, "home": &home}); err != nil || uid != 501 {
		t.Fatal(err)
	}
	b, err := json.Marshal(controlHelperResponse{HelperVersion: "unit", HelperSHA256: "unit"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"helper_sha256"`) || !strings.Contains(string(b), `"helper_version"`) {
		t.Fatal(string(b))
	}
}
func TestControlHelperUNITTrustedPathRejectsSymlinkAndWritable(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "helper")
	if err := os.WriteFile(file, []byte("unit"), 0777); err != nil {
		t.Fatal(err)
	}
	if controlHelperTrustedPath(file, false) == nil {
		t.Fatal("accepted writable helper")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if controlHelperTrustedPath(link, false) == nil {
		t.Fatal("accepted symlink")
	}
}
func TestControlHelperUNITClientErrorIsSanitized(t *testing.T) {
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(unitControlSocketDir(t), "reply.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(io.Discard, c)
		json.NewEncoder(c).Encode(controlHelperResponse{Code: "START_FAILED", Message: "password=SENSITIVE", HelperVersion: "unit"})
	}()
	c, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r, err := controlHelperExchange(context.Background(), c, controlHelperWireRequest{"start", false}, func(net.Conn) (uint32, error) { return 0, nil })
	if err == nil || strings.Contains(err.Error(), "SENSITIVE") || strings.Contains(r.Message, "SENSITIVE") || !strings.Contains(err.Error(), "START_FAILED") {
		t.Fatalf("%+v %v", r, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("UNIT reply server did not finish")
	}
}
func TestControlHelperUNITConfigIdentity(t *testing.T) {
	config := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(config, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	identity, err := controlHelperConfigIdentity(config)
	if err != nil || len(identity) != 64 {
		t.Fatal(identity, err)
	}
	canonical, err := filepath.EvalSymlinks(config)
	if err != nil {
		t.Fatal(err)
	}
	if identity != shaHex([]byte(filepath.Clean(canonical))) {
		t.Fatal("not canonical path SHA")
	}
	link := filepath.Join(t.TempDir(), "alias.yaml")
	if err := os.Symlink(config, link); err != nil {
		t.Fatal(err)
	}
	if got, err := controlHelperConfigIdentity(link); err != nil || got != identity {
		t.Fatal(got, err)
	}
	if err := os.WriteFile(config, []byte("second"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := controlHelperConfigIdentity(config); err != nil || got != identity {
		t.Fatal("content affected identity", got, err)
	}
	for _, bad := range []string{"relative.yaml", config + "-missing", filepath.Dir(config), "/", config + "\n"} {
		if _, err := controlHelperConfigIdentity(bad); err == nil {
			t.Fatal("unsafe identity accepted", bad)
		}
	}
	s := unitControlServer()
	s.registration.Config = config
	for _, raw := range []string{`{"action":"status","allow_insecure":false}`, `{"action":"exec","allow_insecure":false}`} {
		r := unitControlRaw(t, s, raw)
		if r.ConfigIdentity != identity {
			t.Fatal("unbound server reply", r)
		}
	}
}

func TestControlHelperUNITMissingConfigFailsClosed(t *testing.T) {
	s := unitControlServer()
	s.registration.Config = filepath.Join(t.TempDir(), "missing.yaml")
	s.state = func() (bool, bool, error) {
		t.Fatal("read lifecycle with invalid config identity")
		return false, false, nil
	}
	s.stop = func(context.Context) error { t.Fatal("mutated with invalid config identity"); return nil }
	for _, action := range []string{"status", "stop", "start", "reload"} {
		r := unitControlRaw(t, s, `{"action":"`+action+`","allow_insecure":false}`)
		if r.OK || r.Code != "STATE_FAILED" || r.ConfigIdentity != "" {
			t.Fatal(r)
		}
	}
}

func TestControlHelperUNITStrictResponseIdentity(t *testing.T) {
	valid := `{"ok":true,"code":"","message":"unit","loaded":true,"running":true,"helper_version":"unit","helper_sha256":"unit","config_identity":"` + strings.Repeat("a", 64) + `"}`
	for _, raw := range []string{
		valid,
		strings.Replace(valid, `,"config_identity":"`+strings.Repeat("a", 64)+`"`, "", 1), // old helper
		strings.Replace(valid, strings.Repeat("a", 64), "", 1),
		strings.Replace(valid, strings.Repeat("a", 64), "bad", 1),
		strings.Replace(valid, `"config_identity":`, `"ConfigIdentity":`, 1),
		strings.TrimSuffix(valid, "}") + `,"extra":false}`,
		strings.TrimSuffix(valid, "}") + `,"config_identity":"` + strings.Repeat("b", 64) + `"}`,
		strings.Replace(valid, `"config_identity":"`+strings.Repeat("a", 64)+`"`, `"config_identity":null`, 1),
	} {
		t.Run(raw, func(t *testing.T) {
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(unitControlSocketDir(t), "reply.sock"), Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, err := listener.AcceptUnix()
				if err != nil {
					return
				}
				defer c.Close()
				io.Copy(io.Discard, c)
				io.WriteString(c, raw)
			}()
			c, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_, err = controlHelperExchange(context.Background(), c, controlHelperWireRequest{"status", false}, func(net.Conn) (uint32, error) { return 0, nil })
			if raw == valid {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "HELPER_UNAVAILABLE") || !strings.Contains(err.Error(), "install") {
				t.Fatal("incompatible response accepted", err)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("reply server did not finish")
			}
		})
	}
}

func TestControlHelperUNITUnknownErrorNeverEchoed(t *testing.T) {
	r := controlHelperFailure("secret=password")
	if r.Code != "INVALID_REQUEST" || strings.Contains(r.Message, "password") {
		t.Fatal(r)
	}
}
