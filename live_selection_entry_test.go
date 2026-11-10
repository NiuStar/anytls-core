package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This fixture replaces only root ownership and OS process observations. The
// actual executeContext -> selectSaved -> liveExchange -> UDS parser runs.
type liveEntryFixture struct {
	s        *controlHelperServer
	listener *net.UnixListener
	mu       sync.Mutex
	state    liveResponse
	switches atomic.Int32
	reads    atomic.Int32
	onRead   func(int32, *liveResponse) string
	onSwitch func(liveRequest) string
	done     chan struct{}
	ready    chan struct{}
	once     sync.Once
}

func newLiveEntryFixture(t *testing.T) *liveEntryFixture {
	t.Helper()
	dir := unitControlSocketDir(t)
	config := filepath.Join(dir, "config.yaml")
	raw := []byte("nodes:\n - {name: a, type: anytls, server: 192.0.2.1, port: 443, password: p, sni: example.com}\n - {name: b, type: anytls, server: 192.0.2.2, port: 443, password: q, sni: example.com}\nproxy-groups:\n - {name: default, type: select, proxies: [a, b], selected: a}\nrules: ['MATCH,default']\n")
	root := filepath.Join(dir, "service")
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	must(os.Mkdir(root, 0700))
	ca, _ := runtimeCertificate(t)
	caPath := filepath.Join(dir, "fixture-ca.pem")
	must(os.WriteFile(caPath, ca, 0600))
	raw = []byte(strings.ReplaceAll(string(raw), "sni: example.com", "sni: g21.invalid, ca: "+caPath))
	must(os.WriteFile(config, raw, 0600))
	must(os.WriteFile(selectedPath(config), []byte("a\n"), 0600))
	caPin, _, e := captureLiveFile(caPath, snapshotCALimit)
	must(e)
	must(os.WriteFile(filepath.Join(root, "config.yaml"), raw, 0600))
	stagedPin, _, e := captureLiveFile(filepath.Join(root, "config.yaml"), snapshotConfigLimit)
	must(e)
	src, _ := json.Marshal(liveSource{Config: raw, Selected: []byte("a\n"), CAs: map[string]string{caPath: caPin.SHA}, Rules: map[string]liveFilePin{}, CAPins: map[string]liveFilePin{caPath: caPin}, Origin: config, Staged: map[string]liveFilePin{stagedPin.Path: stagedPin, caPin.Path: caPin}})
	must(os.WriteFile(filepath.Join(root, liveSourceName), src, 0600))
	next, e := groupChoiceBytes(raw, "default", "b")
	must(e)
	must(os.WriteFile(config, next, 0600))
	must(os.WriteFile(selectedPath(config), []byte("b\n"), 0600))
	exe := filepath.Join(root, "core")
	pinned := filepath.Join(root, "runtime.json")
	must(os.WriteFile(exe, []byte("fixture executable"), 0600))
	must(os.WriteFile(pinned, []byte("{}"), 0600))
	ri, e := os.Lstat(root)
	must(e)
	ei, e := os.Lstat(exe)
	must(e)
	ci, e := os.Lstat(pinned)
	must(e)
	binding := &startupBinding{root: root, executable: exe, config: pinned, rootInfo: ri, executableInfo: ei, configInfo: ci, process: &startupProcessIdentity{PID: 77, UID: 0, Sec: 1, Usec: 2}}
	s := &controlHelperServer{registration: controlHelperRegistration{UID: 501, Config: config, Home: dir}}
	s.peer = func(net.Conn) (uint32, error) { return 501, nil }
	s.version = "entry-fixture"
	s.sha = strings.Repeat("c", 64)
	s.dns.binding = binding
	s.liveRootCheck = func(path string) error {
		if path != root {
			return os.ErrPermission
		}
		return nil
	}
	s.liveSocketCheck = func(path string) error {
		info, e := os.Lstat(path)
		if e != nil {
			return e
		}
		if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
			return os.ErrPermission
		}
		return nil
	}
	s.livePeer = func(_ net.Conn, b *startupBinding) bool {
		return b.check() && b.process != nil && b.process.PID == 77 && b.process.Sec == 1 && b.process.Usec == 2
	}
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(root, liveSocketName), Net: "unix"})
	must(e)
	must(os.Chmod(l.Addr().String(), 0600))
	f := &liveEntryFixture{s: s, listener: l, state: liveResponse{Code: "READY", Generation: strings.Repeat("a", 32), Revision: 4, Node: "a", PID: 77}, done: make(chan struct{}), ready: make(chan struct{})}
	go func() {
		defer close(f.done)
		for {
			c, e := l.AcceptUnix()
			if e != nil {
				return
			}
			func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				q, e := readLiveRequest(c)
				if e != nil {
					return
				}
				<-f.ready
				f.mu.Lock()
				defer f.mu.Unlock()
				var raw string
				if q.Action == "read" {
					n := f.reads.Add(1)
					if f.onRead != nil {
						raw = f.onRead(n, &f.state)
					}
				} else {
					f.switches.Add(1)
					if f.onSwitch != nil {
						raw = f.onSwitch(q)
					}
					if q.Generation == f.state.Generation && q.Revision == f.state.Revision {
						f.state.Node = q.Node
						f.state.Revision++
					}
					if raw == "DROP" {
						return
					}
				}
				if raw != "" {
					_, _ = c.Write([]byte(raw))
					return
				}
				out := f.state
				if q.Action == "switch" {
					out.Code = "APPLIED"
				}
				_ = json.NewEncoder(c).Encode(out)
			}()
		}
	}()
	t.Cleanup(func() {
		f.begin()
		_ = l.Close()
		select {
		case <-f.done:
		case <-time.After(3 * time.Second):
			t.Error("fixture worker not joined")
		}
	})
	return f
}
func (f *liveEntryFixture) begin() { f.once.Do(func() { close(f.ready) }) }
func (f *liveEntryFixture) call(action string) controlHelperResponse {
	f.begin()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return f.s.executeContext(ctx, controlHelperWireRequest{Action: action})
}
func TestLiveHelperEntryPositive(t *testing.T) {
	f := newLiveEntryFixture(t)
	r := f.call("select")
	if !r.OK || r.Code != "HOT_APPLIED" || f.switches.Load() != 1 || f.reads.Load() != 2 {
		t.Fatalf("response=%+v switches=%d reads=%d", r, f.switches.Load(), f.reads.Load())
	}
	if r.SelectionOperation == nil || r.SelectionOperation.Revision != 5 || r.SelectionOperation.Node != "b" {
		t.Fatalf("missing owned operation: %+v", r)
	}
}
func TestLiveHelperEntryLostACKNoReplay(t *testing.T) {
	f := newLiveEntryFixture(t)
	f.onSwitch = func(liveRequest) string { return "DROP" }
	r := f.call("select")
	if !r.OK || f.switches.Load() != 1 || f.reads.Load() != 2 {
		t.Fatalf("lost ACK: %+v switches=%d reads=%d", r, f.switches.Load(), f.reads.Load())
	}
}
func TestLiveHelperEntryUnknownReadOnly(t *testing.T) {
	f := newLiveEntryFixture(t)
	f.onRead = func(n int32, _ *liveResponse) string {
		if n == 2 {
			return "{}"
		}
		return ""
	}
	r := f.call("select")
	if r.Code != "SWITCH_UNKNOWN" || r.SelectionOperation == nil || f.switches.Load() != 1 {
		t.Fatalf("initial unknown: %+v", r)
	}
	again := f.call("select")
	if again.Code != "SWITCH_UNKNOWN" || f.switches.Load() != 1 || f.reads.Load() != 2 {
		t.Fatalf("unknown replay: %+v", again)
	}
	read := f.call("select-read")
	if !read.OK || read.Code != "HOT_APPLIED" || *read.SelectionOperation != *r.SelectionOperation || f.switches.Load() != 1 || f.reads.Load() != 3 {
		t.Fatalf("read-only recovery: %+v", read)
	}
}
func TestLiveHelperEntrySecurityMatrix(t *testing.T) {
	// Positive reaches the actual mutation seam before any zero-mutation claim.
	t.Run("positive", TestLiveHelperEntryPositive)
	for _, mode := range []string{"wrong_pid", "not_ready", "oversized", "duplicate", "case_alias", "trailing", "saved_read_failure", "saved_changed", "parent_inode", "socket_inode", "wrong_generation", "wrong_revision", "wrong_node", "pid_changed_after", "revision_overflow", "socket_mode", "untrusted_peer", "no_binding"} {
		t.Run(mode, func(t *testing.T) {
			f := newLiveEntryFixture(t)
			late := mode == "wrong_generation" || mode == "wrong_revision" || mode == "wrong_node" || mode == "pid_changed_after"
			f.onRead = func(n int32, r *liveResponse) string {
				if n == 2 {
					switch mode {
					case "wrong_generation":
						r.Generation = strings.Repeat("b", 32)
					case "wrong_revision":
						r.Revision++
					case "wrong_node":
						r.Node = "a"
					case "pid_changed_after":
						r.PID++
					}
					return ""
				}
				if n != 1 {
					return ""
				}
				switch mode {
				case "wrong_pid":
					r.PID++
				case "not_ready":
					r.Code = "NOT_READY"
				case "oversized":
					return strings.Repeat(" ", 4097) + `{}`
				case "duplicate", "case_alias":
					b, _ := json.Marshal(r)
					key := "pid"
					if mode == "case_alias" {
						key = "PID"
					}
					return strings.TrimSuffix(string(b), "}") + `,"` + key + `":77}`
				case "trailing":
					b, _ := json.Marshal(r)
					return string(b) + `{}`
				case "saved_read_failure":
					if e := os.Rename(f.s.registration.Config, f.s.registration.Config+".old"); e != nil {
						t.Error(e)
					}
					if e := os.Mkdir(f.s.registration.Config, 0700); e != nil {
						t.Error(e)
					}
				case "saved_changed":
					if e := os.WriteFile(selectedPath(f.s.registration.Config), []byte("a\n"), 0600); e != nil {
						t.Error(e)
					}
				case "parent_inode":
					dir := filepath.Dir(f.s.registration.Config)
					if e := os.Rename(dir, dir+".old"); e != nil {
						t.Error(e)
					}
					if e := os.Mkdir(dir, 0700); e != nil {
						t.Error(e)
					}
					t.Cleanup(func() {
						_ = os.Remove(dir)
						if e := os.Rename(dir+".old", dir); e != nil {
							t.Error(e)
						}
					})
				case "socket_inode":
					path := f.listener.Addr().String()
					if e := os.Rename(path, path+".old"); e != nil {
						t.Error(e)
					}
					l, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
					if e != nil {
						t.Error(e)
					} else {
						_ = os.Chmod(path, 0600)
						t.Cleanup(func() { _ = l.Close() })
					}
				case "revision_overflow":
					r.Revision = ^uint64(0)
				}
				return ""
			}
			switch mode {
			case "socket_mode":
				_ = os.Chmod(f.listener.Addr().String(), 0666)
			case "untrusted_peer":
				f.s.livePeer = func(net.Conn, *startupBinding) bool { return false }
			case "no_binding":
				f.s.dns.binding = nil
			}
			r := f.call("select")
			want := "RELOAD_REQUIRED"
			count := int32(0)
			if late {
				want = "SWITCH_UNKNOWN"
				count = 1
			}
			if r.OK || r.Code != want || f.switches.Load() != count {
				t.Fatalf("mode=%s response=%+v switches=%d want=%d", mode, r, f.switches.Load(), count)
			}
		})
	}
}
func TestLiveHelperEntryCASAndSameSelection(t *testing.T) {
	f := newLiveEntryFixture(t)
	f.onSwitch = func(q liveRequest) string {
		if q.Action != "switch" || q.Generation != strings.Repeat("a", 32) || q.Revision != 4 || q.Node != "b" {
			t.Errorf("not bound CAS: %+v", q)
		}
		return ""
	}
	if r := f.call("select"); !r.OK {
		t.Fatal(r)
	}
	if r := f.call("select"); !r.OK || f.switches.Load() != 1 || f.reads.Load() != 4 {
		t.Fatalf("same-selection readback: %+v switches=%d reads=%d", r, f.switches.Load(), f.reads.Load())
	}
}
func TestLiveHelperEntryBusyNoQueue(t *testing.T) {
	f := newLiveEntryFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	f.onRead = func(n int32, _ *liveResponse) string {
		if n == 1 {
			close(entered)
			<-release
		}
		return ""
	}
	done := make(chan controlHelperResponse, 1)
	go func() { done <- f.call("select") }()
	defer func() {
		close(release)
		select {
		case result := <-done:
			if !result.OK || f.switches.Load() != 1 {
				t.Errorf("positive owner did not complete exactly once: %+v switches=%d", result, f.switches.Load())
			}
		case <-time.After(3 * time.Second):
			t.Error("mutation did not join")
		}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("positive never reached read seam")
	}
	if r := f.call("select"); r.Code != "BUSY" || f.switches.Load() != 0 {
		t.Fatalf("queued concurrent mutation: %+v", r)
	}
}
func TestLiveHelperHandleEntryFrames(t *testing.T) {
	t.Run("positive", func(t *testing.T) {
		f := newLiveEntryFixture(t)
		f.begin()
		r := unitControlRaw(t, f.s, `{"action":"select","allow_insecure":false}`)
		if !r.OK || r.Code != "HOT_APPLIED" || f.switches.Load() != 1 {
			t.Fatalf("handle chain did not reach switch: %+v", r)
		}
	})
	for _, raw := range []string{`{"action":"select","action":"status","allow_insecure":false}`, `{"action":"select","Action":"status","allow_insecure":false}`, strings.Repeat(" ", 4097) + `{"action":"select","allow_insecure":false}`, `{"action":"select","allow_insecure":true}`, `{"action":"select","allow_insecure":false}{}`} {
		t.Run("reject", func(t *testing.T) {
			f := newLiveEntryFixture(t)
			f.begin()
			r := unitControlRaw(t, f.s, raw)
			if r.OK || r.Code != "INVALID_REQUEST" || f.switches.Load() != 0 || f.reads.Load() != 0 {
				t.Fatalf("unsafe outer frame: %+v", r)
			}
		})
	}
	t.Run("unauthorized", func(t *testing.T) {
		f := newLiveEntryFixture(t)
		f.s.peer = func(net.Conn) (uint32, error) { return 502, nil }
		f.begin()
		r := unitControlRaw(t, f.s, `{"action":"select","allow_insecure":false}`)
		if r.Code != "FORBIDDEN" || f.switches.Load() != 0 {
			t.Fatal(r)
		}
	})
}

func TestLiveHelperExchangePoisonedSuccess(t *testing.T) {
	for _, mode := range []string{"positive", "empty_code", "not_loaded", "not_running", "missing_operation", "operation_alias", "operation_duplicate", "wrong_root_peer", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			r := controlHelperResponse{OK: true, Code: "HOT_APPLIED", Loaded: true, Running: true, HelperVersion: "fixture", HelperSHA256: strings.Repeat("c", 64), ConfigIdentity: strings.Repeat("d", 64), SelectionOperation: &liveSelectionOperation{Operation: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32), Revision: 1, Node: "b"}}
			switch mode {
			case "empty_code":
				r.Code = ""
			case "not_loaded":
				r.Loaded = false
			case "not_running":
				r.Running = false
			case "missing_operation":
				r.SelectionOperation = nil
			}
			raw, _ := json.Marshal(r)
			if mode == "operation_alias" {
				raw = []byte(strings.Replace(string(raw), `"revision":1`, `"revision":1,"Revision":2`, 1))
			}
			if mode == "operation_duplicate" {
				raw = []byte(strings.Replace(string(raw), `"revision":1`, `"revision":1,"revision":2`, 1))
			}
			if mode == "oversized" {
				raw = append([]byte(strings.Repeat(" ", 4097)), raw...)
			}
			dir := unitControlSocketDir(t)
			listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "reply.sock"), Net: "unix"})
			if e != nil {
				t.Fatal(e)
			}
			done := make(chan struct{})
			var requests atomic.Int32
			go func() {
				defer close(done)
				defer listener.Close()
				c, e := listener.AcceptUnix()
				if e != nil {
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				if _, e = controlHelperReadRequest(c); e != nil {
					return
				}
				requests.Add(1)
				_, _ = c.Write(raw)
			}()
			c, e := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, e = controlHelperExchange(ctx, c, controlHelperWireRequest{Action: "select"}, func(net.Conn) (uint32, error) {
				if mode == "wrong_root_peer" {
					return 501, nil
				}
				return 0, nil
			})
			_ = c.Close()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("reply worker not joined")
			}
			if mode == "positive" {
				if e != nil || requests.Load() != 1 {
					t.Fatalf("valid reply: %v", e)
				}
			} else if e == nil {
				t.Fatalf("accepted poisoned helper success: %s", raw)
			}
			if mode == "wrong_root_peer" && requests.Load() != 0 {
				t.Fatal("action disclosed before root peer authentication")
			}
		})
	}
}

func TestLiveHelperEntryReadRequiresLease(t *testing.T) {
	f := newLiveEntryFixture(t)
	r := f.call("select-read")
	if r.Code != "SWITCH_UNKNOWN" || r.OK || f.reads.Load() != 0 || f.switches.Load() != 0 {
		t.Fatalf("invented authority: %+v", r)
	}
}
