package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
)

func TestStartupReadUnixDoesNotEnterMutation(t *testing.T) {
	s := &controlHelperServer{registration: controlHelperRegistration{UID: 501}, peer: func(net.Conn) (uint32, error) { return 501, nil }, state: func() (bool, bool, error) { t.Error("read called state"); return false, false, nil }}
	s.mutation.Lock()
	s.startupRegistration = func() (controlHelperRegistration, error) { return s.registration, nil }
	defer s.mutation.Unlock()
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(t.TempDir(), "s"), Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	go func() {
		c, e := l.AcceptUnix()
		if e == nil {
			s.handle(c)
		}
	}()
	c, e := net.DialUnix("unix", nil, l.Addr().(*net.UnixAddr))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	if e = json.NewEncoder(c).Encode(st.ReadRequest{TimelineSchema: 1, Action: "startup.read"}); e != nil {
		t.Fatal(e)
	}
	c.CloseWrite()
	var r st.ReadResponse
	if e = st.Decode(c, &r); e != nil {
		t.Fatalf("startup.read must return a valid independent response while mutation is held: %v", e)
	}
	if r.Code != "NO_OPERATION" {
		t.Fatalf("code=%s", r.Code)
	}
	_ = context.Background()
}

func startupRawFixture(t *testing.T, s *controlHelperServer, raw []byte) []byte {
	t.Helper()
	c, _ := unitControlPair(t, s)
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, e := c.Write(raw); e != nil {
		t.Fatal(e)
	}
	if e := c.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(c)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestStartupStrictDispatchReadAndAuth(t *testing.T) {
	for _, raw := range []string{
		`{"schema_version":1,"timeline_schema":1,"action":"startup.read","operation_id":null}`,
		`{"timeline_schema":1,"action":"startup.read","operation_id":null,"timeline_schema":1}`,
		`{"timeline_schema":2,"action":"startup.read","operation_id":null}`,
		`{"timeline_schema":1,"action":"startup.read","operation_id":null,"unknown":true}`,
		strings.Repeat(" ", st.LegacyBytes) + `{"timeline_schema":1,"action":"startup.read","operation_id":null}`,
	} {
		s := unitControlServer()
		s.state = func() (bool, bool, error) { t.Fatal("invalid/read called state"); return false, false, nil }
		b := startupRawFixture(t, s, []byte(raw))
		var r st.ReadResponse
		if e := st.Decode(bytes.NewReader(b), &r); e != nil || r.Code != "INVALID_REQUEST" {
			t.Fatalf("strict new frame response=%s err=%v", b, e)
		}
	}
	s := unitControlServer()
	s.peer = func(net.Conn) (uint32, error) { return 0, nil }
	b := startupRawFixture(t, s, []byte(`{"timeline_schema":1,"action":"startup.read","operation_id":null}`))
	var r st.ReadResponse
	var legacy controlHelperResponse
	if e := controlHelperReadResponse(bytes.NewReader(b), &legacy); e != nil || legacy.Code != "FORBIDDEN" {
		t.Fatal("root read authorized", string(b), e)
	}
	s = unitControlServer()
	s.startupRegistration = func() (controlHelperRegistration, error) { v := s.registration; v.UID++; return v, nil }
	b = startupRawFixture(t, s, []byte(`{"timeline_schema":1,"action":"startup.read","operation_id":null}`))
	if e := st.Decode(bytes.NewReader(b), &r); e != nil || r.Code != "FORBIDDEN" {
		t.Fatal("revoked registration read", string(b), e)
	}
	core, _ := st.NewRecorder("CORE", startupProvenance(""))
	q := st.PushRequest{TimelineSchema: 1, Action: "startup.push", OperationID: strings.Repeat("a", 32), HelperEpoch: strings.Repeat("b", 32), Snapshot: st.CoreSnapshot{Stream: core.Snapshot(), StartupResult: "IN_PROGRESS"}}
	raw, _ := st.Encode(q)
	s = unitControlServer()
	b = startupRawFixture(t, s, raw)
	var ack st.PushAck
	if e := st.Decode(bytes.NewReader(b), &ack); e != nil || ack.Code != "FORBIDDEN" {
		t.Fatal("registered UID push authorized", string(b), e)
	}
}
func TestStartupExchangeExactLegacyUnsupported(t *testing.T) {
	q := st.ReadRequest{TimelineSchema: 1, Action: "startup.read"}
	old := controlHelperFailure("INVALID_REQUEST")
	old.ConfigIdentity = strings.Repeat("a", 64)
	good, _ := json.Marshal(old)
	for _, test := range []struct {
		name        string
		raw         []byte
		unsupported bool
	}{{"legacy", good, true}, {"newbad", []byte(`{"timeline_schema":1,"code":"NO_OPERATION"}`), false}, {"legacyextra", append(good[:len(good)-1], []byte(`,"unknown":true}`)...), false}, {"oversize", append(bytes.Repeat([]byte(" "), st.LegacyBytes), good...), false}} {
		t.Run(test.name, func(t *testing.T) {
			l, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(unitControlSocketDir(t), "s"), Net: "unix"})
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, e := l.AcceptUnix()
				if e != nil {
					return
				}
				defer c.Close()
				io.Copy(io.Discard, c)
				c.Write(test.raw)
			}()
			c, e := net.DialUnix("unix", nil, l.Addr().(*net.UnixAddr))
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			var r st.ReadResponse
			e = startupExchange(context.Background(), c, q, &r, time.Second, func(net.Conn) (uint32, error) { return 0, nil })
			<-done
			if startupUnsupported(e) != test.unsupported {
				t.Fatalf("unsupported=%v err=%v", startupUnsupported(e), e)
			}
		})
	}
}
func TestStartupCumulativeCacheRejectsClockAndRegression(t *testing.T) {
	helper, _ := st.NewRecorder("HELPER", startupProvenance(""))
	r, _ := st.NewRecorder("CORE", startupProvenance(""))
	o := &startupOperation{recorder: helper}
	r.Observe("START", "CORE_ENTER", "OK", st.Fields{})
	first := st.CoreSnapshot{Stream: r.Snapshot(), StartupResult: "IN_PROGRESS"}
	if o.acceptCore(first) != "OK" {
		t.Fatal("first snapshot rejected")
	}
	span := r.Begin("START", "CORE_OPEN_SINK", st.Fields{})
	next := st.CoreSnapshot{Stream: r.Snapshot(), StartupResult: "IN_PROGRESS"}
	if o.acceptCore(next) != "OK" {
		t.Fatal("cumulative snapshot rejected")
	}
	if o.acceptCore(first) != "IDENTITY_MISMATCH" {
		t.Fatal("regressed snapshot accepted")
	}
	changed := next
	changed.Stream.ClockID = strings.Repeat("f", 32)
	if o.acceptCore(changed) != "IDENTITY_MISMATCH" {
		t.Fatal("changed clock accepted")
	}
	o.received = time.Now().Add(-2 * time.Second)
	if o.observation().Availability != "STALE" {
		t.Fatal("old snapshot marked current")
	}
	r.End(span, "OK", st.Fields{})
}

func TestStartupLifecycleRollbackRetainsActualEvents(t *testing.T) {
	d, b, c, k, loaded, _ := lifecycleFixture(t)
	primary := errors.New("private HTTPS failure")
	tool := d.tool
	d.tool = func(ctx context.Context, n string, a ...string) (string, error) {
		if n == "/usr/bin/curl" {
			return "", primary
		}
		return tool(ctx, n, a...)
	}
	s := &controlHelperServer{registration: controlHelperRegistration{UID: 501, Config: c}, state: d.state, preflight: func(context.Context, bool) error { return nil }}
	s.start = func(ctx context.Context, allow bool) error { return d.withStartup(ctx, s).start(b, c, k, allow) }
	s.stop = func(ctx context.Context) error { return d.withStartup(ctx, s).stop() }
	identity, e := controlHelperConfigIdentity(c)
	if e != nil {
		t.Fatal(e)
	}
	id := "0123456789abcdef0123456789abcdef"
	result, _ := s.executeStartup(controlHelperWireRequest{"start", true}, id, identity, "MANUAL_START")
	if result.OK || result.Code != "START_FAILED" || *loaded {
		t.Fatal("business failure/rollback changed", result)
	}
	if _, e = os.Stat(d.root); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("rollback did not remove owned snapshot")
	}
	response := s.startupReadCache(st.ReadRequest{TimelineSchema: 1, Action: "startup.read", OperationID: &id})
	if e = st.Validate(response); e != nil {
		t.Fatal("invalid retained trace", e)
	}
	seen := map[string]bool{}
	for _, event := range response.Trace.Streams[0].Events {
		seen[event.Stage] = true
	}
	for _, stage := range []string{"SNAPSHOT_STAGE", "CONFIG_OUTBOUNDS_COMPILE", "BOOTSTRAP", "READINESS_ROUND", "HTTPS_ATTEMPT", "BOOTOUT", "RESTORE_SERVER_ROUTES", "SNAPSHOT_REMOVE", "RECEIPT_WRITE", "HELPER_FINISH"} {
		if !seen[stage] {
			t.Errorf("actual %s absent after rollback", stage)
		}
	}
	if response.Trace.State != "FINISHED" || response.Trace.ReceiptResult != "WRITTEN" {
		t.Fatal("terminal/receipt missing", response.Trace)
	}
}
