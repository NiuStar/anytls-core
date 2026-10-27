package main

import (
	"bytes"
	"context"

	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStartupMutationIPCReadWhileActualLifecycleHeld(t *testing.T) {
	s := unitControlServer()
	s.startupInit()
	s.startupIdentity, _ = controlHelperConfigIdentity(s.registration.Config)
	s.startupRegistration = func() (controlHelperRegistration, error) { return s.registration, nil }
	entered, release := make(chan struct{}), make(chan struct{})
	starts := 0
	s.start = func(ctx context.Context, _ bool) error {
		starts++
		span := st.FromContext(ctx).Begin("START", "SNAPSHOT_STAGE", st.Fields{})
		close(entered)
		<-release
		st.FromContext(ctx).End(span, "OK", st.Fields{})
		return nil
	}
	c, _ := unitControlPair(t, s)
	id := strings.Repeat("a", 32)
	raw, _ := st.Encode(st.MutationRequest{TimelineSchema: 1, Action: "start", OperationID: id})
	c.Write(raw)
	c.CloseWrite()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("actual mutation did not enter")
	}
	read, _ := st.Encode(st.ReadRequest{TimelineSchema: 1, Action: "startup.read", OperationID: &id})
	rraw := startupRawFixture(t, s, read)
	var readResponse st.ReadResponse
	if e := st.Decode(bytes.NewReader(rraw), &readResponse); e != nil {
		close(release)
		t.Fatal(e)
	}
	stream := readResponse.Trace.Streams[0]
	if stream.Current == nil || stream.Current.Stage != "SNAPSHOT_STAGE" || readResponse.Trace.State != "IN_PROGRESS" {
		close(release)
		t.Fatal("blocked actual mutation phase missing")
	}
	close(release)
	var result st.MutationResponse
	if e := st.Decode(c, &result); e != nil || !result.OK || result.OperationID == nil || *result.OperationID != id || starts != 1 {
		t.Fatal("mutation response failed", result, e)
	}
	rraw = startupRawFixture(t, s, read)
	if e := st.Decode(bytes.NewReader(rraw), &readResponse); e != nil || readResponse.Trace.State != "FINISHED" {
		t.Fatal("final cached trace missing", e)
	}
}
func TestStartupReloadSegmentsReceiptsAndStopFailure(t *testing.T) {
	for _, failStop := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "receipt_failure"}[failStop], func(t *testing.T) {
			d, b, c, k, _, _ := lifecycleFixture(t)
			if e := d.start(b, c, k, true); e != nil {
				t.Fatal(e)
			}
			s := unitControlServer()
			s.registration.Config = c
			s.state = d.state
			starts := 0
			s.start = func(ctx context.Context, allow bool) error {
				starts++
				return d.withStartup(ctx, s).start(b, c, k, allow)
			}
			s.stop = func(ctx context.Context) error {
				if failStop {
					receipt := filepath.Join(filepath.Dir(d.root), "service-diagnostic.json")
					if e := os.Remove(receipt); e != nil {
						t.Fatal(e)
					}
					if e := os.Mkdir(receipt, 0700); e != nil {
						t.Fatal(e)
					}
				}
				return d.withStartup(ctx, s).stop()
			}
			identity, _ := controlHelperConfigIdentity(c)
			id := strings.Repeat("c", 32)
			result, _ := s.executeStartup(controlHelperWireRequest{"reload", true}, id, identity, "MANUAL_RELOAD")
			response := s.startupReadCache(st.ReadRequest{TimelineSchema: 1, Action: "startup.read", OperationID: &id})
			if e := st.Validate(response); e != nil {
				t.Fatal(e)
			}
			if failStop {
				if starts != 0 || result.OK || result.Code != "STOP_FAILED" || response.Trace.ReceiptResult != "FAILED" {
					t.Fatal("reload proceeded after STOP receipt failed", starts, result, response.Trace.ReceiptResult)
				}
				return
			}
			if !result.OK || starts != 1 || response.Trace.ReceiptResult != "WRITTEN" {
				t.Fatal("reload result", result, starts)
			}
			segments := map[string]int{}
			for _, event := range response.Trace.Streams[0].Events {
				if event.Stage == "RECEIPT_WRITE" && event.State == "END" {
					segments[event.Segment]++
				}
			}
			if segments["STOP"] != 1 || segments["START"] != 1 {
				t.Fatal("reload receipts lost", segments)
			}
		})
	}
}
func TestStartupFinishRejectsLateCoreAndIDMismatch(t *testing.T) {
	s := unitControlServer()
	id := strings.Repeat("d", 32)
	identity := strings.Repeat("e", 64)
	o := s.startupBegin(id, "start", identity, "MANUAL_START")
	core, _ := st.NewRecorder("CORE", startupProvenance(""))
	snap := st.CoreSnapshot{Stream: core.Snapshot(), StartupResult: "IN_PROGRESS"}
	if code := o.acceptCore(snap); code != "OK" {
		t.Fatal(code)
	}
	s.startupFinish(o, controlHelperResponse{OK: true})
	if code := o.acceptCore(snap); code != "OPERATION_MISMATCH" {
		t.Fatal("accepted late push", code)
	}
	other := strings.Repeat("f", 32)
	r := s.startupReadCache(st.ReadRequest{TimelineSchema: 1, Action: "startup.read", OperationID: &other})
	if r.Code != "OPERATION_MISMATCH" || r.Trace != nil {
		t.Fatal("read leaked another operation")
	}
}

func TestStartupIdentityUnavailableRunsBusinessOnce(t *testing.T) {
	s := unitControlServer()
	s.startupOnce.Do(func() {}) // deterministic failed epoch mint, no ID fallback
	starts := 0
	s.start = func(context.Context, bool) error { starts++; return nil }
	r, o := s.executeStartup(controlHelperWireRequest{"start", false}, strings.Repeat("a", 32), strings.Repeat("b", 64), "MANUAL_START")
	if !r.OK || o != nil || starts != 1 {
		t.Fatal("diagnostic identity failure changed/repeated business", r, o, starts)
	}
}
