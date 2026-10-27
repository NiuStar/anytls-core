package engine

import (
	"context"
	"errors"
	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestStartupActualRunOpenSinkBlockingPhase(t *testing.T) {
	r, e := st.NewRecorder("CORE", st.Provenance{SHAKind: "UNKNOWN", ExecutionMapping: "NOT_ATTESTED"})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(st.WithRecorder(context.Background(), r))
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- RunWithRecords(ctx, loopbackConfig(), &RecordsInput{OpenSink: func() cr.Sink { close(entered); <-release; return nil }})
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("real New did not reach OpenSink")
	}
	snapshot := r.Snapshot()
	if snapshot.Current == nil || snapshot.Current.Stage != "CORE_OPEN_SINK" {
		close(release)
		cancel()
		<-done
		t.Fatalf("blocked real OpenSink must remain visible, current=%v", snapshot.Current)
	}
	cancel()
	close(release)
	select {
	case e = <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run failed to close")
	}
	snapshot = r.Snapshot()
	seen := map[string]int{}
	for _, event := range snapshot.Events {
		if event.State == "BEGIN" {
			seen[event.Stage]++
		}
	}
	for _, stage := range []string{"CORE_DECODE", "CORE_PIN_CA", "CORE_BOX_NEW", "CORE_OPEN_SINK", "CORE_CLOSE"} {
		if seen[stage] != 1 {
			t.Fatalf("%s count=%d", stage, seen[stage])
		}
	}
	if seen["CORE_START"] != 0 {
		t.Fatal("cancelled OpenSink must not Start")
	}
	if e = st.Validate(snapshot); e != nil {
		t.Fatal(e)
	}
}

func TestStartupActualLoopbackStartAndClose(t *testing.T) {
	port := freeLoopbackPort(t)
	r, _ := st.NewRecorder("CORE", st.Provenance{SHAKind: "UNKNOWN", ExecutionMapping: "NOT_ATTESTED"})
	ctx, cancel := context.WithCancel(st.WithRecorder(context.Background(), r))
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RunWithRecords(ctx, loopbackConfig(port), nil) }()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ready := false
	for !ready {
		select {
		case <-r.Notifications():
			for _, event := range r.Snapshot().Events {
				if event.Stage == "CORE_WAIT" {
					ready = true
				}
			}
		case e := <-done:
			t.Fatal("Run ended before actual Start", e)
		case <-deadline.C:
			t.Fatal("actual Start not observed")
		}
	}
	c, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if e != nil {
		t.Fatal("actual listener not started", e)
	}
	c.Close()
	cancel()
	select {
	case e = <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("actual Close blocked")
	}
	listener, e := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if e != nil {
		t.Fatal("Close did not release listener", e)
	}
	listener.Close()
	snapshot := r.Snapshot()
	if e = st.Validate(snapshot); e != nil {
		t.Fatal(e)
	}
	seen := map[string]int{}
	for _, event := range snapshot.Events {
		if event.State == "END" && event.Code == "OK" {
			seen[event.Stage]++
		}
	}
	for _, stage := range []string{"CORE_DECODE", "CORE_BOX_NEW", "CORE_START", "CORE_CLOSE"} {
		if seen[stage] != 1 {
			t.Fatal("missing actual successful stage", stage, seen)
		}
	}
}
