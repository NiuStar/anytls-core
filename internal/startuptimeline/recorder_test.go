package startuptimeline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func unknownProvenance() Provenance {
	return Provenance{SHAKind: "UNKNOWN", ExecutionMapping: "NOT_ATTESTED"}
}
func testRecorder(t *testing.T, role string) *Recorder {
	t.Helper()
	r, e := NewRecorder(role, unknownProvenance())
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestRecorderStack(t *testing.T) {
	r := testRecorder(t, "HELPER")
	a := r.Begin("START", "READINESS_ROUND", Fields{})
	b := r.Begin("START", "READINESS_JOB", Fields{})
	if s := r.Snapshot(); s.Current == nil || s.Current.Stage != "READINESS_JOB" {
		t.Fatal("deepest current missing")
	}
	r.End(b, "OK", Fields{})
	if s := r.Snapshot(); s.Current == nil || s.Current.Stage != "READINESS_ROUND" {
		t.Fatal("parent not restored")
	}
	r.Observe("START", "CORE_SNAPSHOT_CAPTURE", "UNAVAILABLE", Fields{})
	r.End(a, "FAILED", Fields{})
	r.Observe("FINALIZE", "HELPER_FINISH", "FAILED", Fields{})
	r.Finish("FAILED")
	s := r.Snapshot()
	if s.Current != nil || s.Terminal == nil || s.Terminal.Result != "FAILED" {
		t.Fatal("terminal missing")
	}
	if s.Events[len(s.Events)-1].SpanID != nil {
		t.Fatal("unscoped observation not null")
	}
	if Validate(s) != nil {
		t.Fatalf("invalid own snapshot: %+v", s)
	}
	frozen := s
	r.Observe("START", "HELPER_ACCEPT", "OK", Fields{})
	r.Finish("SUCCEEDED")
	if !reflect.DeepEqual(frozen, r.Snapshot()) {
		t.Fatal("finished recorder mutated")
	}
}
func TestRecorderRetention(t *testing.T) {
	for _, role := range []string{"HELPER", "CORE", "WEB"} {
		t.Run(role, func(t *testing.T) {
			r := testRecorder(t, role)
			stage := map[string]string{"HELPER": "HELPER_ACCEPT", "CORE": "CORE_ENTER", "WEB": "WEB_ACCEPT"}[role]
			for i := 0; i < 1300; i++ {
				r.Observe("START", stage, "OK", Fields{})
			}
			s := r.Snapshot()
			h, tail := capacity(role)
			if len(s.Events) != h+tail || s.GeneratedEvents != "1300" || s.DroppedEvents != fmt.Sprint(1300-h-tail) || !s.Gap || s.FirstMissingSeq == nil || *s.FirstMissingSeq != fmt.Sprint(h+1) {
				t.Fatalf("retention counts wrong: %d %+v", len(s.Events), s.RetainedRanges)
			}
			if s.Events[0].Seq != "1" || s.Events[h-1].Seq != fmt.Sprint(h) {
				t.Fatal("head changed")
			}
			if tail > 0 && s.Events[len(s.Events)-1].Seq != "1300" {
				t.Fatal("tail missing")
			}
			if Validate(s) != nil {
				t.Fatal("retained ranges rejected")
			}
			// Returned DTO owns all pointers and backing arrays, not recorder state.
			s.Events[0].Code = "PRIVATE"
			s.RetainedRanges[0].First = "9"
			if r.Snapshot().Events[0].Code != "OK" {
				t.Fatal("snapshot aliases recorder")
			}
		})
	}
}
func TestRecorderClockAndNonblocking(t *testing.T) {
	origin := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ticks := 0
	r, e := newRecorder("HELPER", unknownProvenance(), origin, bytes.NewReader(make([]byte, 16)), func() (time.Time, time.Duration) {
		ticks++
		return origin.Add(-time.Duration(ticks) * time.Hour), time.Duration(ticks) * time.Millisecond
	})
	if e != nil {
		t.Fatal(e)
	}
	a := r.Begin("START", "READINESS_ROUND", Fields{})
	r.End(a, "OK", Fields{})
	s := r.Snapshot()
	if *s.Events[1].DurationNS != "1000000" || s.Events[1].At >= s.Events[0].At || Validate(s) != nil {
		t.Fatal("monotonic/wall domains wrong")
	}
	done := make(chan struct{})
	go func() {
		for i := 0; i < 10000; i++ {
			r.Observe("START", "HELPER_ACCEPT", "OK", Fields{})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("emit waits for unread notification")
	}
	select {
	case <-r.Notifications():
	default:
		t.Fatal("no notification")
	}
}
func TestRecorderInvalidAndContext(t *testing.T) {
	r := testRecorder(t, "CORE")
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), "caller", "kept"))
	ctx = WithRecorder(ctx, r)
	cancel()
	if FromContext(ctx) != r || ctx.Err() != context.Canceled || ctx.Value("caller") != "kept" {
		t.Fatal("context ownership changed")
	}
	a := r.Begin("START", "CORE_COMPILE", Fields{})
	b := r.Begin("START", "CORE_COMPILE_MAP", Fields{})
	r.End(a, "OK", Fields{})
	if s := r.Snapshot(); !s.Gap || s.Current == nil || s.Current.SpanID != fmt.Sprint(b) {
		t.Fatal("mismatched END corrupted stack")
	}
	r.End(b, "OK", Fields{})
	r.End(a, "FAILED", Fields{})
	for i := 0; i < StackDepth+1; i++ {
		r.Begin("START", "CORE_COMPILE", Fields{})
	}
	if !r.Snapshot().Gap {
		t.Fatal("overflow not diagnosed")
	}
	if _, err := newID(io.LimitReader(strings.NewReader("short"), 4)); !errors.Is(err, Unavailable) {
		t.Fatal("rand failure not typed")
	}
	if _, err := NewRecorder("PRIVATE", unknownProvenance()); !errors.Is(err, Invalid) {
		t.Fatal("invalid role accepted")
	}
	for _, err := range []error{context.Canceled, fmt.Errorf("wrapped: %w", context.DeadlineExceeded)} {
		if ResultCode(err) != "CANCELLED" {
			t.Fatal("typed cancellation lost")
		}
	}
	if ResultCode(errors.New("context canceled PRIVATE")) != "FAILED" {
		t.Fatal("classified raw text")
	}
	var disabled *Recorder
	disabled.Observe("START", "CORE_ENTER", "OK", Fields{})
	disabled.End(1, "FAILED", Fields{})
	disabled.Finish("FAILED")
}
func TestReceiptAggregate(t *testing.T) {
	for _, a := range []string{"NOT_ATTEMPTED", "WRITTEN", "UNKNOWN", "FAILED"} {
		for _, b := range []string{"NOT_ATTEMPTED", "WRITTEN", "UNKNOWN", "FAILED"} {
			want := a
			rank := map[string]int{"NOT_ATTEMPTED": 0, "WRITTEN": 1, "UNKNOWN": 2, "FAILED": 3}
			if rank[b] > rank[a] {
				want = b
			}
			if AggregateReceipt(a, b) != want {
				t.Fatalf("receipt %s+%s", a, b)
			}
		}
	}
}
func TestConcurrentEmitSnapshot(t *testing.T) {
	r := testRecorder(t, "WEB")
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				r.Observe("START", "WEB_ACCEPT", "OK", Fields{})
				if Validate(r.Snapshot()) != nil {
					t.Error("concurrent invalid")
				}
			}
		}()
	}
	wg.Wait()
	if r.Snapshot().GeneratedEvents != "400" {
		t.Fatal("sequence lost")
	}
}
