package startuptimeline

import (
	"fmt"
	"strings"
	"testing"
)

func ptr(s string) *string { return &s }
func maxWidthStream(role, stage string, head, tail int) ProcessStream {
	const u = "18446744073709551615"
	const w = "9999-12-31T23:59:59.999999999Z"
	p := Provenance{Version: ptr(strings.Repeat("v", 128)), GitRevision: ptr(strings.Repeat("f", 40)), Dirty: new(bool), SHA256: ptr(strings.Repeat("f", 64)), SHAKind: "FILE_BYTES", ExecutionMapping: "NOT_ATTESTED"}
	s := ProcessStream{Role: role, ClockID: strings.Repeat("f", 32), OriginAt: w, ElapsedNS: u, Provenance: p, Current: &CurrentPhase{stage, "PREFLIGHT", u, w, u}, Events: []Event{}, GeneratedEvents: u, DroppedEvents: fmt.Sprint(^uint64(0) - uint64(head+tail)), FirstMissingSeq: ptr(fmt.Sprint(head + 1)), RetainedRanges: []SeqRange{{"1", fmt.Sprint(head)}}, Gap: true}
	if tail > 0 {
		s.RetainedRanges = append(s.RetainedRanges, SeqRange{fmt.Sprint(^uint64(0) - uint64(tail) + 1), u})
	}
	for i := 0; i < head+tail; i++ {
		seq := fmt.Sprint(i + 1)
		if i >= head {
			seq = fmt.Sprint(^uint64(0) - uint64(tail) + uint64(i-head) + 1)
		}
		e := Event{Seq: seq, SpanID: ptr(u), Segment: "PREFLIGHT", Stage: stage, State: "OBSERVATION", Code: "STATE_UNAVAILABLE", At: w, ElapsedNS: u, Round: ptr("16"), Ordinal: ptr(u), RuleCount: ptr(u), CompletedCount: ptr(u), Job: "NOT_OBSERVED", Tun: "NOT_OBSERVED"}
		if i == 0 {
			e.State = "BEGIN"
			e.Code = "NONE"
		}
		if i >= head {
			e.State = "END"
			e.DurationNS = ptr(u)
		}
		s.Events = append(s.Events, e)
	}
	return s
}
func TestMaximumValidFrames(t *testing.T) {
	const w = "9999-12-31T23:59:59.999999999Z"
	const u = "18446744073709551615"
	id := strings.Repeat("f", 32)
	sha := strings.Repeat("f", 64)
	// Longest enum names per role; bool false is one byte wider than true.
	streams := []ProcessStream{maxWidthStream("HELPER", "HELPER_PREFLIGHT_ENGINE_CHECK", 768, 256), maxWidthStream("CORE", "CORE_RECORDS_SHUTDOWN", 64, 0), maxWidthStream("WEB", "WEB_VERIFY_STATE", 32, 0)}
	d := &Diagnostics{1, "RELOAD", "FAILED", "SERVER_ROUTE", "SERVER_ROUTE_NOT_PHYSICAL", "NOT_ATTEMPTED", "NOT_ATTEMPTED", "NOT_ATTEMPTED", "NOT_ATTEMPTED", "NOT_OBSERVED", "NOT_OBSERVED"}
	tr := Trace{Authority: Authority, OperationID: id, HelperEpoch: &id, ConfigIdentity: &sha, Operation: "RELOAD", Source: "SAVE_SELECTION", StartedAt: w, FinishedAt: ptr(w), State: "FINISHED", LifecycleResult: "NOT_ATTEMPTED", HelperReturn: "NOT_ATTEMPTED", WebReturn: "NOT_ATTEMPTED", ReceiptResult: "NOT_ATTEMPTED", Diagnostics: d, Streams: streams, CoreObservation: CoreObservation{Availability: "STALE", CapturedAt: ptr(w), HelperReceiveElapsedNS: ptr(u), AgeNS: ptr(u), ClockID: &id, Phase: &CurrentPhase{"CORE_RECORDS_SHUTDOWN", "PREFLIGHT", u, w, u}, Gap: false}, Gap: true}
	// Allow tied longest values chosen by the independent Python enumerator.
	b, e := Encode(ReadResponse{1, "OK", &id, &sha, &id, &tr})
	if e != nil {
		t.Fatal(e)
	}
	if len(b) != 475796 || len(b) > ReadBytes {
		t.Fatalf("max read budget %d", len(b))
	}
	var out ReadResponse
	if Decode(strings.NewReader(string(b)), &out) != nil {
		t.Fatal("maximum legal read rejected")
	}
	push := PushRequest{1, "startup.push", id, id, CoreSnapshot{streams[1], "IN_PROGRESS", false}}
	b, e = Encode(push)
	if e != nil {
		t.Fatal(e)
	}
	if len(b) != 27118 || len(b) > PushBytes {
		t.Fatalf("max push budget %d", len(b))
	}
	var pout PushRequest
	if Decode(strings.NewReader(string(b)), &pout) != nil {
		t.Fatal("maximum legal push rejected")
	}
	t.Logf("max read <=475796 bytes; push=%d bytes including newline", len(b))
}
