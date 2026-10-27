package startuptimeline

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestNestedCodec(t *testing.T) {
	r := testRecorder(t, "HELPER")
	a := r.Begin("START", "READINESS_ROUND", Fields{})
	b := r.Begin("START", "READINESS_JOB", Fields{})
	r.End(b, "OK", Fields{})
	r.End(a, "FAILED", Fields{})
	r.Finish("FAILED")
	s := r.Snapshot()
	data, e := Encode(s)
	if e != nil {
		t.Fatal(e)
	}
	var out ProcessStream
	if Decode(strings.NewReader(string(data)), &out) != nil {
		t.Fatal("valid round trip rejected")
	}
	cases := []string{
		strings.Replace(string(data), `"seq":"1"`, `"seq":"1","seq":"1"`, 1),
		strings.Replace(string(data), `"version":null`, `"version":null,"version":"PRIVATE"`, 1),
		strings.Replace(string(data), `"clock_id":`, `"unknown":false,"clock_id":`, 1),
		strings.Replace(string(data), `"generated_events":"4"`, `"generated_events":"04"`, 1),
		strings.Replace(string(data), `"role":"HELPER"`, `"role":"CORE"`, 1),
		strings.Replace(string(data), `"generated_events":"4"`, `"generated_events":"5"`, 1),
		strings.Replace(string(data), `"seq":"1"`, `"seq":"2"`, 1),
		strings.Replace(string(data), `"span_id":"2"`, `"span_id":null`, 1),
		strings.Replace(string(data), `"current":null`, `"current":{"stage":"READINESS_ROUND","segment":"START","span_id":"1","began_at":"2026-01-01T00:00:00Z","began_elapsed_ns":"0"}`, 1),
	}
	for i, bad := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			var dst ProcessStream
			if Decode(strings.NewReader(bad), &dst) == nil {
				t.Fatal("invalid nested DTO accepted")
			}
		})
	}
	// Explicit nullable unknown provenance is legal; missing/null required fields are not.
	var tree map[string]any
	json.Unmarshal(data, &tree)
	tree["events"].([]any)[2].(map[string]any)["duration_ns"] = "0"
	bad, _ := json.Marshal(tree)
	if Decode(strings.NewReader(string(bad)), &out) == nil {
		t.Fatal("END duration inconsistency accepted")
	}
}
func TestExactFrameBudget(t *testing.T) {
	q := ReadRequest{1, "startup.read", nil}
	b, e := Encode(q)
	if e != nil {
		t.Fatal(e)
	}
	for _, n := range []int{LegacyBytes, LegacyBytes + 1} {
		raw := string(b) + strings.Repeat(" ", n-len(b))
		var out ReadRequest
		err := Decode(strings.NewReader(raw), &out)
		if (err == nil) != (n == LegacyBytes) {
			t.Fatalf("exact request boundary %d %v", n, err)
		}
	}
	resp := ReadResponse{TimelineSchema: 1, Code: "NO_OPERATION"}
	b, e = Encode(resp)
	if e != nil {
		t.Fatal(e)
	}
	for _, n := range []int{ReadBytes, ReadBytes + 1} {
		raw := string(b) + strings.Repeat(" ", n-len(b))
		var out ReadResponse
		err := Decode(strings.NewReader(raw), &out)
		if (err == nil) != (n == ReadBytes) {
			t.Fatalf("exact response boundary %d %v", n, err)
		}
	}
	// Shape-bounded input: no unbounded marshal of attacker-sized event arrays.
	s := testRecorder(t, "HELPER").Snapshot()
	s.Events = make([]Event, 1025)
	if _, err := Encode(s); err == nil {
		t.Fatal("oversized DTO accepted")
	}
}
func TestMutationContracts(t *testing.T) {
	id := strings.Repeat("a", 32)
	sha := strings.Repeat("a", 64)
	cases := []any{MutationRequest{1, "start", id, false}, PushAck{1, "OK", id}, OperationReference{1, nil, "UNAVAILABLE"}, MutationResponse{TimelineSchema: 1, Code: "", OK: true, TimelineAvailability: "UNAVAILABLE", ConfigIdentity: sha}, ReadResponse{TimelineSchema: 1, Code: "UNAVAILABLE"}}
	for _, v := range cases {
		if _, e := Encode(v); e != nil {
			t.Fatalf("valid shape %T %v", v, e)
		}
	}
	q := MutationRequest{1, "stop", id, true}
	if Validate(q) == nil {
		t.Fatal("stop insecure accepted")
	}
	d := Diagnostics{1, "RELOAD", "SUCCEEDED", "DIAGNOSTIC", "RECEIPT_WRITE_FAILED", "NOT_ATTEMPTED", "UNKNOWN", "VERIFIED", "FAILED", "NOT_OBSERVED", "NOT_OBSERVED"}
	if !validDiagnostics(&d, false) || validDiagnostics(&d, true) {
		t.Fatal("receipt-only diagnostic changed")
	}
}
