package main

import (
	"strings"
	"testing"
)

func TestLiveProtocolStrict(t *testing.T) {
	valid := `{"action":"switch","generation":"0123456789abcdef0123456789abcdef","revision":0,"node":"b"}`
	if _, e := readLiveRequest(strings.NewReader(valid)); e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{
		strings.Replace(valid, `"action":"switch"`, `"action":"switch","Action":"read"`, 1),
		strings.Replace(valid, `"action":"switch"`, `"action":"switch","action":"read"`, 1),
		strings.Replace(valid, `0123456789abcdef0123456789abcdef`, `x`, 1),
		strings.Replace(valid, `"node":"b"`, `"node":""`, 1),
		valid + `{}`, strings.Repeat(" ", 4097) + valid,
		`{"action":"read","generation":"x","revision":1,"node":"b"}`,
	} {
		if _, e := readLiveRequest(strings.NewReader(raw)); e == nil {
			t.Fatalf("accepted invalid request %q", raw)
		}
	}
}
func TestLiveReconcileLostACK(t *testing.T) {
	before := liveResponse{Code: "READY", Generation: "0123456789abcdef0123456789abcdef", Revision: 4, Node: "a", PID: 7}
	after := before
	after.Revision++
	after.Node = "b"
	if !liveAppliedReadback(before, after, "b") {
		t.Fatal("lost ACK not reconciled")
	}
	for _, mutate := range []func(*liveResponse){func(r *liveResponse) { r.Generation = "other" }, func(r *liveResponse) { r.PID++ }, func(r *liveResponse) { r.Revision++ }, func(r *liveResponse) { r.Node = "a" }, func(r *liveResponse) { r.Code = "NOT_READY" }} {
		bad := after
		mutate(&bad)
		if liveAppliedReadback(before, bad, "b") {
			t.Fatal("invalid reconciliation")
		}
	}
	if !liveAppliedReadback(after, after, "b") {
		t.Fatal("same selection cannot reconcile")
	}
}
