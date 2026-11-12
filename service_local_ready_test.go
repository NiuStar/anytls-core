package main

import (
	"bytes"
	"context"
	"encoding/json"
	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
	"testing"
	"time"
)

// Actual lifecycle entry, real private staging; OS tools/network are injected.
// The old implementation blocks at the held WAN seam, not at compilation.
func TestStartLocalReadyDoesNotWaitForInternet(t *testing.T) {
	d, b, c, k, _, _ := lifecycleFixture(t)
	tool := d.tool
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	defer close(release)
	d.tool = func(ctx context.Context, n string, a ...string) (string, error) {
		if n == "/usr/bin/curl" {
			entered <- struct{}{}
			<-release
			return "", context.DeadlineExceeded
		}
		return tool(ctx, n, a...)
	}
	done := make(chan error, 1)
	go func() { done <- d.start(b, c, k, true) }()
	select {
	case <-entered:
		t.Fatal("startup reached blocking external HTTPS seam")
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("local readiness did not finish")
	}
	v, _ := readDiagnostic(t, d.root)
	if v["readiness"] != "LOCAL_READY" || v["https"] != "NOT_EXECUTED" || v["internet_verification"] != "NOT_RUN" || v["schema_version"] != float64(3) {
		t.Fatalf("false internet success: %v", v)
	}
	if d.receipt != nil {
		t.Fatal("invocation state escaped value receiver")
	}
}

func TestLocalReadyProducerWire(t *testing.T) {
	d, b, c, k, _, _ := lifecycleFixture(t)
	s := unitControlServer()
	s.state = d.state
	s.start = func(ctx context.Context, allow bool) error { return d.withStartup(ctx, s).start(b, c, k, allow) }
	reply := s.executeContext(context.Background(), controlHelperWireRequest{"start", true})
	if !reply.OK || reply.Diagnostics == nil || reply.Diagnostics.Stage != "LOCAL_READY" || reply.Diagnostics.Reason != "INTERNET_UNVERIFIED" || reply.Diagnostics.Receipt != "WRITTEN" {
		t.Fatalf("lost actual producer tuple: %+v", reply)
	}
	raw, err := json.Marshal(reply)
	var legacy controlHelperResponse
	if err != nil || controlHelperReadResponse(bytes.NewReader(raw), &legacy) != nil || legacy.Diagnostics.Stage != "LOCAL_READY" {
		t.Fatal("helper wire lost local readiness")
	}
	modern := st.MutationResponse{TimelineSchema: 1, OK: true, TimelineAvailability: "UNAVAILABLE", ConfigIdentity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Loaded: true, Running: true, Diagnostics: startupDiagnostics(reply.Diagnostics)}
	raw, err = st.Encode(modern)
	var round st.MutationResponse
	if err != nil || st.Decode(bytes.NewReader(raw), &round) != nil || round.Diagnostics.Stage != "LOCAL_READY" {
		t.Fatal("modern wire lost local readiness", err)
	}
	w, password := webFixture(t)
	cookie, csrf := webLogin(t, w, password)
	webStartupRouteIPC(t, w, "start", false)
	w.startupControlRequest = func(ctx context.Context, action string, allow bool, id string) (st.MutationResponse, error) {
		result, err := modern, error(nil)
		w.state = func() (bool, bool, error) { return true, true, nil }
		epoch := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		result.HelperEpoch = &epoch
		result.TimelineAvailability = "AVAILABLE"
		result.OperationID = &id
		identity, e := controlHelperConfigIdentity(w.configPath)
		if e != nil {
			return result, e
		}
		result.ConfigIdentity = identity
		return result, err
	}
	out := webRequest(w, "POST", "/api/v1/service/start", `{"confirm_insecure":true}`, cookie, csrf)
	var body map[string]any
	if json.Unmarshal(out.Body.Bytes(), &body) != nil || out.Code != 200 {
		t.Fatalf("HTTP local-ready rejected: %d %s", out.Code, out.Body.String())
	}
	diag, ok := body["diagnostics"].(map[string]any)
	if !ok || diag["stage"] != "LOCAL_READY" || diag["reason"] != "INTERNET_UNVERIFIED" {
		t.Fatalf("HTTP lost internet-unverified: %s", out.Body.String())
	}
}

func TestLocalReadyDiagnosticTuple(t *testing.T) {
	d := newStartDiagnostics("START")
	d.Stage, d.Reason, d.Job, d.Tun = "LOCAL_READY", "INTERNET_UNVERIFIED", "RUNNING", "TUN"
	d.Receipt = "WRITTEN"
	if !d.valid(true) {
		t.Fatal("local-ready success rejected")
	}
	for _, change := range []func(*startDiagnostics){
		func(d *startDiagnostics) { d.Operation = "STOP" },
		func(d *startDiagnostics) { d.Reason = "NONE" },
		func(d *startDiagnostics) { d.Job = "UNKNOWN" },
		func(d *startDiagnostics) { d.Tun = "NOT_TUN" },
		func(d *startDiagnostics) { d.Outcome = "FAILED" },
		func(d *startDiagnostics) { d.Receipt = "FAILED" },
	} {
		copy := *d
		change(&copy)
		if copy.valid(true) || copy.valid(false) {
			t.Fatalf("poisoned local readiness accepted: %+v", copy)
		}
	}
	legacy := newStartDiagnostics("START")
	if !legacy.valid(true) {
		t.Fatal("legacy strict success no longer readable")
	}
}
