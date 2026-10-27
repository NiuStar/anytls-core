package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
)

func TestRecoveryWarningDTO(t *testing.T) {
	for _, operation := range []string{"STOP", "START", "RELOAD"} {
		for _, recovery := range []string{"FAILED", "UNKNOWN"} {
			t.Run(operation+"/"+recovery, func(t *testing.T) {
				d := newStartDiagnostics(operation)
				d.Restoration, d.Cleanup, d.Receipt = recovery, "VERIFIED", "WRITTEN"
				if operation == "STOP" { d.Job = "UNLOADED" } else { d.Job, d.Tun = "RUNNING", "TUN" }
				if !d.valid(true) { t.Fatal("legal success warning rejected") }
				raw, err := json.Marshal(controlHelperResponse{OK: true, Diagnostics: d})
				var legacy controlHelperResponse
				if err != nil || controlHelperReadResponse(bytes.NewReader(raw), &legacy) != nil || legacy.Diagnostics == nil || !legacy.Diagnostics.valid(true) { t.Fatal("legacy DTO rejected", err) }
				modern := st.MutationResponse{TimelineSchema: 1, OK: true, TimelineAvailability: "UNAVAILABLE", ConfigIdentity: strings.Repeat("a", 64), Loaded: operation != "STOP", Running: operation != "STOP", Diagnostics: &st.Diagnostics{Schema: d.Schema, Operation: d.Operation, Outcome: d.Outcome, Stage: d.Stage, Reason: d.Reason, Rollback: d.Rollback, Restoration: d.Restoration, Cleanup: d.Cleanup, Receipt: d.Receipt, Job: d.Job, Tun: d.Tun}}
				encoded, err := st.Encode(modern)
				var decoded st.MutationResponse
				if err != nil || st.Decode(bytes.NewReader(encoded), &decoded) != nil { t.Fatal("timeline DTO rejected", err) }
				modern.Diagnostics.Outcome = "FAILED"
				if st.Validate(modern) == nil { t.Fatal("failed diagnostics accepted on successful mutation") }
			})
		}
	}
}

// Success diagnostics must survive the modern result path too, not only legacy.
func TestRecoveryWarningModernHTTP(t *testing.T) {
	for _, action := range []string{"stop", "start", "reload"} {
		t.Run(action, func(t *testing.T) {
			w, password := webFixture(t)
			cookie, csrf := webLogin(t, w, password)
			_, _ = webStartupRouteIPC(t, w, action, false)
			original := w.startupControlRequest
			w.startupControlRequest = func(ctx context.Context, verb string, allow bool, id string) (st.MutationResponse, error) {
				r, err := original(ctx, verb, allow, id)
				r.Diagnostics = &st.Diagnostics{Schema: 1, Operation: strings.ToUpper(action), Outcome: "SUCCEEDED", Stage: "NONE", Reason: "NONE", Rollback: "NOT_ATTEMPTED", Restoration: "UNKNOWN", Cleanup: "VERIFIED", Receipt: "WRITTEN", Job: "UNLOADED", Tun: "NOT_OBSERVED"}
				raw, encodeErr := st.Encode(r)
				if err != nil || encodeErr != nil { t.Fatal(err, encodeErr) }
				var decoded st.MutationResponse
				if err := st.Decode(bytes.NewReader(raw), &decoded); err != nil { t.Fatal(err) }
				return decoded, nil
			}
			w.state = func() (bool, bool, error) { return action != "stop", action != "stop", nil }
			input := `{"confirm_insecure":true}`
			if action == "stop" { input = `{}` }
			out := webRequest(w, "POST", "/api/v1/service/"+action, input, cookie, csrf)
			var body struct { Diagnostics *st.Diagnostics `json:"diagnostics"` }
			if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &body) != nil || body.Diagnostics == nil || body.Diagnostics.Restoration != "UNKNOWN" { t.Fatal(out.Code, out.Body.String()) }
		})
	}
}
