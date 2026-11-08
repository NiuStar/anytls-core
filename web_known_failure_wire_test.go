package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
)

// Authenticated HTTP and strict private Unix exchange; only lifecycle and peer
// UID are fixtures. The verbose marker exports non-secret response bytes only.
func TestWebKnownFailureWire(t *testing.T) {
	w, password := webFixture(t)
	cookie, csrf := webLogin(t, w, password)
	calls, _ := webStartupRouteIPC(t, w, "start", false)
	mutations := 0
	w.startupControlRequest = func(ctx context.Context, action string, allow bool, id string) (st.MutationResponse, error) {
		return startupControlWithRequest(ctx, action, allow, id, func(ctx context.Context, q, dst any, bound time.Duration) error {
			request, ok := q.(st.MutationRequest)
			if !ok || request.Action != "start" || !request.AllowInsecure || request.OperationID != id {
				t.Fatal("unexpected mutation")
			}
			mutations++
			identity, err := controlHelperConfigIdentity(w.configPath)
			if err != nil {
				t.Fatal(err)
			}
			epoch := strings.Repeat("b", 32)
			d := &st.Diagnostics{Schema: 1, Operation: "START", Outcome: "FAILED", Stage: "PROXY", Reason: "SYSTEM_PROXY_ACTIVE", Rollback: "NOT_ATTEMPTED", Restoration: "NOT_ATTEMPTED", Cleanup: "VERIFIED", Receipt: "WRITTEN", Job: "UNLOADED", Tun: "NOT_OBSERVED"}
			raw, err := st.Encode(st.MutationResponse{TimelineSchema: 1, Code: "START_FAILED", OK: false, HelperEpoch: &epoch, OperationID: &id, TimelineAvailability: "AVAILABLE", ConfigIdentity: identity, Diagnostics: d})
			if err != nil {
				t.Fatal(err)
			}
			return startupUnknownExchange(t, ctx, q, dst, raw, bound)
		})
	}
	out := webRequest(w, "POST", "/api/v1/service/start", `{"confirm_insecure":true}`, cookie, csrf)
	var body struct {
		Error       string                 `json:"error"`
		Diagnostics *startDiagnostics      `json:"diagnostics"`
		Reference   *st.OperationReference `json:"startup_operation"`
	}
	if err := json.Unmarshal(out.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if out.Code != 503 || body.Error != "START_FAILED" || body.Diagnostics == nil || !body.Diagnostics.valid(false) || body.Diagnostics.Reason != "SYSTEM_PROXY_ACTIVE" || body.Diagnostics.Cleanup != "VERIFIED" || body.Diagnostics.Job != "UNLOADED" || body.Reference == nil || body.Reference.Availability != "AVAILABLE" || body.Reference.OperationID == nil || *body.Reference.OperationID != w.startupLatest.id || w.startupLatest.result != "FAILED" || mutations != 1 || strings.Join(*calls, ",") != "status,startup.read" {
		t.Fatalf("unexpected wire: HTTP=%d body=%s mutations=%d calls=%v", out.Code, out.Body.String(), mutations, *calls)
	}
	t.Log("KNOWN_FAILURE_WIRE_BASE64=" + base64.StdEncoding.EncodeToString(out.Body.Bytes()))
}
