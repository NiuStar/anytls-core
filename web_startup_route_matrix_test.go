package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
)

// Real private Unix sockets and strict production exchange/DTOs; only peer UID
// and the helper's lifecycle response are simulated. Never uses installed IPC,
// launchd, root wrappers, TUN, or external networking.
func webStartupRouteIPC(t *testing.T, w *webConsole, action string, failed bool) (*[]string, *st.MutationResponse) {
	t.Helper()
	calls := []string{}
	var mutation st.MutationResponse
	identity, err := controlHelperConfigIdentity(w.configPath)
	if err != nil {
		t.Fatal(err)
	}
	epoch := strings.Repeat("b", 32)
	w.serviceAction = nil
	exchange := func(ctx context.Context, q, dst any, bound time.Duration) error {
		t.Helper()
		var raw []byte
		var e error
		switch request := q.(type) {
		case st.ReadRequest:
			calls = append(calls, "startup.read")
			raw, e = st.Encode(st.ReadResponse{TimelineSchema: 1, Code: "NO_OPERATION", HelperEpoch: &epoch, ConfigIdentity: &identity, OperationID: request.OperationID})
		case st.MutationRequest:
			calls = append(calls, request.Action)
			if request.Action != action || request.AllowInsecure != (action != "stop") || !webStartupID(request.OperationID) {
				t.Fatalf("unexpected mutation: %+v", request)
			}
			mutation = st.MutationResponse{TimelineSchema: 1, OK: !failed, HelperEpoch: &epoch, OperationID: &request.OperationID, TimelineAvailability: "AVAILABLE", ConfigIdentity: identity, Loaded: action != "stop", Running: action != "stop"}
			if failed {
				mutation.Code = "START_FAILED"
				stage, reason := "HTTPS", "HTTPS_FAILED"
				if action == "stop" {
					mutation.Code, stage, reason = "STOP_FAILED", "STOP", "STOP_FAILED"
				}
				mutation.Diagnostics = &st.Diagnostics{Schema: 1, Operation: strings.ToUpper(action), Outcome: "FAILED", Stage: stage, Reason: reason, Rollback: "NOT_ATTEMPTED", Restoration: "UNKNOWN", Cleanup: "UNKNOWN", Receipt: "WRITTEN", Job: "NOT_OBSERVED", Tun: "NOT_OBSERVED"}
			}
			raw, e = st.Encode(mutation)
		default:
			t.Fatalf("unexpected request %T", q)
		}
		if e != nil {
			t.Fatalf("illegal fixture DTO: %v", e)
		}
		listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(unitControlSocketDir(t), "route.sock"), Net: "unix"})
		if e != nil {
			t.Fatal(e)
		}
		defer listener.Close()
		done := make(chan error, 1)
		go func() {
			c, e := listener.AcceptUnix()
			if e != nil {
				done <- e
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			received, e := io.ReadAll(c)
			expected, encodeErr := st.Encode(q)
			if e == nil && (encodeErr != nil || !bytes.Equal(received, expected)) {
				e = st.Invalid
			}
			if e == nil {
				_, e = c.Write(raw)
			}
			done <- e
		}()
		c, e := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		e = startupExchange(ctx, c, q, dst, bound, func(net.Conn) (uint32, error) { return 0, nil })
		if serverErr := <-done; serverErr != nil {
			t.Fatal(serverErr)
		}
		return e
	}
	w.startupReadRequest = func(ctx context.Context, id *string) (st.ReadResponse, error) {
		var r st.ReadResponse
		e := exchange(ctx, st.ReadRequest{TimelineSchema: 1, Action: "startup.read", OperationID: id}, &r, time.Second)
		return r, e
	}
	w.startupControlRequest = func(ctx context.Context, action string, allow bool, id string) (st.MutationResponse, error) {
		return startupControlWithRequest(ctx, action, allow, id, exchange)
	}
	w.startupLegacyRequest = func(ctx context.Context, action string, allow bool) (controlHelperResponse, error) {
		calls = append(calls, action)
		if action != "status" || allow {
			t.Fatalf("fallback/resend: %s", action)
		}
		s := unitControlServer()
		s.registration.Config = w.configPath
		c, done := unitControlPair(t, s)
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		if e := json.NewEncoder(c).Encode(controlHelperWireRequest{Action: action}); e != nil {
			t.Fatal(e)
		}
		if e := c.CloseWrite(); e != nil {
			t.Fatal(e)
		}
		var r controlHelperResponse
		e := controlHelperReadResponse(c, &r)
		<-done
		return r, e
	}
	return &calls, &mutation
}

func webStartupAssertRouteReference(t *testing.T, w *webConsole, raw []byte, source, action string, mutation *st.MutationResponse) {
	t.Helper()
	var body struct {
		Ref *st.OperationReference `json:"startup_operation"`
	}
	if json.Unmarshal(raw, &body) != nil || body.Ref == nil || st.Validate(*body.Ref) != nil || body.Ref.Availability != "AVAILABLE" || body.Ref.OperationID == nil || mutation.OperationID == nil || *body.Ref.OperationID != *mutation.OperationID {
		t.Fatalf("reference lost: %s", raw)
	}
	op := w.startupLatest
	if op == nil || op.id != *body.Ref.OperationID || op.source != source || op.action != strings.ToUpper(action) || op.finished == nil || op.legacy || op.helperResult == nil || !reflect.DeepEqual(*op.helperResult, *mutation) {
		t.Fatalf("operation/source binding lost: %s", raw)
	}
}

func TestWebStartupAdditionalRealSaveRoutesIPC(t *testing.T) {
	for _, source := range []string{"SAVE_RULE", "PROFILE_SWITCH", "IMPORT_COMMIT", "IMPORT_APPEND"} {
		for _, mode := range []string{"success", "failure", "same", "stopped"} {
			t.Run(source+"/"+mode, func(t *testing.T) {
				w, p := webFixture(t)
				cookie, csrf := webLogin(t, w, p)
				var invoke func() *httptest.ResponseRecorder
				switch source {
				case "SAVE_RULE":
					// The rule editor requires a block sequence, not webFixture's
					// valid-but-uneditable flow rules. Reuse its legal editor fixture.
					if err := os.WriteFile(w.configPath, []byte(singleRuleConfig), 0600); err != nil {
						t.Fatal(err)
					}
					invoke = func() *httptest.ResponseRecorder {
						raw, e := os.ReadFile(w.configPath)
						if e != nil {
							t.Fatal(e)
						}
						return groupETagRequest(w, cookie, csrf, "/api/v1/rules", `{"type":"DOMAIN","value":"route.example","target":"local","no_resolve":false,"position":"before_match","confirm_insecure":true}`, `"`+shaHex(raw)+`"`)
					}
				case "PROFILE_SWITCH":
					out := webRequest(w, "POST", "/api/v1/profiles", `{"name":"saved"}`, cookie, csrf)
					var profile struct {
						ID string `json:"id"`
					}
					if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &profile) != nil || profile.ID == "" {
						t.Fatal(out.Code, out.Body.String())
					}
					raw, e := os.ReadFile(w.configPath)
					if e != nil {
						t.Fatal(e)
					}
					if e = os.WriteFile(w.configPath, append(raw, []byte("# changed current\n")...), 0600); e != nil {
						t.Fatal(e)
					}
					invoke = func() *httptest.ResponseRecorder {
						raw, e := os.ReadFile(w.configPath)
						if e != nil {
							t.Fatal(e)
						}
						return groupETagRequest(w, cookie, csrf, "/api/v1/profiles/switch", `{"id":"`+profile.ID+`","confirm_replace":true,"confirm_insecure":true}`, `"`+shaHex(raw)+`"`)
					}
				default:
					invoke = func() *httptest.ResponseRecorder {
						input := map[string]any{"yaml": webImportYAML}
						confirm := "confirm_replace"
						if source == "IMPORT_APPEND" {
							input["mode"], confirm = "append_nodes", "confirm_append"
						}
						preview := importPreview(t, w, cookie, csrf, input)
						return importRequest(t, w, cookie, csrf, "import/commit", map[string]any{"token": preview["token"], confirm: true, "confirm_insecure": true}, preview["etag"].(string))
					}
				}
				if mode == "same" {
					out := invoke()
					if out.Code != 200 {
						t.Fatal(out.Code, out.Body.String())
					}
				}
				old := w.beginStartup("start", "MANUAL_START")
				before, e := os.ReadFile(w.configPath)
				if e != nil {
					t.Fatal(e)
				}
				calls, mutation := webStartupRouteIPC(t, w, "reload", mode == "failure")
				w.state = func() (bool, bool, error) { return mode != "stopped", mode != "stopped", nil }
				out := invoke()
				var body struct {
					Saved       bool            `json:"saved"`
					Changed     bool            `json:"changed"`
					Applied     bool            `json:"applied"`
					Status      string          `json:"apply_status"`
					Error       string          `json:"apply_error"`
					Diagnostics *st.Diagnostics `json:"diagnostics"`
				}
				if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &body) != nil || !body.Saved || body.Changed != (mode != "same") || body.Applied != (mode == "success") {
					t.Fatal(out.Code, out.Body.String())
				}
				wantStatus := map[string]string{"success": "APPLIED", "failure": "APPLY_FAILED", "same": "NO_CHANGE", "stopped": "SAVED_STOPPED"}[mode]
				if body.Status != wantStatus {
					t.Fatal(out.Body.String())
				}
				after, e := os.ReadFile(w.configPath)
				if e != nil || bytes.Equal(before, after) != (mode == "same") {
					t.Fatal("disk mutation mismatch", e)
				}
				if mode == "same" || mode == "stopped" {
					var fields map[string]json.RawMessage
					if json.Unmarshal(out.Body.Bytes(), &fields) != nil || string(fields["startup_operation"]) != "null" || len(*calls) != 0 || w.startupLatest != old {
						t.Fatal("nonreload replaced operation", out.Body.String(), *calls)
					}
				} else {
					if !reflect.DeepEqual(*calls, []string{"status", "startup.read", "reload"}) {
						t.Fatal("reload/fallback count", *calls)
					}
					webStartupAssertRouteReference(t, w, out.Body.Bytes(), source, "reload", mutation)
					if mode == "failure" && (body.Error != "START_FAILED" || !reflect.DeepEqual(body.Diagnostics, mutation.Diagnostics)) {
						t.Fatal("typed failure/diagnostics lost", out.Body.String())
					}
					trace := webStartupHTTPRequest(w, cookie, "?operation_id="+*mutation.OperationID, nil)
					var result st.ReadResponse
					if trace.Code != 200 || st.Decode(bytes.NewReader(trace.Body.Bytes()), &result) != nil || result.Code != "OK" || result.Trace.Source != source || result.Trace.Operation != "RELOAD" || result.Trace.OperationID != *mutation.OperationID {
						t.Fatal(trace.Code, trace.Body.String())
					}
				}
			})
		}
	}
}

func TestWebStartupManualRealRoutesIPC(t *testing.T) {
	for _, action := range []string{"start", "stop", "reload"} {
		for _, failed := range []bool{false, true} {
			t.Run(action+map[bool]string{false: "/success", true: "/failure"}[failed], func(t *testing.T) {
				w, p := webFixture(t)
				cookie, csrf := webLogin(t, w, p)
				calls, mutation := webStartupRouteIPC(t, w, action, failed)
				w.state = func() (bool, bool, error) { return action != "stop", action != "stop", nil }
				input := `{"confirm_insecure":true}`
				if action == "stop" {
					input = `{}`
				}
				out := webRequest(w, "POST", "/api/v1/service/"+action, input, cookie, csrf)
				wantCode := 200
				if failed {
					wantCode = 503
				}
				if out.Code != wantCode || !reflect.DeepEqual(*calls, []string{"status", "startup.read", action}) {
					t.Fatal(out.Code, out.Body.String(), *calls)
				}
				webStartupAssertRouteReference(t, w, out.Body.Bytes(), "MANUAL_"+strings.ToUpper(action), action, mutation)
				var body struct {
					OK          bool            `json:"ok"`
					Error       string          `json:"error"`
					Diagnostics *st.Diagnostics `json:"diagnostics"`
				}
				if json.Unmarshal(out.Body.Bytes(), &body) != nil || body.OK == failed {
					t.Fatal(out.Body.String())
				}
				if failed && (body.Error != mutation.Code || !reflect.DeepEqual(body.Diagnostics, mutation.Diagnostics)) {
					t.Fatal("manual failure lost", out.Body.String())
				}
				trace := webStartupHTTPRequest(w, cookie, "?operation_id="+*mutation.OperationID, nil)
				var result st.ReadResponse
				if trace.Code != 200 || st.Decode(bytes.NewReader(trace.Body.Bytes()), &result) != nil || result.Code != "OK" || result.Trace.OperationID != *mutation.OperationID || result.Trace.Source != "MANUAL_"+strings.ToUpper(action) || result.Trace.Operation != strings.ToUpper(action) {
					t.Fatal(trace.Code, trace.Body.String())
				}
			})
		}
	}
}
