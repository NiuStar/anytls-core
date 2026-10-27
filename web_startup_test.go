package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
)

func webStartupHTTPRequest(w *webConsole, cookie *http.Cookie, query string, change func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "http://127.0.0.1:18089/api/v1/startup-trace"+query, nil)
	r.Header.Set("X-AnyTLS-Origin", "http://"+r.Host)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if change != nil {
		change(r)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, r)
	return rec
}
func TestWebStartupAuthenticatedReadonlyAndRechecks(t *testing.T) {
	for _, mode := range []string{"positive", "replace", "logout", "config"} {
		t.Run(mode, func(t *testing.T) {
			w, password := webFixture(t)
			cookie, csrf := webLogin(t, w, password)
			op := w.beginStartup("start", "MANUAL_START")
			id := op.id
			identity, _ := controlHelperConfigIdentity(w.configPath)
			calls := 0
			w.state = func() (bool, bool, error) { t.Error("trace read service state"); return false, false, nil }
			w.startupReadRequest = func(ctx context.Context, requested *string) (st.ReadResponse, error) {
				calls++
				if requested == nil || *requested != id {
					t.Error("unbound helper read")
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Error("unbounded trace read")
				}
				switch mode {
				case "replace":
					w.beginStartup("stop", "MANUAL_STOP")
				case "logout":
					webRequest(w, "POST", "/api/v1/logout", `{}`, cookie, csrf)
				case "config":
					old := w.configPath + ".old"
					if err := os.Rename(w.configPath, old); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(old, w.configPath); err != nil {
						t.Fatal(err)
					}
				}
				return st.ReadResponse{TimelineSchema: 1, Code: "NO_OPERATION", ConfigIdentity: &identity, OperationID: &id}, nil
			}
			w.actionMu.Lock()
			rec := webStartupHTTPRequest(w, cookie, "?operation_id="+id, nil)
			w.actionMu.Unlock()
			expected := map[string]int{"positive": 200, "replace": 409, "logout": 401, "config": 503}[mode]
			if rec.Code != expected || calls != 1 {
				t.Fatalf("%s: %d %s calls=%d", mode, rec.Code, rec.Body.String(), calls)
			}
			if mode == "positive" {
				var got st.ReadResponse
				if st.Decode(bytes.NewReader(rec.Body.Bytes()), &got) != nil || got.Code != "OK" || got.Trace.Source != "MANUAL_START" || len(got.Trace.Streams) != 1 || got.Trace.Streams[0].Role != "WEB" {
					t.Fatal(rec.Body.String())
				}
			}
			if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("cache/CORS")
			}
		})
	}
}
func TestWebStartupRejectsBeforeHelper(t *testing.T) {
	w, password := webFixture(t)
	cookie, _ := webLogin(t, w, password)
	op := w.beginStartup("reload", "MANUAL_RELOAD")
	w.startupReadRequest = func(context.Context, *string) (st.ReadResponse, error) {
		t.Error("rejected request contacted helper")
		return st.ReadResponse{}, nil
	}
	for _, tc := range []struct {
		name, query string
		status      int
		change      func(*http.Request)
	}{
		{"no session", "", 401, func(r *http.Request) { r.Header.Del("Cookie") }},
		{"no origin", "", 403, func(r *http.Request) { r.Header.Del("X-AnyTLS-Origin") }},
		{"duplicate origin", "", 403, func(r *http.Request) { r.Header.Add("X-AnyTLS-Origin", "http://"+r.Host) }},
		{"cross site", "", 403, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
		{"missing fetch metadata loopback", "", 403, func(r *http.Request) { r.Header.Del("Sec-Fetch-Site") }},
		{"foreign Origin", "", 403, func(r *http.Request) { r.Header.Set("Origin", "http://evil.test") }},
		{"post", "", 405, func(r *http.Request) { r.Method = "POST"; r.Header.Set("Origin", "http://"+r.Host) }},
		{"unknown", "?path=/secret", 400, nil}, {"duplicate", "?operation_id=" + op.id + "&operation_id=" + op.id, 400, nil},
		{"empty", "?operation_id=", 400, nil}, {"uppercase", "?operation_id=" + strings.Repeat("A", 32), 400, nil},
		{"mismatch", "?operation_id=" + strings.Repeat("f", 32), 409, nil}, {"escape", "?operation_id=%GG", 400, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := webStartupHTTPRequest(w, cookie, tc.query, tc.change)
			if rec.Code != tc.status {
				t.Fatalf("%d %s", rec.Code, rec.Body.String())
			}
		})
	}
}
func TestWebStartupNetworkMissingFetchMetadata(t *testing.T) {
	w, p := webFixture(t)
	cookie, _ := webLogin(t, w, p)
	w.listenHost = "0.0.0.0"
	rec := webStartupHTTPRequest(w, cookie, "", func(r *http.Request) { r.Header.Del("Sec-Fetch-Site") })
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
}
func TestWebStartupControlAtMostOnceAndStrictFallback(t *testing.T) {
	for _, mode := range []string{"success", "failed", "legacy", "timeout", "invalid", "network", "mutate-network", "wrong-id", "random"} {
		t.Run(mode, func(t *testing.T) {
			w, _ := webFixture(t)
			identity, _ := controlHelperConfigIdentity(w.configPath)
			id, epoch := strings.Repeat("a", 32), strings.Repeat("b", 32)
			if mode == "random" {
				id = ""
			}
			statusCalls, legacyCalls, mutations := 0, 0, 0
			legacy := func(_ context.Context, action string, _ bool) (controlHelperResponse, error) {
				if action == "status" {
					statusCalls++
				} else {
					legacyCalls++
				}
				return controlHelperResponse{ConfigIdentity: identity}, nil
			}
			old := errors.New("exact legacy INVALID_REQUEST fixture")
			read := func(context.Context, *string) (st.ReadResponse, error) {
				switch mode {
				case "legacy":
					return st.ReadResponse{}, old
				case "timeout":
					return st.ReadResponse{}, context.DeadlineExceeded
				case "invalid":
					return st.ReadResponse{}, st.Invalid
				case "network":
					return st.ReadResponse{}, errors.New("SECRET_SENTINEL")
				}
				return st.ReadResponse{TimelineSchema: 1, Code: "NO_OPERATION", HelperEpoch: &epoch, ConfigIdentity: &identity}, nil
			}
			mutate := func(context.Context, string, bool, string) (st.MutationResponse, error) {
				mutations++
				if mode == "mutate-network" {
					return st.MutationResponse{}, errors.New("SECRET_SENTINEL")
				}
				resultID := id
				if mode == "wrong-id" {
					resultID = strings.Repeat("f", 32)
				}
				result := st.MutationResponse{TimelineSchema: 1, OK: true, HelperEpoch: &epoch, OperationID: &resultID, TimelineAvailability: "AVAILABLE", ConfigIdentity: identity}
				if mode == "failed" {
					result.OK = false
					result.Code = "START_FAILED"
				}
				return result, nil
			}
			result, err := webControlActionResult(context.Background(), w.configPath, "start", true, id, legacy, read, mutate, func(e error) bool { return e == old })
			ref := result.Reference
			if (mode == "success" || mode == "failed") && result.Helper == nil {
				t.Fatal("successful decode discarded helper result")
			}
			wantLegacy := 0
			if mode == "legacy" || mode == "timeout" || mode == "random" {
				wantLegacy = 1
			}
			wantMutation := 1
			if mode == "legacy" || mode == "timeout" || mode == "random" || mode == "invalid" || mode == "network" {
				wantMutation = 0
			}
			if statusCalls != 1 || legacyCalls != wantLegacy || mutations != wantMutation {
				t.Fatalf("calls status=%d legacy=%d mutation=%d", statusCalls, legacyCalls, mutations)
			}
			shouldError := mode == "failed" || mode == "invalid" || mode == "network" || mode == "mutate-network" || mode == "wrong-id"
			if (err != nil) != shouldError {
				t.Fatal(ref, err)
			}
			if mode == "success" || mode == "failed" {
				if ref.Availability != "AVAILABLE" || ref.OperationID == nil || *ref.OperationID != id {
					t.Fatal(ref)
				}
			}
			if mode == "random" && ref.OperationID != nil {
				t.Fatal("invented random fallback ID")
			}
			if mode == "mutate-network" {
				var uncertain *webControlError
				if !errors.As(err, &uncertain) || !uncertain.StartupUnknown || ref.Availability != "AVAILABLE" {
					t.Fatal("lost mutation reply must be UNKNOWN and queryable", ref, err)
				}
			}
		})
	}
}
func TestWebStartupEightSaveOriginsAndNonreload(t *testing.T) {
	cases := []struct{ path, source string }{
		{"/api/v1/config", "SAVE_YAML"}, {"/api/v1/nodes", "SAVE_NODE"}, {"/api/v1/groups/selection", "SAVE_GROUP"}, {"/api/v1/nodes/selection", "SAVE_SELECTION"}, {"/api/v1/rules", "SAVE_RULE"}, {"/api/v1/profiles/switch", "PROFILE_SWITCH"}, {"/api/v1/import/commit", "IMPORT_COMMIT"}, {"/api/v1/import/commit", "IMPORT_APPEND"},
	}
	for _, tc := range cases {
		t.Run(tc.source, func(t *testing.T) {
			for _, mode := range []string{"apply", "failure", "same", "stopped", "state"} {
				t.Run(mode, func(t *testing.T) {
					w, _ := webFixture(t)
					old := w.beginStartup("start", "MANUAL_START")
					calls := 0
					w.state = func() (bool, bool, error) {
						if mode == "state" {
							return false, false, errors.New("unavailable")
						}
						if mode == "stopped" {
							return true, false, nil
						}
						return true, true, nil
					}
					w.serviceAction = func(context.Context, string, bool) error {
						calls++
						if mode == "failure" {
							return &webControlError{Code: "START_FAILED"}
						}
						return nil
					}
					request := httptest.NewRequest("POST", "http://127.0.0.1:18089"+tc.path, nil)
					if tc.source == "IMPORT_APPEND" {
						request = request.WithContext(context.WithValue(request.Context(), webStartupSourceKey{}, "IMPORT_APPEND"))
					}
					rec := httptest.NewRecorder()
					w.finishConfigSave(rec, request, mode != "same", "", true)
					var body struct {
						Saved   bool                   `json:"saved"`
						Applied bool                   `json:"applied"`
						Ref     *st.OperationReference `json:"startup_operation"`
					}
					if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &body) != nil || !body.Saved {
						t.Fatal(rec.Body.String())
					}
					if mode == "apply" || mode == "failure" {
						if calls != 1 || body.Ref == nil || body.Ref.OperationID == nil || w.startupLatest.source != tc.source || body.Applied != (mode == "apply") {
							t.Fatal(rec.Body.String(), calls)
						}
					} else {
						if calls != 0 || body.Ref != nil || w.startupLatest != old {
							t.Fatal("nonreload changed trace", rec.Body.String())
						}
					}
				})
			}
		})
	}
}
func TestWebStartupRandomFailureBusinessOnce(t *testing.T) {
	w, p := webFixture(t)
	cookie, csrf := webLogin(t, w, p)
	w.startupRandom = strings.NewReader("")
	calls := 0
	w.serviceAction = func(context.Context, string, bool) error { calls++; return nil }
	w.state = func() (bool, bool, error) { return true, true, nil }
	rec := webRequest(w, "POST", "/api/v1/service/start", `{"confirm_insecure":true}`, cookie, csrf)
	var body struct {
		Ref st.OperationReference `json:"startup_operation"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &body) != nil || calls != 1 || body.Ref.OperationID != nil || body.Ref.Availability != "UNAVAILABLE" {
		t.Fatal(rec.Code, rec.Body.String(), calls)
	}
}
