package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWebSelectionUnknownOwnedReadback(t *testing.T) {
	w, cookie, csrf := linkFixture(t, selectionLinkConfig, "a")
	w.state = func() (bool, bool, error) { return true, true, nil }
	identity, e := controlHelperConfigIdentity(w.configPath)
	if e != nil {
		t.Fatal(e)
	}
	op := &liveSelectionOperation{Operation: strings.Repeat("b", 32), Generation: strings.Repeat("a", 32), Revision: 5, Node: "b"}
	var actions []string
	w.selectionRecovery.request = func(_ context.Context, action string, _ bool) (controlHelperResponse, error) {
		actions = append(actions, action)
		r := controlHelperResponse{OK: true, Loaded: true, Running: true, ConfigIdentity: identity}
		if action == "status" {
			return r, nil
		}
		r.SelectionOperation = op
		if action == "select" {
			r.OK = false
			r.Code = "SWITCH_UNKNOWN"
			return r, &webControlError{Code: r.Code}
		}
		r.Code = "HOT_APPLIED"
		return r, nil
	}
	out := groupETagRequest(w, cookie, csrf, "/api/v1/nodes/selection", `{"name":"b","confirm_insecure":true}`, "")
	var body map[string]any
	_ = json.Unmarshal(out.Body.Bytes(), &body)
	if out.Code != 200 || body["apply_status"] != "SWITCH_UNKNOWN" || body["applied"] != false || body["selection_operation"] == nil {
		t.Fatalf("unknown: %d %s", out.Code, out.Body.String())
	}
	before := w.fingerprint()
	again := groupETagRequest(w, cookie, csrf, "/api/v1/nodes/selection", `{"name":"a","confirm_insecure":true}`, "")
	if again.Code != 409 || w.fingerprint() != before || strings.Join(actions, ",") != "status,select" {
		t.Fatalf("POST replay/save while unknown: %d %s %v", again.Code, again.Body.String(), actions)
	}
	get := func(path string, auth bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "http://127.0.0.1:18089"+path, nil)
		if auth {
			r.AddCookie(cookie)
		}
		out := httptest.NewRecorder()
		w.ServeHTTP(out, r)
		return out
	}
	if r := get("/api/v1/status", true); r.Code != 200 {
		t.Fatalf("status refresh failed: %d %s", r.Code, r.Body.String())
	}
	same := groupETagRequest(w, cookie, csrf, "/api/v1/nodes/selection", `{"name":"b","confirm_insecure":true}`, "")
	group := groupETagRequest(w, cookie, csrf, "/api/v1/groups/selection", `{"group":"default","choice":"a","confirm_insecure":true}`, "")
	if same.Code != 409 || group.Code != 409 || w.fingerprint() != before {
		t.Fatalf("refresh/NO_CHANGE unlocked uncertain operation: same=%d group=%d", same.Code, group.Code)
	}
	path := "/api/v1/nodes/selection/readback?operation=" + op.Operation + "&generation=" + op.Generation + "&revision=5&node=" + url.QueryEscape(op.Node)
	if r := get(path, false); r.Code != 401 {
		t.Fatalf("unauthenticated read: %d", r.Code)
	}
	for _, badPath := range []string{
		strings.Replace(path, "revision=5", "revision=6", 1),
		strings.Replace(path, "revision=5", "revision=05", 1),
		strings.Replace(path, "operation="+op.Operation, "operation="+strings.Repeat("c", 32), 1),
		strings.Replace(path, "generation="+op.Generation, "generation="+strings.Repeat("d", 32), 1),
		strings.Replace(path, "node=b", "node=a", 1),
		path + "&revision=5", path + "&extra=1",
	} {
		if r := get(badPath, true); r.Code != 409 {
			t.Fatalf("foreign expectation: %d %s", r.Code, r.Body.String())
		}
	}
	if strings.Join(actions, ",") != "status,select" {
		t.Fatalf("invalid read reached helper: %v", actions)
	}
	read := get(path, true)
	body = nil
	_ = json.Unmarshal(read.Body.Bytes(), &body)
	if read.Code != 200 || body["apply_status"] != "HOT_APPLIED" || body["applied"] != true || body["pendingReload"] != false || body["pendingKnown"] != true || strings.Join(actions, ",") != "status,select,status,select-read" {
		t.Fatalf("readback: %d %s actions=%v", read.Code, read.Body.String(), actions)
	}
	saved, e := captureServiceConfig(w.configPath)
	if e != nil {
		t.Fatal(e)
	}
	etag := `"` + shaHex(saved.config) + `"`
	if body["ok"] != true || body["saved"] != true || body["changed"] != true || body["etag"] != etag || read.Header().Get("ETag") != etag || body["startup_operation"] != nil || body["connection_policy"] != "EXISTING_CONNECTIONS_RETAIN_OLD_EXIT" || body["readback_requires_owned_lease"] != false {
		t.Fatalf("poisoned success envelope: %s", read.Body.String())
	}
	rawOp, e := json.Marshal(body["selection_operation"])
	if e != nil {
		t.Fatal(e)
	}
	var got liveSelectionOperation
	if json.Unmarshal(rawOp, &got) != nil || got != *op {
		t.Fatalf("operation changed: %s", rawOp)
	}
}
func TestWebSelectionPoisonedSuccess(t *testing.T) {
	for _, mode := range []string{"empty_code", "failed_hot_applied", "canceled_result", "not_loaded", "not_running", "missing_operation", "bad_generation", "wrong_node", "missing_identity"} {
		t.Run(mode, func(t *testing.T) {
			w, cookie, csrf := linkFixture(t, selectionLinkConfig, "a")
			w.state = func() (bool, bool, error) { return true, true, nil }
			identity, _ := controlHelperConfigIdentity(w.configPath)
			w.selectionRecovery.request = func(_ context.Context, action string, _ bool) (controlHelperResponse, error) {
				r := controlHelperResponse{OK: true, Loaded: true, Running: true, ConfigIdentity: identity}
				if action == "status" {
					return r, nil
				}
				r.Code = "HOT_APPLIED"
				r.SelectionOperation = &liveSelectionOperation{Operation: strings.Repeat("b", 32), Generation: strings.Repeat("a", 32), Revision: 5, Node: "b"}
				switch mode {
				case "failed_hot_applied":
					r.OK = false
				case "canceled_result":
					return r, context.Canceled
				case "empty_code":
					r.Code = ""
				case "not_loaded":
					r.Loaded = false
				case "not_running":
					r.Running = false
				case "missing_operation":
					r.SelectionOperation = nil
				case "bad_generation":
					r.SelectionOperation.Generation = "bad"
				case "wrong_node":
					r.SelectionOperation.Node = "a"
				case "missing_identity":
					r.ConfigIdentity = ""
				}
				return r, nil
			}
			out := groupETagRequest(w, cookie, csrf, "/api/v1/nodes/selection", `{"name":"b","confirm_insecure":true}`, "")
			var body map[string]any
			_ = json.Unmarshal(out.Body.Bytes(), &body)
			if out.Code != 200 || body["apply_status"] != "SWITCH_UNKNOWN" || body["applied"] != false {
				t.Fatalf("poison accepted: %d %s", out.Code, out.Body.String())
			}
			if (mode == "failed_hot_applied" || mode == "canceled_result") && body["selection_operation"] == nil {
				t.Fatalf("lost authenticated recovery tuple: %s", out.Body.String())
			}
		})
	}
}
func TestWebSelectionHTTPToHelperUDSReadback(t *testing.T) {
	f := newLiveEntryFixture(t)
	w, password := webFixture(t)
	w.configPath = f.s.registration.Config
	if raw, e := os.ReadFile(w.configPath); e != nil {
		t.Fatal(e)
	} else if e = webValidateConfig(w.configPath, raw); e != nil {
		t.Fatalf("UDS fixture config invalid: %v", e)
	}
	cookie, csrf := webLogin(t, w, password)
	w.state = func() (bool, bool, error) { return true, true, nil }
	f.s.state = w.state
	f.onRead = func(n int32, _ *liveResponse) string {
		if n == 2 {
			return "{}"
		}
		return ""
	}
	w.selectionRecovery.request = func(ctx context.Context, action string, allow bool) (controlHelperResponse, error) {
		f.begin()
		c, done := unitControlPair(t, f.s)
		defer c.Close()
		result, e := controlHelperExchange(ctx, c, controlHelperWireRequest{Action: action, AllowInsecure: allow}, func(net.Conn) (uint32, error) { return 0, nil })
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("helper handler not joined")
		}
		return result, e
	}
	out := groupETagRequest(w, cookie, csrf, "/api/v1/nodes/selection", `{"name":"b"}`, "")
	var body struct {
		ApplyStatus string                  `json:"apply_status"`
		Applied     bool                    `json:"applied"`
		Operation   *liveSelectionOperation `json:"selection_operation"`
	}
	if e := json.Unmarshal(out.Body.Bytes(), &body); e != nil {
		t.Fatal(e)
	}
	if out.Code != 200 || body.ApplyStatus != "SWITCH_UNKNOWN" || body.Applied || !body.Operation.valid() || f.switches.Load() != 1 {
		t.Fatalf("HTTP -> helper -> core seam: %d %s switches=%d", out.Code, out.Body.String(), f.switches.Load())
	}
	op := body.Operation
	path := "/api/v1/nodes/selection/readback?operation=" + op.Operation + "&generation=" + op.Generation + "&revision=" + strconv.FormatUint(op.Revision, 10) + "&node=" + url.QueryEscape(op.Node)
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18089"+path, nil)
	r.AddCookie(cookie)
	read := httptest.NewRecorder()
	w.ServeHTTP(read, r)
	body = struct {
		ApplyStatus string                  `json:"apply_status"`
		Applied     bool                    `json:"applied"`
		Operation   *liveSelectionOperation `json:"selection_operation"`
	}{}
	if e := json.Unmarshal(read.Body.Bytes(), &body); e != nil {
		t.Fatal(e)
	}
	if read.Code != 200 || body.ApplyStatus != "HOT_APPLIED" || !body.Applied || !body.Operation.valid() || *body.Operation != *op || f.switches.Load() != 1 || f.reads.Load() != 3 {
		t.Fatalf("HTTP read-only -> actual UDS: %d %s mutations=%d reads=%d", read.Code, read.Body.String(), f.switches.Load(), f.reads.Load())
	}
}
func TestWebSelectionReadbackPoisonKeepsLock(t *testing.T) {
	for _, mode := range []string{"wrong_operation", "wrong_generation", "wrong_revision", "wrong_node", "not_loaded", "not_running", "empty_code", "lost_lease", "transport_error"} {
		t.Run(mode, func(t *testing.T) {
			w, cookie, csrf := linkFixture(t, selectionLinkConfig, "a")
			w.state = func() (bool, bool, error) { return true, true, nil }
			identity, _ := controlHelperConfigIdentity(w.configPath)
			op := liveSelectionOperation{Operation: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32), Revision: 5, Node: "b"}
			mutations := 0
			reads := 0
			w.selectionRecovery.request = func(_ context.Context, action string, _ bool) (controlHelperResponse, error) {
				r := controlHelperResponse{OK: true, Loaded: true, Running: true, ConfigIdentity: identity}
				if action == "status" {
					return r, nil
				}
				copyOp := op
				r.SelectionOperation = &copyOp
				r.Code = "HOT_APPLIED"
				if action == "select" {
					mutations++
					r.OK = false
					r.Code = "SWITCH_UNKNOWN"
					return r, &webControlError{Code: r.Code}
				}
				reads++
				switch mode {
				case "wrong_operation":
					copyOp.Operation = strings.Repeat("c", 32)
				case "wrong_generation":
					copyOp.Generation = strings.Repeat("c", 32)
				case "wrong_revision":
					copyOp.Revision++
				case "wrong_node":
					copyOp.Node = "a"
				case "not_loaded":
					r.Loaded = false
				case "not_running":
					r.Running = false
				case "empty_code":
					r.Code = ""
				case "lost_lease":
					r.OK = false
					r.Code = "SWITCH_UNKNOWN"
					r.SelectionOperation = nil
					return r, &webControlError{Code: r.Code}
				case "transport_error":
					return controlHelperResponse{}, context.DeadlineExceeded
				}
				return r, nil
			}
			post := groupETagRequest(w, cookie, csrf, "/api/v1/nodes/selection", `{"name":"b","confirm_insecure":true}`, "")
			if post.Code != 200 || !strings.Contains(post.Body.String(), `"apply_status":"SWITCH_UNKNOWN"`) {
				t.Fatalf("initial unknown missing: %d %s", post.Code, post.Body.String())
			}
			path := "http://127.0.0.1:18089/api/v1/nodes/selection/readback?operation=" + op.Operation + "&generation=" + op.Generation + "&revision=5&node=b"
			r := httptest.NewRequest(http.MethodGet, path, nil)
			r.AddCookie(cookie)
			out := httptest.NewRecorder()
			w.ServeHTTP(out, r)
			var result map[string]any
			_ = json.Unmarshal(out.Body.Bytes(), &result)
			if out.Code != 200 || result["apply_status"] != "SWITCH_UNKNOWN" || result["applied"] != false || result["pendingKnown"] != false || result["pendingReload"] != true || mutations != 1 || reads != 1 {
				t.Fatalf("poisoned readback: %d %s mutations=%d reads=%d", out.Code, out.Body.String(), mutations, reads)
			}
			if mode == "lost_lease" && result["readback_requires_owned_lease"] != true {
				t.Fatalf("lost helper authority not disclosed: %s", out.Body.String())
			}
			again := groupETagRequest(w, cookie, csrf, "/api/v1/nodes/selection", `{"name":"a","confirm_insecure":true}`, "")
			if again.Code != 409 || mutations != 1 {
				t.Fatalf("poison cleared lock: %d %s", again.Code, again.Body.String())
			}
		})
	}
}

func TestWebSelectionReadWithoutOwnedLease(t *testing.T) {
	w, cookie, _ := linkFixture(t, selectionLinkConfig, "a")
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18089/api/v1/nodes/selection/readback", nil)
	r.AddCookie(cookie)
	out := httptest.NewRecorder()
	w.ServeHTTP(out, r)
	if out.Code != 409 || !strings.Contains(out.Body.String(), `"readback_requires_owned_lease":true`) {
		t.Fatalf("unowned recovery: %d %s", out.Code, out.Body.String())
	}
}
