package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
)

// The response bytes cross a private Unix socket and the production authenticated
// exchange. Peer UID and lifecycle results are simulated; no installed helper.
func startupUnknownExchange(t *testing.T, ctx context.Context, q, dst any, raw []byte, bound time.Duration) error {
	t.Helper()
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(unitControlSocketDir(t), "unknown.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan error, 1)
	go func() {
		c, e := l.AcceptUnix()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		_, e = io.ReadAll(c)
		if e == nil {
			_, e = c.Write(raw)
		}
		done <- e
	}()
	c, err := net.DialUnix("unix", nil, l.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	err = startupExchange(ctx, c, q, dst, bound, func(net.Conn) (uint32, error) { return 0, nil })
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	return err
}

func TestWebStartupUnknownAfterSendPrivateIPC(t *testing.T) {
	for _, mode := range []string{"config-response", "config-drift", "wrong-id", "epoch-drift", "malformed", "business-failed", "success"} {
		t.Run(mode, func(t *testing.T) {
			w, password := webFixture(t)
			cookie, csrf := webLogin(t, w, password)
			calls, _ := webStartupRouteIPC(t, w, "start", false)
			w.state = func() (bool, bool, error) { return true, true, nil }
			mutations := 0
			w.startupControlRequest = func(ctx context.Context, action string, allow bool, id string) (st.MutationResponse, error) {
				return startupControlWithRequest(ctx, action, allow, id, func(ctx context.Context, q, dst any, bound time.Duration) error {
					mutations++
					identity, e := controlHelperConfigIdentity(w.configPath)
					if e != nil {
						t.Fatal(e)
					}
					epoch := strings.Repeat("b", 32)
					resultID := id
					result := st.MutationResponse{TimelineSchema: 1, OK: true, HelperEpoch: &epoch, OperationID: &resultID, TimelineAvailability: "AVAILABLE", ConfigIdentity: identity, Loaded: true, Running: true}
					switch mode {
					case "config-response":
						result.ConfigIdentity = strings.Repeat("f", 64)
					case "config-drift":
						if e := os.Rename(w.configPath, w.configPath+".old"); e != nil {
							t.Fatal(e)
						}
						if e := os.Symlink(w.configPath+".old", w.configPath); e != nil {
							t.Fatal(e)
						}
					case "wrong-id":
						resultID = strings.Repeat("f", 32)
					case "epoch-drift":
						epoch = strings.Repeat("c", 32)
					case "business-failed":
						result.OK = false
						result.Code = "START_FAILED"
					}
					raw, e := st.Encode(result)
					if e != nil {
						t.Fatal(e)
					}
					if mode == "malformed" {
						raw = []byte("{\"timeline_schema\":1,\"SECRET_SENTINEL\":true}\n")
					}
					return startupUnknownExchange(t, ctx, q, dst, raw, bound)
				})
			}
			out := webRequest(w, "POST", "/api/v1/service/start", `{"confirm_insecure":true}`, cookie, csrf)
			var body struct {
				Error     string                 `json:"error"`
				Reference *st.OperationReference `json:"startup_operation"`
			}
			if e := json.Unmarshal(out.Body.Bytes(), &body); e != nil {
				t.Fatal(e)
			}
			wantResult, wantCode, wantHTTP := "UNKNOWN", "HELPER_UNAVAILABLE", 503
			if strings.HasPrefix(mode, "config-") {
				wantCode = "HELPER_CONFIG_MISMATCH"
			}
			if mode == "business-failed" {
				wantResult, wantCode = "FAILED", "START_FAILED"
			}
			if mode == "success" {
				wantResult, wantCode, wantHTTP = "SUCCEEDED", "", 200
			}
			if out.Code != wantHTTP || body.Error != wantCode || w.startupLatest.result != wantResult {
				t.Errorf("result=%s want=%s HTTP=%d code=%s want=%s body=%s", w.startupLatest.result, wantResult, out.Code, body.Error, wantCode, out.Body.String())
			}
			if mutations != 1 || strings.Join(*calls, ",") != "status,startup.read" {
				t.Errorf("mutation=%d legacy/discovery=%v", mutations, *calls)
			}
			if body.Reference == nil || body.Reference.Availability != "AVAILABLE" || body.Reference.OperationID == nil || *body.Reference.OperationID != w.startupLatest.id {
				t.Errorf("lost query reference: %s", out.Body.String())
			}
			if strings.Contains(out.Body.String(), "SECRET_SENTINEL") {
				t.Fatal("raw error leaked")
			}
			// The authenticated trace endpoint must keep the same result, not merely the
			// internal operation. Restore the path after testing local binding drift.
			if mode == "config-drift" {
				if e := os.Remove(w.configPath); e != nil {
					t.Fatal(e)
				}
				if e := os.Rename(w.configPath+".old", w.configPath); e != nil {
					t.Fatal(e)
				}
			}
			trace := webStartupHTTPRequest(w, cookie, "?operation_id="+w.startupLatest.id, nil)
			var got st.ReadResponse
			if trace.Code != 200 || st.Decode(strings.NewReader(trace.Body.String()), &got) != nil || got.Trace == nil || got.Trace.WebReturn != wantResult {
				t.Errorf("trace HTTP=%d: %s", trace.Code, trace.Body.String())
			}
		})
	}
}
