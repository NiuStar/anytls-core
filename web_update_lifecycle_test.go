package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A real owned child, not a mocked Run: publish and exit have separate gates.
// The test executable is used so this requires neither Python nor a shell.
func TestWebUpdateLifecycleChild(t *testing.T) {
	mode := os.Getenv("ANYTLS_LIFECYCLE_CHILD")
	if mode == "" {
		return
	}
	dir := os.Getenv("ANYTLS_LIFECYCLE_DIR")
	mark := func(name string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("ack"), 0600); err != nil {
			os.Exit(2)
		}
	}
	wait := func(name string) {
		deadline := time.Now().Add(15 * time.Second)
		for {
			if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
				return
			}
			if time.Now().After(deadline) {
				os.Exit(3)
			}
			time.Sleep(time.Millisecond)
		}
	}
	switch mode {
	case "check":
		fmt.Print(`{"current_version":"v1.0.0","latest_version":"v1.0.1","update_available":true,"source_only":true}`)
	case "install":
		mark("ready")
		wait("publish-gate")
		mark("published")
		mark("publish-ack")
		wait("exit-gate")
		mark("final-wait-done")
	case "version":
		wait("published")
		mark("verify-ready")
		wait("verify-gate")
		fmt.Println("v1.0.1")
	default:
		os.Exit(4)
	}
	os.Exit(0)
}

func lifecycleWaitMarker(t *testing.T, dir, name string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for child %s", name)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestWebUpdateCancellationOwnsChildAndMutationLock(t *testing.T) {
	for _, cancellation := range []string{"disconnect", "deadline"} {
		t.Run(cancellation, func(t *testing.T) {
			w, password := webFixture(t)
			cookie, csrf := webLogin(t, w, password)
			dir := t.TempDir()
			var install *exec.Cmd
			child := func(ctx context.Context, mode string) *exec.Cmd {
				var cmd *exec.Cmd
				if ctx == nil {
					cmd = exec.Command(os.Args[0], "-test.run=^TestWebUpdateLifecycleChild$")
				} else {
					cmd = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWebUpdateLifecycleChild$")
				}
				cmd.Env = append(os.Environ(), "ANYTLS_LIFECYCLE_CHILD="+mode, "ANYTLS_LIFECYCLE_DIR="+dir)
				return cmd
			}
			w.updateAction = func(ctx context.Context, check bool) (json.RawMessage, error) {
				return webUpdateWithCommands(ctx, check, "synthetic-owned-cli",
					func(ctx context.Context, _ string, args ...string) *exec.Cmd {
						mode := "check"
						if args[0] == "version" {
							mode = "version"
						}
						return child(ctx, mode)
					},
					func(_ string, args ...string) *exec.Cmd {
						if strings.Join(args, " ") != "update --version v1.0.1" {
							panic("untrusted install arguments")
						}
						install = child(nil, "install")
						return install
					})
			}
			ctx, cancel := context.WithCancel(context.Background())
			if cancellation == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
			}
			defer cancel()
			r := httptest.NewRequest("POST", "http://127.0.0.1:18089/api/v1/update", strings.NewReader(`{"confirm":true}`)).WithContext(ctx)
			r.AddCookie(cookie)
			r.Header.Set("Origin", "http://127.0.0.1:18089")
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-CSRF-Token", csrf)
			rec := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { defer close(done); w.ServeHTTP(rec, r) }()
			gate := func(name string) {
				if err := os.WriteFile(filepath.Join(dir, name), []byte("go"), 0600); err != nil {
					t.Error(err)
				}
			}
			defer func() {
				gate("publish-gate")
				gate("exit-gate")
				gate("verify-gate")
				select {
				case <-done:
				case <-time.After(18 * time.Second):
					t.Error("owned child/handler was not joined")
				}
			}()
			lifecycleWaitMarker(t, dir, "ready")
			if cancellation == "disconnect" {
				cancel()
			}
			<-ctx.Done()
			assertBusy := func() {
				t.Helper()
				select {
				case <-done:
					t.Fatal("handler returned before owned work joined")
				default:
				}
				for _, action := range []string{"/api/v1/service/stop", "/api/v1/update"} {
					busy := webRequest(w, "POST", action, `{"confirm":true}`, cookie, csrf)
					if busy.Code != 409 || !strings.Contains(busy.Body.String(), "ACTION_BUSY") {
						t.Fatalf("overlapping action %s: %d %s", action, busy.Code, busy.Body.String())
					}
				}
			}
			assertBusy()
			gate("publish-gate")
			lifecycleWaitMarker(t, dir, "publish-ack") // publication AFTER cancellation is intentional
			assertBusy()                               // publication is not completion: child still owns the lock
			gate("exit-gate")
			lifecycleWaitMarker(t, dir, "verify-ready")
			assertBusy() // independent version readback also retains the action lock
			gate("verify-gate")
			select {
			case <-done:
			case <-time.After(8 * time.Second):
				t.Fatal("update failed to finish after child exit")
			}
			lifecycleWaitMarker(t, dir, "final-wait-done")
			if install == nil || install.ProcessState == nil || !install.ProcessState.Exited() || !install.ProcessState.Success() {
				t.Fatal("owned installer Run did not reap successful child")
			}
			if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"updated":true`) || !strings.Contains(rec.Body.String(), `"status":"UPDATED"`) {
				t.Fatalf("canceled request lost real update result: %d %s", rec.Code, rec.Body.String())
			}
			if !w.actionMu.TryLock() {
				t.Fatal("action lock was not released after wait and verification")
			}
			w.actionMu.Unlock()
		})
	}
}

func TestWebUpdateCanceledCheckDoesNotStartInstall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := webUpdateWithCommands(ctx, false, "synthetic-owned-cli", exec.CommandContext,
		func(string, ...string) *exec.Cmd { t.Fatal("install admitted after canceled check"); return nil })
	if err == nil {
		t.Fatal("canceled check succeeded")
	}
}

func TestWebUpdateLifecycleNotice(t *testing.T) {
	w, _ := webFixture(t)
	rec := webRequest(w, "GET", "/", "", nil, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "十分钟请求超时均不会停止安装") {
		t.Fatal("page does not disclose update cancellation semantics")
	}
}
