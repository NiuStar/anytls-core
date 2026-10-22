package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests use only pre-existing seams so identical bytes compile on the baseline.
func TestUpdatePrebuiltMetadata(t *testing.T) {
	for _, mode := range []string{"complete", "missing-binary", "missing-ccs", "other-arch", "duplicate", "wrong-url"} {
		t.Run(mode, func(t *testing.T) {
			tag := "v1.2.3"
			fixture := updateFixture(tag)
			arch := runtime.GOARCH // Never silently assume the native test runner is ARM.
			if mode == "other-arch" {
				if arch == "arm64" {
					arch = "amd64"
				} else {
					arch = "arm64"
				}
			}
			binary := "anytls-core-" + tag + "-darwin-" + arch + ".tar.gz"
			ccs := "anytls-core-" + tag + "-corresponding-source.tar.gz"
			if arch == "amd64" {
				ccs = "anytls-core-" + tag + "-darwin-amd64-corresponding-source.tar.gz"
			}
			assets := fixture["assets"].([]map[string]string)
			for _, name := range []string{binary, ccs} {
				if mode == "missing-binary" && name == binary || mode == "missing-ccs" && name == ccs {
					continue
				}
				u := updateRepository + "/releases/download/" + tag + "/" + name
				if mode == "wrong-url" && name == binary {
					u = "https://untrusted.invalid/secret"
				}
				asset := map[string]string{"name": name, "browser_download_url": u}
				assets = append(assets, asset)
				if mode == "duplicate" && name == binary {
					assets = append(assets, asset)
				}
			}
			fixture["assets"] = assets
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { json.NewEncoder(w).Encode(fixture) }))
			defer s.Close()
			got, err := readUpdateRelease(context.Background(), s.Client(), s.URL, "")
			if mode == "duplicate" || mode == "wrong-url" {
				if err == nil {
					t.Fatal("accepted ambiguous/untrusted current architecture asset")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.SourceOnly != (mode != "complete") {
				t.Fatalf("binary availability for %s: %+v", runtime.GOARCH, got)
			}
		})
	}
}

func TestUpdatePrebuiltProtocolChild(t *testing.T) {
	if os.Getenv("ANYTLS_PREBUILT_CHILD") != "1" {
		return
	}
	if command := os.Getenv("ANYTLS_PREBUILT_MAIN"); command != "" {
		os.Args = []string{"anytls", command, "--unknown-prebuilt-regression"}
		main()
		os.Exit(0)
	}
	fmt.Print(os.Getenv("ANYTLS_PREBUILT_OUTPUT"))
	code, _ := strconv.Atoi(os.Getenv("ANYTLS_PREBUILT_EXIT"))
	os.Exit(code)
}

func prebuiltChild(ctx context.Context, output string, code int) *exec.Cmd {
	var cmd *exec.Cmd
	if ctx == nil {
		cmd = exec.Command(os.Args[0], "-test.run=^TestUpdatePrebuiltProtocolChild$")
	} else {
		cmd = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestUpdatePrebuiltProtocolChild$")
	}
	cmd.Env = append(os.Environ(), "ANYTLS_PREBUILT_CHILD=1", "ANYTLS_PREBUILT_OUTPUT="+output, "ANYTLS_PREBUILT_EXIT="+strconv.Itoa(code))
	return cmd
}

func TestWebUpdatePrebuiltContract(t *testing.T) {
	for _, mode := range []string{"lost-response", "available-restart", "installed", "verify-mismatch", "verify-exit", "missing-source-only", "unsafe-version", "source-only"} {
		t.Run(mode, func(t *testing.T) {
			w, p := webFixture(t)
			cookie, csrf := webLogin(t, w, p)
			installed, latest, available := "v1.0.1", "v1.0.1", false
			check := mode == "lost-response" || mode == "available-restart"
			if !check || mode == "available-restart" {
				latest, available = "v1.0.2", true
			}
			data := map[string]any{"current_version": installed, "latest_version": latest, "update_available": available, "source_only": mode == "source-only"}
			if mode == "unsafe-version" {
				data["latest_version"] = "v1.0.2;touch secret"
			}
			if mode == "missing-source-only" {
				delete(data, "source_only")
			}
			b, _ := json.Marshal(data)
			installs := 0
			w.updateAction = func(ctx context.Context, onlyCheck bool) (json.RawMessage, error) {
				return webUpdateWithCommands(ctx, onlyCheck, "owned-fixture", func(ctx context.Context, _ string, args ...string) *exec.Cmd {
					if args[0] != "version" {
						return prebuiltChild(ctx, string(b), 0)
					}
					if mode == "verify-exit" {
						return prebuiltChild(ctx, "", 1)
					}
					if mode == "verify-mismatch" {
						return prebuiltChild(ctx, installed, 0)
					}
					return prebuiltChild(ctx, latest, 0)
				}, func(_ string, args ...string) *exec.Cmd {
					installs++
					if strings.Join(args, " ") != "update --version "+latest {
						t.Error("untrusted arguments")
					}
					return prebuiltChild(nil, "", 0)
				})
			}
			method, path, body := "POST", "/api/v1/update", `{"confirm":true}`
			if check {
				method, path, body = "GET", "/api/v1/update-check", ""
			}
			r := webRequest(w, method, path, body, cookie, csrf)
			wantError := ""
			switch mode {
			case "verify-mismatch", "verify-exit":
				wantError = "UPDATE_VERIFY_FAILED"
			case "missing-source-only", "unsafe-version":
				wantError = "UPDATE_CHECK_FAILED"
			case "source-only":
				wantError = "UPDATE_BINARY_UNAVAILABLE"
			}
			if wantError != "" {
				if r.Code != 503 || strings.TrimSpace(r.Body.String()) != `{"error":"`+wantError+`"}` {
					t.Fatalf("%d %s", r.Code, r.Body.String())
				}
				if wantError != "UPDATE_VERIFY_FAILED" && installs != 0 {
					t.Fatal("invalid check admitted installation")
				}
				return
			}
			var result map[string]any
			if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &result) != nil {
				t.Fatalf("%d %s", r.Code, r.Body.String())
			}
			wantStatus := "UPDATED"
			if mode == "lost-response" {
				wantStatus = "RESTART_REQUIRED"
			}
			if mode == "available-restart" {
				wantStatus = "UPDATE_AVAILABLE"
			}
			wantInstalled := installed
			if !check {
				wantInstalled = latest
			}
			if result["status"] != wantStatus || result["current"] != currentVersion() || result["installed"] != wantInstalled || result["restartRequired"] != true {
				t.Fatalf("incorrect process/disk identity: %s", r.Body.String())
			}
		})
	}
}

func TestUpdatePrebuiltMainNarrowExit(t *testing.T) {
	for _, command := range []string{"update", "version", "webui"} {
		t.Run(command, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := prebuiltChild(ctx, "", 0)
			cmd.Env = append(cmd.Env, "ANYTLS_PREBUILT_MAIN="+command)
			err := cmd.Run()
			var exit *exec.ExitError
			want := 1
			if command == "update" {
				want = 40
			}
			if !errors.As(err, &exit) || exit.ExitCode() != want {
				t.Fatalf("%s: exit %v, want %d", command, err, want)
			}
		})
	}
}

func TestWebUpdatePrebuiltExitWhitelist(t *testing.T) {
	codes := map[int]string{40: "UPDATE_CHECK_FAILED", 41: "UPDATE_PYTHON_REQUIRED", 42: "UPDATE_BINARY_UNAVAILABLE", 43: "UPDATE_DOWNLOAD_FAILED", 44: "UPDATE_VALIDATION_FAILED", 45: "UPDATE_PUBLISH_FAILED", 46: "UPDATE_VERIFY_FAILED", 47: "UPDATE_UNAVAILABLE", 1: "UPDATE_UNAVAILABLE", 2: "UPDATE_UNAVAILABLE", 99: "UPDATE_UNAVAILABLE"}
	for _, check := range []bool{true, false} {
		for code, want := range codes {
			t.Run(fmt.Sprintf("check=%v/exit=%d", check, code), func(t *testing.T) {
				w, p := webFixture(t)
				cookie, csrf := webLogin(t, w, p)
				w.updateAction = func(ctx context.Context, onlyCheck bool) (json.RawMessage, error) {
					return webUpdateWithCommands(ctx, onlyCheck, "owned-fixture", func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
						if check {
							return prebuiltChild(ctx, "secret stderr must not leak", code)
						}
						return prebuiltChild(ctx, `{"current_version":"v1.0.0","latest_version":"v1.0.1","update_available":true,"source_only":false}`, 0)
					}, func(string, ...string) *exec.Cmd { return prebuiltChild(nil, "secret", code) })
				}
				method, path := "POST", "/api/v1/update"
				if check {
					method, path = "GET", "/api/v1/update-check"
				}
				r := webRequest(w, method, path, `{"confirm":true}`, cookie, csrf)
				if r.Code != 503 || strings.TrimSpace(r.Body.String()) != `{"error":"`+want+`"}` {
					t.Fatalf("%d %s", r.Code, r.Body.String())
				}
			})
		}
	}
}
