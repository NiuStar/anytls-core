package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func completedConsole(r desktopMigrationMetadata, uid int) map[string]any {
	return map[string]any{"pid": 12345, "uid": uid, "seconds": 1, "micros": 2, "argv": []any{r.Binary, "webui", "--listen", "0.0.0.0", "--port", "18089"}, "sha": r.OldBinarySHA256, "managed": false}
}
func completedEditIntent(t *testing.T, m desktopMigration, name string, edit func(map[string]any)) {
	t.Helper()
	p := filepath.Join(m.home, ".anytls-desktop-state", name+".json")
	raw, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	var o map[string]any
	if e = json.Unmarshal(raw, &o); e != nil {
		t.Fatal(e)
	}
	edit(o)
	raw, e = json.Marshal(o)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(p, raw, 0600); e != nil {
		t.Fatal(e)
	}
}
func TestDesktopMigrationCompletedNativeConsoleContract(t *testing.T) {
	for _, managed := range []bool{false, true} {
		t.Run(fmt.Sprint(managed), func(t *testing.T) {
			m, _, c, _, _, r := completedRecoveryFixture(t)
			completedEditIntent(t, m, "recovery", func(o map[string]any) {
				pin := completedConsole(r, m.uid)
				if managed {
					pin["managed"] = true
					label := desktopSum([]byte(fmt.Sprintf("%d\x00%s\x00%s", m.uid, r.Binary, r.Config)))[:24]
					pin["argv"] = []any{r.Binary, "webui", "--port", "18089", "--managed-agent", "com.anytls.webui." + label, "--listen", "0.0.0.0"}
				}
				o["console"] = pin
			})
			completedNextBundle(t, m, "v2026-11-08-04")
			completedReadOnlyPreview(t, m, c)
			raw, _ := os.ReadFile(filepath.Join(m.home, ".anytls-desktop-state", "recovery.json"))
			t.Logf("ACTUAL_NATIVE_RECOVERY_JSON %s", raw)
		})
	}
}
func TestDesktopMigrationCompletedConsoleClosedContract(t *testing.T) {
	for _, kind := range []string{"null", "scalar", "missing", "extra", "pid-type", "pid-range", "uid-range", "uid-relation", "seconds-type", "seconds-range", "micros-range", "argv-type", "argv-member", "argv-relation", "sha-relation", "managed-type", "top-extra", "operation-relation", "authorization-console", "authorization-resume"} {
		t.Run(kind, func(t *testing.T) {
			m, _, c, _, _, r := completedRecoveryFixture(t)
			completedEditIntent(t, m, "recovery", func(o map[string]any) {
				pin := completedConsole(r, m.uid)
				o["console"] = pin
				switch kind {
				case "null":
					o["console"] = nil
				case "scalar":
					o["console"] = true
				case "missing":
					delete(pin, "pid")
				case "extra":
					pin["resume"] = false
				case "pid-type":
					pin["pid"] = "12345"
				case "pid-range":
					pin["pid"] = int64(1) << 31
				case "uid-range":
					pin["uid"] = int64(1) << 32
				case "uid-relation":
					pin["uid"] = m.uid + 1
				case "seconds-type":
					pin["seconds"] = true
				case "seconds-range":
					pin["seconds"] = -1
				case "micros-range":
					pin["micros"] = 1000000
				case "argv-type":
					pin["argv"] = "webui"
				case "argv-member":
					pin["argv"] = []any{r.Binary, 1}
				case "argv-relation":
					pin["argv"] = []any{m.source, "webui"}
				case "sha-relation":
					pin["sha"] = r.BinarySHA256
				case "managed-type":
					pin["managed"] = 0
				case "top-extra":
					o["resume"] = false
				case "operation-relation":
					o["operation"] = r.RecoveryOf
				}
			})
			if strings.HasPrefix(kind, "authorization-") {
				completedEditIntent(t, m, "authorization", func(o map[string]any) {
					if kind == "authorization-console" {
						o["console"] = completedConsole(r, m.uid)
					} else {
						o["resume"] = true
					}
				})
			}
			records, e := m.recoveryRecords()
			if e != nil {
				t.Fatal(e)
			}
			if m.recoveryIntents(records[r.Operation], records) == nil {
				t.Fatal("malformed intent accepted")
			}
			completedNextBundle(t, m, "v2026-11-08-04")
			p, e := m.inspect()
			if e == nil || p.Phase == "INSPECTED" || *c != 1 {
				t.Fatalf("must HOLD without STOP: %+v %v %d", p, e, *c)
			}
		})
	}
}
func TestDesktopMigrationCompletedCanonicalCallbackContract(t *testing.T) {
	for _, when := range []int{1, 2} {
		t.Run(string(rune('0'+when)), func(t *testing.T) {
			m, h, c, _, _, r := completedRecoveryFixture(t)
			completedNextBundle(t, m, "v2026-11-08-04")
			marker := filepath.Join(m.home, "unexpected-execution")
			calls := 0
			m.status = func(context.Context) (controlHelperResponse, error) {
				calls++
				if calls == when {
					replacement := filepath.Join(m.home, "replacement")
					raw := []byte("#!/bin/sh\nprintf ran > '" + marker + "'\nprintf '" + h.HelperVersion + "\\n'\n")
					if e := os.WriteFile(replacement, raw, 0755); e != nil {
						t.Fatal(e)
					}
					if e := os.Rename(replacement, r.Binary); e != nil {
						t.Fatal(e)
					}
				}
				return *h, nil
			}
			p, e := m.inspect()
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("unproven mutable canonical executed", err)
			}
			if e == nil || p.Phase == "INSPECTED" || *c != 1 {
				t.Fatalf("must HOLD after callback replacement: %+v %v calls=%d", p, e, calls)
			}
		})
	}
}
func TestDesktopMigrationCompletedHelperCallbackContract(t *testing.T) {
	for _, kind := range []string{"sha", "version", "running", "loaded"} {
		t.Run(kind, func(t *testing.T) {
			m, h, c, _, _, _ := completedRecoveryFixture(t)
			completedNextBundle(t, m, "v2026-11-08-04")
			calls := 0
			m.status = func(context.Context) (controlHelperResponse, error) {
				calls++
				reply := *h
				if calls == 2 {
					switch kind {
					case "sha":
						reply.HelperSHA256 = strings.Repeat("a", 64)
					case "version":
						reply.HelperVersion = "v2026-11-10-01"
					case "running":
						reply.Running = true
					case "loaded":
						reply.Loaded = true
					}
				}
				return reply, nil
			}
			p, e := m.inspect()
			if e == nil || p.Phase == "INSPECTED" || *c != 1 {
				t.Fatalf("final helper must bind lineage: %+v %v calls=%d", p, e, calls)
			}
		})
	}
}

func completedPublishedScript(t *testing.T, script string) (desktopMigration, *int) {
	t.Helper()
	m, h, c, _, _ := recoveryFixture(t)
	if e := os.WriteFile(m.source, []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	saved := Version
	Version = "v2026-11-07-03"
	t.Cleanup(func() { Version = saved })
	p := recoveryAwaiting(t, m)
	h.HelperSHA256, h.HelperVersion = p.BinarySHA256, currentVersion()
	p, e := m.finish(p.Operation)
	if e != nil {
		t.Fatal(e)
	}
	completedIntents(t, m, p, p)
	completedNextBundle(t, m, "v2026-11-08-04")
	return m, c
}
func TestDesktopMigrationCompletedVersionBoundContract(t *testing.T) {
	for _, kind := range []string{"inherited-pipe", "deadline", "stdout", "stderr", "captured-image"} {
		t.Run(kind, func(t *testing.T) {
			script := "#!/bin/sh\n"
			pidfile := filepath.Join(t.TempDir(), "owned-probe-pid")
			switch kind {
			case "inherited-pipe":
				script += "sleep 2 &\nprintf 'v2026-11-07-03\\n'\n"
			case "deadline":
				script += "printf '%s' \"$$\" > '" + pidfile + "'\nexec sleep 5\n"
			case "stdout":
				script += "i=0; while [ $i -lt 4096 ]; do printf '0123456789012345678901234567890123456789012345678901234567890123456789'; i=$((i+1)); done\n"
			case "stderr":
				script += "i=0; while [ $i -lt 4096 ]; do printf '0123456789012345678901234567890123456789012345678901234567890123456789' >&2; i=$((i+1)); done\nprintf 'v2026-11-07-03\\n'\n"
			case "captured-image":
				script += "case \"$0\" in */.migration-version-*/anytls-macos) ;; *) exit 41;; esac\n[ \"$#\" = 1 ] && [ \"$1\" = -version ] || exit 42\nprintf 'v2026-11-07-03\\n'\n"
			}
			m, c := completedPublishedScript(t, script)
			start := time.Now()
			p, e := m.inspect()
			elapsed := time.Since(start)
			if kind == "deadline" {
				raw, err := os.ReadFile(pidfile)
				if err != nil {
					t.Fatal(err)
				}
				pid, err := strconv.Atoi(string(raw))
				if err != nil || pid <= 1 {
					t.Fatal("owned PID", err)
				}
				if err = syscall.Kill(pid, 0); err != syscall.ESRCH {
					t.Fatalf("direct owned child not reaped: pid=%d err=%v", pid, err)
				}
				t.Log("OWNED_DIRECT_CHILD_REAPED")
			}
			t.Logf("VERSION_BOUND kind=%s elapsed=%s phase=%s err=%v", kind, elapsed, p.Phase, e)
			if kind == "captured-image" {
				if e != nil || p.Phase != "INSPECTED" {
					t.Fatalf("must execute owned captured image: %+v %v", p, e)
				}
			} else if e == nil || p.Phase == "INSPECTED" {
				t.Fatalf("must HOLD: %+v %v", p, e)
			}
			max := 1500 * time.Millisecond
			if kind == "deadline" {
				max = 4 * time.Second
			}
			if elapsed > max {
				t.Fatalf("version bound exceeded %s > %s", elapsed, max)
			}
			if *c != 1 {
				t.Fatal("STOP replay")
			}
			entries, err := filepath.Glob(filepath.Join(m.home, ".anytls", ".migration-version-*"))
			if err != nil || len(entries) != 0 {
				t.Fatal("owned probe leaked", entries, err)
			}
		})
	}
}

// Cleanup failure is not a successful read-only inspection. This finite
// fixture makes only its owned probe directory non-writable; test cleanup
// restores and removes that exact directory without product-side retries.
func TestDesktopMigrationCompletedProbeCleanupFailure(t *testing.T) {
	for _, validVersion := range []bool{true, false} {
		t.Run(fmt.Sprint(validVersion), func(t *testing.T) {
			version := "v2026-11-07-03"
			if !validVersion {
				version = "invalid"
			}
			script := "#!/bin/sh\nchmod 500 \"${0%/*}\"\nprintf '" + version + "\\n'\n"
			m, c := completedPublishedScript(t, script)
			defer func() {
				dirs, e := filepath.Glob(filepath.Join(m.home, ".anytls", ".migration-version-*"))
				if e != nil {
					t.Error(e)
					return
				}
				for _, dir := range dirs {
					if e = os.Chmod(dir, 0700); e != nil {
						t.Error(e)
						continue
					}
					if e = os.RemoveAll(dir); e != nil {
						t.Error(e)
					}
				}
			}()
			p, e := m.inspect()
			dirs, globErr := filepath.Glob(filepath.Join(m.home, ".anytls", ".migration-version-*"))
			if globErr != nil {
				t.Fatal(globErr)
			}
			// Positive injection precondition: exercise a real removal failure.
			if len(dirs) != 1 {
				t.Fatalf("cleanup fault not reached: retained=%d", len(dirs))
			}
			if e == nil || p.Phase == "INSPECTED" || p.Operation != "" || *c != 1 {
				t.Fatalf("cleanup failure must HOLD without STOP replay: phase=%s err=%v STOP=%d", p.Phase, e, *c)
			}
			t.Logf("PROBE_CLEANUP_HOLD validVersion=%t retained=%d error=%v STOP=%d", validVersion, len(dirs), e, *c)
		})
	}
}
