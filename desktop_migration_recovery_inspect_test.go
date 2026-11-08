package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the real inspector, then the exact public result-code/projection
// contract at desktopDispatch's migration seam (identity/helper IO is fixture
// injected, not installed helper IPC). Native Swift consumes these bytes too.
func recoveryInspectWire(t *testing.T, m desktopMigration) (desktopMigrationMetadata, error, int, []byte) {
	t.Helper()
	p, err := m.inspect()
	var out bytes.Buffer
	code := 0
	if err != nil {
		code = 1
		if p.Operation != "" {
			if e := json.NewEncoder(&out).Encode(struct {
				Schema    int                      `json:"schema"`
				Error     string                   `json:"error"`
				Migration desktopMigrationMetadata `json:"migration"`
			}{1, err.Error(), p}); e != nil {
				t.Fatal(e)
			}
		} else {
			t.Fatal("inspection returned no continuation metadata", err)
		}
	} else if e := json.NewEncoder(&out).Encode(p); e != nil {
		t.Fatal(e)
	}
	// DesktopMigration.parse uses flat JSON only for code0, nested migration for
	// nonzero. Do not let a test-only flat/nonzero combination hide a seam bug.
	var object map[string]json.RawMessage
	if e := json.Unmarshal(out.Bytes(), &object); e != nil {
		t.Fatal(e)
	}
	raw := out.Bytes()
	if code != 0 {
		raw = object["migration"]
	}
	var parsed desktopMigrationMetadata
	if e := json.Unmarshal(raw, &parsed); e != nil {
		t.Fatal(e)
	}
	if parsed != p {
		t.Fatal("public metadata drift")
	}
	return parsed, err, code, out.Bytes()
}

func TestDesktopMigrationRecoveryInspectCommittedContract(t *testing.T) {
	m, h, c, old, retained := recoveryFixture(t)
	p := recoveryAwaiting(t, m)
	h.HelperSHA256, h.HelperVersion = p.BinarySHA256, currentVersion()
	m.journal = func(path string, b []byte, mode os.FileMode) error {
		if filepath.Base(path) == "supersession.json" {
			return os.ErrPermission
		}
		return controlInstallAtomic(path, b, mode)
	}
	if _, e := m.finish(p.Operation); e == nil {
		t.Fatal("fixture must lose terminal after publication")
	}
	r, e := m.record(p.Operation)
	if e != nil || r.Metadata.Phase != "COMMITTED" {
		t.Fatal("fixture not durably COMMITTED", e)
	}
	before, e := os.Lstat(p.Binary)
	if e != nil {
		t.Fatal(e)
	}
	// Any attempted inspector journal write fails this contract, including
	// attempts to silently repair the missing terminal.
	m.journal = func(string, []byte, os.FileMode) error { t.Fatal("inspect wrote a journal"); return os.ErrPermission }
	got, held, code, wire := recoveryInspectWire(t, m)
	if got != r.Metadata || held == nil || code != 1 {
		t.Fatalf("COMMITTED recovery must expose exact new continuation metadata, not old UNKNOWN/fresh preview: got=%+v error=%v code=%d", got, held, code)
	}
	t.Logf("RECOVERY_INSPECT_WIRE missing-terminal code=%d %s", code, wire)
	if _, e = os.Lstat(filepath.Join(m.opPath(p.Operation), "supersession.json")); !os.IsNotExist(e) {
		t.Fatal("inspection repaired terminal", e)
	}
	after, e := os.Lstat(p.Binary)
	if e != nil || !reloadStable(before, after) || *c != 1 {
		t.Fatal("inspection published or replayed STOP", e, *c)
	}
	recoveryRetained(t, m, old, retained)
}

func TestDesktopMigrationRecoveryInspectRejectsUnprovenCommitted(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		label := "missing"
		if terminal {
			label = "terminal"
		}
		t.Run(label, func(t *testing.T) {
			for _, kind := range []string{"helper-sha", "helper-version", "helper-config", "helper-loaded", "helper-running", "bundle", "canonical", "config", "backup", "stage", "old-stage", "old-sent", "response", "read", "sent", "marker", "other-pending", "reload", "ambiguous", "terminal-corrupt"} {
				t.Run(kind, func(t *testing.T) {
					m, h, c, old, _ := recoveryFixture(t)
					p := recoveryAwaiting(t, m)
					h.HelperSHA256, h.HelperVersion = p.BinarySHA256, currentVersion()
					if _, e := m.finish(p.Operation); e != nil {
						t.Fatal(e)
					}
					dir := m.opPath(p.Operation)
					term := filepath.Join(dir, "supersession.json")
					if !terminal {
						if e := os.Remove(term); e != nil {
							t.Fatal(e)
						}
					}
					switch kind {
					case "helper-sha":
						h.HelperSHA256 = strings.Repeat("b", 64)
					case "helper-version":
						h.HelperVersion = "wrong"
					case "helper-config":
						h.ConfigIdentity = strings.Repeat("b", 64)
					case "helper-loaded":
						h.Loaded = true
					case "helper-running":
						h.Running = true
					case "bundle":
						os.WriteFile(m.source, []byte("drift"), 0700)
					case "canonical":
						os.WriteFile(p.Binary, []byte("drift"), 0755)
					case "config":
						os.WriteFile(p.Config, []byte("drift"), 0600)
					case "backup":
						os.WriteFile(filepath.Join(dir, "old-binary"), []byte("drift"), 0700)
					case "stage":
						os.WriteFile(p.Stage, []byte("drift"), 0700)
					case "old-stage":
						os.WriteFile(old.Metadata.Stage, []byte("drift"), 0700)
					case "old-sent":
						os.WriteFile(filepath.Join(m.opPath(old.Metadata.Operation), ".sent"), []byte("START\n"), 0600)
					case "response":
						os.Remove(filepath.Join(dir, "stop-response.json"))
					case "read":
						os.WriteFile(filepath.Join(dir, "stop-read.json"), []byte("{}"), 0600)
					case "sent":
						os.Remove(filepath.Join(dir, ".sent"))
					case "marker":
						os.Remove(filepath.Join(dir, "evidence-schema"))
					case "other-pending":
						other := old
						other.Metadata.Operation = strings.Repeat("e", 64)
						other.Metadata.Stage = filepath.Join(m.home, ".anytls", ".desktop-candidate-"+other.Metadata.Operation)
						os.Mkdir(m.opPath(other.Metadata.Operation), 0700)
						m.save(other)
					case "reload":
						os.Mkdir(filepath.Join(m.home, ".anytls", ".core-reload-"+strings.Repeat("e", 32)), 0700)
					case "ambiguous":
						other, e := m.record(p.Operation)
						if e != nil {
							t.Fatal(e)
						}
						other.Metadata.Operation = strings.Repeat("f", 64)
						other.Metadata.Stage = filepath.Join(m.home, ".anytls", ".desktop-candidate-"+other.Metadata.Operation)
						otherDir := m.opPath(other.Metadata.Operation)
						os.Mkdir(otherDir, 0700)
						entries, e := os.ReadDir(dir)
						if e != nil {
							t.Fatal(e)
						}
						for _, entry := range entries {
							b, e := os.ReadFile(filepath.Join(dir, entry.Name()))
							if e != nil {
								t.Fatal(e)
							}
							mode := os.FileMode(0600)
							if entry.Name() == "old-binary" {
								mode = 0700
							}
							if e = os.WriteFile(filepath.Join(otherDir, entry.Name()), b, mode); e != nil {
								t.Fatal(e)
							}
						}
						if e = m.save(other); e != nil {
							t.Fatal(e)
						}
					case "terminal-corrupt":
						os.WriteFile(term, []byte("{}"), 0600)
					}
					// Snapshot all actual journal/stage/canonical/config leaves. An inspector
					// must neither repair faults nor publish even when the write seam is not
					// involved (e.g. an accidental direct os.WriteFile).
					before := map[string][]byte{}
					infos := map[string]os.FileInfo{}
					e := filepath.Walk(m.home, func(path string, info os.FileInfo, err error) error {
						if err != nil {
							return err
						}
						infos[path] = info
						if info.Mode().IsRegular() {
							b, e := os.ReadFile(path)
							if e != nil {
								return e
							}
							before[path] = b
						}
						return nil
					})
					if e != nil {
						t.Fatal(e)
					}
					m.journal = func(string, []byte, os.FileMode) error { t.Fatal("inspector write"); return os.ErrPermission }
					got, err := m.inspect()
					if err == nil || (got.Phase == "COMMITTED" && got.RecoveryOf != "") {
						t.Fatalf("unproven committed exposed: %+v %v", got, err)
					}
					seen := 0
					e = filepath.Walk(m.home, func(path string, info os.FileInfo, err error) error {
						if err != nil {
							return err
						}
						seen++
						prior, ok := infos[path]
						if !ok || !reloadStable(prior, info) {
							t.Fatalf("inspection changed identity %s", path)
						}
						if info.Mode().IsRegular() {
							b, e := os.ReadFile(path)
							if e != nil {
								return e
							}
							if !bytes.Equal(b, before[path]) {
								t.Fatalf("inspection changed bytes %s", path)
							}
						}
						return nil
					})
					if e != nil || seen != len(infos) || *c != 1 {
						t.Fatal("inspection mutation or STOP", e, seen, len(infos), *c)
					}
				})
			}
		})
	}
}

func TestDesktopMigrationRecoveryInspectTerminalCompletionLoss(t *testing.T) {
	m, h, c, old, retained := recoveryFixture(t)
	p := recoveryAwaiting(t, m)
	h.HelperSHA256, h.HelperVersion = p.BinarySHA256, currentVersion()
	p, e := m.finish(p.Operation)
	if e != nil {
		t.Fatal(e)
	}
	// Native may have saved READY but lost recovery DONE after Go committed.
	state := filepath.Join(m.home, ".anytls-desktop-state")
	if e = os.Mkdir(state, 0700); e != nil {
		t.Fatal(e)
	}
	intent, _ := json.Marshal(map[string]any{"schema": 1, "operation": p.Operation, "stage": p.Stage, "sha": p.BinarySHA256, "state": "READY", "resume": false})
	if e = os.WriteFile(filepath.Join(state, "authorization.json"), intent, 0600); e != nil {
		t.Fatal(e)
	}
	m.journal = func(string, []byte, os.FileMode) error { t.Fatal("inspect wrote"); return os.ErrPermission }
	got, err, code, wire := recoveryInspectWire(t, m)
	if got != p || err != nil || code != 0 {
		t.Fatalf("terminal recovery must survive app DONE loss: got=%+v err=%v code=%d", got, err, code)
	}
	t.Logf("RECOVERY_INSPECT_WIRE valid-terminal code=%d %s", code, wire)
	m.journal = nil
	if final, e := m.recoveryFinalize(p.Operation); e != nil || final != p {
		t.Fatal("idempotent no-STOP finalization", e)
	}
	if *c != 1 {
		t.Fatal("STOP replay", *c)
	}
	recoveryRetained(t, m, old, retained)
}
