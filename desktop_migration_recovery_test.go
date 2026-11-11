package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Semantic baseline: the closed production dispatcher must recognize the new
// command, not fail compilation because a future Go method is absent.
func TestDesktopMigrationRecoveryCommandContract(t *testing.T) {
	var b bytes.Buffer
	_ = desktopDispatch([]string{"migration-recovery-inspect"}, &b)
	if strings.Contains(b.String(), "INVALID_COMMAND") {
		t.Fatal("explicit legacy recovery command is not implemented")
	}
}

func recoveryFixture(t *testing.T) (desktopMigration, *controlHelperResponse, *int, desktopMigrationRecord, map[string][]byte) {
	t.Helper()
	m, h, c := migrationIncumbentFixture(t)
	m.recoveryDiagnostic = func(reason string) { t.Log("RECOVERY_REJECTION", reason) }
	// The original preview observed running; current recovery observes stopped.
	h.Loaded = true
	h.Running = true
	old, e := m.preflight()
	if e != nil {
		t.Fatal(e)
	}
	old.EvidenceSchema = 0
	old.Metadata.Plan = ""
	legacyRaw, _ := json.Marshal(struct {
		Record desktopMigrationRecord
		Loaded bool
	}{old, old.WasLoaded})
	legacyRaw = bytes.Replace(legacyRaw, []byte(`"EvidenceSchema":0,`), nil, 1)
	old.Metadata.Plan = desktopSum(legacyRaw)
	old.Metadata.Operation = strings.Repeat("1", 64)
	old.Metadata.Stage = filepath.Join(m.home, ".anytls", ".desktop-candidate-"+old.Metadata.Operation)
	old.Metadata.Phase = "UNKNOWN"
	old.Action = "STOP"
	if e = os.Mkdir(m.opPath(old.Metadata.Operation), 0700); e != nil {
		t.Fatal(e)
	}
	image, e := os.ReadFile(m.source)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(old.Metadata.Stage, image, 0700); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(old)
	raw = bytes.Replace(raw, []byte(`"EvidenceSchema":0,`), nil, 1)
	if e = os.WriteFile(filepath.Join(m.opPath(old.Metadata.Operation), "plan.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(m.opPath(old.Metadata.Operation), ".sent"), []byte("STOP\n"), 0600); e != nil {
		t.Fatal(e)
	}
	h.Loaded = false
	h.Running = false
	if e = os.WriteFile(m.source, []byte("new App B image"), 0700); e != nil {
		t.Fatal(e)
	}
	before := map[string][]byte{}
	for _, p := range []string{old.Metadata.Stage, filepath.Join(m.opPath(old.Metadata.Operation), "plan.json"), filepath.Join(m.opPath(old.Metadata.Operation), ".sent"), old.Metadata.Config, filepath.Join(m.home, ".anytls", "webui.password")} {
		before[p], e = os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
	}
	return m, h, c, old, before
}
func recoveryRetained(t *testing.T, m desktopMigration, old desktopMigrationRecord, before map[string][]byte) {
	t.Helper()
	for p, b := range before {
		got, e := os.ReadFile(p)
		if e != nil || !bytes.Equal(got, b) {
			t.Fatal("historical/config bytes changed", p, e)
		}
	}
	entries, e := os.ReadDir(m.opPath(old.Metadata.Operation))
	if e != nil || len(entries) != 2 {
		t.Fatal("old membership", e)
	}
	r, e := m.record(old.Metadata.Operation)
	if e != nil || r.Metadata.Phase != "UNKNOWN" {
		t.Fatal("old outcome rewritten", e)
	}
}
func recoveryAwaiting(t *testing.T, m desktopMigration) desktopMigrationMetadata {
	t.Helper()
	r, e := m.recoveryPreview()
	if e != nil {
		t.Fatal("preview", e)
	}
	p, e := m.commitMigration(r.Metadata.Plan, true)
	if e != nil {
		t.Fatal("commit", e)
	}
	return p
}
func TestDesktopMigrationRecoveryHappy(t *testing.T) {
	m, h, c, old, before := recoveryFixture(t)
	if m.pending("") == nil {
		t.Fatal("implicit recovery")
	}
	if _, e := m.finish(old.Metadata.Operation); e == nil {
		t.Fatal("old finish")
	}
	r, e := m.recoveryPreview()
	if e != nil {
		t.Fatal(e)
	}
	if r.Metadata.Phase != "RECOVERY_INSPECTED" || r.Metadata.WasRunning || r.Metadata.BinarySHA256 == old.Metadata.BinarySHA256 || r.Metadata.RecoveryOf != old.Metadata.Operation {
		t.Fatal(r.Metadata)
	}
	stop := m.stop
	m.stop = func(ctx context.Context, id string) (st.MutationResponse, error) {
		if !reloadID.MatchString(id) || id == old.StopOperation {
			t.Fatal("not fresh STOP")
		}
		records, e := m.recoveryRecords()
		if e != nil {
			t.Fatal(e)
		}
		found := false
		for op, v := range records {
			if op != old.Metadata.Operation {
				if v.StopOperation != id || v.Metadata.Phase != "STOP_SENT" || v.Recovery == nil {
					t.Fatal("missing durable fresh intent")
				}
				found = true
			}
		}
		if !found {
			t.Fatal("no new transaction")
		}
		recoveryRetained(t, m, old, before)
		return stop(ctx, id)
	}
	p, e := m.commitMigration(r.Metadata.Plan, true)
	if e != nil {
		t.Fatal(e)
	}
	rec, err := m.record(p.Operation)
	if err != nil || rec.StopDisposition != "NEW_STOP_CONFIRMED_NO_BASELINE" {
		t.Fatal("missing explicit new STOP disposition", err, rec.StopDisposition)
	}
	if p.Operation == old.Metadata.Operation || p.Stage == old.Metadata.Stage || p.Phase != "AWAITING_HELPER" || *c != 1 {
		t.Fatal(p, *c)
	}
	held, e := m.inspect()
	if e == nil || held.Operation != p.Operation {
		t.Fatal("auth continuation metadata", held, e)
	}
	if _, e = m.finish(p.Operation); e == nil {
		t.Fatal("no explicit helper auth/readiness")
	}
	h.HelperSHA256 = p.BinarySHA256
	h.HelperVersion = currentVersion()
	p, e = m.finish(p.Operation)
	if e != nil || p.Phase != "COMMITTED" {
		t.Fatal(p, e)
	}
	if e = m.pending(""); e != nil {
		t.Fatal("terminal admission", e)
	}
	if _, e = m.recoveryPreview(); e == nil {
		t.Fatal("second recovery")
	}
	if *c != 1 {
		t.Fatal("replayed STOP", *c)
	}
	recoveryRetained(t, m, old, before)
}
func TestDesktopMigrationRecoveryFinalizeOnly(t *testing.T) {
	m, h, c, old, before := recoveryFixture(t)
	p := recoveryAwaiting(t, m)
	h.HelperSHA256 = p.BinarySHA256
	h.HelperVersion = currentVersion()
	m.journal = func(path string, b []byte, mode os.FileMode) error {
		if filepath.Base(path) == "supersession.json" {
			return errors.New("terminal fsync fault")
		}
		return controlInstallAtomic(path, b, mode)
	}
	if _, e := m.finish(p.Operation); e == nil {
		t.Fatal("terminal fault ignored")
	}
	r, e := m.record(p.Operation)
	if e != nil || r.Metadata.Phase != "COMMITTED" {
		t.Fatal(r, e)
	}
	if m.pending("") == nil {
		t.Fatal("committed-only waiver")
	}
	if _, e = m.inspect(); e == nil {
		t.Fatal("inspector repaired")
	}
	if _, e = os.Lstat(filepath.Join(m.opPath(p.Operation), "supersession.json")); !os.IsNotExist(e) {
		t.Fatal("inspector wrote terminal")
	}
	m.journal = nil
	beforeBinary, e := os.Lstat(p.Binary)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.recoveryFinalize(p.Operation); e != nil {
		t.Fatal(e)
	}
	afterBinary, e := os.Lstat(p.Binary)
	if e != nil || !reloadStable(beforeBinary, afterBinary) {
		t.Fatal("finalizer republished canonical", e)
	}
	if *c != 1 {
		t.Fatal("finalization STOP")
	}
	recoveryRetained(t, m, old, before)
}
func TestDesktopMigrationRecoveryEligibility(t *testing.T) {
	for _, kind := range []string{"two", "reload", "sent", "extra", "old-stage", "old-stage-link", "old-plan-alias", "config", "binary", "helper", "helper-version", "auth-armed", "auth-alias", "auth-directory", "backup", "stop-binding", "lock", "old-token", "reserved-case"} {
		t.Run(kind, func(t *testing.T) {
			m, h, c, old, _ := recoveryFixture(t)
			r, e := m.recoveryPreview()
			if e != nil {
				t.Fatal(e)
			}
			root := filepath.Join(m.home, ".anytls")
			switch kind {
			case "two":
				x := old
				x.Metadata.Operation = strings.Repeat("2", 64)
				x.Metadata.Stage = filepath.Join(root, ".desktop-candidate-"+x.Metadata.Operation)
				os.Mkdir(m.opPath(x.Metadata.Operation), 0700)
				m.save(x)
			case "reload":
				os.Mkdir(filepath.Join(root, ".core-reload-"+strings.Repeat("3", 32)), 0700)
			case "sent":
				os.WriteFile(filepath.Join(m.opPath(old.Metadata.Operation), ".sent"), []byte("START\n"), 0600)
			case "extra":
				os.WriteFile(filepath.Join(m.opPath(old.Metadata.Operation), "extra"), []byte("x"), 0600)
			case "old-stage":
				os.WriteFile(old.Metadata.Stage, []byte("drift"), 0700)
			case "old-stage-link":
				os.Link(old.Metadata.Stage, old.Metadata.Stage+".link")
			case "old-plan-alias":
				p := filepath.Join(m.opPath(old.Metadata.Operation), "plan.json")
				b, _ := os.ReadFile(p)
				os.WriteFile(p, bytes.Replace(b, []byte(`"Metadata"`), []byte(`"metadata"`), 1), 0600)
			case "config":
				os.WriteFile(old.Metadata.Config, []byte("drift"), 0600)
			case "binary":
				os.WriteFile(old.Metadata.Binary, []byte("drift"), 0700)
			case "helper":
				h.HelperSHA256 = strings.Repeat("b", 64)
			case "helper-version":
				h.HelperVersion = "different"
			case "backup":
				old.BackupSHA256 = strings.Repeat("a", 64)
				m.save(old)
			case "stop-binding":
				old.StopOperation = strings.Repeat("a", 32)
				m.save(old)
			case "old-token":
				old.Metadata.Plan = strings.Repeat("a", 64)
				m.save(old)
			case "reserved-case":
				os.Mkdir(filepath.Join(root, ".Desktop-Migration-"+strings.Repeat("f", 64)), 0700)
			case "lock":
				l, e := m.lock()
				if e != nil {
					t.Fatal(e)
				}
				defer l.Close()
			default:
				d := filepath.Join(m.home, ".anytls-desktop-state")
				os.Mkdir(d, 0700)
				if kind == "auth-directory" {
					os.Mkdir(filepath.Join(d, "authorization.json"), 0700)
				} else {
					state := "ARMED"
					if kind == "auth-alias" {
						state = "DONE"
					}
					b, _ := json.Marshal(map[string]any{"schema": 1, "operation": old.Metadata.Operation, "stage": old.Metadata.Stage, "sha": old.Metadata.BinarySHA256, "state": state, "resume": false})
					if kind == "auth-alias" {
						b = bytes.Replace(b, []byte(`"state"`), []byte(`"State"`), 1)
					}
					os.WriteFile(filepath.Join(d, "authorization.json"), b, 0600)
				}
			}
			if _, e = m.commitMigration(r.Metadata.Plan, true); e == nil || *c != 0 {
				t.Fatal("eligibility bypass", e, *c)
			}
		})
	}
}
func TestDesktopMigrationRecoveryNoRetry(t *testing.T) {
	for _, kind := range []string{"STOP_SENT", "STOP_VERIFIED", "AWAITING_HELPER", "lost-ack", "lost-read", "ack-write", "proof-write", "old-drift-on-stage"} {
		t.Run(kind, func(t *testing.T) {
			m, _, c, old, _ := recoveryFixture(t)
			r, e := m.recoveryPreview()
			if e != nil {
				t.Fatal(e)
			}
			m.journal = func(path string, b []byte, mode os.FileMode) error {
				var v desktopMigrationRecord
				json.Unmarshal(b, &v)
				if v.Metadata.Phase == kind {
					return errors.New("injected journal fault")
				}
				if kind == "proof-write" && v.StopReadSHA256 != "" {
					return errors.New("injected proof link fault")
				}
				if kind == "old-drift-on-stage" {
					os.WriteFile(old.Metadata.Stage, []byte("drift"), 0700)
				}
				return controlInstallAtomic(path, b, mode)
			}
			stop := m.stop
			m.stop = func(ctx context.Context, id string) (st.MutationResponse, error) {
				a, e := stop(ctx, id)
				if kind == "lost-ack" {
					e = context.DeadlineExceeded
				}
				if kind == "ack-write" {
					records, _ := m.recoveryRecords()
					for op := range records {
						if op != old.Metadata.Operation {
							os.Mkdir(filepath.Join(m.opPath(op), "stop-response.json"), 0700)
						}
					}
				}
				return a, e
			}
			read := m.stopRead
			m.stopRead = func(ctx context.Context, id *string) (st.ReadResponse, error) {
				v, e := read(ctx, id)
				if kind == "lost-read" {
					e = context.DeadlineExceeded
				}
				return v, e
			}
			if _, e = m.commitMigration(r.Metadata.Plan, true); e == nil {
				t.Fatal("fault ignored")
			}
			sent := *c
			if _, e = m.commitMigration(r.Metadata.Plan, true); e == nil || *c != sent {
				t.Fatal("replayed", e, *c)
			}
			if _, e = m.recoveryPreview(); e == nil {
				t.Fatal("uncertain recovered implicitly")
			}
			b, _ := os.ReadFile(old.Metadata.Binary)
			if string(b) != "old image" {
				t.Fatal("canonical published")
			}
		})
	}
}
func TestDesktopMigrationRecoveryTerminalSafety(t *testing.T) {
	for _, kind := range []string{"missing", "alias", "old-outcome", "digest", "old-bytes", "old-stage", "response", "duplicate", "chain", "dangling", "other-pending", "final-plan"} {
		t.Run(kind, func(t *testing.T) {
			m, h, c, old, _ := recoveryFixture(t)
			p := recoveryAwaiting(t, m)
			h.HelperSHA256 = p.BinarySHA256
			h.HelperVersion = currentVersion()
			if _, e := m.finish(p.Operation); e != nil {
				t.Fatal(e)
			}
			terminal := filepath.Join(m.opPath(p.Operation), "supersession.json")
			switch kind {
			case "missing":
				os.Remove(terminal)
			case "alias":
				b, _ := os.ReadFile(terminal)
				os.WriteFile(terminal, bytes.Replace(b, []byte(`"old_outcome"`), []byte(`"Old_outcome"`), 1), 0600)
			case "old-outcome":
				b, _ := os.ReadFile(terminal)
				os.WriteFile(terminal, bytes.Replace(b, []byte(`"UNKNOWN"`), []byte(`"SUCCEEDED"`), 1), 0600)
			case "digest":
				b, _ := os.ReadFile(terminal)
				var v migrationRecoveryTerminal
				json.Unmarshal(b, &v)
				v.StopReadSHA256 = strings.Repeat("a", 64)
				b, _ = json.Marshal(v)
				os.WriteFile(terminal, b, 0600)
			case "old-bytes":
				path := filepath.Join(m.opPath(old.Metadata.Operation), "plan.json")
				b, _ := os.ReadFile(path)
				os.WriteFile(path, append(b, ' '), 0600)
			case "old-stage":
				os.WriteFile(old.Metadata.Stage, []byte("drift"), 0700)
			case "response":
				os.Remove(filepath.Join(m.opPath(p.Operation), "stop-response.json"))
			case "final-plan":
				v, _ := m.record(p.Operation)
				v.WasLoaded = !v.WasLoaded
				m.save(v)
			case "other-pending":
				x := old
				x.Metadata.Operation = strings.Repeat("0", 64)
				x.Metadata.Stage = filepath.Join(m.home, ".anytls", ".desktop-candidate-"+x.Metadata.Operation)
				os.Mkdir(m.opPath(x.Metadata.Operation), 0700)
				m.save(x)
			default:
				x, _ := m.record(p.Operation)
				if kind == "duplicate" {
					x.Metadata.Operation = strings.Repeat("f", 64)
					x.Metadata.Stage = filepath.Join(m.home, ".anytls", ".desktop-candidate-"+x.Metadata.Operation)
					os.Mkdir(m.opPath(x.Metadata.Operation), 0700)
				}
				if kind == "chain" {
					x.Recovery.OldOperation = p.Operation
					x.Metadata.RecoveryOf = p.Operation
				}
				if kind == "dangling" {
					x.Recovery.OldOperation = strings.Repeat("f", 64)
					x.Metadata.RecoveryOf = x.Recovery.OldOperation
				}
				m.save(x)
			}
			if m.pending("") == nil {
				t.Fatal("malformed terminal accepted")
			}
			if *c != 1 {
				t.Fatal("replayed")
			}
		})
	}
}

func TestDesktopMigrationRecoveryInspectReadonlyAndLock(t *testing.T) {
	m, _, c, old, before := recoveryFixture(t)
	lock, e := m.lock()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.recoveryInspect(); e == nil || e.Error() != "INSTALL_BUSY" {
		t.Fatal("shared lock", e)
	}
	lock.Close()
	a, e := os.ReadDir(filepath.Join(m.home, ".anytls"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.recoveryInspect(); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadDir(filepath.Join(m.home, ".anytls"))
	if e != nil || len(a) != len(b) || *c != 0 {
		t.Fatal("inspector mutated", e)
	}
	recoveryRetained(t, m, old, before)
	// Separate native recovery intent must not conflict with its own operation.
	dir := filepath.Join(m.home, ".anytls-desktop-state")
	os.Mkdir(dir, 0700)
	os.WriteFile(filepath.Join(dir, "recovery.json"), []byte(`{"schema":1,"state":"RECOVERY_ARMED"}`), 0600)
	if _, e = m.recoveryInspect(); e != nil {
		t.Fatal("own recovery consent treated as helper auth", e)
	}
}
func TestDesktopMigrationRecoveryActiveProofOnly(t *testing.T) {
	for _, kind := range []string{"missing-response", "malformed-read", "sent-missing", "backup", "old-drift", "other-pending", "self", "proofless", "format-missing"} {
		t.Run(kind, func(t *testing.T) {
			m, h, c, old, _ := recoveryFixture(t)
			p := recoveryAwaiting(t, m)
			h.HelperSHA256 = p.BinarySHA256
			h.HelperVersion = currentVersion()
			dir := m.opPath(p.Operation)
			switch kind {
			case "missing-response":
				os.Remove(filepath.Join(dir, "stop-response.json"))
			case "malformed-read":
				os.WriteFile(filepath.Join(dir, "stop-read.json"), []byte(`{"Trace":null}`), 0600)
			case "sent-missing":
				os.Remove(filepath.Join(dir, ".sent"))
			case "backup":
				os.WriteFile(filepath.Join(dir, "old-binary"), []byte("drift"), 0700)
			case "old-drift":
				os.WriteFile(old.Metadata.Stage, []byte("drift"), 0700)
			case "other-pending":
				os.Mkdir(filepath.Join(m.home, ".anytls", ".core-reload-"+strings.Repeat("b", 32)), 0700)
			case "self":
				r, _ := m.record(p.Operation)
				r.Recovery.OldOperation = p.Operation
				r.Metadata.RecoveryOf = p.Operation
				m.save(r)
			case "format-missing":
				path := filepath.Join(dir, "plan.json")
				raw, _ := os.ReadFile(path)
				var v map[string]any
				json.Unmarshal(raw, &v)
				delete(v, "EvidenceSchema")
				raw, _ = json.Marshal(v)
				os.WriteFile(path, raw, 0600)
			case "proofless":
				r, _ := m.record(p.Operation)
				r.StopOperation = ""
				r.StopResponseSHA256 = ""
				r.StopReadSHA256 = ""
				m.save(r)
			}
			if _, e := m.finish(p.Operation); e == nil {
				t.Fatal("active state-only authority")
			}
			target, _ := os.ReadFile(p.Binary)
			if string(target) != "old image" || *c != 1 {
				t.Fatal("publication or STOP replay")
			}
		})
	}
}
func TestDesktopMigrationRecoveryPublicationFaults(t *testing.T) {
	for _, phase := range []string{"PUBLISHING", "COMMITTED"} {
		t.Run(phase, func(t *testing.T) {
			m, h, c, old, before := recoveryFixture(t)
			p := recoveryAwaiting(t, m)
			h.HelperSHA256 = p.BinarySHA256
			h.HelperVersion = currentVersion()
			m.journal = func(path string, b []byte, mode os.FileMode) error {
				var r desktopMigrationRecord
				json.Unmarshal(b, &r)
				if r.Metadata.Phase == phase {
					return errors.New("injected publication journal fault")
				}
				return controlInstallAtomic(path, b, mode)
			}
			if _, e := m.finish(p.Operation); e == nil {
				t.Fatal("fault ignored")
			}
			if m.pending("") == nil {
				t.Fatal("uncertain publication admitted")
			}
			if _, e := m.commitMigration(p.Plan, true); e == nil || *c != 1 {
				t.Fatal("uncertain replay")
			}
			if _, e := m.recoveryFinalize(p.Operation); e == nil {
				t.Fatal("noncommitted finalize")
			}
			recoveryRetained(t, m, old, before)
		})
	}
}

func TestDesktopMigrationRecoveryUnsafeHistory(t *testing.T) {
	for _, kind := range []string{"sent-fifo", "sent-hardlink", "plan-link", "dir-link", "stage-symlink", "terminal-symlink", "terminal-hardlink", "terminal-duplicate", "terminal-recomputed-semantic", "cycle"} {
		t.Run(kind, func(t *testing.T) {
			m, h, c, old, _ := recoveryFixture(t)
			if strings.HasPrefix(kind, "terminal-") || kind == "cycle" {
				p := recoveryAwaiting(t, m)
				h.HelperSHA256 = p.BinarySHA256
				h.HelperVersion = currentVersion()
				if _, e := m.finish(p.Operation); e != nil {
					t.Fatal(e)
				}
				path := filepath.Join(m.opPath(p.Operation), "supersession.json")
				b, _ := os.ReadFile(path)
				switch kind {
				case "terminal-symlink":
					os.Rename(path, path+".saved")
					os.Symlink(path+".saved", path)
				case "terminal-hardlink":
					os.Link(path, path+".link")
				case "terminal-duplicate":
					b = append([]byte(`{"old_outcome":"UNKNOWN",`), b[1:]...)
					os.WriteFile(path, b, 0600)
				case "terminal-recomputed-semantic":
					r, _ := m.record(p.Operation)
					r.Recovery.OldPlan = strings.Repeat("e", 64)
					m.save(r)
				case "cycle":
					r, _ := m.record(p.Operation)
					old.Recovery = &desktopMigrationRecovery{OldOperation: p.Operation}
					old.Metadata.RecoveryOf = p.Operation
					m.save(old)
					r.Recovery.OldOperation = old.Metadata.Operation
					m.save(r)
				}
				if m.pending("") == nil || *c != 1 {
					t.Fatal("unsafe terminal admitted")
				}
				return
			}
			switch kind {
			case "sent-fifo":
				path := filepath.Join(m.opPath(old.Metadata.Operation), ".sent")
				os.Remove(path)
				if e := syscall.Mkfifo(path, 0600); e != nil {
					t.Fatal(e)
				}
			case "sent-hardlink":
				path := filepath.Join(m.opPath(old.Metadata.Operation), ".sent")
				os.Link(path, filepath.Join(m.home, "sent-link"))
			case "plan-link":
				path := filepath.Join(m.opPath(old.Metadata.Operation), "plan.json")
				os.Rename(path, filepath.Join(m.home, "plan-saved"))
				os.Symlink(filepath.Join(m.home, "plan-saved"), path)
			case "dir-link":
				path := m.opPath(old.Metadata.Operation)
				os.Rename(path, filepath.Join(m.home, "old-saved"))
				os.Symlink(filepath.Join(m.home, "old-saved"), path)
			case "stage-symlink":
				os.Rename(old.Metadata.Stage, old.Metadata.Stage+".saved")
				os.Symlink(old.Metadata.Stage+".saved", old.Metadata.Stage)
			}
			if _, e := m.recoveryPreview(); e == nil || *c != 0 {
				t.Fatal("unsafe history admitted")
			}
		})
	}
}

func TestDesktopMigrationRecoveryNilDiagnosticsRefused(t *testing.T) {
	m, _, c, _, _ := recoveryFixture(t)
	r, e := m.recoveryPreview()
	if e != nil {
		t.Fatal(e)
	}
	stop := m.stop
	m.stop = func(ctx context.Context, id string) (st.MutationResponse, error) {
		a, e := stop(ctx, id)
		a.Diagnostics = nil
		return a, e
	}
	read := m.stopRead
	m.stopRead = func(ctx context.Context, id *string) (st.ReadResponse, error) {
		v, e := read(ctx, id)
		v.Trace.Diagnostics = nil
		return v, e
	}
	if _, e = m.commitMigration(r.Metadata.Plan, true); e == nil {
		t.Fatal("diagnostic-free recovery authority")
	}
	if _, e = m.commitMigration(r.Metadata.Plan, true); e == nil || *c != 1 {
		t.Fatal("nil diagnostic STOP replay")
	}
}

func TestDesktopMigrationRecoveryArguments(t *testing.T) {
	for _, args := range [][]string{{"migration-recovery-inspect", "extra"}, {"migration-recovery-commit"}, {"migration-recovery-commit", strings.Repeat("A", 64)}, {"migration-recovery-finalize", strings.Repeat("a", 32)}, {"migration-recovery-finalize", "../escape"}, {"migration-recovery-finalize", strings.Repeat("0", 64), "extra"}} {
		var out bytes.Buffer
		if desktopDispatch(args, &out) == nil || !strings.Contains(out.String(), "INVALID_COMMAND") {
			t.Fatal(args, out.String())
		}
	}
}
func TestDesktopMigrationRecoverySafeDoneIntent(t *testing.T) {
	m, _, _, old, _ := recoveryFixture(t)
	// An earlier safely completed authorization must reference a real different
	// COMMITTED migration. It cannot stand in for recovery consent or new auth.
	historical := old
	historical.Metadata.Operation = strings.Repeat("8", 64)
	historical.Metadata.Stage = filepath.Join(m.home, ".anytls", ".desktop-candidate-"+historical.Metadata.Operation)
	historical.Metadata.Phase = "COMMITTED"
	historical.BackupSHA256 = historical.Metadata.OldBinarySHA256
	dir := m.opPath(historical.Metadata.Operation)
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e := m.save(historical); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, ".sent"), []byte("STOP\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, "old-binary"), []byte("old image"), 0700); e != nil {
		t.Fatal(e)
	}
	state := filepath.Join(m.home, ".anytls-desktop-state")
	if e := os.Mkdir(state, 0700); e != nil {
		t.Fatal(e)
	}
	intent := map[string]any{"schema": 1, "operation": historical.Metadata.Operation, "stage": historical.Metadata.Stage, "sha": historical.Metadata.BinarySHA256, "state": "DONE", "resume": false}
	b, _ := json.Marshal(intent)
	if e := os.WriteFile(filepath.Join(state, "authorization.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := m.recoveryPreview(); e != nil {
		t.Fatal("safe DONE intent rejected", e)
	}
	intent["resume"] = true
	b, _ = json.Marshal(intent)
	os.WriteFile(filepath.Join(state, "authorization.json"), b, 0600)
	if _, e := m.recoveryPreview(); e == nil {
		t.Fatal("unfinished activation permission accepted")
	}
}
