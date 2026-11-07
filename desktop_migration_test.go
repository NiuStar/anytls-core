package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func migrationFixture(t *testing.T) (desktopMigration, *controlHelperResponse, *int) {
	t.Helper()
	home, source := desktopFixture(t)
	root := filepath.Join(home, ".anytls")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	for n, b := range map[string]string{"anytls-macos": "old image", "config.yaml": "proxies:\n - name: synthetic\n   password: fixture-secret\n   ca: CA.pem\nrules: [MATCH,DIRECT]\n", "config.yaml.selected": "synthetic", "webui.password": "synthetic-private-password", "CA.pem": "synthetic CA", "rules.json": "synthetic rules", "unknown": "keep me"} {
		mode := os.FileMode(0600)
		if n == "anytls-macos" {
			mode = 0700
		}
		if err := os.WriteFile(filepath.Join(root, n), []byte(b), mode); err != nil {
			t.Fatal(err)
		}
	}
	r := &controlHelperResponse{OK: true, HelperSHA256: desktopSum([]byte("protected old helper")), HelperVersion: "0.2.1", ConfigIdentity: desktopSum([]byte(filepath.Join(root, "config.yaml"))), Loaded: true, Running: true}
	calls := new(int)
	m := desktopMigration{home: home, source: source, uid: os.Getuid()}
	m.status = func(context.Context) (controlHelperResponse, error) { return *r, nil }
	m.stop = func(context.Context) (controlHelperResponse, error) {
		*calls++
		r.Loaded = false
		r.Running = false
		return *r, nil
	}
	return m, r, calls
}
func TestDesktopMigrationTransaction(t *testing.T) {
	for _, mode := range []os.FileMode{0700, 0755} {
		t.Run(mode.String(), func(t *testing.T) {
			m, r, calls := migrationFixture(t)
			root := filepath.Join(m.home, ".anytls")
			target := filepath.Join(root, "anytls-macos")
			os.Chmod(target, mode)
			before := map[string][]byte{}
			for _, n := range []string{"config.yaml", "config.yaml.selected", "webui.password", "CA.pem", "rules.json", "unknown"} {
				before[n], _ = os.ReadFile(filepath.Join(root, n))
			}
			p, e := m.inspect()
			if e != nil {
				t.Fatal(e)
			}
			if p.HelperVersion != "0.2.1" || !p.WasRunning {
				t.Fatal(p)
			}
			raw, _ := json.Marshal(p)
			if bytes.Contains(raw, []byte("fixture-secret")) || bytes.Contains(raw, []byte("synthetic-private-password")) {
				t.Fatal("secret exported")
			}
			originalStop := m.stop
			m.stop = func(ctx context.Context) (controlHelperResponse, error) {
				entries, _ := filepath.Glob(filepath.Join(root, ".desktop-migration-*", "plan.json"))
				if len(entries) != 1 {
					t.Fatal("intent not durable before STOP")
				}
				b, _ := os.ReadFile(entries[0])
				if !bytes.Contains(b, []byte("STOP_SENT")) {
					t.Fatal("missing intent")
				}
				old, _ := os.ReadFile(target)
				if string(old) != "old image" {
					t.Fatal("published before STOP")
				}
				return originalStop(ctx)
			}
			p, e = m.commit(p.Plan)
			if e != nil {
				t.Fatal(e)
			}
			if p.Phase != "AWAITING_HELPER" || *calls != 1 {
				t.Fatal(p, *calls)
			}
			old, _ := os.ReadFile(target)
			if string(old) != "old image" {
				t.Fatal("published before authorization")
			}
			stage, _ := os.ReadFile(p.Stage)
			if desktopSum(stage) != p.BinarySHA256 {
				t.Fatal("stage digest")
			}
			if _, e = m.finish(p.Operation); e == nil {
				t.Fatal("old helper accepted")
			}
			r.HelperSHA256 = p.BinarySHA256
			r.HelperVersion = currentVersion()
			p, e = m.finish(p.Operation)
			if e != nil || p.Phase != "COMMITTED" {
				t.Fatal(p, e)
			}
			if _, e = m.finish(p.Operation); e != nil || *calls != 1 {
				t.Fatal("finish replay", e)
			}
			for n, b := range before {
				got, _ := os.ReadFile(filepath.Join(root, n))
				if !bytes.Equal(got, b) {
					t.Fatal("changed", n)
				}
			}
			backup := filepath.Join(root, ".desktop-migration-"+p.Operation, "old-binary")
			b, e := os.ReadFile(backup)
			if e != nil || string(b) != "old image" {
				t.Fatal("backup", e)
			}
			s, _ := os.Stat(backup)
			if s.Mode().Perm() != 0700 {
				t.Fatal("backup mode")
			}
			s, _ = os.Stat(target)
			if s.Mode().Perm() != 0755 {
				t.Fatal("publication mode")
			}
		})
	}
}
func TestDesktopMigrationStopUncertaintyNoReplay(t *testing.T) {
	for _, kind := range []string{"timeout", "failed", "identity", "readback"} {
		t.Run(kind, func(t *testing.T) {
			m, r, calls := migrationFixture(t)
			p, e := m.inspect()
			if e != nil {
				t.Fatal(e)
			}
			m.stop = func(context.Context) (controlHelperResponse, error) {
				*calls++
				if kind == "timeout" {
					return controlHelperResponse{}, context.DeadlineExceeded
				}
				v := *r
				v.Loaded = false
				v.Running = false
				if kind == "failed" {
					v.Diagnostics = newStartDiagnostics("STOP")
					v.Diagnostics.Restoration = "FAILED"
				}
				if kind == "identity" {
					v.ConfigIdentity = strings.Repeat("a", 64)
				}
				return v, nil
			}
			_, e = m.commit(p.Plan)
			if e == nil {
				t.Fatal("uncertain STOP accepted")
			}
			_, e = m.commit(p.Plan)
			if e == nil || e.Error() != "MIGRATION_UNKNOWN" || *calls != 1 {
				t.Fatal("replay", e, *calls)
			}
			old, _ := os.ReadFile(filepath.Join(m.home, ".anytls", "anytls-macos"))
			if string(old) != "old image" {
				t.Fatal("old changed")
			}
			if _, e = m.inspect(); e == nil {
				t.Fatal("pending inspect not HOLD")
			}
		})
	}
}
func TestDesktopMigrationGuards(t *testing.T) {
	for _, kind := range []string{"legacy", "dual", "hardlink", "symlink", "source-link", "root-writable", "root-readonly", "pending", "foreign", "helper-config", "helper-unreadable", "config-drift", "selected-drift", "helper-drift", "inode-drift"} {
		t.Run(kind, func(t *testing.T) {
			m, r, calls := migrationFixture(t)
			root := filepath.Join(m.home, ".anytls")
			target := filepath.Join(root, "anytls-macos")
			p, e := m.inspect()
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "legacy":
				os.Rename(target, filepath.Join(root, "anytls"))
			case "dual":
				os.WriteFile(filepath.Join(root, "anytls"), []byte("legacy"), 0700)
			case "hardlink":
				os.Link(target, target+".link")
			case "symlink":
				os.Remove(target)
				os.Symlink(m.source, target)
			case "source-link":
				os.Rename(m.source, m.source+".real")
				os.Symlink(m.source+".real", m.source)
			case "root-writable":
				os.Chmod(root, 0777)
			case "root-readonly":
				os.Chmod(root, 0500)
				t.Cleanup(func() { os.Chmod(root, 0700) })
			case "pending":
				os.WriteFile(filepath.Join(root, ".core-reload-pending"), []byte("unknown"), 0600)
			case "foreign":
				os.Mkdir(filepath.Join(root, ".desktop-migration-foreign"), 0700)
			case "helper-config":
				r.ConfigIdentity = strings.Repeat("b", 64)
			case "helper-unreadable":
				m.status = func(context.Context) (controlHelperResponse, error) {
					return *r, errors.New("unreadable protected image")
				}
			case "config-drift":
				os.WriteFile(filepath.Join(root, "config.yaml"), []byte("drift"), 0600)
			case "selected-drift":
				os.WriteFile(filepath.Join(root, "config.yaml.selected"), []byte("drift"), 0600)
			case "helper-drift":
				r.HelperSHA256 = strings.Repeat("c", 64)
			case "inode-drift":
				os.Rename(target, target+".old")
				os.WriteFile(target, []byte("old image"), 0700)
			}
			if _, e = m.commit(p.Plan); e == nil {
				t.Fatal("unsafe accepted")
			}
			if *calls != 0 {
				t.Fatal("STOP before guard")
			}
		})
	}
}
func TestDesktopMigrationStoppedStillStops(t *testing.T) {
	m, r, c := migrationFixture(t)
	r.Loaded = false
	r.Running = false
	p, e := m.inspect()
	if e != nil {
		t.Fatal(e)
	}
	p, e = m.commit(p.Plan)
	if e != nil || *c != 1 || p.WasRunning {
		t.Fatal(p, e, *c)
	}
}
func TestDesktopMigrationFinishDrift(t *testing.T) {
	for _, kind := range []string{"config", "stage", "runtime", "helper-running"} {
		t.Run(kind, func(t *testing.T) {
			m, r, c := migrationFixture(t)
			p, _ := m.inspect()
			p, e := m.commit(p.Plan)
			if e != nil {
				t.Fatal(e)
			}
			r.HelperSHA256 = p.BinarySHA256
			r.HelperVersion = currentVersion()
			switch kind {
			case "config":
				os.WriteFile(p.Config, []byte("drift"), 0600)
			case "stage":
				os.WriteFile(p.Stage, []byte("drift"), 0700)
			case "runtime":
				os.WriteFile(p.Binary, []byte("drift"), 0700)
			case "helper-running":
				r.Running = true
			}
			if _, e = m.finish(p.Operation); e == nil {
				t.Fatal("drift accepted")
			}
			if *c != 1 {
				t.Fatal("STOP replay")
			}
		})
	}
}
func TestDesktopMigrationPostCaptureDrift(t *testing.T) {
	for _, kind := range []string{"config", "helper", "parent"} {
		t.Run(kind, func(t *testing.T) {
			m, r, c := migrationFixture(t)
			p, _ := m.inspect()
			original := m.status
			reads := 0
			m.status = func(ctx context.Context) (controlHelperResponse, error) {
				reads++
				if reads == 2 {
					switch kind {
					case "config":
						os.WriteFile(filepath.Join(m.home, ".anytls", "config.yaml"), []byte("late drift"), 0600)
					case "helper":
						r.HelperSHA256 = strings.Repeat("e", 64)
					case "parent":
						root := filepath.Join(m.home, ".anytls")
						os.Rename(root, root+".saved")
						os.Mkdir(root, 0700)
					}
				}
				return original(ctx)
			}
			if _, e := m.commit(p.Plan); e == nil || *c != 0 {
				t.Fatal("late drift", e, *c)
			}
		})
	}
}
func TestDesktopMigrationDiagnostics(t *testing.T) {
	if !migrationAck(controlHelperResponse{}) {
		t.Fatal("legacy absent diagnostics")
	}
	for _, field := range []string{"outcome", "restoration", "cleanup", "receipt", "operation", "schema"} {
		for _, bad := range []string{"FAILED", "UNKNOWN"} {
			d := newStartDiagnostics("STOP")
			d.Restoration = "VERIFIED"
			d.Cleanup = "VERIFIED"
			d.Receipt = "WRITTEN"
			switch field {
			case "outcome":
				d.Outcome = bad
			case "restoration":
				d.Restoration = bad
			case "cleanup":
				d.Cleanup = bad
			case "receipt":
				d.Receipt = bad
			case "operation":
				d.Operation = "START"
			case "schema":
				d.Schema = 2
			}
			if migrationAck(controlHelperResponse{Diagnostics: d}) {
				t.Fatal(field, bad)
			}
		}
	}
	for _, v := range []string{"NOT_ATTEMPTED", "VERIFIED"} {
		d := newStartDiagnostics("STOP")
		d.Restoration = v
		d.Cleanup = v
		if !migrationAck(controlHelperResponse{Diagnostics: d}) {
			t.Fatal(v)
		}
	}
}
func TestDesktopMigrationCrashJournal(t *testing.T) {
	for _, phase := range []string{"STOP_SENT", "STOP_VERIFIED", "AWAITING_HELPER", "PUBLISHING", "COMMITTED"} {
		t.Run(phase, func(t *testing.T) {
			m, r, c := migrationFixture(t)
			p, _ := m.inspect()
			m.journal = func(path string, b []byte, mode os.FileMode) error {
				var rec desktopMigrationRecord
				if json.Unmarshal(b, &rec) != nil {
					t.Fatal("journal")
				}
				if rec.Metadata.Phase == phase {
					return errors.New("injected fsync failure")
				}
				return controlInstallAtomic(path, b, mode)
			}
			result, e := m.commit(p.Plan)
			if phase == "PUBLISHING" || phase == "COMMITTED" {
				if e != nil {
					t.Fatal(e)
				}
				r.HelperSHA256 = result.BinarySHA256
				r.HelperVersion = currentVersion()
				_, e = m.finish(result.Operation)
			}
			if e == nil {
				t.Fatal("fault ignored")
			}
			sent := *c
			if _, e = m.commit(p.Plan); e == nil || *c != sent {
				t.Fatal("crash replay", e, *c)
			}
			old, _ := os.ReadFile(filepath.Join(m.home, ".anytls", "anytls-macos"))
			if phase == "COMMITTED" {
				if desktopSum(old) != result.BinarySHA256 {
					t.Fatal("expected published but uncertain")
				}
			} else if string(old) != "old image" {
				t.Fatal("publication before durable phase")
			}
		})
	}
}
func TestDesktopMigrationLockAndReadOnly(t *testing.T) {
	m, _, c := migrationFixture(t)
	root := filepath.Join(m.home, ".anytls")
	before, _ := os.ReadDir(root)
	p, e := m.inspect()
	if e != nil {
		t.Fatal(e)
	}
	after, _ := os.ReadDir(root)
	if len(before) != len(after) {
		t.Fatal("inspection wrote")
	}
	lock, e := m.lock()
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	if _, e = m.commit(p.Plan); e == nil || e.Error() != "INSTALL_BUSY" || *c != 0 {
		t.Fatal(e, *c)
	}
}
func TestDesktopMigrationPendingReadback(t *testing.T) {
	m, r, c := migrationFixture(t)
	p, _ := m.inspect()
	p, e := m.commit(p.Plan)
	if e != nil {
		t.Fatal(e)
	}
	held, e := m.inspect()
	if e == nil || held.Operation != p.Operation || held.Phase != "AWAITING_HELPER" || *c != 1 {
		t.Fatal(held, e)
	}
	if _, e = m.commit(p.Plan); e == nil || *c != 1 {
		t.Fatal("pending replay")
	}
	r.HelperSHA256 = p.BinarySHA256
	r.HelperVersion = currentVersion()
	if _, e = m.finish(p.Operation); e != nil {
		t.Fatal(e)
	}
}
func TestDesktopMigrationArguments(t *testing.T) {
	for _, a := range [][]string{{"migration-inspect", "extra"}, {"migration-commit"}, {"migration-commit", "../x"}, {"migration-finish", strings.Repeat("A", 64)}, {"migration-finish", strings.Repeat("0", 63)}} {
		var b bytes.Buffer
		if desktopDispatch(a, &b) == nil || !strings.Contains(b.String(), "INVALID_COMMAND") {
			t.Fatal(a, b.String())
		}
	}
}
