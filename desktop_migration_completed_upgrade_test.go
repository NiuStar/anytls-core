package main

import (
	"bytes"
	"context"
	"encoding/json"
	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
	"os"
	"path/filepath"
	"testing"
)

func completedRecoveryFixture(t *testing.T) (desktopMigration, *controlHelperResponse, *int, desktopMigrationRecord, map[string][]byte, desktopMigrationMetadata) {
	t.Helper()
	m, h, c, old, retained := recoveryFixture(t)
	// Executable fixture: version is read from the proven published bytes, not
	// from today's candidate or a guessed historical label.
	if e := os.WriteFile(m.source, []byte("#!/bin/sh\nprintf 'v2026-11-07-03\\n'\n"), 0700); e != nil {
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
	return m, h, c, old, retained, p
}
func completedIntents(t *testing.T, m desktopMigration, recovery, auth desktopMigrationMetadata) {
	t.Helper()
	root := filepath.Join(m.home, ".anytls-desktop-state")
	if e := os.MkdirAll(root, 0700); e != nil {
		t.Fatal(e)
	}
	for name, v := range map[string]any{
		"authorization.json": map[string]any{"schema": 1, "state": "DONE", "resume": false, "operation": auth.Operation, "stage": auth.Stage, "sha": auth.BinarySHA256},
		"recovery.json":      map[string]any{"schema": 1, "state": "DONE", "consent": "EXPLICIT_NEW_STOP", "plan": recovery.Plan, "recoveryOf": recovery.RecoveryOf, "recoveryPlanSHA": recovery.RecoveryPlanSHA256, "sha": recovery.BinarySHA256, "operation": recovery.Operation},
	} {
		raw, _ := json.Marshal(v)
		if e := os.WriteFile(filepath.Join(root, name), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
}
func completedNextBundle(t *testing.T, m desktopMigration, version string) {
	t.Helper()
	Version = version
	if e := os.WriteFile(m.source, []byte("#!/bin/sh\nprintf '"+version+"\\n'\n"), 0700); e != nil {
		t.Fatal(e)
	}
}
func completedReadOnlyPreview(t *testing.T, m desktopMigration, c *int) desktopMigrationMetadata {
	t.Helper()
	before := map[string][]byte{}
	infos := map[string]os.FileInfo{}
	e := filepath.Walk(m.home, func(p string, i os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		infos[p] = i
		if i.Mode().IsRegular() {
			b, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			before[p] = b
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	count := *c
	p, e, code, wire := recoveryInspectWire(t, m)
	if e != nil || code != 0 || p.Phase != "INSPECTED" || p.Operation != "" || p.RecoveryOf != "" {
		t.Fatalf("new upgrade preview required: %+v err=%v code=%d", p, e, code)
	}
	image, _ := os.ReadFile(m.source)
	if p.BinarySHA256 != desktopSum(image) {
		t.Fatal("candidate replaced by historical SHA")
	}
	seen := 0
	e = filepath.Walk(m.home, func(path string, i os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		seen++
		// Probe directories are owned, transient children of .anytls; entry
		// timestamps change on create/remove, but directory identity/security
		// and final membership must remain unchanged (also on APFS).
		stable := reloadStable(infos[path], i)
		if i.IsDir() {
			stable = migrationDirectorySame(infos[path], i)
		}
		if !stable {
			t.Fatalf("inspect identity mutation %s", path)
		}
		if i.Mode().IsRegular() {
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			if !bytes.Equal(b, before[path]) {
				t.Fatalf("inspect bytes mutation %s", path)
			}
		}
		return nil
	})
	if e != nil || seen != len(infos) || *c != count {
		t.Fatal("inspection mutated state", e, *c)
	}
	t.Logf("COMPLETED_UPGRADE_WIRE code=%d %s", code, wire)
	return p
}
func TestDesktopMigrationCompletedRecoveryNextUpgrade(t *testing.T) {
	m, h, c, old, retained, recovery := completedRecoveryFixture(t)
	completedNextBundle(t, m, "v2026-11-08-04")
	p := completedReadOnlyPreview(t, m, c)
	// Normal subsequent migration uses a fresh STOP proof, not recovery replay.
	h.Diagnostics = nil
	m.stop = func(_ context.Context, op string) (st.MutationResponse, error) {
		*c++
		return migrationFixtureAck(*h, op), nil
	}
	m.stopRead = func(_ context.Context, op *string) (st.ReadResponse, error) {
		return migrationFixtureRead(migrationFixtureAck(*h, *op)), nil
	}
	p, e := m.commit(p.Plan)
	if e != nil {
		t.Fatal("next commit", e)
	}
	h.HelperSHA256, h.HelperVersion = p.BinarySHA256, currentVersion()
	p, e = m.finish(p.Operation)
	if e != nil {
		t.Fatal("next finish", e)
	}
	completedIntents(t, m, recovery, p)
	completedNextBundle(t, m, "v2026-11-09-01")
	completedReadOnlyPreview(t, m, c)
	if *c != 2 {
		t.Fatal("unexpected STOP", *c)
	}
	recoveryRetained(t, m, old, retained)
}
