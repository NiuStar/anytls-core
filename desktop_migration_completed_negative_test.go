package main

import (
	"bytes"
	"context"
	"encoding/json"
	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func completedPlainUpgrade(t *testing.T, m desktopMigration, h *controlHelperResponse, c *int, recovery desktopMigrationMetadata) desktopMigrationMetadata {
	t.Helper()
	completedNextBundle(t, m, "v2026-11-08-04")
	p := completedReadOnlyPreview(t, m, c)
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
		t.Fatal(e)
	}
	h.HelperSHA256, h.HelperVersion = p.BinarySHA256, currentVersion()
	p, e = m.finish(p.Operation)
	if e != nil {
		t.Fatal(e)
	}
	completedIntents(t, m, recovery, p)
	return p
}

func TestDesktopMigrationCompletedRecoveryLaterLineageHolds(t *testing.T) {
	for _, kind := range []string{"later-plan", "later-backup", "later-stage", "later-read", "later-sent", "later-helper", "later-pin", "later-branch", "later-disconnected", "later-stale-authorization"} {
		t.Run(kind, func(t *testing.T) {
			m, h, c, _, _, r := completedRecoveryFixture(t)
			p := completedPlainUpgrade(t, m, h, c, r)
			completedNextBundle(t, m, "v2026-11-09-01")
			rec, e := m.record(p.Operation)
			if e != nil {
				t.Fatal(e)
			}
			dir := m.opPath(p.Operation)
			switch kind {
			case "later-stale-authorization":
				completedIntents(t, m, r, r)
			case "later-plan":
				rec.Metadata.Plan = strings.Repeat("a", 64)
				m.save(rec)
			case "later-backup":
				os.WriteFile(filepath.Join(dir, "old-binary"), []byte("drift"), 0700)
			case "later-stage":
				os.WriteFile(p.Stage, []byte("drift"), 0700)
			case "later-read":
				os.WriteFile(filepath.Join(dir, "stop-read.json"), []byte("{}"), 0600)
			case "later-sent":
				os.WriteFile(filepath.Join(dir, ".sent"), []byte("START\n"), 0600)
			case "later-helper", "later-pin", "later-disconnected":
				if kind == "later-helper" {
					rec.Metadata.HelperSHA256 = strings.Repeat("a", 64)
				} else if kind == "later-pin" {
					rec.Pin.Aggregate = strings.Repeat("a", 64)
				} else {
					rec.Metadata.OldBinarySHA256 = strings.Repeat("a", 64)
				}
				// Recompute preview so semantic lineage checks, not stale plan detection,
				// must reject these otherwise closed record mutations.
				preview := rec
				preview.Metadata.Phase = "INSPECTED"
				preview.Metadata.Operation = ""
				preview.Metadata.Stage = ""
				preview.Metadata.Plan = ""
				preview.Action = ""
				preview.BackupSHA256 = ""
				preview.StopOperation = ""
				preview.StopReadSHA256 = ""
				preview.StopResponseSHA256 = ""
				preview.StopDisposition = ""
				raw, _ := json.Marshal(struct {
					Record desktopMigrationRecord
					Loaded bool
				}{preview, preview.WasLoaded})
				rec.Metadata.Plan = desktopSum(raw)
				m.save(rec)
			case "later-branch":
				op := strings.Repeat("a", 64)
				os.Mkdir(m.opPath(op), 0700)
				entries, _ := os.ReadDir(dir)
				for _, v := range entries {
					b, _ := os.ReadFile(filepath.Join(dir, v.Name()))
					mode := os.FileMode(0600)
					if v.Name() == "old-binary" {
						mode = 0700
					}
					os.WriteFile(filepath.Join(m.opPath(op), v.Name()), b, mode)
				}
				rec.Metadata.Operation = op
				rec.Metadata.Stage = filepath.Join(m.home, ".anytls", ".desktop-candidate-"+op)
				b, _ := os.ReadFile(p.Stage)
				os.WriteFile(rec.Metadata.Stage, b, 0700)
				m.save(rec)
			}
			got, e := m.inspect()
			if e == nil || got.Phase == "INSPECTED" {
				t.Fatalf("unproven later lineage %+v %v", got, e)
			}
			if *c != 2 {
				t.Fatal("STOP replay")
			}
		})
	}
}

func TestDesktopMigrationCompletedRecoveryUpgradeHolds(t *testing.T) {
	for _, kind := range []string{"missing-terminal", "terminal", "record", "old-sent", "old-stage", "backup", "stage", "stop-read", "mode", "root-mode", "config", "canonical", "helper-sha", "helper-version", "helper-config", "helper-running", "authorization-missing", "authorization-ready", "recovery-missing", "recovery-ready", "recovery-link", "pending", "candidate-mode", "candidate-layout"} {
		t.Run(kind, func(t *testing.T) {
			m, h, c, old, _, p := completedRecoveryFixture(t)
			completedNextBundle(t, m, "v2026-11-08-04")
			dir := m.opPath(p.Operation)
			state := filepath.Join(m.home, ".anytls-desktop-state")
			write := func(path string, b []byte) {
				t.Helper()
				if e := os.WriteFile(path, b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			switch kind {
			case "missing-terminal":
				os.Remove(filepath.Join(dir, "supersession.json"))
			case "terminal":
				write(filepath.Join(dir, "supersession.json"), []byte("{}"))
			case "record":
				write(filepath.Join(dir, "plan.json"), []byte("{}"))
			case "old-sent":
				write(filepath.Join(m.opPath(old.Metadata.Operation), ".sent"), []byte("START\n"))
			case "old-stage":
				write(old.Metadata.Stage, []byte("tampered"))
			case "backup":
				write(filepath.Join(dir, "old-binary"), []byte("tampered"))
			case "stage":
				write(p.Stage, []byte("tampered"))
			case "stop-read":
				write(filepath.Join(dir, "stop-read.json"), []byte("{}"))
			case "mode":
				os.Chmod(filepath.Join(dir, "supersession.json"), 0644)
			case "root-mode":
				os.Chmod(filepath.Join(m.home, ".anytls"), 0755)
			case "config":
				write(p.Config, []byte("stranger"))
			case "canonical":
				write(p.Binary, []byte("stranger"))
			case "helper-sha":
				h.HelperSHA256 = strings.Repeat("f", 64)
			case "helper-version":
				h.HelperVersion = "v2026-11-06-03"
			case "helper-config":
				h.ConfigIdentity = strings.Repeat("f", 64)
			case "helper-running":
				h.Running = true
			case "authorization-missing":
				os.Remove(filepath.Join(state, "authorization.json"))
			case "authorization-ready", "recovery-ready", "recovery-link":
				name := "recovery.json"
				if kind == "authorization-ready" {
					name = "authorization.json"
				}
				path := filepath.Join(state, name)
				raw, _ := os.ReadFile(path)
				var v map[string]any
				json.Unmarshal(raw, &v)
				if kind == "recovery-link" {
					v["recoveryOf"] = strings.Repeat("f", 64)
				} else {
					v["state"] = "READY"
				}
				raw, _ = json.Marshal(v)
				write(path, raw)
			case "recovery-missing":
				os.Remove(filepath.Join(state, "recovery.json"))
			case "pending":
				os.Mkdir(m.opPath(strings.Repeat("e", 64)), 0700)
			case "candidate-mode":
				os.Chmod(m.source, 0777)
			case "candidate-layout":
				m.source = p.Stage
			}
			// Snapshot after stimulus; inspection must preserve every regular file.
			before := map[string][]byte{}
			filepath.Walk(m.home, func(path string, i os.FileInfo, e error) error {
				if e == nil && i.Mode().IsRegular() {
					before[path], _ = os.ReadFile(path)
				}
				return e
			})
			got, e := m.inspect()
			if e == nil || got.Phase == "INSPECTED" {
				t.Fatalf("unsafe preview %+v %v", got, e)
			}
			if *c != 1 {
				t.Fatal("STOP replay")
			}
			for path, b := range before {
				got, e := os.ReadFile(path)
				if e != nil || !bytes.Equal(b, got) {
					t.Fatal("inspect wrote", path, e)
				}
			}
		})
	}
}
