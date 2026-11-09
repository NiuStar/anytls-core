package main

import (
	"context"
	"encoding/json"
	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Reproduce the retained MacStudio shape through real commit/serializer paths:
// historical UNKNOWN + completed recovery + a different, not-yet-published App.
func completedAwaitingFixture(t *testing.T) (desktopMigration, *controlHelperResponse, *int, desktopMigrationMetadata) {
	t.Helper()
	m, h, c, _, _, _ := completedRecoveryFixture(t)
	completedNextBundle(t, m, "v2026-11-09-01")
	preview := completedReadOnlyPreview(t, m, c)
	h.Diagnostics = nil
	m.stop = func(_ context.Context, op string) (st.MutationResponse, error) {
		*c++
		return migrationFixtureAck(*h, op), nil
	}
	m.stopRead = func(_ context.Context, op *string) (st.ReadResponse, error) {
		return migrationFixtureRead(migrationFixtureAck(*h, *op)), nil
	}
	p, e := m.commit(preview.Plan)
	if e != nil {
		t.Fatal(e)
	}
	// Native authorization timeout persists UNKNOWN and retains the old console.
	auth := map[string]any{"schema": 1, "state": "UNKNOWN", "resume": false, "operation": p.Operation, "stage": p.Stage, "sha": p.BinarySHA256,
		"console": map[string]any{"pid": 80587, "uid": m.uid, "seconds": 1794150660, "micros": 703446, "managed": false, "sha": p.OldBinarySHA256, "argv": []string{p.Binary, "webui", "--listen", "0.0.0.0", "--port", "18089"}}}
	raw, _ := json.Marshal(auth)
	if e = os.WriteFile(filepath.Join(m.home, ".anytls-desktop-state", "authorization.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	return m, h, c, p
}

func awaitingSnapshot(t *testing.T, home string) map[string]string {
	t.Helper()
	out := map[string]string{}
	if e := filepath.Walk(home, func(p string, i os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		if i.Mode().IsRegular() {
			b, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			out[p] = desktopSum(b)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	return out
}

func TestDesktopMigrationCompletedRecoveryAwaitingHelper(t *testing.T) {
	m, _, c, p := completedAwaitingFixture(t)
	before := awaitingSnapshot(t, m.home)
	stops := *c
	m.journal = func(string, []byte, os.FileMode) error {
		t.Fatal("inspect/failed finish wrote journal")
		return os.ErrPermission
	}
	got, held, code, wire := recoveryInspectWire(t, m)
	if held == nil || code != 1 || got != p {
		t.Fatalf("exact pending metadata required: got=%+v want=%+v err=%v code=%d", got, p, held, code)
	}
	if _, e := m.finish(p.Operation); e == nil || e.Error() != "NEW_HELPER_NOT_READY" {
		t.Fatal("old helper must not publish", e)
	}
	if *c != stops || !reflect.DeepEqual(before, awaitingSnapshot(t, m.home)) {
		t.Fatal("read-only continuation mutated state or replayed STOP")
	}
	if export := os.Getenv("ANYTLS_AWAITING_WIRE_EXPORT"); export != "" {
		if e := os.WriteFile(export, wire, 0600); e != nil {
			t.Fatal(e)
		}
	}
	t.Logf("AWAITING_HISTORY_WIRE %s", wire)
}

func TestDesktopMigrationCompletedRecoveryAwaitingRejectsCorruption(t *testing.T) {
	for _, name := range []string{"auth-operation", "auth-sha", "auth-state", "console-sha", "terminal", "stage", "backup", "stop-proof", "candidate"} {
		t.Run(name, func(t *testing.T) {
			m, _, c, p := completedAwaitingFixture(t)
			authPath := filepath.Join(m.home, ".anytls-desktop-state", "authorization.json")
			raw, _ := os.ReadFile(authPath)
			var auth map[string]any
			json.Unmarshal(raw, &auth)
			switch name {
			case "auth-operation":
				auth["operation"] = p.Plan
			case "auth-sha":
				auth["sha"] = p.OldBinarySHA256
			case "auth-state":
				auth["state"] = "DONE"
			case "console-sha":
				auth["console"].(map[string]any)["sha"] = p.BinarySHA256
			case "terminal":
				records, _ := m.recoveryRecords()
				for _, r := range records {
					if r.Recovery != nil {
						os.WriteFile(filepath.Join(m.opPath(r.Metadata.Operation), "supersession.json"), []byte("{}"), 0600)
					}
				}
			case "stage":
				os.WriteFile(p.Stage, []byte("changed"), 0700)
			case "backup":
				os.WriteFile(filepath.Join(m.opPath(p.Operation), "old-binary"), []byte("changed"), 0700)
			case "stop-proof":
				os.WriteFile(filepath.Join(m.opPath(p.Operation), "stop-read.json"), []byte("{}"), 0600)
			case "candidate":
				os.WriteFile(m.source, []byte("other candidate"), 0700)
			}
			raw, _ = json.Marshal(auth)
			if e := os.WriteFile(authPath, raw, 0600); e != nil {
				t.Fatal(e)
			}
			before := awaitingSnapshot(t, m.home)
			stops := *c
			got, e := m.inspect()
			if e == nil || got.Operation != "" {
				t.Fatalf("corrupt %s exposed continuation %+v %v", name, got, e)
			}
			if *c != stops || !reflect.DeepEqual(before, awaitingSnapshot(t, m.home)) {
				t.Fatal("corruption inspection mutated")
			}
		})
	}
}

func TestDesktopMigrationCompletedRecoveryAwaitingHelperReady(t *testing.T) {
	m, h, c, p := completedAwaitingFixture(t)
	stops := *c
	h.HelperSHA256, h.HelperVersion = p.BinarySHA256, currentVersion()
	got, held, code, _ := recoveryInspectWire(t, m)
	if got != p || held == nil || code != 1 {
		t.Fatal("ready helper still exposes exact pending, not publication", got, held, code)
	}
	committed, e := m.finish(p.Operation)
	if e != nil || committed.Phase != "COMMITTED" || *c != stops {
		t.Fatal("exact ready helper finish", committed, e, *c)
	}
}
