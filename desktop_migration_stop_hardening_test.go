package main

import (
	"context"
	"encoding/json"
	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDesktopMigrationStopTerminalEnvelopeContract(t *testing.T) {
	m, _, _ := migrationIncumbentFixture(t)
	r, e := m.preflight()
	if e != nil {
		t.Fatal(e)
	}
	r.StopOperation = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	a, e := m.stop(context.Background(), r.StopOperation)
	if e != nil {
		t.Fatal(e)
	}
	read, e := m.stopRead(context.Background(), &r.StopOperation)
	if e != nil {
		t.Fatal(e)
	}
	if !migrationStopProof(r, a, read) {
		t.Fatal("valid producer rejected")
	}
	read.Trace.Streams[0].Terminal.ElapsedNS = "0"
	if migrationStopProof(r, a, read) {
		t.Fatal("accepted impossible terminal elapsed before 14 events")
	}
}

func TestDesktopMigrationStopFormatOmissionContract(t *testing.T) {
	m, h, c := migrationFixture(t)
	p, e := m.inspect()
	if e != nil {
		t.Fatal(e)
	}
	p, e = m.commit(p.Plan)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(m.opPath(p.Operation), "plan.json")
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var tree map[string]any
	if json.Unmarshal(b, &tree) != nil {
		t.Fatal("fixture JSON")
	}
	for _, key := range []string{"StopOperation", "StopResponseSHA256", "StopReadSHA256"} {
		delete(tree, key)
	}
	b, _ = json.Marshal(tree)
	if e = os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	for _, n := range []string{"stop-response.json", "stop-read.json"} {
		if e = os.Remove(filepath.Join(m.opPath(p.Operation), n)); e != nil {
			t.Fatal(e)
		}
	}
	h.HelperSHA256 = p.BinarySHA256
	h.HelperVersion = currentVersion()
	if _, e = m.finish(p.Operation); e == nil {
		t.Fatal("new evidence format silently downgraded to legacy")
	}
	actual, _ := os.ReadFile(p.Binary)
	if string(actual) != "old image" || *c != 1 {
		t.Fatal("published or replayed on missing proof")
	}
}

func TestDesktopMigrationStopCurrentProducerCompatibility(t *testing.T) {
	m, h, c := migrationFixture(t)
	h.Loaded = false
	h.Running = false
	m.stop = func(_ context.Context, id string) (st.MutationResponse, error) {
		*c++
		d, _, config, _, _, _ := lifecycleFixture(t)
		s := unitControlServer()
		s.registration.Config = config
		s.sha = h.HelperSHA256
		s.state = d.state
		s.stop = func(ctx context.Context) error { return d.withStartup(ctx, s).stop() }
		result, _ := s.executeStartup(controlHelperWireRequest{"stop", false}, id, h.ConfigIdentity, "MANUAL_STOP")
		if !result.OK || result.Diagnostics == nil || result.Diagnostics.Restoration != "NOT_ATTEMPTED" {
			t.Fatal("current producer diagnostic", result.Diagnostics)
		}
		h.Diagnostics = result.Diagnostics
		return migrationFixtureAck(*h, id), nil
	}
	p, e := m.inspect()
	if e != nil {
		t.Fatal(e)
	}
	p, e = m.commit(p.Plan)
	if e != nil || p.Phase != "AWAITING_HELPER" || *c != 1 {
		t.Fatal(p, e, *c)
	}
}
func TestDesktopMigrationStopGoldenTemporalMatrix(t *testing.T) {
	for _, kind := range []string{"terminal-zero", "terminal-unequal", "event-after-terminal", "clock-adjustment", "origin-mismatch"} {
		t.Run(kind, func(t *testing.T) {
			m, h, _ := migrationIncumbentFixture(t)
			r, e := m.preflight()
			if e != nil {
				t.Fatal(e)
			}
			r.StopOperation = strings.Repeat("a", 32)
			a := migrationFixtureAck(*h, r.StopOperation)
			a.Diagnostics = &st.Diagnostics{Schema: 1, Operation: "STOP", Outcome: "SUCCEEDED", Stage: "NONE", Reason: "NONE", Rollback: "NOT_ATTEMPTED", Restoration: "UNKNOWN", Cleanup: "VERIFIED", Receipt: "WRITTEN", Job: "UNLOADED", Tun: "NOT_OBSERVED"}
			read := migrationFixtureRead(a)
			var stream st.ProcessStream
			if e = st.Decode(strings.NewReader(migrationObservedIncumbentStream), &stream); e != nil {
				t.Fatal(e)
			}
			read.Trace.Streams = []st.ProcessStream{stream}
			read.Trace.StartedAt = stream.OriginAt
			at := stream.Terminal.At
			read.Trace.FinishedAt = &at
			read.Trace.ReceiptResult = "WRITTEN"
			switch kind {
			case "terminal-zero":
				stream.Terminal.ElapsedNS = "0"
			case "terminal-unequal":
				stream.ElapsedNS = "999999999"
			case "event-after-terminal":
				stream.ElapsedNS = "0"
				stream.Terminal.ElapsedNS = "0"
			case "origin-mismatch":
				read.Trace.StartedAt = "2000-01-01T00:00:00Z"
			case "clock-adjustment":
				stream.Events[13].At = "2000-01-01T00:00:00Z"
				stream.Terminal.At = "1999-01-01T00:00:00Z"
			}
			read.Trace.Streams[0] = stream
			if migrationStopProof(r, a, read) != (kind == "clock-adjustment") {
				t.Fatal("temporal producer contract", kind)
			}
		})
	}
}

func TestDesktopMigrationStopLegacyAwaitingFormat(t *testing.T) {
	m, h, c := migrationFixture(t)
	old, e := m.preflight()
	if e != nil {
		t.Fatal(e)
	}
	old.EvidenceSchema = 0
	old.Metadata.Operation = strings.Repeat("a", 64)
	old.Metadata.Stage = filepath.Join(m.home, ".anytls", ".desktop-candidate-"+old.Metadata.Operation)
	old.Metadata.Phase = "AWAITING_HELPER"
	old.Action = "STOP"
	old.BackupSHA256 = old.Metadata.OldBinarySHA256
	dir := m.opPath(old.Metadata.Operation)
	if e = os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e = m.save(old); e != nil {
		t.Fatal(e)
	}
	for name, b := range map[string][]byte{".sent": []byte("STOP\n"), "old-binary": []byte("old image")} {
		mode := os.FileMode(0600)
		if name == "old-binary" {
			mode = 0700
		}
		if e = os.WriteFile(filepath.Join(dir, name), b, mode); e != nil {
			t.Fatal(e)
		}
	}
	image, e := os.ReadFile(m.source)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(old.Metadata.Stage, image, 0700); e != nil {
		t.Fatal(e)
	}
	h.Loaded = false
	h.Running = false
	h.HelperSHA256 = old.Metadata.BinarySHA256
	h.HelperVersion = currentVersion()
	if _, e = m.finish(old.Metadata.Operation); e != nil || *c != 0 {
		t.Fatal("genuine historical awaiting format rejected", e, *c)
	}
}
