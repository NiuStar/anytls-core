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

// Historical test adapter: execute the live stopped/no-snapshot branch and
// recorder, then restore only its original incumbent UNKNOWN diagnostic. This
// is not an old binary execution; frozen observed stream separately tests the
// consumer and source-qualified producer provenance is synthetic here.
func migrationIncumbentFixture(t *testing.T) (desktopMigration, *controlHelperResponse, *int) {
	t.Helper()
	m, h, c := migrationFixture(t)
	h.HelperVersion = "v2026-11-06-03"
	h.HelperSHA256 = "1142fb1d250495541fd19231091698bd5e23986599d62c69d4cee276d1a8f8ff"
	h.Loaded = false
	h.Running = false
	var response st.ReadResponse
	m.stop = func(_ context.Context, op string) (st.MutationResponse, error) {
		*c++
		d, _, config, _, _, _ := lifecycleFixture(t)
		s := unitControlServer()
		s.registration.Config = config
		s.sha = h.HelperSHA256
		s.state = d.state
		s.stop = func(ctx context.Context) error { return d.withStartup(ctx, s).stop() }
		result, _ := s.executeStartup(controlHelperWireRequest{"stop", false}, op, h.ConfigIdentity, "MANUAL_STOP")
		if !result.OK {
			t.Fatal("producer STOP failed", result)
		}
		response = s.startupReadCache(st.ReadRequest{TimelineSchema: 1, Action: "startup.read", OperationID: &op})
		if result.Diagnostics == nil || result.Diagnostics.Cleanup != "VERIFIED" || result.Diagnostics.Job != "UNLOADED" || len(response.Trace.Streams) != 1 || len(response.Trace.Streams[0].Events) != 14 || response.Trace.Streams[0].Events[5].Stage != "SNAPSHOT_EXISTENCE" {
			t.Fatal("not the exact stopped/no-snapshot producer branch")
		}
		result.Diagnostics.Restoration = "UNKNOWN"
		response.Trace.Diagnostics.Restoration = "UNKNOWN"
		// Fixture process build provenance is not the installed incumbent binary.
		stream := &response.Trace.Streams[0]
		rev := "9e6e996bda684ecfce134dc842edf1b96c8ca256"
		dirty := false
		stream.Provenance = st.Provenance{Version: &h.HelperVersion, SHA256: &h.HelperSHA256, GitRevision: &rev, Dirty: &dirty, SHAKind: "FILE_BYTES", ExecutionMapping: "NOT_ATTESTED"}
		h.Diagnostics = result.Diagnostics
		a := migrationFixtureAck(*h, op)
		a.HelperEpoch = response.HelperEpoch
		return a, nil
	}
	m.stopRead = func(_ context.Context, _ *string) (st.ReadResponse, error) { return response, nil }
	return m, h, c
}
func TestDesktopMigrationStopIncumbentCompatibility(t *testing.T) {
	m, h, c := migrationIncumbentFixture(t)
	p, e := m.inspect()
	if e != nil {
		t.Fatal(e)
	}
	p, e = m.commit(p.Plan)
	if e != nil || p.Phase != "AWAITING_HELPER" || *c != 1 {
		t.Fatal(p, e, *c)
	}
	if migrationAck(*h) {
		t.Fatal("UNKNOWN globally waived")
	}
	rec, e := m.record(p.Operation)
	if e != nil || rec.StopOperation == "" || rec.StopReadSHA256 == "" || rec.StopResponseSHA256 == "" {
		t.Fatal(rec, e)
	}
}
func TestDesktopMigrationStopProofRejectsDrift(t *testing.T) {
	for _, kind := range []string{"op", "epoch", "config", "helper", "version", "revision", "dirty", "source", "baseline", "missing", "gap", "receipt", "job", "tun", "code", "segment", "core", "trace-diagnostics", "response-lost", "read-lost", "evidence-unwritable", "lock"} {
		t.Run(kind, func(t *testing.T) {
			m, _, c := migrationIncumbentFixture(t)
			p, e := m.inspect()
			if e != nil {
				t.Fatal(e)
			}
			stop, read := m.stop, m.stopRead
			m.stop = func(ctx context.Context, op string) (st.MutationResponse, error) {
				a, e := stop(ctx, op)
				switch kind {
				case "response-lost":
					return a, context.DeadlineExceeded
				case "op":
					v := strings.Repeat("f", 32)
					a.OperationID = &v
				case "helper":
					v := strings.Repeat("f", 64)
					a.HelperSHA256 = &v
				case "version":
					v := "v2026-11-07-01"
					a.HelperVersion = &v
				case "evidence-unwritable":
					files, _ := filepath.Glob(filepath.Join(m.home, ".anytls", ".desktop-migration-*"))
					if e := os.Mkdir(filepath.Join(files[0], "stop-response.json"), 0700); e != nil {
						t.Fatal(e)
					}
				}
				return a, e
			}
			m.stopRead = func(ctx context.Context, op *string) (st.ReadResponse, error) {
				r, e := read(ctx, op)
				s := &r.Trace.Streams[0]
				switch kind {
				case "read-lost":
					return r, context.DeadlineExceeded
				case "epoch":
					v := strings.Repeat("f", 32)
					r.HelperEpoch = &v
					r.Trace.HelperEpoch = &v
				case "config":
					v := strings.Repeat("f", 64)
					r.ConfigIdentity = &v
					r.Trace.ConfigIdentity = &v
				case "source":
					r.Trace.Source = "LEGACY_CONTROL"
				case "revision":
					v := strings.Repeat("f", 40)
					s.Provenance.GitRevision = &v
				case "dirty":
					v := true
					s.Provenance.Dirty = &v
				case "baseline":
					s.Events[5].Stage = "STOP_BASELINE"
					s.Events[6].Stage = "STOP_BASELINE"
				case "missing":
					s.Events = s.Events[:13]
				case "gap":
					s.Gap = true
				case "receipt":
					r.Trace.ReceiptResult = "FAILED"
				case "trace-diagnostics":
					copy := *r.Trace.Diagnostics
					copy.Cleanup = "UNKNOWN"
					r.Trace.Diagnostics = &copy
				case "job":
					s.Events[4].Job = "RUNNING"
				case "tun":
					s.Events[4].Tun = "TUN"
				case "code":
					s.Events[6].Code = "FAILED"
				case "segment":
					s.Events[6].Segment = "ROLLBACK"
				case "core":
					r.Trace.CoreObservation.Availability = "UNAVAILABLE"
				}
				return r, e
			}
			if kind == "lock" {
				lock, e := m.lock()
				if e != nil {
					t.Fatal(e)
				}
				defer lock.Close()
			}
			if _, e = m.commit(p.Plan); e == nil {
				t.Fatal("unsafe proof accepted")
			}
			expected := 1
			if kind == "lock" {
				expected = 0
			}
			if *c != expected {
				t.Fatal("dispatch count", *c)
			}
			if _, e = m.commit(p.Plan); e == nil || *c != expected {
				t.Fatal("STOP replay", e, *c)
			}
			old, _ := os.ReadFile(p.Binary)
			if string(old) != "old image" {
				t.Fatal("runtime mutated")
			}
		})
	}
}
func TestDesktopMigrationStopEvidenceRetainedSafety(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "mode", "digest", "duplicate", "alias", "oversize", "missing", "plan-alias", "plan-duplicate"} {
		t.Run(kind, func(t *testing.T) {
			m, h, c := migrationIncumbentFixture(t)
			p, _ := m.inspect()
			p, e := m.commit(p.Plan)
			if e != nil {
				t.Fatal(e)
			}
			h.HelperSHA256 = p.BinarySHA256
			h.HelperVersion = currentVersion()
			path := filepath.Join(m.opPath(p.Operation), "stop-read.json")
			b, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "symlink":
				os.Rename(path, path+".real")
				os.Symlink(path+".real", path)
			case "hardlink":
				os.Link(path, path+".link")
			case "mode":
				os.Chmod(path, 0644)
			case "digest":
				os.WriteFile(path, append(b, ' '), 0600)
			case "duplicate":
				os.WriteFile(path, bytes.Replace(b, []byte(`"code":"OK"`), []byte(`"code":"OK","code":"OK"`), 1), 0600)
			case "alias":
				os.WriteFile(path, bytes.Replace(b, []byte(`"code":"OK"`), []byte(`"Code":"OK"`), 1), 0600)
			case "oversize":
				os.WriteFile(path, bytes.Repeat([]byte(" "), reloadReceiptLimit+1), 0600)
			case "missing":
				os.Remove(path)
			case "plan-alias", "plan-duplicate":
				path = filepath.Join(m.opPath(p.Operation), "plan.json")
				b, _ = os.ReadFile(path)
				replacement := `"stopoperation":`
				if kind == "plan-duplicate" {
					replacement = `"StopOperation":"00000000000000000000000000000000","StopOperation":`
				}
				os.WriteFile(path, bytes.Replace(b, []byte(`"StopOperation":`), []byte(replacement), 1), 0600)
			}
			if kind == "duplicate" || kind == "alias" {
				// Recompute the digest: prove strict parsing, not stale-hash rejection.
				planPath := filepath.Join(m.opPath(p.Operation), "plan.json")
				planBytes, _ := os.ReadFile(planPath)
				var record desktopMigrationRecord
				json.Unmarshal(planBytes, &record)
				mutated, _ := os.ReadFile(path)
				record.StopReadSHA256 = desktopSum(mutated)
				planBytes, _ = json.Marshal(record)
				os.WriteFile(planPath, planBytes, 0600)
			}
			if _, e = m.finish(p.Operation); e == nil {
				t.Fatal("unsafe retained evidence accepted")
			}
			if *c != 1 {
				t.Fatal("replayed STOP")
			}
			old, _ := os.ReadFile(p.Binary)
			if string(old) != "old image" {
				t.Fatal("published with corrupt proof")
			}
		})
	}
}
func TestDesktopMigrationStopHistoricalUnknownHeld(t *testing.T) {
	m, _, c := migrationFixture(t)
	p, _ := m.inspect()
	m.stop = func(context.Context, string) (st.MutationResponse, error) {
		*c++
		return st.MutationResponse{}, context.DeadlineExceeded
	}
	m.commit(p.Plan)
	files, _ := filepath.Glob(filepath.Join(m.home, ".anytls", ".desktop-migration-*", "plan.json"))
	b, _ := os.ReadFile(files[0])
	var r desktopMigrationRecord
	json.Unmarshal(b, &r)
	r.StopOperation = ""
	r.StopReadSHA256 = ""
	r.StopResponseSHA256 = ""
	b, _ = json.Marshal(r)
	os.WriteFile(files[0], b, 0600)
	before, _ := os.ReadFile(files[0])
	if _, e := m.finish(r.Metadata.Operation); e == nil {
		t.Fatal("historical UNKNOWN rewritten")
	}
	if _, e := m.commit(p.Plan); e == nil {
		t.Fatal("historical UNKNOWN bypassed")
	}
	m.inspect()
	after, _ := os.ReadFile(files[0])
	if !bytes.Equal(before, after) || *c != 1 {
		t.Fatal("historical evidence mutated or STOP replayed")
	}
}
