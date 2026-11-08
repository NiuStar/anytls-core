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

func TestDesktopMigrationStopEvidenceWriteAhead(t *testing.T) {
	m, _, _ := migrationFixture(t)
	p, e := m.inspect()
	if e != nil {
		t.Fatal(e)
	}
	stop := m.stop
	m.stop = func(ctx context.Context, op string) (st.MutationResponse, error) {
		files, _ := filepath.Glob(filepath.Join(m.home, ".anytls", ".desktop-migration-*", "plan.json"))
		if len(files) != 1 {
			t.Fatal("missing STOP intent")
		}
		b, _ := os.ReadFile(files[0])
		var record map[string]any
		if json.Unmarshal(b, &record) != nil {
			t.Fatal("invalid intent")
		}
		id, _ := record["StopOperation"].(string)
		if !reloadID.MatchString(id) {
			t.Fatal("STOP intent lacks distinct valid 32-hex operation binding")
		}
		if op != id {
			t.Fatal("dispatched a different STOP id")
		}
		return stop(ctx, op)
	}
	p, e = m.commit(p.Plan)
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"stop-response.json", "stop-read.json"} {
		if _, e = os.Stat(filepath.Join(m.opPath(p.Operation), name)); e != nil {
			t.Fatal("missing durable STOP evidence", name, e)
		}
	}
}

func migrationFixtureAck(r controlHelperResponse, op string) st.MutationResponse {
	epoch := strings.Repeat("e", 32)
	return st.MutationResponse{TimelineSchema: 1, OK: r.OK, Code: r.Code, HelperEpoch: &epoch, OperationID: &op, TimelineAvailability: "AVAILABLE", HelperVersion: &r.HelperVersion, HelperSHA256: &r.HelperSHA256, ConfigIdentity: r.ConfigIdentity, Loaded: r.Loaded, Running: r.Running, Diagnostics: startupDiagnostics(r.Diagnostics)}
}
func migrationFixtureRead(a st.MutationResponse) st.ReadResponse {
	rec, _ := st.NewRecorder("HELPER", startupProvenance(*a.HelperSHA256))
	rec.Observe("PREFLIGHT", "HELPER_ACCEPT", "OK", st.Fields{})
	rec.Finish("SUCCEEDED")
	stream := rec.Snapshot()
	at := stream.Terminal.At
	return st.ReadResponse{TimelineSchema: 1, Code: "OK", HelperEpoch: a.HelperEpoch, ConfigIdentity: &a.ConfigIdentity, OperationID: a.OperationID, Trace: &st.Trace{Authority: st.Authority, OperationID: *a.OperationID, HelperEpoch: a.HelperEpoch, ConfigIdentity: &a.ConfigIdentity, Operation: "STOP", Source: "MANUAL_STOP", StartedAt: stream.OriginAt, FinishedAt: &at, State: "FINISHED", LifecycleResult: "SUCCEEDED", HelperReturn: "SUCCEEDED", WebReturn: "NOT_ATTEMPTED", ReceiptResult: "NOT_ATTEMPTED", Diagnostics: a.Diagnostics, Streams: []st.ProcessStream{stream}, CoreObservation: st.CoreObservation{Availability: "NOT_OBSERVED", Gap: true}, Gap: true}}
}
