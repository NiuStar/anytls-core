package main

// STOP receipts preserve normalized typed JSON, never original wire-byte hashes.
// The timeline remains auxiliary except for this closed, producer-pinned branch
// proof, combined with the authenticated mutation acknowledgement.
import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
)

func migrationStopProof(r desktopMigrationRecord, a st.MutationResponse, read st.ReadResponse) bool {
	p := r.Metadata
	eq := func(v *string, want string) bool { return v != nil && *v == want }
	if a.TimelineAvailability != "AVAILABLE" || st.Validate(a) != nil || st.Validate(read) != nil || !reloadID.MatchString(r.StopOperation) || !a.OK || a.Loaded || a.Running || !eq(a.OperationID, r.StopOperation) || a.HelperEpoch == nil || !eq(a.HelperSHA256, p.HelperSHA256) || !eq(a.HelperVersion, p.HelperVersion) || a.ConfigIdentity != p.ConfigIdentity || read.Code != "OK" || !eq(read.OperationID, r.StopOperation) || !eq(read.HelperEpoch, *a.HelperEpoch) || !eq(read.ConfigIdentity, p.ConfigIdentity) {
		return false
	}
	t := read.Trace
	if t == nil || t.Source != "MANUAL_STOP" || t.Operation != "STOP" || t.State != "FINISHED" || t.LifecycleResult != "SUCCEEDED" || t.HelperReturn != "SUCCEEDED" || !reflect.DeepEqual(t.Diagnostics, a.Diagnostics) {
		return false
	}
	if a.Diagnostics == nil {
		return r.Recovery == nil
	} // authenticated legacy acknowledgement
	d := a.Diagnostics
	if migrationAck(controlHelperResponse{Diagnostics: &startDiagnostics{Schema: d.Schema, Operation: d.Operation, Outcome: d.Outcome, Restoration: d.Restoration, Cleanup: d.Cleanup, Receipt: d.Receipt}}) {
		return true
	}
	// Only this clean incumbent producer has the audited UNKNOWN/no-baseline
	// branch. Version alone, a stopped status or SNAPSHOT_EXISTENCE alone is not proof.
	if p.HelperVersion != "v2026-11-06-03" || p.HelperSHA256 != "1142fb1d250495541fd19231091698bd5e23986599d62c69d4cee276d1a8f8ff" || *d != (st.Diagnostics{Schema: 1, Operation: "STOP", Outcome: "SUCCEEDED", Stage: "NONE", Reason: "NONE", Rollback: "NOT_ATTEMPTED", Restoration: "UNKNOWN", Cleanup: "VERIFIED", Receipt: "WRITTEN", Job: "UNLOADED", Tun: "NOT_OBSERVED"}) || t.ReceiptResult != "WRITTEN" || t.WebReturn != "NOT_ATTEMPTED" || len(t.Streams) != 1 || t.CoreObservation != (st.CoreObservation{Availability: "NOT_OBSERVED", Gap: true}) {
		return false
	}
	s := t.Streams[0]
	if t.StartedAt != s.OriginAt {
		return false
	}
	if s.Role != "HELPER" || s.Gap || s.Current != nil || s.Terminal == nil || s.Terminal.Result != "SUCCEEDED" || s.GeneratedEvents != "14" || s.DroppedEvents != "0" || s.FirstMissingSeq != nil || len(s.Events) != 14 || !eq(s.Provenance.Version, p.HelperVersion) || !eq(s.Provenance.SHA256, p.HelperSHA256) || !eq(s.Provenance.GitRevision, "9e6e996bda684ecfce134dc842edf1b96c8ca256") || s.Provenance.Dirty == nil || *s.Provenance.Dirty {
		return false
	}
	// Recorder.Finish writes one monotonic value to both fields; events
	// precede that value. Wall timestamps can jump and are not ordered here.
	terminalNS, err := strconv.ParseUint(s.Terminal.ElapsedNS, 10, 64)
	if err != nil || s.Terminal.ElapsedNS != s.ElapsedNS {
		return false
	}
	for _, event := range s.Events {
		elapsed, err := strconv.ParseUint(event.ElapsedNS, 10, 64)
		if err != nil || elapsed > terminalNS {
			return false
		}
	}
	stages := strings.Fields("HELPER_ACCEPT STOP_CAPTURE STOP_CAPTURE JOB_INITIAL JOB_INITIAL SNAPSHOT_EXISTENCE SNAPSHOT_EXISTENCE RECEIPT_FINISH RECEIPT_WRITE RECEIPT_WRITE RECEIPT_FINISH HELPER_FINAL_STATE HELPER_FINAL_STATE HELPER_FINISH")
	states := strings.Fields("OBSERVATION BEGIN END BEGIN END BEGIN END BEGIN BEGIN END END BEGIN END OBSERVATION")
	spans := strings.Fields("- 1 1 2 2 3 3 4 5 5 4 6 6 -")
	for i, e := range s.Events {
		if spans[i] == "-" && e.SpanID != nil || spans[i] != "-" && !eq(e.SpanID, spans[i]) {
			return false
		}
		segment := "STOP"
		if i == 0 {
			segment = "PREFLIGHT"
		}
		if i >= 11 {
			segment = "FINALIZE"
		}
		code := "OK"
		if states[i] == "BEGIN" {
			code = "NONE"
		}
		job := "NOT_OBSERVED"
		if i == 4 {
			job = "UNLOADED"
		}
		if e.Stage != stages[i] || e.State != states[i] || e.Segment != segment || e.Code != code || e.Job != job || e.Tun != "NOT_OBSERVED" || e.Round != nil || e.Ordinal != nil || e.RuleCount != nil || e.CompletedCount != nil {
			return false
		}
	}
	return true
}

func (m desktopMigration) retainStop(r *desktopMigrationRecord, name string, v any) error {
	b, e := st.Encode(v)
	if e != nil {
		return desktopError("STOP_EVIDENCE_INVALID")
	}
	dir := m.opPath(r.Metadata.Operation)
	anchor, e := desktopDir(dir, m.uid, true)
	if e != nil {
		return e
	}
	if e = desktopPublish(dir, name, b, 0600, anchor); e != nil {
		return e
	}
	actual, _, e := reloadCapture(filepath.Join(dir, name), m.uid)
	if e != nil || !bytes.Equal(b, actual) {
		return desktopError("JOURNAL_UNCERTAIN")
	}
	if name == "stop-response.json" {
		r.StopResponseSHA256 = desktopSum(b)
	} else {
		r.StopReadSHA256 = desktopSum(b)
	}
	return nil
}
func (m desktopMigration) stopEvidence(r desktopMigrationRecord) error {
	dir := m.opPath(r.Metadata.Operation)
	anchor, e := desktopDir(dir, m.uid, true)
	if e != nil {
		return e
	}
	var a st.MutationResponse
	var read st.ReadResponse
	for _, v := range []struct {
		name, sha string
		dst       any
	}{{"stop-response.json", r.StopResponseSHA256, &a}, {"stop-read.json", r.StopReadSHA256, &read}} {
		b, _, e := reloadCapture(filepath.Join(dir, v.name), m.uid)
		if e != nil || !desktopMigrationToken(v.sha) || desktopSum(b) != v.sha || st.Decode(bytes.NewReader(b), v.dst) != nil {
			return desktopError("STOP_EVIDENCE_INVALID")
		}
	}
	if r.Recovery != nil && r.StopDisposition != migrationRecoveryDisposition(a) {
		return desktopError("STOP_EVIDENCE_INVALID")
	}
	final, e := desktopDir(dir, m.uid, true)
	if e != nil || !os.SameFile(anchor, final) || anchor.Mode() != final.Mode() || reflect.ValueOf(anchor.Sys()).Elem().FieldByName("Gid").Uint() != reflect.ValueOf(final.Sys()).Elem().FieldByName("Gid").Uint() || !migrationStopProof(r, a, read) {
		return desktopError("STOP_EVIDENCE_INVALID")
	}
	return nil
}

// Separate new-transaction disposition, never a relabel of historical UNKNOWN.
func migrationRecoveryDisposition(a st.MutationResponse) string {
	if a.Diagnostics != nil && a.Diagnostics.Restoration == "UNKNOWN" {
		return "NEW_STOP_CONFIRMED_NO_BASELINE"
	}
	return "NEW_STOP_CONFIRMED"
}
