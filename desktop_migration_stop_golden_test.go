package main

import (
	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
	"strings"
	"testing"
)

// Frozen sanitized incumbent stream. Synthetic bindings below never authorize
// or correlate the historical Mac STOP; the original mutation ACK is absent.
const migrationObservedIncumbentStream = `{"role":"HELPER","clock_id":"ffb27c50f44457e12cdedd82c98af8fc","origin_at":"2026-11-08T06:37:08.360364Z","elapsed_ns":"32540167","provenance":{"version":"v2026-11-06-03","git_revision":"9e6e996bda684ecfce134dc842edf1b96c8ca256","dirty":false,"sha256":"1142fb1d250495541fd19231091698bd5e23986599d62c69d4cee276d1a8f8ff","sha_kind":"FILE_BYTES","execution_mapping":"NOT_ATTESTED"},"current":null,"events":[{"seq":"1","span_id":null,"segment":"PREFLIGHT","stage":"HELPER_ACCEPT","state":"OBSERVATION","code":"OK","at":"2026-11-08T06:37:08.360482Z","elapsed_ns":"117917","duration_ns":null,"round":null,"ordinal":null,"rule_count":null,"completed_count":null,"job":"NOT_OBSERVED","tun":"NOT_OBSERVED"},{"seq":"2","span_id":"1","segment":"STOP","stage":"STOP_CAPTURE","state":"BEGIN","code":"NONE","at":"2026-11-08T06:37:08.360806Z","elapsed_ns":"442125","duration_ns":null,"round":null,"ordinal":null,"rule_count":null,"completed_count":null,"job":"NOT_OBSERVED","tun":"NOT_OBSERVED"},{"seq":"3","span_id":"1","segment":"STOP","stage":"STOP_CAPTURE","state":"END","code":"OK","at":"2026-11-08T06:37:08.360849Z","elapsed_ns":"485292","duration_ns":"43167","round":null,"ordinal":null,"rule_count":null,"completed_count":null,"job":"NOT_OBSERVED","tun":"NOT_OBSERVED"},{"seq":"4","span_id":"2","segment":"STOP","stage":"JOB_INITIAL","state":"BEGIN","code":"NONE","at":"2026-11-08T06:37:08.360853Z","elapsed_ns":"488625","duration_ns":null,"round":null,"ordinal":null,"rule_count":null,"completed_count":null,"job":"NOT_OBSERVED","tun":"NOT_OBSERVED"},{"seq":"5","span_id":"2","segment":"STOP","stage":"JOB_INITIAL","state":"END","code":"OK","at":"2026-11-08T06:37:08.375804Z","elapsed_ns":"15439750","duration_ns":"14951125","round":null,"ordinal":null,"rule_count":null,"completed_count":null,"job":"UNLOADED","tun":"NOT_OBSERVED"},{"seq":"6","span_id":"3","segment":"STOP","stage":"SNAPSHOT_EXISTENCE","state":"BEGIN","code":"NONE","at":"2026-11-08T06:37:08.375842Z","elapsed_ns":"15477542","duration_ns":null,"round":null,"ordinal":null,"rule_count":null,"completed_count":null,"job":"NOT_OBSERVED","tun":"NOT_OBSERVED"},{"seq":"7","span_id":"3","segment":"STOP","stage":"SNAPSHOT_EXISTENCE","state":"END","code":"OK","at":"2026-11-08T06:37:08.375882Z","elapsed_ns":"15518333","duration_ns":"40791","round":null,"ordinal":null,"rule_count":null,"completed_count":null,"job":"NOT_OBSERVED","tun":"NOT_OBSERVED"},{"seq":"8","span_id":"4","segment":"STOP","stage":"RECEIPT_FINISH","state":"BEGIN","code":"NONE","at":"2026-11-08T06:37:08.37661Z","elapsed_ns":"16245917","duration_ns":null,"round":null,"ordinal":null,"rule_count":null,"completed_count":null,"job":"NOT_OBSERVED","tun":"NOT_OBSERVED"},{"seq":"9","span_id":"5","segment":"STOP","stage":"RECEIPT_WRITE","state":"BEGIN","code":"NONE","at":"2026-11-08T06:37:08.376616Z","elapsed_ns":"16252250","duration_ns":null,"round":null,"ordinal":null,"rule_count":null,"completed_count":null,"job":"NOT_OBSERVED","tun":"NOT_OBSERVED"},{"seq":"10","span_id":"5","segment":"STOP","stage":"RECEIPT_WRITE","state":"END","code":"OK","at":"2026-11-08T06:37:08.3823Z","elapsed_ns":"21936167","duration_ns":"5683917","round":null,"ordinal":null,"rule_count":null,"completed_count":null,"job":"NOT_OBSERVED","tun":"NOT_OBSERVED"},{"seq":"11","span_id":"4","segment":"STOP","stage":"RECEIPT_FINISH","state":"END","code":"OK","at":"2026-11-08T06:37:08.382318Z","elapsed_ns":"21953625","duration_ns":"5707708","round":null,"ordinal":null,"rule_count":null,"completed_count":null,"job":"NOT_OBSERVED","tun":"NOT_OBSERVED"},{"seq":"12","span_id":"6","segment":"FINALIZE","stage":"HELPER_FINAL_STATE","state":"BEGIN","code":"NONE","at":"2026-11-08T06:37:08.382324Z","elapsed_ns":"21959333","duration_ns":null,"round":null,"ordinal":null,"rule_count":null,"completed_count":null,"job":"NOT_OBSERVED","tun":"NOT_OBSERVED"},{"seq":"13","span_id":"6","segment":"FINALIZE","stage":"HELPER_FINAL_STATE","state":"END","code":"OK","at":"2026-11-08T06:37:08.392834Z","elapsed_ns":"32469667","duration_ns":"10510334","round":null,"ordinal":null,"rule_count":null,"completed_count":null,"job":"NOT_OBSERVED","tun":"NOT_OBSERVED"},{"seq":"14","span_id":null,"segment":"FINALIZE","stage":"HELPER_FINISH","state":"OBSERVATION","code":"OK","at":"2026-11-08T06:37:08.392877Z","elapsed_ns":"32512667","duration_ns":null,"round":null,"ordinal":null,"rule_count":null,"completed_count":null,"job":"NOT_OBSERVED","tun":"NOT_OBSERVED"}],"generated_events":"14","dropped_events":"0","first_missing_seq":null,"retained_ranges":[{"first":"1","last":"14"}],"terminal":{"result":"SUCCEEDED","at":"2026-11-08T06:37:08.392904Z","elapsed_ns":"32540167"},"gap":false}`

func TestDesktopMigrationStopObservedIncumbentGolden(t *testing.T) {
	m, h, _ := migrationIncumbentFixture(t)
	r, e := m.preflight()
	if e != nil {
		t.Fatal(e)
	}
	r.StopOperation = strings.Repeat("a", 32)
	d := &st.Diagnostics{Schema: 1, Operation: "STOP", Outcome: "SUCCEEDED", Stage: "NONE", Reason: "NONE", Rollback: "NOT_ATTEMPTED", Restoration: "UNKNOWN", Cleanup: "VERIFIED", Receipt: "WRITTEN", Job: "UNLOADED", Tun: "NOT_OBSERVED"}
	a := migrationFixtureAck(*h, r.StopOperation)
	a.Diagnostics = d
	read := migrationFixtureRead(a)
	var stream st.ProcessStream
	if e = st.Decode(strings.NewReader(migrationObservedIncumbentStream), &stream); e != nil {
		t.Fatal(e)
	}
	read.Trace.Streams = []st.ProcessStream{stream}
	read.Trace.StartedAt = stream.OriginAt
	at := "2026-11-08T06:37:08.392905Z"
	read.Trace.FinishedAt = &at
	read.Trace.ReceiptResult = "WRITTEN"
	if !migrationStopProof(r, a, read) {
		t.Fatal("observed incumbent branch rejected")
	}
	r.StopOperation = ""
	if migrationStopProof(r, a, read) {
		t.Fatal("historical unbound trace accepted")
	}
}
