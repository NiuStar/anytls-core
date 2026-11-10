package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"reflect"
	"time"

	tl "github.com/NiuStar/anytls-core/internal/startuptimeline"
)

// Historical explicit operator proof is a third, disjoint receipt family.
// UNKNOWN remains UNKNOWN: this validates the frozen authorization to unlink
// pending, never today's worker, process, config contents, or helper state.
func reloadOperator(files map[string][]byte, app, op string) bool {
	docs := map[string]map[string]any{}
	for _, n := range []string{"operator-reconciled.json", "job.json", "intent.json", "response.json", "result.json", "claim.json", "timeline.json"} {
		v, e := reloadJSON(files[n])
		if e != nil {
			return false
		}
		docs[n] = v
	}
	m, j, i, r, c, response := docs["operator-reconciled.json"], docs["job.json"], docs["intent.json"], docs["result.json"], docs["claim.json"], docs["response.json"]
	if !reloadShape(m, "schema status operation_id helper_epoch receipt_sha256 pending_raw_base64 pending_sha256 stop_read current authorization historical_process_identity action") || m["schema"] != json.Number("1") || m["status"] != "RECONCILED_RELOAD_STOPPED" || m["operation_id"] != op || m["authorization"] != "EXPLICIT_OPERATOR" || m["historical_process_identity"] != "UNAVAILABLE" || m["action"] != "UNLINK_PENDING_ONLY" {
		return false
	}
	hashes := reloadMap(m["receipt_sha256"])
	if !reloadShape(hashes, "job.json intent.json response.json result.json claim.json timeline.json worker.log") {
		return false
	}
	for n, h := range hashes {
		raw, ok := files[n]
		if !ok || h != desktopSum(raw) {
			return false
		}
	}
	identity := desktopSum([]byte(filepath.Join(app, "config.yaml")))
	digest, tag, rev, epoch := reloadString(j["digest"]), reloadString(j["tag"]), reloadString(j["revision"]), reloadString(i["helper_epoch"])
	local, valid := reloadJobSchema(j)
	if !valid || j["app"] != app || j["operation_id"] != op || !desktopMigrationToken(digest) || !reloadTag.MatchString(tag) || !reloadRevision.MatchString(rev) || !reloadShape(c, "pid") || !reloadInt(c["pid"], true) || !reloadShape(r, "state operation_id error_class code") || r["state"] != "UNKNOWN" || r["operation_id"] != op || r["error_class"] != "ValueError" || r["code"] != "CORE_RELOAD_NEW_PROCESS" {
		return false
	}
	before := reloadMap(j["before"])
	keys := "state config core"
	if prior, ok := before["status"]; ok {
		keys += " status"
		p := reloadMap(prior)
		pd, pt := reloadString(p["helper_sha256"]), reloadString(p["helper_version"])
		if !desktopMigrationToken(pd) || !reloadTag.MatchString(pt) || !reloadStatus(prior, pd, pt, identity, true, local) {
			return false
		}
	}
	if !reloadShape(before, keys) || before["state"] != "RUNNING" || !reloadConfig(before["config"], identity) || !reloadCore(before["core"], app) || !reloadShape(i, "operation_id helper_epoch action allow_insecure single_dispatch") || i["operation_id"] != op || !reloadID.MatchString(epoch) || m["helper_epoch"] != epoch || i["action"] != "reload" || i["single_dispatch"] != true {
		return false
	}
	if _, ok := i["allow_insecure"].(bool); !ok {
		return false
	}
	if !reloadShape(response, "timeline_schema code ok helper_epoch operation_id timeline_availability helper_version helper_sha256 config_identity loaded running diagnostics") || response["timeline_schema"] != json.Number("1") || response["code"] != "" || response["ok"] != true || response["loaded"] != true || response["running"] != true || response["operation_id"] != op || response["helper_epoch"] != epoch || response["timeline_availability"] != "AVAILABLE" || response["helper_sha256"] != digest || response["helper_version"] != tag || response["config_identity"] != identity || !reloadSuccessDiagnostics(response["diagnostics"], local) {
		return false
	}
	raw := reloadString(m["pending_raw_base64"])
	if len(raw) > 4096 {
		return false
	}
	pending, e := base64.StdEncoding.Strict().DecodeString(raw)
	if e != nil || base64.StdEncoding.EncodeToString(pending) != raw || m["pending_sha256"] != desktopSum(pending) {
		return false
	}
	p, e := reloadJSON(pending)
	if e != nil || !reloadShape(p, "operation_id") || p["operation_id"] != op {
		return false
	}
	timeline := docs["timeline.json"]
	var read tl.ReadResponse
	if tl.Decode(bytes.NewReader(files["timeline.json"]), &read) != nil || read.Code != "OK" || !reloadPtr(read.OperationID, op) || !reloadPtr(read.HelperEpoch, epoch) || !reloadPtr(read.ConfigIdentity, identity) || read.Trace == nil {
		return false
	}
	t := read.Trace
	if t.OperationID != op || !reloadPtr(t.HelperEpoch, epoch) || !reloadPtr(t.ConfigIdentity, identity) || t.Operation != "RELOAD" || t.Source != "MANUAL_RELOAD" || t.State != "FINISHED" || t.LifecycleResult != "SUCCEEDED" || t.HelperReturn != "SUCCEEDED" || t.WebReturn != "NOT_ATTEMPTED" || t.ReceiptResult != "WRITTEN" || t.FinishedAt == nil || len(t.Streams) != 2 || !reflect.DeepEqual(reloadMap(timeline["trace"])["diagnostics"], response["diagnostics"]) {
		return false
	}
	coreStart := false
	for _, s := range t.Streams {
		p := s.Provenance
		if (s.Role != "HELPER" && s.Role != "CORE") || !reloadPtr(p.Version, tag) || !reloadPtr(p.GitRevision, rev) || p.Dirty == nil || *p.Dirty || !reloadPtr(p.SHA256, digest) || p.SHAKind != "FILE_BYTES" || p.ExecutionMapping != "NOT_ATTESTED" {
			return false
		}
		for _, e := range s.Events {
			if s.Role == "CORE" && e.Stage == "CORE_START" && e.State == "END" && e.Code == "OK" {
				coreStart = true
			}
		}
	}
	if !coreStart {
		return false
	}
	stop := reloadMap(m["stop_read"])
	sop := reloadString(stop["operation_id"])
	if !reloadID.MatchString(sop) || sop == op || !reloadTrace(stop, sop, epoch, digest, tag, rev, identity, true) {
		return false
	}
	start, _ := time.Parse(time.RFC3339Nano, t.StartedAt)
	finish, _ := time.Parse(time.RFC3339Nano, *t.FinishedAt)
	st := reloadMap(stop["trace"])
	ss, e := time.Parse(time.RFC3339Nano, reloadString(st["started_at"]))
	if e != nil {
		return false
	}
	sf, e := time.Parse(time.RFC3339Nano, reloadString(st["finished_at"]))
	if e != nil || finish.Before(start) || ss.Before(finish) || sf.Before(ss) {
		return false
	}
	current := reloadMap(m["current"])
	return reloadShape(current, "state config core status") && current["state"] == "STOPPED" && current["core"] == nil && reloadConfig(current["config"], identity) && reloadStatus(current["status"], digest, tag, identity, false, local)
}
func reloadSuccessDiagnostics(v any, localReady ...bool) bool {
	m := reloadMap(v)
	return reloadDiagnostics(v, false, localReady...) && m["operation"] == "RELOAD" && m["job"] == "RUNNING" && m["tun"] == "TUN" && m["receipt"] == "WRITTEN"
}
