package main

// Retained receipts are historical app-user authority, not live process probes.
// This reader never reconciles, dispatches, repairs, or removes a journal.
import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	tl "github.com/NiuStar/anytls-core/internal/startuptimeline"
)

const reloadReceiptLimit = 768 * 1024

var reloadID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var reloadRevision = regexp.MustCompile(`^[0-9a-f]{40}$`)
var reloadTag = regexp.MustCompile(`^v[0-9A-Za-z.+_-]+$`)
var reloadInterface = regexp.MustCompile(`^utun[0-9]+$`)
var reloadInvalid = desktopError("CORE_RELOAD_PENDING")

// Compare syscall security/identity/change fields, excluding atime (our own
// reads may update it). Reflection names are portable Linux/Darwin Stat_t fields.
func reloadStable(a, b os.FileInfo) bool {
	if a == nil || b == nil || !os.SameFile(a, b) || a.Mode() != b.Mode() || a.Size() != b.Size() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	x, y := reflect.ValueOf(a.Sys()).Elem(), reflect.ValueOf(b.Sys()).Elem()
	for _, n := range []string{"Uid", "Gid", "Nlink", "Ctim", "Ctimespec"} {
		u, v := x.FieldByName(n), y.FieldByName(n)
		if u.IsValid() != v.IsValid() || u.IsValid() && !reflect.DeepEqual(u.Interface(), v.Interface()) {
			return false
		}
	}
	return true
}
func reloadCapture(path string, uid int) ([]byte, os.FileInfo, error) {
	before, e := desktopFile(path, uid, 0600)
	if e != nil || before.Mode() != 0600 || before.Size() < 0 || before.Size() > reloadReceiptLimit {
		return nil, nil, reloadInvalid
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, nil, reloadInvalid
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !reloadStable(before, opened) {
		return nil, nil, reloadInvalid
	}
	raw, e := io.ReadAll(io.LimitReader(f, reloadReceiptLimit+1))
	if e != nil || int64(len(raw)) != before.Size() {
		return nil, nil, reloadInvalid
	}
	after, e := f.Stat()
	if e != nil || !reloadStable(before, after) {
		return nil, nil, reloadInvalid
	}
	final, e := os.Lstat(path)
	if e != nil || !reloadStable(before, final) {
		return nil, nil, reloadInvalid
	}
	return raw, before, nil
}

// Narrow bounded JSON tree: duplicate (including case alias), trailing, null
// and exact closed-schema types are checked before any authority decisions.
func reloadJSON(raw []byte) (map[string]any, error) {
	if len(raw) > reloadReceiptLimit || !utf8.Valid(raw) {
		return nil, reloadInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, e := reloadValue(d, 0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, reloadInvalid
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, reloadInvalid
	}
	return m, nil
}
func reloadValue(d *json.Decoder, depth int) (any, error) {
	if depth > 24 {
		return nil, reloadInvalid
	}
	t, e := d.Token()
	if e != nil {
		return nil, reloadInvalid
	}
	switch v := t.(type) {
	case string:
		if len(v) > 16384 || strings.ContainsRune(v, 0) {
			return nil, reloadInvalid
		}
		return v, nil
	case json.Delim:
		if v == '{' {
			m := map[string]any{}
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				s, ok := k.(string)
				if e != nil || !ok || len(s) > 128 || len(m) >= 64 || seen[strings.ToLower(s)] {
					return nil, reloadInvalid
				}
				seen[strings.ToLower(s)] = true
				x, e := reloadValue(d, depth+1)
				if e != nil {
					return nil, e
				}
				m[s] = x
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return nil, reloadInvalid
			}
			return m, nil
		}
		if v == '[' {
			a := []any{}
			for d.More() {
				if len(a) >= 1024 {
					return nil, reloadInvalid
				}
				x, e := reloadValue(d, depth+1)
				if e != nil {
					return nil, e
				}
				a = append(a, x)
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return nil, reloadInvalid
			}
			return a, nil
		}
		return nil, reloadInvalid
	default:
		return t, nil
	}
}
func reloadShape(m map[string]any, keys string) bool {
	if m == nil || len(m) != len(strings.Fields(keys)) {
		return false
	}
	for _, k := range strings.Fields(keys) {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}
func reloadMap(v any) map[string]any { m, _ := v.(map[string]any); return m }
func reloadString(v any) string      { s, _ := v.(string); return s }
func reloadInt(v any, positive bool) bool {
	n, ok := v.(json.Number)
	if !ok {
		return false
	}
	i, e := strconv.ParseInt(string(n), 10, 64)
	return e == nil && strconv.FormatInt(i, 10) == string(n) && (!positive || i > 0)
}
func reloadConfig(v any, identity string) bool {
	m := reloadMap(v)
	return reloadShape(m, "identity config selection") && m["identity"] == identity && desktopMigrationToken(reloadString(m["config"])) && (m["selection"] == nil || desktopMigrationToken(reloadString(m["selection"])))
}
func reloadCore(v any, app string) bool {
	m := reloadMap(v)
	return reloadShape(m, "pid uid birth command") && reloadInt(m["pid"], true) && m["uid"] == json.Number("0") && reloadString(m["birth"]) != "" && strings.HasPrefix(reloadString(m["command"]), filepath.Join(app, "service/anytls-macos")+" ")
}
func reloadDiagnostics(v any, stop bool) bool {
	m := reloadMap(v)
	if !reloadShape(m, "schema operation outcome stage reason rollback restoration cleanup receipt job tun") || m["schema"] != json.Number("1") {
		return false
	}
	enums := map[string]string{"operation": "START RELOAD STOP", "outcome": "SUCCEEDED", "stage": "NONE", "reason": "NONE", "rollback": "NOT_ATTEMPTED VERIFIED FAILED UNKNOWN", "restoration": "NOT_ATTEMPTED VERIFIED FAILED UNKNOWN", "cleanup": "NOT_ATTEMPTED VERIFIED FAILED UNKNOWN", "receipt": "NOT_ATTEMPTED WRITTEN FAILED UNKNOWN", "job": "NOT_OBSERVED RUNNING NOT_RUNNING UNLOADED UNKNOWN", "tun": "NOT_OBSERVED TUN NOT_TUN UNKNOWN"}
	for k, values := range enums {
		found := false
		for _, s := range strings.Fields(values) {
			if m[k] == s {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return !stop || (m["operation"] == "STOP" && m["job"] == "UNLOADED" && m["tun"] != "TUN")
}
func reloadStatus(v any, digest, tag, identity string, loaded bool) bool {
	m := reloadMap(v)
	keys := "ok code message loaded running helper_version helper_sha256 config_identity"
	if _, ok := m["diagnostics"]; ok {
		keys += " diagnostics"
		if !reloadDiagnostics(m["diagnostics"], false) {
			return false
		}
	}
	_, str := m["message"].(string)
	return reloadShape(m, keys) && str && m["ok"] == true && m["code"] == "" && m["loaded"] == loaded && m["running"] == loaded && m["helper_sha256"] == digest && m["helper_version"] == tag && m["config_identity"] == identity
}
func reloadRejectionDiag() map[string]any {
	return map[string]any{"schema": json.Number("1"), "operation": "RELOAD", "outcome": "FAILED", "stage": "HELPER_PREFLIGHT", "reason": "PREFLIGHT_REJECTED", "rollback": "NOT_ATTEMPTED", "restoration": "NOT_ATTEMPTED", "cleanup": "NOT_ATTEMPTED", "receipt": "NOT_ATTEMPTED", "job": "NOT_OBSERVED", "tun": "NOT_OBSERVED"}
}
func reloadResponse(v any, op, epoch, digest, tag, identity string, stop bool) bool {
	m := reloadMap(v)
	if !reloadShape(m, "timeline_schema code ok helper_epoch operation_id timeline_availability helper_version helper_sha256 config_identity loaded running diagnostics") {
		return false
	}
	code := "PREFLIGHT_FAILED"
	if stop {
		code = ""
	}
	diag := reflect.DeepEqual(m["diagnostics"], reloadRejectionDiag())
	if stop {
		diag = reloadDiagnostics(m["diagnostics"], true)
	}
	return m["timeline_schema"] == json.Number("1") && m["code"] == code && m["ok"] == stop && m["loaded"] == false && m["running"] == false && m["operation_id"] == op && m["helper_epoch"] == epoch && m["timeline_availability"] == "AVAILABLE" && m["helper_sha256"] == digest && m["helper_version"] == tag && m["config_identity"] == identity && diag
}
func reloadPtr(p *string, s string) bool { return p != nil && *p == s }
func reloadTrace(v any, op, epoch, digest, tag, revision, identity string, stop bool) bool {
	raw, e := json.Marshal(v)
	if e != nil {
		return false
	}
	var r tl.ReadResponse
	if tl.Decode(bytes.NewReader(raw), &r) != nil {
		return false
	}
	if !stop && r.Code == "OPERATION_MISMATCH" {
		return reloadPtr(r.HelperEpoch, epoch) && reloadPtr(r.ConfigIdentity, identity) && r.OperationID != nil && reloadID.MatchString(*r.OperationID) && *r.OperationID != op && r.Trace == nil
	}
	if r.Code != "OK" || !reloadPtr(r.OperationID, op) || !reloadPtr(r.HelperEpoch, epoch) || !reloadPtr(r.ConfigIdentity, identity) || r.Trace == nil {
		return false
	}
	t := r.Trace
	operation, source, result := "RELOAD", "MANUAL_RELOAD", "FAILED"
	if stop {
		operation, source, result = "STOP", "MANUAL_STOP", "SUCCEEDED"
	}
	if t.OperationID != op || !reloadPtr(t.HelperEpoch, epoch) || !reloadPtr(t.ConfigIdentity, identity) || t.Operation != operation || t.Source != source || t.State != "FINISHED" || t.LifecycleResult != result || t.HelperReturn != result || t.WebReturn != "NOT_ATTEMPTED" || len(t.Streams) != 1 || t.FinishedAt == nil {
		return false
	}
	tm := reloadMap(reloadMap(v)["trace"])
	if stop {
		if !reloadDiagnostics(tm["diagnostics"], true) {
			return false
		}
	} else {
		if !reflect.DeepEqual(tm["diagnostics"], reloadRejectionDiag()) || t.ReceiptResult != "NOT_ATTEMPTED" || !t.Gap || t.CoreObservation != (tl.CoreObservation{Availability: "NOT_OBSERVED", Gap: true}) {
			return false
		}
	}
	s := t.Streams[0]
	p := s.Provenance
	if s.Role != "HELPER" || s.Gap || s.DroppedEvents != "0" || s.FirstMissingSeq != nil || s.Current != nil || !reloadID.MatchString(s.ClockID) || !reloadPtr(p.Version, tag) || !reloadPtr(p.GitRevision, revision) || p.Dirty == nil || *p.Dirty || !reloadPtr(p.SHA256, digest) || p.SHAKind != "FILE_BYTES" || p.ExecutionMapping != "NOT_ATTESTED" || s.GeneratedEvents != strconv.Itoa(len(s.Events)) || len(s.RetainedRanges) != 1 || s.RetainedRanges[0] != (tl.SeqRange{First: "1", Last: strconv.Itoa(len(s.Events))}) || s.Terminal == nil || s.Terminal.Result != result || s.Terminal.ElapsedNS != s.ElapsedNS {
		return false
	}
	expected := [][5]string{{"HELPER_ACCEPT", "OBSERVATION", "OK", "PREFLIGHT", ""}, {"HELPER_PREFLIGHT_CAPTURE", "BEGIN", "NONE", "PREFLIGHT", "1"}, {"HELPER_PREFLIGHT_CAPTURE", "END", "OK", "PREFLIGHT", "1"}, {"HELPER_PREFLIGHT_COMPILE", "BEGIN", "NONE", "PREFLIGHT", "2"}, {"HELPER_PREFLIGHT_COMPILE", "END", "FAILED", "PREFLIGHT", "2"}, {"HELPER_FINISH", "OBSERVATION", "FAILED", "FINALIZE", ""}}
	if !stop && len(s.Events) != 6 {
		return false
	}
	if stop && (len(s.Events) < 4 || s.Events[0].Stage != "HELPER_ACCEPT" || s.Events[len(s.Events)-1].Stage != "HELPER_FINISH" || s.Events[len(s.Events)-1].Code != "OK") {
		return false
	}
	start, _ := time.Parse(time.RFC3339Nano, t.StartedAt)
	finish, _ := time.Parse(time.RFC3339Nano, *t.FinishedAt)
	origin, _ := time.Parse(time.RFC3339Nano, s.OriginAt)
	if origin.Before(start) || finish.Before(origin) {
		return false
	}
	previous := origin
	finalState := false
	for i, e := range s.Events {
		at, _ := time.Parse(time.RFC3339Nano, e.At)
		if at.Before(previous) || at.After(finish) {
			return false
		}
		previous = at
		if !stop {
			span := ""
			if e.SpanID != nil {
				span = *e.SpanID
			}
			if [5]string{e.Stage, e.State, e.Code, e.Segment, span} != expected[i] || e.Job != "NOT_OBSERVED" || e.Tun != "NOT_OBSERVED" || e.Round != nil || e.Ordinal != nil || e.RuleCount != nil || e.CompletedCount != nil {
				return false
			}
		}
		if e.Stage == "HELPER_FINAL_STATE" && e.State == "END" && e.Code == "OK" {
			finalState = true
		}
	}
	terminal, _ := time.Parse(time.RFC3339Nano, s.Terminal.At)
	elapsed, _ := strconv.ParseUint(s.Terminal.ElapsedNS, 10, 64)
	last, _ := strconv.ParseUint(s.Events[len(s.Events)-1].ElapsedNS, 10, 64)
	return (!stop || finalState) && !terminal.Before(previous) && !terminal.After(finish) && elapsed >= last
}
func reloadAccepted(files map[string][]byte, app, op string) bool {
	r, e := reloadJSON(files["result.json"])
	if e != nil || !reloadShape(r, "state operation_id helper_epoch new_core tun interface sha_kind execution_mapping network") || r["state"] != "SUCCEEDED" || r["operation_id"] != op || !reloadID.MatchString(reloadString(r["helper_epoch"])) || !reloadCore(r["new_core"], app) || r["tun"] != "TUN" || !reloadInterface.MatchString(reloadString(r["interface"])) || r["sha_kind"] != "FILE_BYTES" || r["execution_mapping"] != "NOT_ATTESTED" || r["network"] != "NOT_TESTED" {
		return false
	}
	// Match the two commands the worker actually accepts, bound only within
	// this historical receipt (never against today's PID or helper epoch).
	core := reloadMap(r["new_core"])
	command := filepath.Join(app, "service/anytls-macos") + " -config " + filepath.Join(app, "service/config.yaml") + " -network tun -record-service"
	tail := " -startup-operation " + op + " -startup-epoch " + reloadString(r["helper_epoch"]) + " -dns-observe-service run"
	if core["command"] != command+tail && core["command"] != command+" -allow-insecure"+tail {
		return false
	}
	a, e := reloadJSON(files["accepted.json"])
	return e == nil && reloadShape(a, "operation_id result_sha256") && a["operation_id"] == op && a["result_sha256"] == desktopSum(files["result.json"])
}
func reloadReconciled(files map[string][]byte, app, op string) bool {
	docs := map[string]map[string]any{}
	for _, n := range []string{"job.json", "intent.json", "response.json", "result.json", "claim.json", "reconciled.json"} {
		m, e := reloadJSON(files[n])
		if e != nil {
			return false
		}
		docs[n] = m
	}
	j, i, r, c, m := docs["job.json"], docs["intent.json"], docs["result.json"], docs["claim.json"], docs["reconciled.json"]
	identity := desktopSum([]byte(filepath.Join(app, "config.yaml")))
	digest, tag, rev := reloadString(j["digest"]), reloadString(j["tag"]), reloadString(j["revision"])
	epoch := reloadString(i["helper_epoch"])
	if !reloadShape(j, "app operation_id digest tag revision before") || j["app"] != app || j["operation_id"] != op || !desktopMigrationToken(digest) || !reloadTag.MatchString(tag) || !reloadRevision.MatchString(rev) || !reloadShape(c, "pid") || !reloadInt(c["pid"], true) || !reloadShape(r, "state operation_id error_class code") || r["state"] != "UNKNOWN" || r["operation_id"] != op || r["error_class"] != "ValueError" || r["code"] != "CORE_RELOAD_INVALID" {
		return false
	}
	before := reloadMap(j["before"])
	keys := "state config core"
	if prior, ok := before["status"]; ok {
		keys += " status"
		p := reloadMap(prior)
		pd, pt := reloadString(p["helper_sha256"]), reloadString(p["helper_version"])
		if !desktopMigrationToken(pd) || !reloadTag.MatchString(pt) || !reloadStatus(prior, pd, pt, identity, true) {
			return false
		}
	}
	if !reloadShape(before, keys) || before["state"] != "RUNNING" || !reloadConfig(before["config"], identity) || !reloadCore(before["core"], app) || !reloadShape(i, "operation_id helper_epoch action allow_insecure single_dispatch") || i["operation_id"] != op || !reloadID.MatchString(epoch) || i["action"] != "reload" || i["single_dispatch"] != true {
		return false
	}
	if _, ok := i["allow_insecure"].(bool); !ok {
		return false
	}
	if !reloadResponse(docs["response.json"], op, epoch, digest, tag, identity, false) || !reloadShape(m, "schema status operation_id helper_epoch receipt_sha256 helper_read current stop_sha256") || m["schema"] != json.Number("1") || m["status"] != "RECONCILED_PREFLIGHT_REJECTED" || m["operation_id"] != op || m["helper_epoch"] != epoch {
		return false
	}
	hashes := reloadMap(m["receipt_sha256"])
	if !reloadShape(hashes, "job.json intent.json response.json result.json claim.json") {
		return false
	}
	for n, h := range hashes {
		if h != desktopSum(files[n]) {
			return false
		}
	}
	if !reloadTrace(m["helper_read"], op, epoch, digest, tag, rev, identity, false) {
		return false
	}
	current := reloadMap(m["current"])
	if !reloadShape(current, "state config core status") || current["state"] != "STOPPED" || current["core"] != nil || !reloadConfig(current["config"], identity) || !reloadStatus(current["status"], digest, tag, identity, false) {
		return false
	}
	stop := reloadMap(m["stop_sha256"])
	if stop == nil {
		return false
	}
	actual := 0
	for _, n := range []string{"stop-intent.json", "stop-read.json", "stop-response.json"} {
		raw, ok := files[n]
		if ok {
			actual++
			if stop[n] != desktopSum(raw) {
				return false
			}
		} else if _, ok = stop[n]; ok {
			return false
		}
	}
	if len(stop) != actual {
		return false
	}
	if actual == 0 {
		return true
	}
	if actual < 2 || files["stop-intent.json"] == nil || files["stop-read.json"] == nil {
		return false
	}
	si, e := reloadJSON(files["stop-intent.json"])
	sop := reloadString(si["operation_id"])
	if e != nil || !reloadShape(si, "operation_id helper_epoch action allow_insecure single_dispatch") || !reloadID.MatchString(sop) || sop == op || si["helper_epoch"] != epoch || si["action"] != "stop" || si["allow_insecure"] != false || si["single_dispatch"] != true {
		return false
	}
	sr, e := reloadJSON(files["stop-read.json"])
	if e != nil || !reloadTrace(sr, sop, epoch, digest, tag, rev, identity, true) {
		return false
	}
	if actual == 3 {
		response, e := reloadJSON(files["stop-response.json"])
		if e != nil || !reloadResponse(response, sop, epoch, digest, tag, identity, true) {
			return false
		}
	}
	return true
}

// Fail closed on filesystem-resolving sentinels, including aliases not covered
// by Unicode simple folding. Lstat also sees dangling symlinks; errors hold.
func reloadSentinelsAbsent(dir string) bool {
	for _, n := range []string{"pending.json"} {
		if _, e := os.Lstat(filepath.Join(dir, n)); !os.IsNotExist(e) {
			return false
		}
	}
	return true
}

func (m desktopMigration) reloadTerminal(name string) error {
	op := strings.TrimPrefix(name, ".core-reload-")
	if !reloadID.MatchString(op) {
		return reloadInvalid
	}
	app, e := desktopBase(m.home, m.uid, false)
	if e != nil {
		return reloadInvalid
	}
	dir := filepath.Join(app, name)
	physical, e := filepath.EvalSymlinks(dir)
	if e != nil || physical != dir {
		return reloadInvalid
	}
	anchor, e := desktopDir(app, m.uid, false)
	if e != nil {
		return reloadInvalid
	}
	root, e := desktopDir(dir, m.uid, true)
	if e != nil || root.Mode() != os.ModeDir|0700 || !reloadSentinelsAbsent(dir) {
		return reloadInvalid
	}
	// Bound enumeration before allocation; legal regular ancillary receipts/logs
	// remain retained. No exact two-file allowlist on the accepted path.
	f, e := os.Open(dir)
	if e != nil {
		return reloadInvalid
	}
	entries, e := f.ReadDir(65)
	f.Close()
	if e != nil && e != io.EOF || len(entries) > 64 {
		return reloadInvalid
	}
	files := map[string][]byte{}
	stamps := map[string]os.FileInfo{}
	total := 0
	for _, entry := range entries {
		n := entry.Name()
		if n == "pending.json" {
			return reloadInvalid
		}
		// Reserved names cannot become ancillary authority through case aliases,
		// even on a filesystem where the two spellings are distinct entries.
		for _, reserved := range []string{"pending.json", "operator-reconciled.json", "accepted.json", "reconciled.json", "timeline.json", "stop-intent.json", "stop-read.json", "stop-response.json", "job.json", "intent.json", "response.json", "result.json", "claim.json"} {
			if n != reserved && strings.EqualFold(n, reserved) {
				return reloadInvalid
			}
		}
		raw, st, e := reloadCapture(filepath.Join(dir, n), m.uid)
		if e != nil {
			return reloadInvalid
		}
		total += len(raw)
		if total > 12*reloadReceiptLimit {
			return reloadInvalid
		}
		files[n], stamps[n] = raw, st
	}
	if _, ok := files["operator-reconciled.json"]; ok {
		if files["accepted.json"] != nil || files["reconciled.json"] != nil || !reloadOperator(files, app, op) {
			return reloadInvalid
		}
	} else if _, ok := files["accepted.json"]; ok {
		if files["reconciled.json"] != nil || !reloadAccepted(files, app, op) {
			return reloadInvalid
		}
	} else {
		if files["timeline.json"] != nil || !reloadReconciled(files, app, op) {
			return reloadInvalid
		}
	}
	for n, raw := range files {
		again, st, e := reloadCapture(filepath.Join(dir, n), m.uid)
		if e != nil || !reloadStable(stamps[n], st) || !bytes.Equal(raw, again) {
			return reloadInvalid
		}
	}
	// Explicit membership fence, not only inode/mtime: even a newly resurrected
	// pending sentinel must hold this provisional read.
	f, e = os.Open(dir)
	if e != nil {
		return reloadInvalid
	}
	finalEntries, e := f.ReadDir(65)
	f.Close()
	if e != nil && e != io.EOF || len(finalEntries) != len(entries) {
		return reloadInvalid
	}
	for _, entry := range finalEntries {
		if _, ok := files[entry.Name()]; !ok {
			return reloadInvalid
		}
	}
	final, e := os.Lstat(dir)
	if e != nil || !reloadStable(root, final) {
		return reloadInvalid
	}
	end, e := os.Lstat(app)
	if e != nil || !reloadStable(anchor, end) {
		return reloadInvalid
	}
	physical, e = filepath.EvalSymlinks(dir)
	if e != nil || physical != dir || !reloadSentinelsAbsent(dir) {
		return reloadInvalid
	}
	return nil
}
