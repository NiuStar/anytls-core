package startuptimeline

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type Code string

const (
	Invalid     Code = "INVALID_TRACE"
	TooLarge    Code = "FRAME_TOO_LARGE"
	Unavailable Code = "UNAVAILABLE"
)

func (c Code) Error() string { return string(c) }
func frameLimit(v any) int {
	switch v.(type) {
	case ReadRequest, *ReadRequest, MutationRequest, *MutationRequest, MutationResponse, *MutationResponse, PushAck, *PushAck, OperationReference, *OperationReference:
		return LegacyBytes
	case PushRequest, *PushRequest, CoreSnapshot, *CoreSnapshot:
		return PushBytes
	case ReadResponse, *ReadResponse, Trace, *Trace, ProcessStream, *ProcessStream:
		return ReadBytes
	}
	return 0
}

// Encode validates bounded fields before allocating a JSON frame. No partial
// frame is returned. Newline is included in the direction-specific budget.
func Encode(v any) ([]byte, error) {
	if frameLimit(v) == 0 {
		return nil, Invalid
	}
	if err := Validate(v); err != nil {
		return nil, err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, Invalid
	}
	if len(b)+1 > frameLimit(v) {
		return nil, TooLarge
	}
	return append(b, '\n'), nil
}

// Decode rejects duplicates at every depth before assigning the destination.
// A bounded raw syntax tree is checked against exact typed keys, then decoded
// into a temporary DTO. Errors never expose attacker-controlled content.
func Decode(r io.Reader, v any) error {
	limit := frameLimit(v)
	rv := reflect.ValueOf(v)
	if limit == 0 || rv.Kind() != reflect.Pointer || rv.IsNil() {
		return Invalid
	}
	b, err := io.ReadAll(io.LimitReader(r, int64(limit+1)))
	if err != nil {
		return Unavailable
	}
	if len(b) > limit {
		return TooLarge
	}
	if !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return Invalid
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	raw, err := readValue(d, 0)
	if err != nil {
		return Invalid
	}
	if _, err = d.Token(); err != io.EOF {
		return Invalid
	}
	if !shape(raw, rv.Elem().Type()) {
		return Invalid
	}
	temp := reflect.New(rv.Elem().Type())
	if json.Unmarshal(b, temp.Interface()) != nil {
		return Invalid
	}
	if err = Validate(temp.Interface()); err != nil {
		return err
	}
	rv.Elem().Set(temp.Elem())
	return nil
}
func readValue(d *json.Decoder, depth int) (any, error) {
	if depth > 24 {
		return nil, Invalid
	}
	t, e := d.Token()
	if e != nil {
		return nil, Invalid
	}
	switch x := t.(type) {
	case string:
		if len(x) > 128 || strings.ContainsRune(x, 0) || !utf8.ValidString(x) {
			return nil, Invalid
		}
		return x, nil
	case json.Delim:
		if x == '{' {
			m := map[string]any{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return nil, Invalid
				}
				s, ok := k.(string)
				if !ok || len(s) > 128 {
					return nil, Invalid
				}
				if _, ok = m[s]; ok {
					return nil, Invalid
				}
				v, e := readValue(d, depth+1)
				if e != nil {
					return nil, e
				}
				m[s] = v
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return nil, Invalid
			}
			return m, nil
		}
		if x == '[' {
			a := []any{}
			for d.More() {
				if len(a) >= HelperHead+HelperTail {
					return nil, Invalid
				}
				v, e := readValue(d, depth+1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return nil, Invalid
			}
			return a, nil
		}
		return nil, Invalid
	default:
		return t, nil
	}
}
func shape(x any, t reflect.Type) bool {
	if t.Kind() == reflect.Pointer {
		return x == nil || shape(x, t.Elem())
	}
	if x == nil {
		return false
	}
	switch t.Kind() {
	case reflect.Struct:
		m, ok := x.(map[string]any)
		if !ok || len(m) != t.NumField() {
			return false
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			v, ok := m[f.Tag.Get("json")]
			if !ok || !shape(v, f.Type) {
				return false
			}
		}
		return true
	case reflect.Slice:
		a, ok := x.([]any)
		if !ok {
			return false
		}
		for _, v := range a {
			if !shape(v, t.Elem()) {
				return false
			}
		}
		return true
	case reflect.String:
		_, ok := x.(string)
		return ok
	case reflect.Bool:
		_, ok := x.(bool)
		return ok
	case reflect.Int:
		n, ok := x.(json.Number)
		return ok && n.String() == "1"
	}
	return false
}

var hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)
var hex40 = regexp.MustCompile(`^[0-9a-f]{40}$`)
var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var version = regexp.MustCompile(`^[A-Za-z0-9.+_-]{1,128}$`)

func in(s, values string) bool {
	return strings.Contains(" "+values+" ", " "+s+" ") && !strings.ContainsAny(s, " \t\n\r") && s != ""
}
func dec(s string) (uint64, bool) {
	n, e := strconv.ParseUint(s, 10, 64)
	return n, e == nil && strconv.FormatUint(n, 10) == s
}
func decimal(s *string) bool {
	if s == nil {
		return true
	}
	_, ok := dec(*s)
	return ok
}
func wall(s string) bool {
	t, e := time.Parse(time.RFC3339Nano, s)
	return e == nil && t.Year() >= 0 && t.Year() <= 9999 && t.UTC().Format(time.RFC3339Nano) == s
}
func nullable(s *string, f func(string) bool) bool { return s == nil || f(*s) }
func id(s string) bool                             { return hex32.MatchString(s) }
func digest(s string) bool                         { return hex64.MatchString(s) }
func result(s string) bool {
	return in(s, "NOT_ATTEMPTED IN_PROGRESS SUCCEEDED FAILED CANCELLED UNKNOWN")
}
func receipt(s string) bool { return in(s, "NOT_ATTEMPTED WRITTEN FAILED UNKNOWN") }
func phase(p CurrentPhase) bool {
	n, ok := dec(p.SpanID)
	_, timeok := dec(p.BeganElapsedNS)
	return ok && n > 0 && timeok && wall(p.BeganAt) && segment(p.Segment) && stageRole(p.Stage) != ""
}
func segment(s string) bool { return in(s, "PREFLIGHT STOP START ROLLBACK FINALIZE") }

var stageRoles = map[string]string{}

func init() {
	for _, s := range strings.Fields("WEB_ACCEPT WEB_BOUND_STATUS WEB_WAIT_HELPER WEB_VERIFY_STATE WEB_FINISH") {
		stageRoles[s] = "WEB"
	}
	for _, s := range strings.Fields("HELPER_ACCEPT HELPER_PREFLIGHT_CAPTURE HELPER_PREFLIGHT_COMPILE HELPER_PREFLIGHT_CA HELPER_PREFLIGHT_ENGINE_CHECK HELPER_RELOAD_JOB JOB_INITIAL SNAPSHOT_EXISTENCE SNAPSHOT_STAGE SNAPSHOT_APP_CONFIG_SELECTED SNAPSHOT_RULES SNAPSHOT_CA SNAPSHOT_IDENTITY RECEIPT_CAPTURE CONFIG_OUTBOUNDS_COMPILE PROXY_CHECK BASELINE_SERVER_ROUTES BASELINE_PUBLIC_ROUTE BASELINE_DNS BASELINE_WRITE BASELINE_REVALIDATE PLIST_CREATE_WRITE_CLOSE PLIST_LINT BOOTSTRAP READINESS_ROUND READINESS_JOB READINESS_PUBLIC_ROUTE READINESS_SERVER_ROUTES READINESS_PAUSE CORE_SNAPSHOT_CAPTURE HTTPS_ATTEMPT HTTPS_RETRY_JOB HTTPS_RETRY_PUBLIC_ROUTE HTTPS_RETRY_SERVER_ROUTES FINAL_JOB FINAL_PUBLIC_ROUTE FINAL_SERVER_ROUTES FINAL_DNS STOP_CAPTURE STOP_BASELINE BOOTOUT STOP_ROUND RESTORE_JOB RESTORE_PUBLIC_ROUTE RESTORE_SERVER_ROUTES RESTORE_DNS SNAPSHOT_REMOVE RECEIPT_FINISH RECEIPT_WRITE HELPER_FINAL_STATE HELPER_FINISH") {
		stageRoles[s] = "HELPER"
	}
	for _, s := range strings.Fields("CORE_ENTER CORE_COMPILE CORE_COMPILE_MAP CORE_JSON_ENCODE CORE_MANIFEST_CA CORE_MANIFEST_DIGEST CORE_DISPATCH CORE_DECODE CORE_PIN_CA CORE_BOX_NEW CORE_OPEN_SINK CORE_BIND_RECORDS CORE_START CORE_WAIT CORE_CLOSE CORE_RECORDS_SHUTDOWN CORE_FINISH") {
		stageRoles[s] = "CORE"
	}
}
func stageRole(s string) string { return stageRoles[s] }
func event(e Event) bool {
	seq, ok := dec(e.Seq)
	if !ok || seq == 0 || !nullable(e.SpanID, func(s string) bool { n, ok := dec(s); return ok && n > 0 }) || !segment(e.Segment) || stageRole(e.Stage) == "" || !wall(e.At) || !decimal(&e.ElapsedNS) || !decimal(e.DurationNS) || !decimal(e.Round) || !decimal(e.Ordinal) || !decimal(e.RuleCount) || !decimal(e.CompletedCount) || !in(e.Job, "NOT_OBSERVED RUNNING NOT_RUNNING UNLOADED UNKNOWN") || !in(e.Tun, "NOT_OBSERVED TUN NOT_TUN UNKNOWN") {
		return false
	}
	if !in(e.Code, "NONE OK FAILED CANCELLED UNKNOWN UNAVAILABLE SKIPPED GAP STALE IDENTITY_MISMATCH NO_CHANGE SAVED_STOPPED APPLIED APPLY_FAILED STATE_UNAVAILABLE") {
		return false
	}
	switch e.State {
	case "BEGIN":
		if e.Code != "NONE" || e.DurationNS != nil || e.SpanID == nil {
			return false
		}
	case "END":
		if e.Code == "NONE" || e.DurationNS == nil || e.SpanID == nil {
			return false
		}
	case "OBSERVATION":
		if e.DurationNS != nil || e.Code == "NONE" {
			return false
		}
	default:
		return false
	}
	if e.Round != nil {
		n, _ := dec(*e.Round)
		max := uint64(16)
		if e.Segment == "STOP" || e.Segment == "ROLLBACK" {
			max = 12
		}
		if e.Stage == "HTTPS_ATTEMPT" || strings.HasPrefix(e.Stage, "HTTPS_RETRY_") {
			max = 3
		}
		if n < 1 || n > max {
			return false
		}
	}
	if e.Ordinal != nil {
		n, _ := dec(*e.Ordinal)
		if n < 1 {
			return false
		}
	}
	return true
}
func provenance(p Provenance) bool {
	return nullable(p.Version, version.MatchString) && nullable(p.GitRevision, hex40.MatchString) && nullable(p.SHA256, digest) && ((p.SHA256 == nil && p.SHAKind == "UNKNOWN") || (p.SHA256 != nil && p.SHAKind == "FILE_BYTES")) && p.ExecutionMapping == "NOT_ATTESTED"
}
func Validate(v any) error {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return Invalid
	}
	if rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return Invalid
		}
		return Validate(rv.Elem().Interface())
	}
	good := false
	switch x := v.(type) {
	case ReadRequest:
		good = x.TimelineSchema == 1 && x.Action == "startup.read" && nullable(x.OperationID, id)
	case MutationRequest:
		good = x.TimelineSchema == 1 && in(x.Action, "start stop reload") && id(x.OperationID) && !(x.Action == "stop" && x.AllowInsecure)
	case PushRequest:
		good = x.TimelineSchema == 1 && x.Action == "startup.push" && id(x.HelperEpoch) && id(x.OperationID) && Validate(x.Snapshot) == nil
	case Event:
		good = event(x)
	case Diagnostics:
		good = validDiagnosticsEither(&x)
	case CurrentPhase:
		good = phase(x)
	case Provenance:
		good = provenance(x)
	case ProcessStream:
		good = validStream(x)
	case CoreSnapshot:
		good = x.Stream.Role == "CORE" && validStream(x.Stream) && result(x.StartupResult) && ((x.Complete && x.StartupResult != "IN_PROGRESS" && x.StartupResult != "NOT_ATTEMPTED") || (!x.Complete && x.StartupResult == "IN_PROGRESS"))
	case CoreObservation:
		good = validObservation(x)
	case Trace:
		good = validTrace(x)
	case ReadResponse:
		good = x.TimelineSchema == 1 && in(x.Code, "OK NO_OPERATION UNSUPPORTED BUSY FORBIDDEN INVALID_REQUEST INVALID_TRACE HELPER_UNAVAILABLE HELPER_CONFIG_MISMATCH OPERATION_MISMATCH HISTORY_UNAVAILABLE UNAVAILABLE") && nullable(x.HelperEpoch, id) && nullable(x.ConfigIdentity, digest) && nullable(x.OperationID, id)
		if x.Code == "OK" {
			good = good && x.Trace != nil && validTrace(*x.Trace) && x.OperationID != nil && *x.OperationID == x.Trace.OperationID && same(x.HelperEpoch, x.Trace.HelperEpoch) && same(x.ConfigIdentity, x.Trace.ConfigIdentity)
		} else {
			good = good && x.Trace == nil
		}
	case PushAck:
		good = x.TimelineSchema == 1 && id(x.OperationID) && in(x.Code, "OK BUSY FORBIDDEN INVALID_REQUEST OPERATION_MISMATCH IDENTITY_MISMATCH")
	case OperationReference:
		good = x.TimelineSchema == 1 && in(x.Availability, "AVAILABLE UNSUPPORTED UNAVAILABLE") && nullable(x.OperationID, id) && (x.Availability != "AVAILABLE" || x.OperationID != nil)
	case MutationResponse:
		good = x.TimelineSchema == 1 && (x.Code == "" || in(x.Code, "PREFLIGHT_FAILED STOP_FAILED START_FAILED STATE_FAILED BUSY FORBIDDEN INVALID_REQUEST")) && x.OK == (x.Code == "") && nullable(x.HelperEpoch, id) && nullable(x.OperationID, id) && nullable(x.HelperVersion, version.MatchString) && nullable(x.HelperSHA256, digest) && digest(x.ConfigIdentity) && validDiagnostics(x.Diagnostics, x.OK)
		good = good && ((x.TimelineAvailability == "AVAILABLE" && x.HelperEpoch != nil && x.OperationID != nil) || (x.TimelineAvailability == "UNAVAILABLE" && x.HelperEpoch == nil && x.OperationID == nil))
	}
	if !good {
		return Invalid
	}
	return nil
}
func same(a, b *string) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }
func validStream(s ProcessStream) bool {
	head, tail := capacity(s.Role)
	if head == 0 || !id(s.ClockID) || !wall(s.OriginAt) || !provenance(s.Provenance) || s.Events == nil || s.RetainedRanges == nil || len(s.Events) > head+tail || len(s.RetainedRanges) > 2 {
		return false
	}
	n, ok := dec(s.GeneratedEvents)
	if !ok {
		return false
	}
	d, ok := dec(s.DroppedEvents)
	if !ok || n < uint64(len(s.Events)) || n-uint64(len(s.Events)) != d || d > 0 && !s.Gap {
		return false
	}
	elapsed, ok := dec(s.ElapsedNS)
	if !ok {
		return false
	}
	want := ranges(n, head, tail)
	if !reflect.DeepEqual(want, s.RetainedRanges) {
		return false
	}
	if d == 0 {
		if s.FirstMissingSeq != nil {
			return false
		}
	} else if s.FirstMissingSeq == nil || *s.FirstMissingSeq != strconv.Itoa(head+1) {
		return false
	}
	if s.Current != nil {
		e, _ := dec(s.Current.BeganElapsedNS)
		if !phase(*s.Current) || stageRole(s.Current.Stage) != s.Role || e > elapsed {
			return false
		}
	}
	if s.Terminal != nil {
		e, ok := dec(s.Terminal.ElapsedNS)
		if !ok || e > elapsed || !wall(s.Terminal.At) || !in(s.Terminal.Result, "SUCCEEDED FAILED CANCELLED UNKNOWN") || s.Current != nil {
			return false
		}
	}
	var last, prev uint64
	stack := []Event{}
	unknown := false
	idx := 0
	for _, rg := range want {
		first, _ := dec(rg.First)
		end, _ := dec(rg.Last)
		if idx > 0 && first != prev+1 {
			stack = nil
			unknown = true
		}
		for seq := first; ; seq++ {
			if idx >= len(s.Events) {
				return false
			}
			e := s.Events[idx]
			idx++
			en, ok := dec(e.ElapsedNS)
			if !event(e) || stageRole(e.Stage) != s.Role || e.Seq != strconv.FormatUint(seq, 10) || !ok || en < last || en > elapsed {
				return false
			}
			last = en
			prev = seq
			switch e.State {
			case "BEGIN":
				if len(stack) >= StackDepth {
					return false
				}
				for _, a := range stack {
					if *a.SpanID == *e.SpanID {
						return false
					}
				}
				stack = append(stack, e)
			case "END":
				if len(stack) == 0 {
					if !unknown {
						return false
					}
				} else {
					a := stack[len(stack)-1]
					an, _ := dec(a.ElapsedNS)
					du, _ := dec(*e.DurationNS)
					if *a.SpanID != *e.SpanID || a.Stage != e.Stage || a.Segment != e.Segment || en-an != du {
						return false
					}
					stack = stack[:len(stack)-1]
				}
			case "OBSERVATION":
				if len(stack) > 0 {
					if e.SpanID == nil || *e.SpanID != *stack[len(stack)-1].SpanID {
						return false
					}
				} else if !unknown && e.SpanID != nil {
					return false
				}
			}
			if seq == end {
				break
			}
		}
	}
	if idx != len(s.Events) {
		return false
	}
	// Without missing or diagnostic loss, the retained stack proves current.
	if !s.Gap {
		if len(stack) == 0 {
			if s.Current != nil {
				return false
			}
		} else {
			a := stack[len(stack)-1]
			if s.Current == nil || s.Current.SpanID != *a.SpanID || s.Current.Stage != a.Stage || s.Current.Segment != a.Segment || s.Current.BeganElapsedNS != a.ElapsedNS || s.Current.BeganAt != a.At {
				return false
			}
		}
	}
	return true
}
func validObservation(o CoreObservation) bool {
	if !in(o.Availability, "NOT_ATTEMPTED NOT_OBSERVED OBSERVED STALE INVALID TRUNCATED IDENTITY_MISMATCH UNSUPPORTED HISTORY_UNAVAILABLE UNAVAILABLE") || !nullable(o.CapturedAt, wall) || !decimal(o.HelperReceiveElapsedNS) || !decimal(o.AgeNS) || !nullable(o.ClockID, id) {
		return false
	}
	if o.Availability == "OBSERVED" || o.Availability == "STALE" {
		if o.CapturedAt == nil || o.HelperReceiveElapsedNS == nil || o.AgeNS == nil || o.ClockID == nil {
			return false
		}
		n, _ := dec(*o.AgeNS)
		if (o.Availability == "OBSERVED") != (n <= 1500000000) {
			return false
		}
		return o.Phase == nil || phase(*o.Phase) && stageRole(o.Phase.Stage) == "CORE"
	}
	return o.Phase == nil
}
func validTrace(t Trace) bool {
	if t.Authority != Authority || !id(t.OperationID) || !nullable(t.HelperEpoch, id) || !nullable(t.ConfigIdentity, digest) || !in(t.Operation, "START STOP RELOAD") || !in(t.Source, "MANUAL_START MANUAL_STOP MANUAL_RELOAD SAVE_YAML SAVE_NODE SAVE_GROUP SAVE_SELECTION SAVE_RULE PROFILE_SWITCH IMPORT_COMMIT IMPORT_APPEND LEGACY_CONTROL") || !wall(t.StartedAt) || !nullable(t.FinishedAt, wall) || !result(t.LifecycleResult) || !result(t.HelperReturn) || !result(t.WebReturn) || !receipt(t.ReceiptResult) || !validDiagnosticsEither(t.Diagnostics) || !validObservation(t.CoreObservation) || t.Streams == nil || len(t.Streams) > 3 {
		return false
	}
	if t.State == "IN_PROGRESS" {
		if t.FinishedAt != nil {
			return false
		}
	} else if t.State == "FINISHED" {
		if t.FinishedAt == nil || t.WebReturn == "IN_PROGRESS" || t.HelperReturn == "IN_PROGRESS" {
			return false
		}
	} else if t.State != "UNKNOWN" {
		return false
	}
	seen := map[string]bool{}
	for _, s := range t.Streams {
		if seen[s.Role] || !validStream(s) || s.Gap && !t.Gap {
			return false
		}
		seen[s.Role] = true
	}
	return !t.CoreObservation.Gap || t.Gap
}
