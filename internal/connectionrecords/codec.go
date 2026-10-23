package connectionrecords

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// EncodeBounded emits fixed DTOs directly, checking capacity during escaping.
// It never invokes json.Marshal/Encoder (which buffer a whole value internally).
// No partial JSON is returned. Strings are read in place, not copied wholesale.
func EncodeBounded(value any, budget int) ([]byte, error) {
	if budget < 1 {
		return nil, ErrTooLarge
	}
	if err := Validate(value); err != nil {
		return nil, err
	}
	e := boundedEncoder{limit: budget}
	if err := e.value(reflect.ValueOf(value), 0); err != nil {
		return nil, err
	}
	return e.b, nil
}

type boundedEncoder struct {
	b     []byte
	limit int
}

func (e *boundedEncoder) add(s string) error {
	if len(s) > e.limit-len(e.b) {
		return ErrTooLarge
	}
	// Explicit growth avoids append's capacity overshoot beyond the byte budget.
	if len(e.b)+len(s) > cap(e.b) {
		n := cap(e.b) * 2
		if n < 256 {
			n = 256
		}
		if n < len(e.b)+len(s) {
			n = len(e.b) + len(s)
		}
		if n > e.limit {
			n = e.limit
		}
		b := make([]byte, len(e.b), n)
		copy(b, e.b)
		e.b = b
	}
	e.b = append(e.b, s...)
	return nil
}
func (e *boundedEncoder) quoted(s string) error {
	if !utf8.ValidString(s) || strings.IndexByte(s, 0) >= 0 {
		return ErrInvalid
	}
	if err := e.add("\""); err != nil {
		return err
	}
	for i := 0; i < len(s); {
		c := s[i]
		var part string
		switch c {
		case '"':
			part = "\\\""
		case '\\':
			part = "\\\\"
		case '\b':
			part = "\\b"
		case '\f':
			part = "\\f"
		case '\n':
			part = "\\n"
		case '\r':
			part = "\\r"
		case '\t':
			part = "\\t"
		default:
			if c < 0x20 {
				const hex = "0123456789abcdef"
				part = "\\u00" + string(hex[c>>4]) + string(hex[c&15])
			} else {
				_, n := utf8.DecodeRuneInString(s[i:])
				part = s[i : i+n]
				i += n
				if err := e.add(part); err != nil {
					return err
				}
				continue
			}
		}
		if err := e.add(part); err != nil {
			return err
		}
		i++
	}
	return e.add("\"")
}

type wireField struct {
	name  string
	index []int
}

func fields(t reflect.Type, prefix []int) []wireField {
	var result []wireField
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue
		}
		index := append(append([]int(nil), prefix...), i)
		if f.Anonymous {
			result = append(result, fields(f.Type, index)...)
			continue
		}
		name := f.Tag.Get("json")
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		result = append(result, wireField{name, index})
	}
	return result
}
func (e *boundedEncoder) value(v reflect.Value, depth int) error {
	if depth > 32 {
		return ErrInvalid
	}
	if !v.IsValid() {
		return e.add("null")
	}
	if v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return e.add("null")
		}
		return e.value(v.Elem(), depth+1)
	}
	switch v.Kind() {
	case reflect.String:
		return e.quoted(v.String())
	case reflect.Bool:
		return e.add(strconv.FormatBool(v.Bool()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return e.add(strconv.FormatInt(v.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return e.add(strconv.FormatUint(v.Uint(), 10))
	case reflect.Struct:
		if err := e.add("{"); err != nil {
			return err
		}
		for i, f := range fields(v.Type(), nil) {
			if i > 0 {
				if err := e.add(","); err != nil {
					return err
				}
			}
			if err := e.quoted(f.name); err != nil {
				return err
			}
			if err := e.add(":"); err != nil {
				return err
			}
			if err := e.value(v.FieldByIndex(f.index), depth+1); err != nil {
				return err
			}
		}
		return e.add("}")
	case reflect.Slice:
		if v.IsNil() {
			return e.add("null")
		}
		if err := e.add("["); err != nil {
			return err
		}
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				if err := e.add(","); err != nil {
					return err
				}
			}
			if err := e.value(v.Index(i), depth+1); err != nil {
				return err
			}
		}
		return e.add("]")
	default:
		return ErrInvalid
	}
}

// DecodeStrict is transactional and bounded before tokenization. Every declared
// field is required, including explicit nullable keys. Unknown/duplicate keys
// are rejected recursively; no permissive encoding/json struct conversion occurs.
func DecodeStrict(data []byte, out any, budget int) error {
	if budget < 1 || len(data) > budget {
		return ErrTooLarge
	}
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return ErrInvalid
	}
	p := reflect.ValueOf(out)
	if p.Kind() != reflect.Pointer || p.IsNil() {
		return ErrInvalid
	}
	temp := reflect.New(p.Elem().Type()).Elem()
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := decodeValue(d, temp, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalid
	}
	if err := Validate(temp.Interface()); err != nil {
		return err
	}
	p.Elem().Set(temp)
	return nil
}

// ReadStrict consumes at most budget+1 bytes. It does not own/close r.
func ReadStrict(r io.Reader, out any, budget int) error {
	if budget < 1 || budget == math.MaxInt {
		return ErrTooLarge
	}
	b, err := io.ReadAll(io.LimitReader(r, int64(budget)+1))
	if err != nil {
		return err
	}
	return DecodeStrict(b, out, budget)
}
func decodeValue(d *json.Decoder, v reflect.Value, depth int) error {
	if depth > 32 {
		return ErrInvalid
	}
	token, err := d.Token()
	if err != nil {
		return ErrInvalid
	}
	if token == nil {
		if v.Kind() == reflect.Pointer || v.Kind() == reflect.Slice {
			v.SetZero()
			return nil
		}
		return ErrInvalid
	}
	if v.Kind() == reflect.Pointer {
		v.Set(reflect.New(v.Type().Elem()))
		return decodeToken(d, v.Elem(), token, depth)
	}
	return decodeToken(d, v, token, depth)
}
func decodeToken(d *json.Decoder, v reflect.Value, token any, depth int) error {
	switch v.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return ErrInvalid
		}
		fs := fields(v.Type(), nil)
		seen := make(map[string]bool, len(fs))
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return ErrInvalid
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return ErrInvalid
			}
			seen[name] = true
			found := false
			for _, f := range fs {
				if f.name == name {
					found = true
					if err := decodeValue(d, v.FieldByIndex(f.index), depth+1); err != nil {
						return err
					}
					break
				}
			}
			if !found {
				return ErrInvalid
			}
		}
		if len(seen) != len(fs) {
			return ErrInvalid
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return ErrInvalid
		}
		return nil
	case reflect.Slice:
		if token != json.Delim('[') {
			return ErrInvalid
		}
		v.Set(reflect.MakeSlice(v.Type(), 0, 0))
		for d.More() {
			item := reflect.New(v.Type().Elem()).Elem()
			if err := decodeValue(d, item, depth+1); err != nil {
				return err
			}
			v.Set(reflect.Append(v, item))
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return ErrInvalid
		}
		return nil
	case reflect.String:
		s, ok := token.(string)
		if !ok || !utf8.ValidString(s) || strings.IndexByte(s, 0) >= 0 {
			return ErrInvalid
		}
		v.SetString(s)
		return nil
	case reflect.Bool:
		b, ok := token.(bool)
		if !ok {
			return ErrInvalid
		}
		v.SetBool(b)
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, ok := token.(json.Number)
		if !ok {
			return ErrInvalid
		}
		i, err := strconv.ParseInt(string(n), 10, v.Type().Bits())
		if err != nil {
			return ErrInvalid
		}
		v.SetInt(i)
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, ok := token.(json.Number)
		if !ok {
			return ErrInvalid
		}
		i, err := strconv.ParseUint(string(n), 10, v.Type().Bits())
		if err != nil {
			return ErrInvalid
		}
		v.SetUint(i)
		return nil
	default:
		return ErrInvalid
	}
}

// requestWire is the only request wire shape; PageRequest itself is not encoded.
type requestWire struct {
	Action        string  `json:"action"`
	SchemaVersion int     `json:"schema_version"`
	InstanceID    *string `json:"instance_id"`
	Generation    *string `json:"generation"`
	ManifestID    *string `json:"manifest_id"`
	After         Decimal `json:"after"`
	Limit         int     `json:"limit"`
}

func EncodeRequest(q PageRequest) ([]byte, error) {
	if err := ValidatePageRequest(q); err != nil {
		return nil, err
	}
	w := requestWire{Action: "records.read", SchemaVersion: q.SchemaVersion, After: q.After, Limit: q.Limit}
	if q.Binding != nil {
		w.InstanceID = &q.Binding.InstanceID
		w.Generation = &q.Binding.Generation
		w.ManifestID = &q.Binding.ManifestID
	}
	return EncodeBounded(w, MaxRequestBytes)
}

// DecodeRequest accepts omitted after/limit only, defaulting to "0"/100.
func DecodeRequest(data []byte) (PageRequest, error) {
	var q PageRequest
	if len(data) > MaxRequestBytes {
		return q, ErrTooLarge
	}
	// First scan the bounded envelope for duplicates and exact allowed keys. Raw
	// values remain bounded; DecodeStrict below handles nested/type/null checks.
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return q, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return q, ErrInvalid
	}
	values := make(map[string]json.RawMessage, 7)
	for d.More() {
		k, e := d.Token()
		if e != nil {
			return q, ErrInvalid
		}
		key, ok := k.(string)
		if !ok {
			return q, ErrInvalid
		}
		switch key {
		case "action", "schema_version", "instance_id", "generation", "manifest_id", "after", "limit":
		default:
			return q, ErrInvalid
		}
		if _, ok := values[key]; ok {
			return q, ErrInvalid
		}
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return q, ErrInvalid
		}
		values[key] = raw
	}
	if t, e := d.Token(); e != nil || t != json.Delim('}') {
		return q, ErrInvalid
	}
	if _, e := d.Token(); e != io.EOF {
		return q, ErrInvalid
	}
	if _, ok := values["after"]; !ok {
		values["after"] = json.RawMessage(`"0"`)
	}
	if _, ok := values["limit"]; !ok {
		values["limit"] = json.RawMessage(`100`)
	}
	if len(values) != 7 {
		return q, ErrInvalid
	}
	// Reconstruct at most the already bounded request plus default-field overhead.
	var b bytes.Buffer
	b.WriteByte('{')
	keys := []string{"action", "schema_version", "instance_id", "generation", "manifest_id", "after", "limit"}
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`"` + k + `":`)
		b.Write(values[k])
	}
	b.WriteByte('}')
	var w requestWire
	if err := DecodeStrict(b.Bytes(), &w, MaxRequestBytes+64); err != nil {
		return q, err
	}
	if w.Action != "records.read" {
		return q, ErrInvalid
	}
	q = PageRequest{SchemaVersion: w.SchemaVersion, After: w.After, Limit: w.Limit}
	if w.InstanceID != nil || w.Generation != nil || w.ManifestID != nil {
		if w.InstanceID == nil || w.Generation == nil || w.ManifestID == nil {
			return PageRequest{}, ErrInvalid
		}
		q.Binding = &Binding{*w.InstanceID, *w.Generation, *w.ManifestID}
	}
	return q, ValidatePageRequest(q)
}
func ValidatePageRequest(q PageRequest) error {
	if q.SchemaVersion != SchemaVersion || q.Limit < 1 || q.Limit > MaxPageLimit {
		return ErrInvalid
	}
	if _, err := q.After.Uint64(); err != nil {
		return err
	}
	if q.Binding != nil {
		return validateBinding(*q.Binding)
	}
	return nil
}
func validHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := range s {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}
func validateBinding(b Binding) error {
	if !validHex(b.InstanceID, 32) || !validHex(b.Generation, 32) || !validHex(b.ManifestID, 64) {
		return ErrInvalid
	}
	return nil
}
func utc(s string) bool {
	t, e := time.Parse(time.RFC3339Nano, s)
	return e == nil && strings.HasSuffix(s, "Z") && t.Location() == time.UTC
}
func one(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}
func validHost(s string) bool {
	if len(s) == 0 || len(s) > 253 || strings.ContainsAny(s, "/:?#@\\ \t\r\n") {
		return false
	}
	s = strings.TrimSuffix(s, ".")
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// Validate enforces leaf formats and the route-only semantic null rules. It is
// shared by encoding and decoding so locally constructed DTOs cannot bypass it.
func Validate(value any) error { return validateValue(reflect.ValueOf(value), 0) }

// ManifestDigest hashes the fixed field-order canonical projection, excluding
// manifest_id itself. All slices keep compiler order; absent sources stay null.
// budget bounds transient encoding, not accepted config/history retention.
func ManifestDigest(m Manifest, budget int) (string, error) {
	m.ManifestID = strings.Repeat("0", 64)
	if err := Validate(m); err != nil {
		return "", err
	}
	view := struct {
		SchemaVersion       int              `json:"schema_version"`
		InstanceID          string           `json:"instance_id"`
		Generation          string           `json:"generation"`
		SelectionGeneration string           `json:"selection_generation"`
		RuntimeSHA256       string           `json:"runtime_sha256"`
		CapturedSources     []CapturedSource `json:"captured_sources"`
		Rules               []RuleOrigin     `json:"rules"`
		FinalOrigin         RouteProjection  `json:"final_origin"`
		Outbounds           []OutboundOrigin `json:"outbounds"`
	}{m.SchemaVersion, m.InstanceID, m.Generation, m.SelectionGeneration, m.RuntimeSHA256, m.CapturedSources, m.Rules, m.FinalOrigin, m.Outbounds}
	b, err := EncodeBounded(view, budget)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// NamespaceDigest uses only root-registration scope, never request parameters.
func NamespaceDigest(scope Scope) (string, error) {
	if scope.UID == 0 || !validHex(scope.ConfigIdentity, 64) {
		return "", ErrInvalid
	}
	view := struct {
		SchemaVersion  int    `json:"schema_version"`
		UID            uint32 `json:"uid"`
		ConfigIdentity string `json:"config_identity"`
	}{1, scope.UID, scope.ConfigIdentity}
	b, err := EncodeBounded(view, MaxHeaderBytes)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
func validateValue(v reflect.Value, depth int) error {
	if depth > 32 {
		return ErrInvalid
	}
	if !v.IsValid() {
		return ErrInvalid
	}
	if v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return nil
		}
		return validateValue(v.Elem(), depth+1)
	}
	if v.Kind() == reflect.String {
		if !utf8.ValidString(v.String()) || strings.IndexByte(v.String(), 0) >= 0 {
			return ErrInvalid
		}
	}
	switch x := v.Interface().(type) {
	case Decimal:
		_, err := x.Uint64()
		return err
	case Binding:
		return validateBinding(x)
	case Header:
		if x.SchemaVersion != 1 || !validHex(x.ConfigIdentity, 64) || !validHex(x.RuntimeSHA256, 64) || !utc(x.CreatedAt) {
			return ErrInvalid
		}
	case Latest:
		if x.SchemaVersion != 1 || !validHex(x.InstanceID, 32) {
			return ErrInvalid
		}
	case Collection:
		if !one(string(x), "RECORDING", "CLOSING", "CLOSED", "IO_FAILED", "INIT_FAILED", "WORKER_FAILED", "ID_EXHAUSTED", "UNKNOWN") {
			return ErrInvalid
		}
	case ProvenanceStatus:
		if !one(string(x), "VERIFIED", "MISMATCH", "UNKNOWN") {
			return ErrInvalid
		}
	case Hook:
		if !one(string(x), "tcp", "udp", "flow") {
			return ErrInvalid
		}
	case Network:
		if !one(string(x), "tcp", "udp", "UNKNOWN") {
			return ErrInvalid
		}
	case HostSource:
		if !one(string(x), "DESTINATION_FQDN", "METADATA_DOMAIN", "UNKNOWN") {
			return ErrInvalid
		}
	case TerminalKind:
		if !one(string(x), "DIRECT", "NODE", "UNKNOWN") {
			return ErrInvalid
		}
	case RuleKind:
		if !one(string(x), "DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR", "RULE-SET", "MATCH", "DEFAULT_SELECTED", "UNKNOWN") {
			return ErrInvalid
		}
	case HistoryKind:
		if !one(string(x), "LAST_RECORDED", "HISTORICAL") {
			return ErrInvalid
		}
	case Freshness:
		if !one(string(x), "FRESH", "STALE", "UNKNOWN") {
			return ErrInvalid
		}
	case Continuity:
		if !one(string(x), "CLOSED", "UNKNOWN") {
			return ErrInvalid
		}
	case ErrorCode:
		if !one(string(x), "", "INVALID_REQUEST", "FORBIDDEN", "BUSY", "STALE_GENERATION", "TELEMETRY_UNAVAILABLE", "STORE_INVALID", "UNSUPPORTED") {
			return ErrInvalid
		}
	case CleanupState:
		if !one(string(x), "VERIFIED", "UNKNOWN", "FAILED") {
			return ErrInvalid
		}
	case ErrorResponse:
		if x.SchemaVersion != 1 || x.ErrorCode == NoError {
			return ErrInvalid
		}
	case SyntheticKind:
		if !one(string(x), "NONE", "SNIFF", "RESOLVE", "HIJACK") {
			return ErrInvalid
		}
	case SourceKind:
		if !one(string(x), "CONFIG", "SELECTION", "RULE_SET", "CA") {
			return ErrInvalid
		}
	case CapturedSource:
		if x.Ordinal < 0 || x.Present != (x.SHA256 != nil) || x.SHA256 != nil && !validHex(*x.SHA256, 64) {
			return ErrInvalid
		}
	case Destination:
		if x.Host != nil && !validHost(*x.Host) {
			return ErrInvalid
		}
		if (x.Host == nil) != (x.HostSource == HostUnknown) {
			return ErrInvalid
		}
		if x.IP != nil {
			a, e := netip.ParseAddr(*x.IP)
			if e != nil || !a.IsValid() {
				return ErrInvalid
			}
		}
	case Condition:
		switch x.Kind {
		case RuleDomain, RuleDomainSuffix:
			if !validHost(x.Value) {
				return ErrInvalid
			}
		case RuleIPCIDR:
			if _, e := netip.ParsePrefix(x.Value); e != nil {
				return ErrInvalid
			}
		case RuleSet:
			if x.Value == "" {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	case RuleSetProjection:
		if x.Label == "" || !validHex(x.SHA256, 64) {
			return ErrInvalid
		}
	case RouteProjection:
		if x.SourceIndex != nil && *x.SourceIndex < 0 {
			return ErrInvalid
		}
		if x.Evidence != ProvenanceVerified {
			if x.SourceID != nil || x.SourceIndex != nil || x.Kind != RuleUnknown || x.Condition != nil || x.RuleSet != nil || x.ConfiguredTarget != nil || x.GroupPath != nil || x.TerminalKind != TerminalUnknown || x.FinalNodeID != nil || x.FinalNodeLabel != nil || x.SelectionGeneration != nil {
				return ErrInvalid
			}
		} else {
			if x.Kind == RuleUnknown || x.ConfiguredTarget == nil || x.GroupPath == nil || x.SelectionGeneration == nil || !validHex(*x.SelectionGeneration, 32) || x.TerminalKind == TerminalUnknown {
				return ErrInvalid
			}
			if x.Kind == RuleDefault {
				if x.SourceID != nil || x.SourceIndex != nil || x.Condition != nil {
					return ErrInvalid
				}
			} else if x.SourceID == nil || x.SourceIndex == nil {
				return ErrInvalid
			}
			if x.Kind == RuleMatch {
				if x.Condition != nil {
					return ErrInvalid
				}
			} else if x.Kind != RuleDefault && (x.Condition == nil || x.Condition.Kind != x.Kind) {
				return ErrInvalid
			}
			if (x.Kind == RuleSet) != (x.RuleSet != nil) {
				return ErrInvalid
			}
			if x.TerminalKind == TerminalNode && (x.FinalNodeID == nil || x.FinalNodeLabel == nil) {
				return ErrInvalid
			}
		}
	case Record:
		if x.SchemaVersion != 1 || x.Seq == "0" || x.ObservationID == "0" || !utc(x.ObservedAt) || x.Event != "ROUTED" || x.State != "ROUTED" || x.Connected != nil || x.Active != nil || x.Duration != nil || x.EndedAt != nil || x.Error != nil {
			return ErrInvalid
		}
		if e := routeIDs(x.Route, x.Generation); e != nil {
			return e
		}
	case State:
		h, e := x.HighWaterSeq.Uint64()
		if e != nil {
			return e
		}
		index, e := x.CommittedIndexBytes.Uint64()
		if e != nil || h > math.MaxUint64/16 || index != h*16 || x.Revision == "0" || !utc(x.Timestamp) {
			return ErrInvalid
		}
		data, e := x.CommittedDataBytes.Uint64()
		if e != nil || h == 0 && data != 0 || h > 0 && data/5 < h {
			return ErrInvalid
		}
		if x.Collection == CollectionUnknown || x.Closed != (x.Collection == Closed) {
			return ErrInvalid
		}
		if !x.Gap && lossRequiresGap(x.LostTotal, x.LossReasons, x.CounterSaturated) {
			return ErrInvalid
		}
	case Coverage:
		if !x.Gap && lossRequiresGap(x.LostTotal, x.LossReasons, x.CounterSaturated) {
			return ErrInvalid
		}
		if x.Complete || len(x.Unobserved) != 3 || x.Unobserved[0] != "REJECT" || x.Unobserved[1] != "DNS" || x.Unobserved[2] != "EARLY_ERROR" {
			return ErrInvalid
		}
	case DNSStatus:
		if x.Status != "UNKNOWN" || x.Evidence != nil {
			return ErrInvalid
		}
	case PageResponse:
		high, e := x.HighWaterSeq.Uint64()
		if e != nil {
			return e
		}
		next, e := x.NextAfter.Uint64()
		if e != nil || next > high || len(x.Records) > MaxPageLimit || !utc(x.Timestamp) || x.Records == nil {
			return ErrInvalid
		}
		if high == 0 {
			if x.HistoryStartSeq != nil {
				return ErrInvalid
			}
		} else if x.HistoryStartSeq == nil || *x.HistoryStartSeq != "1" {
			return ErrInvalid
		}
		if x.HasMore != (next < high) || x.Closed != (x.Collection == Closed) {
			return ErrInvalid
		}
		if !x.Closed && x.Coverage.Continuity == ContinuityClosed {
			return ErrInvalid
		}
		if (!x.Closed && x.Freshness != Fresh || x.Collection == CollectionUnknown || x.Collection == IOFailed || x.Collection == InitFailed || x.Collection == WorkerFailed || x.Collection == IDExhausted) && !x.Coverage.Gap {
			return ErrInvalid
		}
		var prev uint64
		for i, r := range x.Records {
			n, e := r.Seq.Uint64()
			if e != nil || r.Binding != x.Binding || n > high || (i > 0 && n != prev+1) {
				return ErrInvalid
			}
			prev = n
		}
		if len(x.Records) > 0 && prev != next {
			return ErrInvalid
		}
	case Manifest:
		if x.SchemaVersion != 1 || x.SelectionGeneration != x.Generation || !validHex(x.RuntimeSHA256, 64) || len(x.CapturedSources) < 2 || x.Rules == nil || x.Outbounds == nil {
			return ErrInvalid
		}
		if x.CapturedSources[0].Kind != SourceConfig || x.CapturedSources[0].Ordinal != 0 || !x.CapturedSources[0].Present || x.CapturedSources[1].Kind != SourceSelection || x.CapturedSources[1].Ordinal != 0 {
			return ErrInvalid
		}
		for i, s := range x.CapturedSources {
			if i > 1 && (s.Kind == SourceConfig || s.Kind == SourceSelection) {
				return ErrInvalid
			}
		}
		for _, r := range x.Rules {
			if r.Type == "" || r.ActionType == "" {
				return ErrInvalid
			}
			if e := routeIDs(r.Route, x.Generation); e != nil {
				return e
			}
		}
		if e := routeIDs(x.FinalOrigin, x.Generation); e != nil {
			return e
		}
		for i, o := range x.Outbounds {
			if o.Tag == "" || o.Type == "" {
				return ErrInvalid
			}
			for j := 0; j < i; j++ {
				if x.Outbounds[j].Tag == o.Tag {
					return ErrInvalid
				}
			}
			if o.TerminalKind == TerminalNode && (o.NodeID == nil || o.NodeLabel == nil) {
				return ErrInvalid
			}
			if o.NodeID != nil {
				prefix := x.Generation + ":node:"
				if !strings.HasPrefix(*o.NodeID, prefix) {
					return ErrInvalid
				}
				if _, e := Decimal(strings.TrimPrefix(*o.NodeID, prefix)).Uint64(); e != nil {
					return e
				}
			}
		}
	case PageRequest:
		return ErrInvalid // use explicit request codec
	}
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).PkgPath == "" {
				if err := validateValue(v.Field(i), depth+1); err != nil {
					return err
				}
			}
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			if err := validateValue(v.Index(i), depth+1); err != nil {
				return err
			}
		}
	case reflect.String, reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
	default:
		return ErrInvalid
	}
	return nil
}

// Known loss or saturation requires GAP; nil counters remain UNKNOWN. No
// equality between totals and reasons is inferred from partial knowledge.
func lossRequiresGap(total *Decimal, reasons LossReasons, saturated bool) bool {
	if saturated {
		return true
	}
	for _, n := range []*Decimal{total, reasons.QueueFull, reasons.Oversize, reasons.AdmissionClosed, reasons.EncodingFailed, reasons.IOFailed, reasons.WorkerFailed, reasons.IDExhausted, reasons.ShutdownDiscarded} {
		if n != nil && *n != "0" {
			return true
		}
	}
	return false
}

func routeIDs(r RouteProjection, generation string) error {
	if r.Evidence != ProvenanceVerified {
		return nil
	}
	if r.SelectionGeneration == nil || *r.SelectionGeneration != generation {
		return ErrInvalid
	}
	if r.SourceID != nil {
		if r.SourceIndex == nil || *r.SourceID != generation+":rule:"+strconv.Itoa(*r.SourceIndex) {
			return ErrInvalid
		}
	}
	if r.FinalNodeID != nil {
		prefix := generation + ":node:"
		if !strings.HasPrefix(*r.FinalNodeID, prefix) {
			return ErrInvalid
		}
		d := Decimal(strings.TrimPrefix(*r.FinalNodeID, prefix))
		if _, e := d.Uint64(); e != nil {
			return e
		}
	}
	return nil
}
