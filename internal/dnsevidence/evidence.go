// Package dnsevidence contains no SDK dependencies and retains no DNS names or errors.
package dnsevidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	PushBytes = 65536
	ReadBytes = 8192
	Capacity  = 64
)

var Invalid = errors.New("INVALID_DNS_EVIDENCE")

type Binding struct {
	InstanceID    string `json:"instance_id"`
	Generation    string `json:"generation"`
	ManifestID    string `json:"manifest_id"`
	RuntimeSHA256 string `json:"runtime_sha256"`
}
type Transport struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	ServerIP string `json:"server_ip"`
	Port     string `json:"port"`
	SNI      string `json:"sni"`
	TLS      string `json:"tls"`
	Detour   string `json:"detour"`
}
type Policy struct {
	Source     string      `json:"source"`
	Final      string      `json:"final"`
	Transports []Transport `json:"transports"`
	Capture    string      `json:"capture"`
}
type Connections struct {
	Acquisitions string `json:"acquisitions"`
	New          string `json:"new"`
	Reused       string `json:"reused"`
	Idle         string `json:"idle"`
}
type Event struct {
	Kind        string      `json:"kind"`
	Seq         string      `json:"seq"`
	OperationID string      `json:"upstream_operation_id"`
	TransportID string      `json:"transport_id"`
	QType       string      `json:"qtype"`
	Outcome     string      `json:"outcome"`
	RCODE       *string     `json:"rcode"`
	Validation  string      `json:"response_validation"`
	DurationNS  string      `json:"duration_ns"`
	Connections Connections `json:"connections"`
}
type Coverage struct {
	Scope     string `json:"scope"`
	Missing   string `json:"missing"`
	Gap       bool   `json:"gap"`
	Dropped   string `json:"dropped_events"`
	Saturated bool   `json:"counter_saturated"`
}
type Snapshot struct {
	Revision   string   `json:"revision"`
	CapturedAt string   `json:"captured_at"`
	ElapsedNS  string   `json:"elapsed_ns"`
	State      string   `json:"state"`
	Policy     Policy   `json:"policy"`
	Events     []Event  `json:"events"`
	Coverage   Coverage `json:"coverage"`
}
type Push struct {
	DNSSchema      int      `json:"dns_schema"`
	Action         string   `json:"action"`
	HelperEpoch    string   `json:"helper_epoch"`
	OperationID    string   `json:"operation_id"`
	ConfigIdentity string   `json:"config_identity"`
	Binding        Binding  `json:"binding"`
	Snapshot       Snapshot `json:"snapshot"`
}
type Read struct {
	DNSSchema  int     `json:"dns_schema"`
	Action     string  `json:"action"`
	InstanceID *string `json:"instance_id"`
	Generation *string `json:"generation"`
	ManifestID *string `json:"manifest_id"`
}
type Response struct {
	DNSSchema      int       `json:"dns_schema"`
	Code           string    `json:"code"`
	HelperEpoch    *string   `json:"helper_epoch"`
	ConfigIdentity *string   `json:"config_identity"`
	Binding        *Binding  `json:"binding"`
	ReceivedAt     *string   `json:"received_at"`
	AgeNS          *string   `json:"age_ns"`
	Availability   string    `json:"availability"`
	Snapshot       *Snapshot `json:"snapshot"`
}
type Ack struct {
	DNSSchema int    `json:"dns_schema"`
	Code      string `json:"code"`
}

const Missing = "CAPTURE_CACHE_COALESCING_HTTP_STATUS_FRESH_TLS_CONCRETE_DETOUR_QUERY_JOIN_NOT_OBSERVED"

var hex32 = regexp.MustCompile(`^[a-f0-9]{32}$`)
var hex64 = regexp.MustCompile(`^[a-f0-9]{64}$`)

func Decimal(s string) bool {
	n, e := strconv.ParseUint(s, 10, 64)
	return e == nil && strconv.FormatUint(n, 10) == s
}
func IsID(s string) bool     { return hex32.MatchString(s) }
func IsDigest(s string) bool { return hex64.MatchString(s) }
func ValidBinding(b Binding) bool {
	return IsID(b.InstanceID) && IsID(b.Generation) && IsDigest(b.ManifestID) && IsDigest(b.RuntimeSHA256)
}
func one(s, set string) bool {
	return s != "" && !strings.ContainsAny(s, " \r\n\t") && strings.Contains(" "+set+" ", " "+s+" ")
}
func Validate(v any) error {
	switch x := v.(type) {
	case *Push:
		return Validate(*x)
	case *Read:
		return Validate(*x)
	case *Response:
		return Validate(*x)
	case *Ack:
		return Validate(*x)
	case Push:
		if x.DNSSchema != 1 || x.Action != "dns.push" || !IsID(x.HelperEpoch) || !IsID(x.OperationID) || !IsDigest(x.ConfigIdentity) || !ValidBinding(x.Binding) {
			return Invalid
		}
		return Validate(x.Snapshot)
	case Read:
		if x.DNSSchema != 1 || x.Action != "dns.read" {
			return Invalid
		}
		if x.InstanceID == nil && x.Generation == nil && x.ManifestID == nil {
			return nil
		}
		if x.InstanceID == nil || x.Generation == nil || x.ManifestID == nil || !IsID(*x.InstanceID) || !IsID(*x.Generation) || !IsDigest(*x.ManifestID) {
			return Invalid
		}
	case Ack:
		if x.DNSSchema != 1 || !one(x.Code, "OK FORBIDDEN INVALID_REQUEST IDENTITY_MISMATCH STALE_GENERATION UNAVAILABLE") {
			return Invalid
		}
	case Response:
		if x.DNSSchema != 1 || !one(x.Code, "OK FORBIDDEN INVALID_REQUEST STALE_GENERATION UNAVAILABLE UNSUPPORTED") || !one(x.Availability, "OBSERVED STALE UNAVAILABLE") {
			return Invalid
		}
		if x.HelperEpoch != nil && !IsID(*x.HelperEpoch) || x.ConfigIdentity != nil && !IsDigest(*x.ConfigIdentity) || x.Binding != nil && !ValidBinding(*x.Binding) {
			return Invalid
		}
		if x.Snapshot != nil {
			if x.Code != "OK" || x.Binding == nil || x.HelperEpoch == nil || x.ConfigIdentity == nil || x.ReceivedAt == nil || x.AgeNS == nil || !Decimal(*x.AgeNS) || !wall(*x.ReceivedAt) {
				return Invalid
			}
			return Validate(*x.Snapshot)
		}
		if x.Availability != "UNAVAILABLE" {
			return Invalid
		}
	case Snapshot:
		if !Decimal(x.Revision) || !Decimal(x.ElapsedNS) || !wall(x.CapturedAt) || !one(x.State, "STARTING LOADED CLOSED") || len(x.Events) > Capacity || x.Events == nil {
			return Invalid
		}
		if x.Coverage.Scope != "HTTPS_TRANSPORT_COMPLETION" || x.Coverage.Missing != Missing || !Decimal(x.Coverage.Dropped) || x.Coverage.Saturated && !x.Coverage.Gap {
			return Invalid
		}
		if e := Validate(x.Policy); e != nil {
			return e
		}
		dropped, _ := strconv.ParseUint(x.Coverage.Dropped, 10, 64)
		if dropped > 0 && (!x.Coverage.Gap || len(x.Events) != Capacity) {
			return Invalid
		}
		if dropped > 0 {
			first, _ := strconv.ParseUint(x.Events[0].Seq, 10, 64)
			if first <= dropped {
				return Invalid
			}
		}
		var prev uint64
		for _, e := range x.Events {
			if Validate(e) != nil {
				return Invalid
			}
			n, _ := strconv.ParseUint(e.Seq, 10, 64)
			if n <= prev || !x.Coverage.Gap && n != prev+1 {
				return Invalid
			}
			prev = n
		}
	case Policy:
		if x.Source != "DECODED_INSTANCE_AND_FACTORY" || !one(x.Final, "SUPPORTED NOT_OBSERVED") || x.Capture != "NOT_OBSERVED" || x.Transports == nil || len(x.Transports) > 4 {
			return Invalid
		}
		for _, t := range x.Transports {
			if Validate(t) != nil {
				return Invalid
			}
		}
	case Transport:
		if !Decimal(x.ID) || x.ID == "0" || x.Type != "HTTPS" || !Decimal(x.Port) || !one(x.SNI, "cloudflare-dns.com example.com REDACTED") || !one(x.TLS, "STRICT_CONFIGURED UNSUPPORTED") || x.Detour != "CONFIGURED_ONLY" {
			return Invalid
		}
		n, _ := strconv.ParseUint(x.Port, 10, 64)
		if n > 65535 {
			return Invalid
		}
		if x.ServerIP != "REDACTED" {
			a, e := netip.ParseAddr(x.ServerIP)
			if e != nil || a.String() != x.ServerIP {
				return Invalid
			}
		}
	case Event:
		if x.Kind != "HTTPS_EXCHANGE_COMPLETED" || !Decimal(x.Seq) || x.Seq == "0" || !Decimal(x.OperationID) || x.OperationID == "0" || !Decimal(x.TransportID) || !one(x.QType, "A AAAA OTHER") || !one(x.Outcome, "NOERROR NXDOMAIN SERVFAIL OTHER_RCODE CANCELED TIMEOUT TLS_FAILURE OTHER_ERROR") || !one(x.Validation, "MATCHED MISMATCH NOT_OBSERVED") || !Decimal(x.DurationNS) {
			return Invalid
		}
		if x.RCODE != nil {
			n, e := strconv.ParseUint(*x.RCODE, 10, 16)
			if e != nil || n > 4095 || !Decimal(*x.RCODE) {
				return Invalid
			}
		}
		for _, s := range []string{x.Connections.Acquisitions, x.Connections.New, x.Connections.Reused, x.Connections.Idle} {
			if !Decimal(s) {
				return Invalid
			}
		}
	default:
		return Invalid
	}
	return nil
}
func wall(s string) bool {
	t, e := time.Parse(time.RFC3339Nano, s)
	return e == nil && t.UTC().Format(time.RFC3339Nano) == s
}
func limit(v any) int {
	switch v.(type) {
	case Read, *Read:
		return ReadBytes
	case Push, *Push, Response, *Response, Ack, *Ack:
		return PushBytes
	}
	return 0
}

// Fixed DTO limits make admission bounded; the writer checks every chunk before buffering.
type bounded struct {
	bytes.Buffer
	max int
}

func (b *bounded) Write(p []byte) (int, error) {
	if len(p) > b.max-b.Len() {
		return 0, Invalid
	}
	return b.Buffer.Write(p)
}
func Encode(v any) ([]byte, error) {
	if Validate(v) != nil || limit(v) == 0 {
		return nil, Invalid
	}
	w := &bounded{max: limit(v)}
	if encodeValue(w, reflect.ValueOf(v)) != nil {
		return nil, Invalid
	}
	return w.Bytes(), nil
}
func encodeValue(w *bounded, v reflect.Value) error {
	add := func(s string) error { _, e := w.Write([]byte(s)); return e }
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return add("null")
		}
		return encodeValue(w, v.Elem())
	case reflect.Struct:
		if e := add("{"); e != nil {
			return e
		}
		for i := 0; i < v.NumField(); i++ {
			if i > 0 {
				if e := add(","); e != nil {
					return e
				}
			}
			if e := add(strconv.Quote(v.Type().Field(i).Tag.Get("json")) + ":"); e != nil {
				return e
			}
			if e := encodeValue(w, v.Field(i)); e != nil {
				return e
			}
		}
		return add("}")
	case reflect.Slice:
		if e := add("["); e != nil {
			return e
		}
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				if e := add(","); e != nil {
					return e
				}
			}
			if e := encodeValue(w, v.Index(i)); e != nil {
				return e
			}
		}
		return add("]")
	case reflect.String:
		return add(strconv.Quote(v.String()))
	case reflect.Bool:
		return add(strconv.FormatBool(v.Bool()))
	case reflect.Int:
		return add(strconv.FormatInt(v.Int(), 10))
	}
	return Invalid
}

// Decode uses exact key spelling and recursive duplicate rejection, not Go's case-insensitive struct matching.
func Decode(b []byte, v any) error {
	rv := reflect.ValueOf(v)
	if limit(v) == 0 || len(b) > limit(v) || !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 || rv.Kind() != reflect.Pointer || rv.IsNil() {
		return Invalid
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	raw, e := value(d, 0)
	if e != nil {
		return Invalid
	}
	if _, e = d.Token(); e != io.EOF || !shape(raw, rv.Elem().Type()) {
		return Invalid
	}
	tmp := reflect.New(rv.Elem().Type())
	if json.Unmarshal(b, tmp.Interface()) != nil || Validate(tmp.Interface()) != nil {
		return Invalid
	}
	rv.Elem().Set(tmp.Elem())
	return nil
}
func value(d *json.Decoder, depth int) (any, error) {
	if depth > 12 {
		return nil, Invalid
	}
	t, e := d.Token()
	if e != nil {
		return nil, Invalid
	}
	switch x := t.(type) {
	case string:
		if len(x) > 128 || strings.ContainsRune(x, 0) {
			return nil, Invalid
		}
		return x, nil
	case json.Delim:
		if x == '{' {
			m := map[string]any{}
			for d.More() {
				k, e := d.Token()
				s, ok := k.(string)
				if e != nil || !ok || len(m) > 32 {
					return nil, Invalid
				}
				if _, ok = m[s]; ok {
					return nil, Invalid
				}
				v, e := value(d, depth+1)
				if e != nil {
					return nil, e
				}
				m[s] = v
			}
			_, e = d.Token()
			return m, e
		}
		if x == '[' {
			a := []any{}
			for d.More() {
				if len(a) >= 64 {
					return nil, Invalid
				}
				v, e := value(d, depth+1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			_, e = d.Token()
			return a, e
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
func Matches(q Read, b Binding) bool {
	return q.InstanceID != nil && *q.InstanceID == b.InstanceID && *q.Generation == b.Generation && *q.ManifestID == b.ManifestID
}
func Clone(s Snapshot) Snapshot {
	s.Policy.Transports = append([]Transport{}, s.Policy.Transports...)
	s.Events = append([]Event{}, s.Events...)
	for i := range s.Events {
		if s.Events[i].RCODE != nil {
			v := *s.Events[i].RCODE
			s.Events[i].RCODE = &v
		}
	}
	return s
}

type Collector struct {
	mu                         sync.Mutex
	binding                    Binding
	origin                     time.Time
	s                          Snapshot
	seq, op, revision, dropped uint64
}

func New(b Binding) *Collector {
	if !ValidBinding(b) {
		return nil
	}
	return &Collector{binding: b, origin: time.Now(), s: Snapshot{State: "STARTING", Policy: Policy{Source: "DECODED_INSTANCE_AND_FACTORY", Final: "NOT_OBSERVED", Transports: []Transport{}, Capture: "NOT_OBSERVED"}, Events: []Event{}, Coverage: Coverage{Scope: "HTTPS_TRANSPORT_COMPLETION", Missing: Missing, Dropped: "0"}}}
}
func (c *Collector) Binding() Binding {
	if c == nil {
		return Binding{}
	}
	return c.binding
}
func (c *Collector) SetPolicy(p Policy) {
	if c == nil || Validate(p) != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.s.State == "STARTING" {
		c.s.Policy = p
		c.s.Policy.Transports = append([]Transport{}, p.Transports...)
	}
}
func (c *Collector) Loaded() {
	if c != nil {
		c.mu.Lock()
		c.s.State = "LOADED"
		c.mu.Unlock()
	}
}
func (c *Collector) Closed() {
	if c != nil {
		c.mu.Lock()
		c.s.State = "CLOSED"
		c.mu.Unlock()
	}
}
func (c *Collector) NextOperation() string {
	if c == nil {
		return "0"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.op == ^uint64(0) {
		c.s.Coverage.Saturated = true
		c.s.Coverage.Gap = true
		return "0"
	}
	c.op++
	return strconv.FormatUint(c.op, 10)
}
func (c *Collector) Complete(e Event) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seq == ^uint64(0) {
		c.s.Coverage.Saturated = true
		c.s.Coverage.Gap = true
		return
	}
	c.seq++
	e.Kind = "HTTPS_EXCHANGE_COMPLETED"
	e.Seq = strconv.FormatUint(c.seq, 10)
	if e.OperationID == "" {
		e.OperationID = e.Seq
	}
	if Validate(e) != nil {
		c.s.Coverage.Gap = true
		return
	}
	if e.RCODE != nil {
		v := *e.RCODE
		e.RCODE = &v
	}
	if len(c.s.Events) == Capacity {
		copy(c.s.Events, c.s.Events[1:])
		c.s.Events = c.s.Events[:Capacity-1]
		if c.dropped < ^uint64(0) {
			c.dropped++
		} else {
			c.s.Coverage.Saturated = true
		}
		c.s.Coverage.Dropped = strconv.FormatUint(c.dropped, 10)
		c.s.Coverage.Gap = true
	}
	c.s.Events = append(c.s.Events, e)
}
func (c *Collector) Snapshot() Snapshot {
	if c == nil {
		return Snapshot{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.revision < ^uint64(0) {
		c.revision++
	} else {
		c.s.Coverage.Saturated = true
		c.s.Coverage.Gap = true
	}
	c.s.Revision = strconv.FormatUint(c.revision, 10)
	c.s.CapturedAt = time.Now().UTC().Format(time.RFC3339Nano)
	elapsed := uint64(time.Since(c.origin))
	if elapsed < c.revision {
		elapsed = c.revision
	}
	c.s.ElapsedNS = strconv.FormatUint(elapsed, 10)
	return Clone(c.s)
}
