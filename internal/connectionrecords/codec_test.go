package connectionrecords

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func ptr[T any](v T) *T { return &v }
func fixtureBinding() Binding {
	return Binding{strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 64)}
}
func fixtureHeader() Header {
	return Header{SchemaVersion: 1, ConfigIdentity: strings.Repeat("d", 64), Binding: fixtureBinding(), RuntimeSHA256: strings.Repeat("e", 64), CreatedAt: "2026-10-22T00:00:00Z"}
}
func fixtureRecord() Record {
	return Record{SchemaVersion: 1, Binding: fixtureBinding(), Seq: "1", ObservationID: "9007199254740993", ObservedAt: "2026-10-22T00:00:00Z", Event: "ROUTED", Hook: HookTCP, Network: NetworkTCP, Destination: Destination{Host: ptr("example.com"), Port: ptr(uint16(443)), HostSource: HostDestination}, Route: RouteProjection{Evidence: ProvenanceUnknown, Kind: RuleUnknown, TerminalKind: TerminalUnknown, OutboundTag: "direct", OutboundType: "direct"}, State: "ROUTED"}
}
func TestDecimalCanonical(t *testing.T) {
	for _, s := range []Decimal{"0", "1", "9007199254740993", "18446744073709551615"} {
		n, e := s.Uint64()
		if e != nil || DecimalFromUint64(n) != s {
			t.Fatalf("valid %q: %v", s, e)
		}
	}
	for _, s := range []Decimal{"", "00", "01", "+1", "-1", "1.0", "1e2", " 1", "18446744073709551616"} {
		if _, e := s.Uint64(); e == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}
func TestRecordRoundTripAndExactBudgets(t *testing.T) {
	r := fixtureRecord()
	b, e := EncodeBounded(r, MaxRecordBytes)
	if e != nil {
		t.Fatal(e)
	}
	var got Record
	if e = DecodeStrict(b, &got, MaxRecordBytes); e != nil {
		t.Fatal(e)
	}
	reference, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(reference, b) {
		t.Fatalf("wire differs:\n%s\n%s", reference, b)
	}
	if _, e = EncodeBounded(r, len(b)); e != nil {
		t.Fatal(e)
	}
	if _, e = EncodeBounded(r, len(b)-1); !errors.Is(e, ErrTooLarge) {
		t.Fatal(e)
	}
	if e = DecodeStrict(b, &got, len(b)-1); !errors.Is(e, ErrTooLarge) {
		t.Fatal(e)
	}
	if !bytes.Contains(b, []byte(`"connected":null`)) || !bytes.Contains(b, []byte(`"group_path":null`)) {
		t.Fatal("explicit null missing")
	}
}
func TestStrictRecursiveRejections(t *testing.T) {
	b, e := EncodeBounded(fixtureRecord(), MaxRecordBytes)
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	cases := []string{
		strings.Replace(s, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1),
		strings.Replace(s, `"host_source":"DESTINATION_FQDN"`, `"host_source":"DESTINATION_FQDN","host_source":"UNKNOWN"`, 1),
		strings.Replace(s, `"host_source":"DESTINATION_FQDN"`, `"host_source":"DESTINATION_FQDN","secret":"hidden"`, 1),
		strings.Replace(s, `"connected":null`, `"connected":false`, 1),
		strings.Replace(s, `"seq":"1"`, `"seq":"01"`, 1),
		strings.Replace(s, `"seq":"1"`, `"seq":1`, 1),
		strings.Replace(s, `"hook":"tcp"`, `"hook":null`, 1),
		strings.Replace(s, `"instance_id":"`+fixtureBinding().InstanceID+`"`, `"instance_id":"`+strings.Repeat("A", 32)+`"`, 1),
		strings.Replace(s, `"host":"example.com"`, `"host":"https://example.com/private?secret"`, 1),
		strings.Replace(s, `"host":"example.com"`, `"host":"bad\u0000host"`, 1),
		strings.Replace(s, `"host":"example.com"`, `"host":"`+string([]byte{255})+`"`, 1),
		strings.Replace(s, `"event":"ROUTED",`, "", 1),
		s + ` {}`, s + "\x00",
	}
	for i, bad := range cases {
		var out Record
		if e := DecodeStrict([]byte(bad), &out, MaxRecordBytes); e == nil {
			t.Fatalf("case %d accepted", i)
		}
		if out.Seq != "" {
			t.Fatal("failed decode mutated destination")
		}
	}
}
func TestEscapingIsBounded(t *testing.T) {
	r := fixtureRecord()
	r.Route.OutboundTag = strings.Repeat("\x01", MaxRecordBytes)
	if b, e := EncodeBounded(r, MaxRecordBytes); !errors.Is(e, ErrTooLarge) || b != nil {
		t.Fatalf("oversize result %d %v", len(b), e)
	}
	e := boundedEncoder{limit: 31}
	if err := e.quoted(strings.Repeat("\x01", 1000000)); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
	if len(e.b) > 31 || cap(e.b) > 31 {
		t.Fatal("buffer exceeded budget")
	}
	for _, s := range []string{"quote\"\\\n\t", "中文😀", "\x01\b\f\r"} {
		e := boundedEncoder{limit: 100}
		if err := e.quoted(s); err != nil {
			t.Fatal(err)
		}
		var got string
		if json.Unmarshal(e.b, &got) != nil || got != s {
			t.Fatalf("escape %q", s)
		}
	}
}

type countReader struct {
	read      int
	remaining int
}

func (r *countReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > r.remaining {
		n = r.remaining
	}
	for i := 0; i < n; i++ {
		p[i] = ' '
	}
	r.remaining -= n
	r.read += n
	return n, nil
}
func TestReadBoundBeforeDecode(t *testing.T) {
	r := &countReader{remaining: 100000}
	var h Header
	if e := ReadStrict(r, &h, 128); !errors.Is(e, ErrTooLarge) || r.read != 129 {
		t.Fatalf("read %d err %v", r.read, e)
	}
}
func TestRequestDefaultsBindingAndStrictness(t *testing.T) {
	raw := `{"action":"records.read","schema_version":1,"instance_id":null,"generation":null,"manifest_id":null}`
	q, e := DecodeRequest([]byte(raw))
	if e != nil || q.Binding != nil || q.After != "0" || q.Limit != 100 {
		t.Fatalf("defaults %+v %v", q, e)
	}
	q.Binding = ptr(fixtureBinding())
	q.After = "9007199254740993"
	q.Limit = 500
	b, e := EncodeRequest(q)
	if e != nil {
		t.Fatal(e)
	}
	got, e := DecodeRequest(b)
	if e != nil || *got.Binding != *q.Binding || got.After != q.After {
		t.Fatalf("roundtrip %+v %v", got, e)
	}
	for _, bad := range []string{
		strings.Replace(raw, `"instance_id":null`, `"instance_id":"`+fixtureBinding().InstanceID+`"`, 1),
		strings.Replace(raw, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1),
		strings.Replace(raw, `"schema_version":1`, `"schema_version":2`, 1),
		strings.Replace(raw, `"manifest_id":null`, `"manifest_id":null,"after":null`, 1),
		strings.Replace(raw, `"manifest_id":null`, `"manifest_id":null,"limit":501`, 1),
		strings.Replace(raw, `"manifest_id":null`, `"manifest_id":null,"limit":1.0`, 1),
		strings.Replace(raw, `"manifest_id":null`, `"manifest_id":null,"path":"/private"`, 1),
		strings.Replace(raw, `"manifest_id":null`, `"manifest_id":{"x":1,"x":2}`, 1), raw + `{}`,
	} {
		if _, e := DecodeRequest([]byte(bad)); e == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}
func TestHeaderStateAndAttributionRules(t *testing.T) {
	h := fixtureHeader()
	b, e := EncodeBounded(h, MaxHeaderBytes)
	if e != nil {
		t.Fatal(e)
	}
	var got Header
	if e = DecodeStrict(b, &got, MaxHeaderBytes); e != nil {
		t.Fatal(e)
	}
	state := State{Header: h, Revision: "1", HighWaterSeq: "0", CommittedDataBytes: "0", CommittedIndexBytes: "0", Collection: Recording, ProvenanceStatus: ProvenanceUnknown, Timestamp: h.CreatedAt}
	if _, e := EncodeBounded(state, MaxStateBytes); e != nil {
		t.Fatal(e)
	}
	state.CommittedIndexBytes = "16"
	if Validate(state) == nil {
		t.Fatal("inconsistent committed prefix")
	}
	r := fixtureRecord()
	r.Route.SourceID = ptr("fabricated")
	if Validate(r) == nil {
		t.Fatal("unknown attribution retained claims")
	}
	r = fixtureRecord()
	g := r.Generation
	r.Route = RouteProjection{Evidence: ProvenanceVerified, SourceID: ptr(g + ":rule:0"), SourceIndex: ptr(0), Kind: RuleDomain, Condition: &Condition{RuleDomain, "example.com"}, ConfiguredTarget: ptr("DIRECT"), GroupPath: []GroupEdge{}, TerminalKind: TerminalDirect, OutboundTag: "direct", OutboundType: "direct", SelectionGeneration: &g}
	if e := Validate(r); e != nil {
		t.Fatal(e)
	}
	r.Route.SourceID = ptr(g + ":rule:00")
	if Validate(r) == nil {
		t.Fatal("noncanonical source ID")
	}
}

// Exercise semantic rejection through the decoder, not only local validation.
func TestDecoderSemanticRejectionsRemainTransactional(t *testing.T) {
	base, err := EncodeBounded(fixtureRecord(), MaxRecordBytes)
	if err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"unknown_route_claim": strings.Replace(string(base), `"source_id":null`, `"source_id":"fabricated"`, 1),
		"connection_claim":    strings.Replace(string(base), `"connected":null`, `"connected":true`, 1),
		"zero_observation":    strings.Replace(string(base), `"observation_id":"9007199254740993"`, `"observation_id":"0"`, 1),
		"unknown_enum":        strings.Replace(string(base), `"network":"tcp"`, `"network":"invented"`, 1),
		"invalid_ip":          strings.Replace(string(base), `"ip":null`, `"ip":"999.1.1.1"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			out := fixtureRecord()
			out.Seq = "777"
			if err := DecodeStrict([]byte(bad), &out, MaxRecordBytes); !errors.Is(err, ErrInvalid) {
				t.Fatalf("semantic input accepted: %v", err)
			}
			if out.Seq != "777" {
				t.Fatal("failed decode changed existing destination")
			}
		})
	}
}

func TestDecoderInvalidDestinationsDoNotPanic(t *testing.T) {
	var nilRecord *Record
	var unsupported map[string]string
	for _, out := range []any{nil, Record{}, nilRecord, &unsupported} {
		if err := DecodeStrict([]byte(`{}`), out, MaxRecordBytes); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid destination accepted: %T %v", out, err)
		}
	}
}

func TestPageCoverageAndUnknownCounters(t *testing.T) {
	h := fixtureHeader()
	p := PageResponse{Header: h, HistoryKind: LastRecorded, ProvenanceStatus: ProvenanceUnknown, Collection: CollectionUnknown, Freshness: FreshnessUnknown, Timestamp: h.CreatedAt, HighWaterSeq: "0", NextAfter: "0", Records: []Record{}, Coverage: Coverage{Unobserved: []string{"REJECT", "DNS", "EARLY_ERROR"}, Gap: true, Continuity: ContinuityUnknown}, DNS: DNSStatus{Status: "UNKNOWN"}}
	b, e := EncodeBounded(p, MaxResponseBytes)
	if e != nil {
		t.Fatal(e)
	}
	var got PageResponse
	if e := DecodeStrict(b, &got, MaxResponseBytes); e != nil {
		t.Fatal(e)
	}
	if got.Pending != nil || got.Coverage.LostTotal != nil {
		t.Fatal("unknown became zero")
	}
	p.DNS.Evidence = ptr("inferred")
	if Validate(p) == nil {
		t.Fatal("DNS inference accepted")
	}
}
