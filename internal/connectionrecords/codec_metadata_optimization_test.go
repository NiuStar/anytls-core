package connectionrecords

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Synthetic repeated DTOs, not compiler output or an end-to-end startup claim.
func metadataFixture(n int) Manifest {
	m := systemDigestFixture()
	m.Rules = make([]RuleOrigin, n)
	for i := range m.Rules {
		m.Rules[i] = RuleOrigin{Type: "field", ActionType: "synthetic", Synthetic: SyntheticNone, Route: RouteProjection{Evidence: ProvenanceUnknown, Kind: RuleUnknown, TerminalKind: TerminalUnknown}}
	}
	return m
}

func metadataPositiveFixtures() []any {
	h, r, m := fixtureHeader(), fixtureRecord(), systemDigestMixedFixture()
	coverage := Coverage{Unobserved: []string{"REJECT", "DNS", "EARLY_ERROR"}, Gap: true, Continuity: ContinuityUnknown}
	state := State{Header: h, Revision: "1", HighWaterSeq: "0", CommittedDataBytes: "0", CommittedIndexBytes: "0", Collection: Recording, ProvenanceStatus: ProvenanceUnknown, Timestamp: h.CreatedAt}
	page := PageResponse{Header: h, HistoryKind: LastRecorded, ProvenanceStatus: ProvenanceUnknown, Collection: CollectionUnknown, Freshness: FreshnessUnknown, Timestamp: h.CreatedAt, HighWaterSeq: "0", NextAfter: "0", Records: []Record{}, Coverage: coverage, DNS: DNSStatus{Status: "UNKNOWN"}}
	// PageRequest has an explicit wire codec and is deliberately rejected by the
	// generic codec. Interfaces (Sink/WriterAPI/etc.) are not wire DTOs.
	return []any{Decimal("18446744073709551615"), Recording, ProvenanceVerified, CleanupVerified, InvalidRequest, HookTCP, NetworkTCP, HostDestination, TerminalDirect, RuleDomain, SyntheticNone, LastRecorded, Fresh, ContinuityUnknown, SourceConfig,
		h.Binding, Scope{UID: 501, ConfigIdentity: h.ConfigIdentity}, h, Latest{1, h.InstanceID}, m.CapturedSources[0], m.Rules[0].Route.GroupPath[0], *m.Rules[0].Route.Condition, *m.Rules[4].Route.RuleSet, m.Rules[0].Route, m.Rules[0], m.Outbounds[1], m, r.Destination,
		Observation{Hook: r.Hook, Network: r.Network, Destination: r.Destination, Route: r.Route}, ShutdownResult{Recording, CleanupVerified, NoError}, r, LossReasons{QueueFull: ptr(Decimal("0"))}, state, coverage, page.DNS, page, ErrorResponse{1, InvalidRequest}, requestWire{Action: "records.read", SchemaVersion: 1, After: "0", Limit: 100},
		[]GroupEdge(nil), []GroupEdge{}, (*Binding)(nil), &h,
		GroupEdge{Group: "中文😀\"\\\b\f\n\r\t\x01\x1f<>&\u2028\u2029", Selected: "escaped"}}
}

func metadataCheck(t *testing.T, value any) {
	t.Helper()
	before := systemDigestCloneValue(reflect.ValueOf(value)).Interface()
	want, err := metadataOldEncodeBounded(value, int(^uint(0)>>1))
	if err != nil {
		t.Fatalf("invalid positive %T: %v", value, err)
	}
	for _, budget := range []int{len(want), len(want) - 1, 0} {
		old, oldErr := metadataOldEncodeBounded(value, budget)
		got, gotErr := EncodeBounded(value, budget)
		if gotErr != oldErr || !bytes.Equal(got, old) || (got == nil) != (old == nil) {
			t.Fatalf("%T encode budget=%d differs: %v / %v", value, budget, gotErr, oldErr)
		}
		a, b := reflect.New(reflect.TypeOf(value)), reflect.New(reflect.TypeOf(value))
		// Seed both outputs with independent nonzero values; failures must not commit.
		a.Elem().Set(systemDigestCloneValue(reflect.ValueOf(value)))
		b.Elem().Set(systemDigestCloneValue(reflect.ValueOf(value)))
		input := bytes.Clone(want)
		oldErr = metadataOldDecodeStrict(input, a.Interface(), budget)
		gotErr = DecodeStrict(input, b.Interface(), budget)
		if gotErr != oldErr || !reflect.DeepEqual(a.Interface(), b.Interface()) || !bytes.Equal(input, want) {
			t.Fatalf("%T decode budget=%d differs or mutated input: %v / %v", value, budget, gotErr, oldErr)
		}
		if gotErr != nil && !reflect.DeepEqual(b.Elem().Interface(), before) {
			t.Fatal("failed decode mutated destination")
		}
		if gotErr == nil && !reflect.DeepEqual(b.Elem().Interface(), value) {
			t.Fatalf("%T roundtrip changed nil/empty/value", value)
		}
	}
	if !reflect.DeepEqual(value, before) {
		t.Fatal("encode mutated caller input")
	}
}

func TestCodecMetadataEquivalent(t *testing.T) {
	for i, value := range metadataPositiveFixtures() {
		t.Run(fmt.Sprintf("dto_%02d_%T", i, value), func(t *testing.T) { metadataCheck(t, value) })
	}
	for _, n := range []int{0, 1000, 10000, 91982} {
		t.Run("rules_"+strconv.Itoa(n), func(t *testing.T) {
			m := metadataFixture(n)
			metadataCheck(t, m)
			before := systemDigestClone(m)
			budget := ManifestBudget(&m)
			want, err := metadataOldManifestDigest(m, budget)
			got, gotErr := ManifestDigest(m, budget)
			if err != nil || gotErr != err || got != want || !reflect.DeepEqual(m, before) {
				t.Fatalf("digest mismatch or mutation: %v / %v", gotErr, err)
			}
		})
	}
}

func TestCodecMetadataEncodeRejections(t *testing.T) {
	for _, value := range []any{nil, map[string]int{"x": 1}, float64(1), make(chan int), PageRequest{}, GroupEdge{Group: "bad\x00"}, GroupEdge{Group: string([]byte{255})}, Decimal("01")} {
		for _, budget := range []int{10000, 1, 0, -1} {
			old, oldErr := metadataOldEncodeBounded(value, budget)
			got, gotErr := EncodeBounded(value, budget)
			expected := ErrInvalid
			if budget < 1 {
				expected = ErrTooLarge
			}
			if gotErr != oldErr || gotErr != expected || got != nil || old != nil {
				t.Fatalf("%T budget=%d: got %v old %v expected %v", value, budget, gotErr, oldErr, expected)
			}
		}
	}
}

func TestCodecMetadataDecodeTransactional(t *testing.T) {
	wire, err := metadataOldEncodeBounded(fixtureRecord(), MaxRecordBytes)
	if err != nil {
		t.Fatal(err)
	}
	s := string(wire)
	cases := []string{s + `{}`, s + "\x00", s[:len(s)-1], `null`, `{}`}
	for _, change := range [][2]string{
		{`"schema_version":1`, `"schema_version":1,"schema_version":1`},
		{`"host":"example.com"`, `"host":"example.com","host":"example.com"`},
		{`"host":"example.com"`, `"host":"example.com","unknown":true`},
		{`"event":"ROUTED",`, ``}, {`,"host_source":"DESTINATION_FQDN"`, ``},
		{`"seq":"1"`, `"seq":1`}, {`"seq":"1"`, `"seq":"01"`},
		{`"port":443`, `"port":65536`}, {`"port":443`, `"port":1.0`},
		{`"hook":"tcp"`, `"hook":null`}, {`"connected":null`, `"connected":true`},
		{`"host":"example.com"`, `"host":"bad\u0000host"`},
		{`"host":"example.com"`, `"host":"` + string([]byte{255}) + `"`},
	} {
		cases = append(cases, strings.Replace(s, change[0], change[1], 1))
	}
	for i, bad := range cases {
		for _, budget := range []int{len(bad), len(bad) - 1, 0} {
			before := fixtureRecord()
			before.Seq = "777"
			a := systemDigestCloneValue(reflect.ValueOf(before)).Interface().(Record)
			b := systemDigestCloneValue(reflect.ValueOf(before)).Interface().(Record)
			input := []byte(bad)
			oldErr := metadataOldDecodeStrict(input, &a, budget)
			gotErr := DecodeStrict(input, &b, budget)
			expected := ErrInvalid
			if budget < 1 || len(input) > budget {
				expected = ErrTooLarge
			}
			if gotErr != oldErr || gotErr != expected || !reflect.DeepEqual(a, before) || !reflect.DeepEqual(b, before) || string(input) != bad {
				t.Fatalf("case=%d budget=%d: got %v old %v; transactional mismatch", i, budget, gotErr, oldErr)
			}
		}
	}
	var nilRecord *Record
	var unsupported map[string]string
	for _, out := range []any{nil, Record{}, nilRecord, &unsupported} {
		if oldErr, gotErr := metadataOldDecodeStrict([]byte(`{}`), out, 2), DecodeStrict([]byte(`{}`), out, 2); gotErr != oldErr || gotErr != ErrInvalid {
			t.Fatalf("destination %T: %v / %v", out, gotErr, oldErr)
		}
	}
}

func TestCodecMetadataConcurrent(t *testing.T) {
	m := metadataFixture(3)
	budget := ManifestBudget(&m)
	wire, err := metadataOldEncodeBounded(m, budget)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := metadataOldManifestDigest(m, budget)
	if err != nil {
		t.Fatal(err)
	}
	before := systemDigestClone(m)
	var wg sync.WaitGroup
	for worker := 0; worker < 32; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for repeat := 0; repeat < 3; repeat++ {
				got, err := EncodeBounded(m, budget)
				if err != nil || !bytes.Equal(got, wire) {
					t.Errorf("concurrent encode: %v", err)
					return
				}
				var out Manifest
				if err := DecodeStrict(wire, &out, budget); err != nil || !reflect.DeepEqual(out, m) {
					t.Errorf("concurrent decode: %v", err)
					return
				}
				if got, err := ManifestDigest(m, budget); err != nil || got != digest {
					t.Errorf("concurrent digest: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if !reflect.DeepEqual(m, before) {
		t.Fatal("concurrent calls mutated input")
	}
}

// Use -benchtime=1x -count=5: repetitions share a process, not fresh processes.
// Fixture preparation and oracle validation are outside the measured interval.
func BenchmarkCodecMetadata(b *testing.B) {
	for _, n := range []int{0, 1000, 10000, 91982} {
		b.Run("rules_"+strconv.Itoa(n), func(b *testing.B) {
			m := metadataFixture(n)
			budget := ManifestBudget(&m)
			wire, err := metadataOldEncodeBounded(m, budget)
			if err != nil {
				b.Fatal(err)
			}
			digest, err := metadataOldManifestDigest(m, budget)
			if err != nil {
				b.Fatal(err)
			}
			sum := sha256.Sum256(wire)
			for _, op := range []string{"encode", "decode", "digest"} {
				b.Run(op, func(b *testing.B) {
					b.Logf("fixture=synthetic_UNKNOWN operation=%s rules=%d outbounds=%d sources=%d wire_bytes=%d manifest_budget=%d wire_sha256=%x canonical_sha256=%s", op, n, len(m.Outbounds), len(m.CapturedSources), len(wire), budget, sum, digest)
					b.ReportAllocs()
					b.SetBytes(int64(len(wire)))
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						switch op {
						case "encode":
							got, err := EncodeBounded(m, budget)
							if err != nil || !bytes.Equal(got, wire) {
								b.Fatalf("encode: %v", err)
							}
						case "decode":
							var out Manifest
							if err := DecodeStrict(wire, &out, budget); err != nil || len(out.Rules) != n {
								b.Fatalf("decode: %v", err)
							}
						case "digest":
							got, err := ManifestDigest(m, budget)
							if err != nil || got != digest {
								b.Fatalf("digest: %v", err)
							}
						}
					}
				})
			}
		})
	}
}
