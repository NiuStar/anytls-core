package dnsevidence

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func TestMaximumLegalFrames(t *testing.T) {
	// Fixed schema proof: every free decimal uses uint64 max (20 bytes), every
	// ID/digest its exact width, all four transports and 64 events. IPv6 uses
	// eight uncompressible 4-digit groups (39 bytes); UTC wall values use the
	// longest accepted RFC3339Nano spelling (30 bytes). Longest enum per field.
	max := "18446744073709551615"
	wall := "9999-12-31T23:59:59.999999999Z"
	s := Snapshot{Revision: max, CapturedAt: wall, ElapsedNS: max, State: "STARTING", Policy: Policy{Source: "DECODED_INSTANCE_AND_FACTORY", Final: "NOT_OBSERVED", Capture: "NOT_OBSERVED", Transports: []Transport{}}, Events: []Event{}, Coverage: Coverage{Scope: "HTTPS_TRANSPORT_COMPLETION", Missing: Missing, Gap: true, Dropped: "18446744073709551551", Saturated: false}}
	for i := 0; i < 4; i++ {
		s.Policy.Transports = append(s.Policy.Transports, Transport{ID: max, Type: "HTTPS", ServerIP: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Port: "65535", SNI: "cloudflare-dns.com", TLS: "STRICT_CONFIGURED", Detour: "CONFIGURED_ONLY"})
	}
	rcode := "4095"
	for i := 0; i < Capacity; i++ {
		s.Events = append(s.Events, Event{Kind: "HTTPS_EXCHANGE_COMPLETED", Seq: strconv.FormatUint(^uint64(0)-uint64(Capacity-1-i), 10), OperationID: max, TransportID: max, QType: "OTHER", Outcome: "OTHER_RCODE", RCODE: &rcode, Validation: "NOT_OBSERVED", DurationNS: max, Connections: Connections{Acquisitions: max, New: max, Reused: max, Idle: max}})
	}
	epoch, identity := strings.Repeat("e", 32), strings.Repeat("f", 64)
	binding := testBinding()
	push := Push{DNSSchema: 1, Action: "dns.push", HelperEpoch: epoch, OperationID: epoch, ConfigIdentity: identity, Binding: binding, Snapshot: s}
	response := Response{DNSSchema: 1, Code: "OK", HelperEpoch: &epoch, ConfigIdentity: &identity, Binding: &binding, ReceivedAt: &wall, AgeNS: &max, Availability: "UNAVAILABLE", Snapshot: &s}
	read := Read{DNSSchema: 1, Action: "dns.read", InstanceID: &binding.InstanceID, Generation: &binding.Generation, ManifestID: &binding.ManifestID}
	for _, v := range []any{push, response, read, Ack{DNSSchema: 1, Code: "IDENTITY_MISMATCH"}} {
		wire, e := Encode(v)
		oracle, _ := json.Marshal(v)
		if e != nil || !bytes.Equal(wire, oracle) || len(wire) > limit(v) {
			t.Fatalf("maximum %T bytes=%d error=%v", v, len(wire), e)
		}
		switch v.(type) {
		case Push:
			var q Push
			e = Decode(wire, &q)
		case Response:
			var q Response
			e = Decode(wire, &q)
		case Read:
			var q Read
			e = Decode(wire, &q)
		case Ack:
			var q Ack
			e = Decode(wire, &q)
		}
		if e != nil {
			t.Fatalf("maximum roundtrip %T: %v", v, e)
		}
		t.Logf("fixed-schema maximum %T bytes=%d budget=%d", v, len(wire), limit(v))
	}
	// Both the writer and decoder enforce byte budgets independently.
	w := &bounded{max: ReadBytes}
	if _, e := w.Write(make([]byte, ReadBytes)); e != nil {
		t.Fatal(e)
	}
	if _, e := w.Write([]byte{0}); e == nil {
		t.Fatal("writer exceeded exact budget")
	}
	var dst Push
	if Decode(bytes.Repeat([]byte{' '}, PushBytes+1), &dst) == nil {
		t.Fatal("oversized push")
	}
}
