package dnsevidence

import (
	"strings"
	"testing"
)

func testBinding() Binding {
	return Binding{InstanceID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32), ManifestID: strings.Repeat("c", 64), RuntimeSHA256: strings.Repeat("d", 64)}
}
func TestCollectorVertical(t *testing.T) {
	c := New(testBinding())
	c.SetPolicy(Policy{Source: "DECODED_INSTANCE_AND_FACTORY", Final: "SUPPORTED", Transports: []Transport{{ID: "1", Type: "HTTPS", ServerIP: "127.0.0.1", Port: "443", SNI: "example.com", TLS: "STRICT_CONFIGURED", Detour: "CONFIGURED_ONLY"}}, Capture: "NOT_OBSERVED"})
	c.Loaded()
	for i := 0; i < 66; i++ {
		c.Complete(Event{TransportID: "1", QType: "A", Outcome: "NOERROR", Validation: "MATCHED", DurationNS: "1", RCODE: strptr("0"), Connections: Connections{Acquisitions: "1", New: "1", Reused: "0", Idle: "0"}})
	}
	s := c.Snapshot()
	if s.State != "LOADED" || len(s.Events) != 64 || !s.Coverage.Gap || s.Coverage.Dropped != "2" || s.Events[0].Seq != "3" {
		t.Fatalf("bounded completion missing: state=%s events=%d dropped=%s", s.State, len(s.Events), s.Coverage.Dropped)
	}
	s.Events[0].Outcome = "OTHER_ERROR"
	s.Policy.Transports[0].SNI = "REDACTED"
	fresh := c.Snapshot()
	if fresh.Events[0].Outcome != "NOERROR" || fresh.Policy.Transports[0].SNI != "example.com" {
		t.Fatal("snapshot aliases owner")
	}
	b, e := Encode(Push{DNSSchema: 1, Action: "dns.push", HelperEpoch: strings.Repeat("e", 32), OperationID: strings.Repeat("f", 32), ConfigIdentity: strings.Repeat("1", 64), Binding: testBinding(), Snapshot: fresh})
	if e != nil || len(b) > PushBytes {
		t.Fatal("encode", e, len(b))
	}
	var p Push
	if Decode(b, &p) != nil {
		t.Fatal("round trip")
	}
}
func strptr(s string) *string { return &s }
