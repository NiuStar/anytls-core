package dnsevidence

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestStrictCodecBoundaries(t *testing.T) {
	q := Read{DNSSchema: 1, Action: "dns.read"}
	b, e := Encode(q)
	if e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{strings.Replace(string(b), `"dns_schema":1`, `"dns_schema":1,"dns_schema":1`, 1), strings.Replace(string(b), `"action"`, `"Action"`, 1), strings.Replace(string(b), `"dns_schema":1`, `"dns_schema":1,"timeline_schema":1`, 1), string(b) + ` {}`, strings.Replace(string(b), `"generation":null`, `"generation":"`+strings.Repeat("a", 32)+`"`, 1), string(b) + strings.Repeat(" ", ReadBytes)} {
		dst := Read{Action: "untouched"}
		if Decode([]byte(raw), &dst) == nil || dst.Action != "untouched" {
			t.Fatal("invalid or nontransactional decode")
		}
	}
	c := New(testBinding())
	c.Loaded()
	for i := 0; i < 64; i++ {
		c.Complete(Event{TransportID: "18446744073709551615", QType: "AAAA", Outcome: "OTHER_ERROR", Validation: "NOT_OBSERVED", DurationNS: "18446744073709551615", Connections: Connections{Acquisitions: "18446744073709551615", New: "18446744073709551615", Reused: "18446744073709551615", Idle: "18446744073709551615"}})
	}
	s := c.Snapshot()
	for i := range s.Events {
		s.Events[i].Seq = strings.Repeat("0", 0) + s.Events[i].Seq
		s.Events[i].OperationID = "18446744073709551615"
	}
	p := Push{DNSSchema: 1, Action: "dns.push", HelperEpoch: strings.Repeat("e", 32), OperationID: strings.Repeat("f", 32), ConfigIdentity: strings.Repeat("1", 64), Binding: testBinding(), Snapshot: s}
	b, e = Encode(p)
	oracle, _ := json.Marshal(p)
	if e != nil || !bytes.Equal(b, oracle) || len(b) > PushBytes {
		t.Fatal("legal maximum bounded frame", len(b), e)
	}
	var decoded Push
	if Decode(b, &decoded) != nil {
		t.Fatal("maximum round trip")
	}
	nested := strings.Replace(string(b), `"state":"LOADED"`, `"state":"LOADED","state":"LOADED"`, 1)
	if Decode([]byte(nested), &decoded) == nil {
		t.Fatal("nested duplicate")
	}
	c.seq = ^uint64(0)
	c.Complete(Event{})
	if !c.Snapshot().Coverage.Saturated {
		t.Fatal("sequence exhaustion hidden")
	}
}
