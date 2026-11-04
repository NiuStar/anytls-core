package trafficstats

import (
	"strings"
	"testing"
	"time"
)

func TestTrafficSamplerDoesNotBridgeUnavailableOrStarting(t *testing.T) {
	c := new(Counter)
	s := New(c, testHeader())
	now := time.Now()
	s.Sample(now, "STARTING")
	c.Upload(5)
	if got := s.Sample(now.Add(5*time.Second), "RUNNING"); got.Rate != nil {
		t.Fatal("first running sample bridges startup")
	}
	s.Sample(now.Add(10*time.Second), "UNAVAILABLE")
	c.Upload(7)
	got := s.Sample(now.Add(2*time.Minute), "RUNNING")
	if got.Rate != nil || len(got.History) != 0 {
		t.Fatal("bridged unavailable span", got)
	}
	c.Upload(11)
	got = s.Sample(now.Add(2*time.Minute+5*time.Second), "RUNNING")
	if got.Rate == nil || got.Rate.Upload != "11" {
		t.Fatal("did not resume", got)
	}
}

func TestTrafficStrictCodecRejectsNoncanonicalNestedAndMissing(t *testing.T) {
	c := new(Counter)
	s := New(c, testHeader())
	now := time.Now()
	s.Sample(now, "RUNNING")
	c.Upload(2)
	snap := s.Sample(now.Add(5*time.Second), "RUNNING")
	b, e := Encode(Response{1, "OBSERVED", &snap})
	if e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{
		strings.Replace(string(b), `"end_ns":"5000000000"`, `"end_ns":"1"`, 1),
		strings.Replace(string(b), `"start_ns":"0"`, `"start_ns":"00"`, 1),
		strings.Replace(string(b), `"history":[]`, `"history":null`, 1),
		strings.Replace(string(b), `"saturated":false,`, "", 1),
		strings.Replace(string(b), `"start_ns":"0"`, `"start_ns":"0","start_ns":"0"`, 1),
	} {
		var out Response
		if Decode([]byte(bad), &out) == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}
