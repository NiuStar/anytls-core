package trafficstats

import (
	"bytes"
	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

func testHeader() cr.Header {
	return cr.Header{SchemaVersion: 1, ConfigIdentity: strings.Repeat("a", 64), Binding: cr.Binding{InstanceID: strings.Repeat("b", 32), Generation: strings.Repeat("c", 32), ManifestID: strings.Repeat("d", 64)}, RuntimeSHA256: strings.Repeat("e", 64), CreatedAt: "2026-01-01T00:00:00Z"}
}
func TestCounterExactConcurrentAndSaturation(t *testing.T) {
	c := new(Counter)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 1000 {
				c.Upload(7)
				c.Download(11)
			}
		})
	}
	wg.Wait()
	u, d, s := c.Totals()
	if u != 56000 || d != 88000 || s {
		t.Fatal(u, d, s)
	}
	c.up.Store(math.MaxUint64 - 3)
	c.Upload(5)
	c.Upload(99)
	u, _, s = c.Totals()
	if u != math.MaxUint64 || !s {
		t.Fatal("wrapped", u, s)
	}
	c.Download(-1)
	var off *Counter
	off.Upload(9)
	if got := testing.AllocsPerRun(1000, func() { c.Download(1) }); got != 0 {
		t.Fatal("callback allocates", got)
	}
}
func TestMonotonicRateBoundedHistoryNoBackfill(t *testing.T) {
	c := new(Counter)
	s := New(c, testHeader())
	now := time.Now()
	first := s.Sample(now, "RUNNING")
	if first.Rate != nil || len(first.History) != 0 {
		t.Fatal("invented first sample")
	}
	c.Upload(23)
	c.Download(31)
	got := s.Sample(now.Add(7*time.Second), "RUNNING")
	if got.Rate == nil || got.Rate.Upload != "23" || got.Rate.Download != "31" || got.Rate.EndNS != "7000000000" {
		t.Fatal(got)
	}
	for i := 1; i <= 1500; i++ {
		c.Upload(1)
		got = s.Sample(now.Add(time.Duration(i)*time.Minute), "RUNNING")
	}
	if len(got.History) != MaxHistory || got.History[0].StartNS != "3600000000000" {
		t.Fatal("bad retention", len(got.History), got.History[0])
	}
	got.History[0].Upload = "9999"
	if s.Sample(now.Add(1500*time.Minute+time.Second), "RUNNING").History[0].Upload == "9999" {
		t.Fatal("mutable history")
	}
	restarted := New(c, testHeader()).Sample(now, "RUNNING")
	if restarted.Rate != nil || len(restarted.History) != 0 {
		t.Fatal("adopted old history")
	}
	bad := s.Sample(now, "RUNNING")
	if bad.State != "UNAVAILABLE" || bad.Rate != nil {
		t.Fatal("negative clock delta accepted")
	}
}
func TestStrictCodecAndBeyondJSInteger(t *testing.T) {
	c := new(Counter)
	c.up.Store(9007199254740993)
	snap := New(c, testHeader()).Sample(time.Now(), "RUNNING")
	b, e := Encode(Response{1, "OBSERVED", &snap})
	if e != nil || !bytes.Contains(b, []byte(`"9007199254740993"`)) {
		t.Fatal(e, string(b))
	}
	var r Response
	if Decode(b, &r) != nil {
		t.Fatal("roundtrip")
	}
	for _, bad := range []string{strings.Replace(string(b), `"source":"SDK_ROUTED_PAYLOAD"`, `"source":"NIC"`, 1), strings.Replace(string(b), `"state":"RUNNING"`, `"state":"CLOSED"`, 1), strings.Replace(string(b), `"traffic_schema":1`, `"traffic_schema":1,"traffic_schema":1`, 1), strings.Replace(string(b), `"traffic_schema":1`, `"traffic_schema":1,"path":"/secret"`, 1), strings.Replace(string(b), `"upload_bytes":"9007199254740993"`, `"upload_bytes":"01"`, 1), string(b) + `{}`, strings.Repeat(" ", MaxBytes+1)} {
		if Decode([]byte(bad), &r) == nil {
			t.Fatal("accepted malformed payload")
		}
	}
	for _, q := range []string{`{"action":"traffic.read","traffic_schema":1}`, `{"traffic_schema":1,"action":"traffic.read"}`} {
		var v Read
		if Decode([]byte(q), &v) != nil {
			t.Fatal(q)
		}
	}
}
