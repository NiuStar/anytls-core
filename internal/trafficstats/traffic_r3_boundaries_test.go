package trafficstats

import (
	"encoding/json"
	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	"math"
	"testing"
	"time"
)

func TestTrafficR3HistoryConsistencyBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name     string
		up, down string
		history  []Interval
		rate     *Interval
		valid    bool
	}{
		{"max exact sum", "18446744073709551615", "18446744073709551615", []Interval{{"0", "60000000000", "18446744073709551614", "18446744073709551614"}, {"60000000000", "120000000000", "1", "1"}}, nil, true},
		{"upload overflow", "18446744073709551615", "2", []Interval{{"0", "60000000000", "18446744073709551615", "1"}, {"60000000000", "120000000000", "1", "1"}}, nil, false},
		{"download overflow", "2", "18446744073709551615", []Interval{{"0", "60000000000", "1", "18446744073709551615"}, {"60000000000", "120000000000", "1", "1"}}, nil, false},
		{"gaps and partial retention", "99", "99", []Interval{{"0", "60000000000", "1", "2"}, {"120000000000", "180000000000", "3", "4"}}, &Interval{"175000000000", "180000000000", "3", "4"}, true},
		{"contained download exceeds", "99", "99", []Interval{{"120000000000", "180000000000", "3", "4"}}, &Interval{"175000000000", "180000000000", "3", "5"}, false},
		{"equal interval exceeds", "99", "99", []Interval{{"120000000000", "180000000000", "3", "4"}}, &Interval{"120000000000", "180000000000", "4", "4"}, false},
		{"rate spans gap not contained", "99", "99", []Interval{{"0", "60000000000", "1", "2"}, {"120000000000", "180000000000", "3", "4"}}, &Interval{"55000000000", "180000000000", "50", "50"}, true},
		{"minute minus ns", "0", "0", []Interval{{"0", "59999999999", "0", "0"}}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap := New(new(Counter), testHeader()).Sample(time.Now(), "RUNNING")
			snap.ElapsedNS = "180000000000"
			snap.Upload = cr.Decimal(tc.up)
			snap.Download = cr.Decimal(tc.down)
			snap.History = tc.history
			snap.Rate = tc.rate
			wire, err := json.Marshal(Response{1, "OBSERVED", &snap})
			if err != nil {
				t.Fatal(err)
			}
			var got Response
			if err = Decode(wire, &got); (err == nil) != tc.valid {
				t.Fatalf("valid=%v decode=%v", tc.valid, err)
			}
		})
	}
}

func TestTrafficR3GeneratedHistoryPassesStrictCodec(t *testing.T) {
	c := new(Counter)
	s := New(c, testHeader())
	now := time.Now()
	for i := 0; i <= 1500; i++ {
		c.Upload(7)
		c.Download(11)
		snap := s.Sample(now.Add(time.Duration(i)*time.Minute), "RUNNING")
		if err := Validate(snap); err != nil {
			t.Fatalf("generated minute %d rejected: %v", i, err)
		}
	}
	// Near-uint64 legitimate totals must not require all history to be retained.
	c.up.Store(math.MaxUint64)
	snap := s.Sample(now.Add(1501*time.Minute), "RUNNING")
	if err := Validate(snap); err != nil {
		t.Fatal(err)
	}
}
