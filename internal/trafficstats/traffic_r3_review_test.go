package trafficstats

import (
	"encoding/json"
	"testing"
	"time"
)

// An impossible pair of disjoint retained intervals cannot consume more bytes
// than the same-run cumulative total. Exercises the public helper wire decoder.
func TestReviewR2ImpossibleHistorySum(t *testing.T) {
	snap := New(new(Counter), testHeader()).Sample(time.Now(), "RUNNING")
	snap.ElapsedNS = "120000000000"
	snap.Upload = "10"
	snap.Download = "20"
	snap.History = []Interval{{"0", "60000000000", "10", "20"}, {"60000000000", "120000000000", "10", "20"}}
	b, e := json.Marshal(Response{1, "OBSERVED", &snap})
	if e != nil {
		t.Fatal(e)
	}
	var out Response
	if e = Decode(b, &out); e == nil {
		t.Fatalf("accepted impossible retained sums up=20>10 down=40>20: %s", b)
	}
}
func TestReviewR2IncompleteMinuteHistory(t *testing.T) {
	snap := New(new(Counter), testHeader()).Sample(time.Now(), "RUNNING")
	snap.ElapsedNS = "1"
	snap.History = []Interval{{"0", "1", "0", "0"}}
	b, e := json.Marshal(Response{1, "OBSERVED", &snap})
	if e != nil {
		t.Fatal(e)
	}
	var out Response
	if Decode(b, &out) == nil {
		t.Fatal("accepted 1ns completed minute history")
	}
}
func TestReviewR2RateContainedInHistoryExceedsHistory(t *testing.T) {
	snap := New(new(Counter), testHeader()).Sample(time.Now(), "RUNNING")
	snap.ElapsedNS = "60000000000"
	snap.Upload = "100"
	snap.History = []Interval{{"0", "60000000000", "1", "0"}}
	snap.Rate = &Interval{"55000000000", "60000000000", "99", "0"}
	b, e := json.Marshal(Response{1, "OBSERVED", &snap})
	if e != nil {
		t.Fatal(e)
	}
	var out Response
	if Decode(b, &out) == nil {
		t.Fatal("accepted contained 99-byte rate inside 1-byte history")
	}
}
