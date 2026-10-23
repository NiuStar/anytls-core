package connectionrecords

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func qb01Page() PageResponse {
	h := fixtureHeader()
	return PageResponse{Header: h, HistoryKind: LastRecorded, ProvenanceStatus: ProvenanceUnknown, Collection: Recording, Freshness: Fresh, Timestamp: h.CreatedAt, HighWaterSeq: "0", NextAfter: "0", Records: []Record{}, Coverage: Coverage{Unobserved: []string{"REJECT", "DNS", "EARLY_ERROR"}, Continuity: ContinuityUnknown}, DNS: DNSStatus{Status: "UNKNOWN"}}
}

// Uses only pre-fix APIs: identical bytes must produce a business RED on old code.
func TestQB01CrossFieldSemantics(t *testing.T) {
	mutations := []struct {
		name   string
		change func(*PageResponse)
	}{
		{"lost_total", func(p *PageResponse) { p.Coverage.LostTotal = ptr(Decimal("1")) }},
		{"saturated", func(p *PageResponse) { p.Coverage.CounterSaturated = true }},
		{"unclosed_continuity", func(p *PageResponse) { p.Coverage.Continuity = ContinuityClosed }},
	}
	for i := 0; i < 8; i++ {
		index := i
		mutations = append(mutations, struct {
			name   string
			change func(*PageResponse)
		}{"reason_" + []string{"queue", "oversize", "admission", "encoding", "io", "worker", "id", "shutdown"}[i], func(p *PageResponse) {
			reflect.ValueOf(&p.Coverage.LossReasons).Elem().Field(index).Set(reflect.ValueOf(ptr(Decimal("1"))))
		}})
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			p := qb01Page()
			tc.change(&p)
			if err := Validate(p); !errors.Is(err, ErrInvalid) {
				t.Errorf("QB01 invalid cross-field page accepted by Validate: %v", err)
			}
			if b, err := EncodeBounded(p, MaxResponseBytes); !errors.Is(err, ErrInvalid) || b != nil {
				t.Errorf("QB01 invalid page encoded: bytes=%d err=%v", len(b), err)
			}
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			out := qb01Page()
			out.NextAfter = "77"
			before, _ := json.Marshal(out)
			if err := DecodeStrict(raw, &out, MaxResponseBytes); !errors.Is(err, ErrInvalid) {
				t.Errorf("QB01 invalid page decoded: %v", err)
			}
			after, _ := json.Marshal(out)
			if !bytes.Equal(before, after) {
				t.Error("QB01 failed decode changed destination")
			}
		})
	}
	// State and page must enforce the same loss contract, without requiring known totals.
	for _, tc := range mutations {
		if tc.name == "unclosed_continuity" {
			continue
		}
		t.Run("state_"+tc.name, func(t *testing.T) {
			p := qb01Page()
			tc.change(&p)
			s := State{Header: p.Header, Revision: "1", HighWaterSeq: "0", CommittedDataBytes: "0", CommittedIndexBytes: "0", Collection: Recording, ProvenanceStatus: ProvenanceUnknown, Timestamp: p.Timestamp, LostTotal: p.Coverage.LostTotal, LossReasons: p.Coverage.LossReasons, CounterSaturated: p.Coverage.CounterSaturated}
			if err := Validate(s); !errors.Is(err, ErrInvalid) {
				t.Errorf("QB01 invalid state accepted: %v", err)
			}
			if b, err := EncodeBounded(s, MaxStateBytes); !errors.Is(err, ErrInvalid) || b != nil {
				t.Errorf("QB01 invalid state encoded: %v", err)
			}
			raw, _ := json.Marshal(s)
			out := s
			out.Revision = "99"
			before, _ := json.Marshal(out)
			if err := DecodeStrict(raw, &out, MaxStateBytes); !errors.Is(err, ErrInvalid) {
				t.Errorf("QB01 invalid state decoded: %v", err)
			}
			after, _ := json.Marshal(out)
			if !bytes.Equal(before, after) {
				t.Error("QB01 state destination changed")
			}
		})
	}
}

func TestQB01LegalUnknownAndClosed(t *testing.T) {
	for _, name := range []string{"unknown", "zero", "known_loss_unknown_total", "known_total_unknown_reasons", "saturated_gap", "closed", "closed_unknown_continuity"} {
		t.Run(name, func(t *testing.T) {
			p := qb01Page()
			switch name {
			case "zero":
				p.Coverage.LostTotal = ptr(Decimal("0"))
				p.Coverage.LossReasons.QueueFull = ptr(Decimal("0"))
			case "known_loss_unknown_total":
				p.Coverage.Gap = true
				p.Coverage.LossReasons.QueueFull = ptr(Decimal("1"))
			case "known_total_unknown_reasons":
				p.Coverage.Gap = true
				p.Coverage.LostTotal = ptr(Decimal("5"))
			case "saturated_gap":
				p.Coverage.Gap = true
				p.Coverage.CounterSaturated = true
			case "closed":
				p.Collection = Closed
				p.Closed = true
				p.Coverage.Continuity = ContinuityClosed
			case "closed_unknown_continuity":
				p.Collection = Closed
				p.Closed = true
			}
			if err := Validate(p); err != nil {
				t.Fatal(err)
			}
			raw, err := EncodeBounded(p, MaxResponseBytes)
			if err != nil {
				t.Fatal(err)
			}
			var got PageResponse
			if err := DecodeStrict(raw, &got, MaxResponseBytes); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(p, got) {
				t.Fatal("positive changed nullable values")
			}
			if name == "unknown" && (!bytes.Contains(raw, []byte(`"lost_total":null`)) || !bytes.Contains(raw, []byte(`"queue_full":null`)) || got.Pending != nil) {
				t.Fatal("UNKNOWN defaulted to zero")
			}
		})
	}
}
