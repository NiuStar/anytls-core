package connectionrecords

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

// This exact file runs on the prior candidate and the amended reader/codec.
// Persisted state compatibility is distinct from public completion authority.
func TestConservativeTerminalProjection(t *testing.T) {
	h := fixtureHeader()
	at, err := time.Parse(time.RFC3339Nano, h.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, collection := range []Collection{Recording, Closing, Closed, IOFailed, InitFailed, WorkerFailed, IDExhausted} {
		t.Run(string(collection), func(t *testing.T) {
			s := State{Header: h, Revision: "1", HighWaterSeq: "0", CommittedDataBytes: "0", CommittedIndexBytes: "0", Collection: collection, ProvenanceStatus: ProvenanceVerified, Timestamp: h.CreatedAt, Closed: collection == Closed, Pending: ptr(Decimal("0")), LostTotal: ptr(Decimal("0")), LossEpoch: ptr(Decimal("0")), LossReasons: LossReasons{QueueFull: ptr(Decimal("0"))}}
			// Old clean CLOSED remains readable on disk, including its known zeros.
			raw, err := EncodeBounded(s, MaxStateBytes)
			if err != nil {
				t.Fatal(err)
			}
			var stored State
			if err := DecodeStrict(raw, &stored, MaxStateBytes); err != nil || !reflect.DeepEqual(s, stored) {
				t.Fatalf("disk state compatibility: %v", err)
			}
			for _, now := range []time.Time{at, at.Add(24 * time.Hour)} {
				p := pageFromState(stored, h.InstanceID, 0, now)
				if p.Coverage.Continuity != ContinuityUnknown {
					t.Error("conservative continuity must always be UNKNOWN")
				}
				if collection == Closed {
					if !p.Closed || p.Collection != Closed || p.Freshness != FreshnessUnknown || !p.Coverage.Gap || p.Pending != nil || p.Coverage.LostTotal != nil || p.Coverage.LossEpoch != nil || p.Coverage.LossReasons != (LossReasons{}) || !reflect.DeepEqual(p.Header, s.Header) || p.ProvenanceStatus != s.ProvenanceStatus {
						t.Errorf("conservative CLOSED projection violated: %+v", p)
					}
				}
				if err := Validate(p); err != nil {
					t.Fatalf("projected page invalid: %v", err)
				}
			}
		})
	}
}

func TestConservativeTerminalValidation(t *testing.T) {
	base := qb01Page()
	base.Collection, base.Closed = Closed, true
	base.Freshness, base.Coverage.Gap = FreshnessUnknown, true
	for _, name := range []string{"closed-continuity", "active-continuity", "fresh", "stale", "no-gap", "pending", "loss-total", "loss-epoch", "loss-reason"} {
		t.Run(name, func(t *testing.T) {
			p := base
			switch name {
			case "closed-continuity":
				p.Coverage.Continuity = ContinuityClosed
			case "active-continuity":
				p.Collection, p.Closed, p.Freshness = Recording, false, Fresh
				p.Coverage.Continuity = ContinuityClosed
			case "fresh":
				p.Freshness = Fresh
			case "stale":
				p.Freshness = Stale
			case "no-gap":
				p.Coverage.Gap = false
			case "pending":
				p.Pending = ptr(Decimal("0"))
			case "loss-total":
				p.Coverage.LostTotal = ptr(Decimal("0"))
			case "loss-epoch":
				p.Coverage.LossEpoch = ptr(Decimal("0"))
			case "loss-reason":
				p.Coverage.LossReasons.QueueFull = ptr(Decimal("0"))
			}
			if !errors.Is(Validate(p), ErrInvalid) {
				t.Error("conservative inconsistent public page accepted")
			}
			if b, err := EncodeBounded(p, MaxResponseBytes); b != nil || !errors.Is(err, ErrInvalid) {
				t.Error("conservative inconsistent public page encoded")
			}
			raw, _ := json.Marshal(p)
			out := base
			before, _ := json.Marshal(out)
			if !errors.Is(DecodeStrict(raw, &out, MaxResponseBytes), ErrInvalid) {
				t.Error("conservative inconsistent public page decoded")
			}
			after, _ := json.Marshal(out)
			if !bytes.Equal(before, after) {
				t.Error("failed decode mutated destination")
			}
		})
	}
	if err := Validate(base); err != nil {
		t.Fatalf("legal conservative CLOSED rejected: %v", err)
	}
}
