package dnsevidence

import "testing"

func TestSnapshotContinuityShape(t *testing.T) {
	c := New(testBinding())
	c.Loaded()
	e := Event{TransportID: "1", QType: "A", Outcome: "NOERROR", Validation: "MATCHED", DurationNS: "1", Connections: Connections{Acquisitions: "0", New: "0", Reused: "0", Idle: "0"}}
	c.Complete(e)
	c.Complete(e)
	s := c.Snapshot()
	for _, mode := range []string{"lost_prefix", "internal_jump", "hidden_dropped", "saturation_without_gap"} {
		t.Run(mode, func(t *testing.T) {
			next := Clone(s)
			switch mode {
			case "lost_prefix":
				next.Events = next.Events[1:]
			case "internal_jump":
				next.Events[1].Seq = "3"
			case "hidden_dropped":
				next.Coverage.Dropped = "1"
			case "saturation_without_gap":
				next.Coverage.Saturated = true
			}
			if Validate(next) == nil {
				t.Fatal("invalid continuity shape", mode)
			}
		})
	}
	// Invalid completion consumes a sequence but marks GAP; this is distinct
	// from ring eviction, so don't invent dropped counts or demand contiguous
	// sequence numbers when GAP is explicitly present.
	c.Complete(Event{})
	c.Complete(e)
	if s := c.Snapshot(); Validate(s) != nil || !s.Coverage.Gap {
		t.Fatal("honest invalid-event gap rejected")
	}
}
