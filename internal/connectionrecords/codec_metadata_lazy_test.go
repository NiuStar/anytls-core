package connectionrecords

import (
	"reflect"
	"testing"
)

// The prior eager-map candidate added two allocations to one-off DTOs. Keep
// singleton operations on the original field-discovery path until a repeated
// struct collection justifies a cache. This does not cap input size.
func TestCodecMetadataLazyAdmission(t *testing.T) {
	for _, value := range []any{fixtureRecord(), State{Header: fixtureHeader(), Revision: "1", HighWaterSeq: "0", CommittedDataBytes: "0", CommittedIndexBytes: "0", Collection: Recording, ProvenanceStatus: ProvenanceUnknown, Timestamp: fixtureHeader().CreatedAt}} {
		encoder := boundedEncoder{limit: MaxRecordBytes}
		if err := encoder.value(reflect.ValueOf(value), 0); err != nil {
			t.Fatal(err)
		}
		if encoder.metadata != nil {
			t.Fatalf("one-off %T allocated schema cache", value)
		}
	}
	repeated := metadataFixture(3)
	encoder := boundedEncoder{limit: ManifestBudget(&repeated)}
	if err := encoder.value(reflect.ValueOf(repeated), 0); err != nil {
		t.Fatal(err)
	}
	if len(encoder.metadata) == 0 {
		t.Fatal("repeated struct collection did not reuse schema")
	}
}

func TestCodecMetadataRecordAllocationParity(t *testing.T) {
	record := fixtureRecord()
	wire, err := metadataOldEncodeBounded(record, MaxRecordBytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"encode", "decode"} {
		run := func(old bool) float64 {
			return testing.AllocsPerRun(100, func() {
				if op == "encode" {
					var err error
					if old {
						_, err = metadataOldEncodeBounded(record, MaxRecordBytes)
					} else {
						_, err = EncodeBounded(record, MaxRecordBytes)
					}
					if err != nil {
						panic(err)
					}
				} else {
					var out Record
					var err error
					if old {
						err = metadataOldDecodeStrict(wire, &out, MaxRecordBytes)
					} else {
						err = DecodeStrict(wire, &out, MaxRecordBytes)
					}
					if err != nil {
						panic(err)
					}
				}
			})
		}
		old, new := run(true), run(false)
		if new > old {
			t.Fatalf("single Record %s allocations %.0f exceed uncached %.0f", op, new, old)
		}
	}
}
