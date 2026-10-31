package dnsmetrics

import (
	"encoding/json"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestAllFixedCategories(t *testing.T) {
	for q := A; q < QTypeCount; q++ {
		for o := NoError; o < OutcomeCount; o++ {
			var s Store
			s.Observe(UpstreamAttempt, q, o, 0)
			c := s.Snapshot().Layers[UpstreamAttempt]
			if c.QTypes[q] != 1 || c.Outcomes[o] != 1 {
				t.Fatalf("q=%d outcome=%d: %+v", q, o, c)
			}
		}
	}
	for _, unknown := range []uint8{uint8(OutcomeCount), 127, 255} {
		var s Store
		s.Observe(Kind(unknown), QType(unknown), Outcome(unknown), -1)
		if c := s.Snapshot().Layers[OtherKind]; c.Total != 1 || c.Outcomes[OtherError] != 1 || c.QTypes[OtherQType] != 1 {
			t.Fatalf("unknown=%d: %+v", unknown, c)
		}
	}
}

func assertConsistent(t *testing.T, snap Snapshot) {
	t.Helper()
	for _, c := range snap.Layers {
		var q, o, d uint64
		for _, n := range c.QTypes {
			q += n
		}
		for _, n := range c.Outcomes {
			o += n
		}
		for _, n := range c.DurationBuckets {
			d += n
		}
		if q != c.Total || o != c.Total || d != c.Total {
			t.Fatalf("inconsistent snapshot: %+v", c)
		}
	}
}

func TestConcurrentSnapshotsRemainConsistentAndIndependent(t *testing.T) {
	var s Store
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				s.Observe(UpstreamAttempt, A, NoError, time.Duration(i))
			}
		}()
	}
	for i := 0; i < 2000; i++ {
		assertConsistent(t, s.Snapshot())
	}
	wg.Wait()
	got := s.Snapshot()
	assertConsistent(t, got)
	if got.Layers[UpstreamAttempt].Total != 8000 {
		t.Fatalf("lost observations: %+v", got)
	}
	got.Layers[UpstreamAttempt].Total = 0
	got.DurationUpperBounds[0] = -1
	if fresh := s.Snapshot(); fresh.Layers[UpstreamAttempt].Total != 8000 || fresh.DurationUpperBounds[0] != time.Millisecond {
		t.Fatal("snapshot aliases store or schema")
	}
}

func TestPublicSchemaCannotCarryNamesOrRawErrors(t *testing.T) {
	var check func(reflect.Type)
	check = func(typ reflect.Type) {
		switch typ.Kind() {
		case reflect.Struct:
			for i := 0; i < typ.NumField(); i++ {
				check(typ.Field(i).Type)
			}
		case reflect.Array:
			check(typ.Elem())
		case reflect.Uint64, reflect.Int64:
		default:
			t.Fatalf("non-numeric or variable-size public schema: %v", typ)
		}
	}
	check(reflect.TypeOf(Snapshot{}))
	method := reflect.TypeOf((*Store).Observe)
	if method.NumIn() != 5 || method.NumOut() != 0 {
		t.Fatalf("unexpected observation API: %v", method)
	}
	for i, want := range []reflect.Type{reflect.TypeOf((*Store)(nil)), reflect.TypeOf(Kind(0)), reflect.TypeOf(QType(0)), reflect.TypeOf(Outcome(0)), reflect.TypeOf(time.Duration(0))} {
		if method.In(i) != want {
			t.Fatalf("Observe argument %d can carry unexpected data: %v", i, method.In(i))
		}
	}
	var s Store
	data, err := json.Marshal(s.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var got Snapshot
	if err := json.Unmarshal(data, &got); err != nil || got != s.Snapshot() {
		t.Fatalf("JSON schema round-trip: %s, %v", data, err)
	}
}

func TestObserveAllocatesNothing(t *testing.T) {
	var s Store
	if n := testing.AllocsPerRun(1000, func() { s.Observe(UpstreamAttempt, A, NoError, time.Millisecond) }); n != 0 {
		t.Fatalf("Observe allocs=%v", n)
	}
	var disabled *Store
	if n := testing.AllocsPerRun(1000, func() { disabled.Observe(UpstreamAttempt, A, NoError, 0) }); n != 0 {
		t.Fatalf("disabled Observe allocs=%v", n)
	}
}

func TestCompletedEventsStayInTheirLayer(t *testing.T) {
	var s Store
	s.Observe(UpstreamAttempt, A, NoError, 3*time.Millisecond)
	s.Observe(QueryCompleted, AAAA, NXDomain, 7*time.Millisecond)
	got := s.Snapshot()
	for _, tc := range []struct {
		kind    Kind
		qtype   QType
		outcome Outcome
		elapsed time.Duration
	}{
		{UpstreamAttempt, A, NoError, 3 * time.Millisecond},
		{QueryCompleted, AAAA, NXDomain, 7 * time.Millisecond},
	} {
		c := got.Layers[tc.kind]
		if c.Total != 1 || c.QTypes[tc.qtype] != 1 || c.Outcomes[tc.outcome] != 1 || c.MaxDuration != tc.elapsed {
			t.Fatalf("layer %d: completed event lost or mixed: %+v", tc.kind, c)
		}
	}
	if got.Layers[OtherKind].Total != 0 {
		t.Fatal("known layers leaked into OtherKind")
	}
}

func TestNilStoreDisablesObservations(t *testing.T) {
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("disabled store must be a no-op: %v", p)
		}
	}()
	var s *Store
	s.Observe(UpstreamAttempt, A, NoError, time.Second)
	got := s.Snapshot()
	if got.Layers != [KindCount]Counters{} {
		t.Fatalf("disabled store has data: %+v", got)
	}
}

func TestUnknownEnumsFallBackToOther(t *testing.T) {
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("unknown enums must aggregate into Other, not panic: %v", p)
		}
	}()
	var s Store
	s.Observe(Kind(255), QType(255), Outcome(255), -time.Second)
	c := s.Snapshot().Layers[OtherKind]
	if c.Total != 1 || c.QTypes[OtherQType] != 1 || c.Outcomes[OtherError] != 1 || c.DurationBuckets[0] != 1 || c.MaxDuration != 0 {
		t.Fatalf("unknown enums / negative duration: %+v", c)
	}
}

func TestDurationBucketsAreDisjointAndInclusive(t *testing.T) {
	bounds := [DurationBucketCount - 1]time.Duration{time.Millisecond, 5 * time.Millisecond, 10 * time.Millisecond, 25 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond, time.Second}
	var s Store
	for _, elapsed := range append(bounds[:], time.Hour) {
		s.Observe(UpstreamAttempt, A, NoError, elapsed)
	}
	got := s.Snapshot()
	if got.DurationUpperBounds != bounds {
		t.Fatalf("bucket schema: %v", got.DurationUpperBounds)
	}
	for i, n := range got.Layers[UpstreamAttempt].DurationBuckets {
		if n != 1 {
			t.Fatalf("bucket %d count = %d, want 1", i, n)
		}
	}
	for i, bound := range bounds {
		var next Store
		next.Observe(QueryCompleted, A, NoError, bound+1)
		if next.Snapshot().Layers[QueryCompleted].DurationBuckets[i+1] != 1 {
			t.Fatalf("bound %v+1ns did not enter next bucket", bound)
		}
	}
}
