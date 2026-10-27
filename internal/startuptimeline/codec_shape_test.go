package startuptimeline

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestRecursiveExactShape(t *testing.T) {
	id := strings.Repeat("a", 32)
	sha := strings.Repeat("b", 64)
	s := testRecorder(t, "HELPER")
	s.Observe("START", "HELPER_ACCEPT", "OK", Fields{})
	s.Finish("SUCCEEDED")
	tr := Trace{Authority: Authority, OperationID: id, HelperEpoch: &id, ConfigIdentity: &sha, Operation: "START", Source: "MANUAL_START", StartedAt: "2026-01-01T00:00:00Z", FinishedAt: ptr("2026-01-01T00:00:01Z"), State: "FINISHED", LifecycleResult: "SUCCEEDED", HelperReturn: "SUCCEEDED", WebReturn: "SUCCEEDED", ReceiptResult: "WRITTEN", Streams: []ProcessStream{s.Snapshot()}, CoreObservation: CoreObservation{Availability: "NOT_OBSERVED", Gap: true}, Gap: true}
	valid := ReadResponse{1, "OK", &id, &sha, &id, &tr}
	raw, err := Encode(valid)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if json.Unmarshal(raw, &obj) != nil {
		t.Fatal("fixture")
	}
	visited := 0
	var walk func(map[string]any, string)
	walk = func(m map[string]any, path string) {
		for k, v := range m {
			visited++
			old := m[k]
			delete(m, k)
			bad, _ := json.Marshal(obj)
			var dst ReadResponse
			if Decode(strings.NewReader(string(bad)), &dst) == nil {
				t.Fatalf("missing field accepted: %s/%s", path, k)
			}
			m[k] = old
			if v != nil {
				m[k] = map[string]any{"PRIVATE": true}
				bad, _ = json.Marshal(obj)
				if Decode(strings.NewReader(string(bad)), &dst) == nil {
					t.Fatalf("wrong type accepted: %s/%s", path, k)
				}
				m[k] = old
			}
			switch x := v.(type) {
			case map[string]any:
				walk(x, path+"/"+k)
			case []any:
				for i, a := range x {
					if mm, ok := a.(map[string]any); ok {
						walk(mm, fmt.Sprintf("%s/%s/%d", path, k, i))
					}
				}
			}
		}
	}
	walk(obj, "")
	t.Logf("checked %d exact fields recursively", visited)
	// Cross-stream identity and lifecycle gap must not be silently repaired.
	valid.OperationID = ptr(strings.Repeat("c", 32))
	if Validate(valid) == nil {
		t.Fatal("binding mismatch accepted")
	}
}
func TestRandomUnavailableRecorder(t *testing.T) {
	r, e := newRecorder("CORE", unknownProvenance(), time.Now(), strings.NewReader("short"), nil)
	if r != nil || e != Unavailable {
		t.Fatal("random failure invented identity")
	}
}
