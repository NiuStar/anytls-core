package connectionrecords

import (
	"bytes"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

// Frozen pre-cleanup implementations; differential oracles, not production helpers.
func oldManifestBudget(m *Manifest) int {
	max := int(^uint(0) >> 1)
	total := 1024
	var walk func(reflect.Value) bool
	walk = func(v reflect.Value) bool {
		if !v.IsValid() {
			return true
		}
		if total > max-512 {
			return false
		}
		total += 512
		switch v.Kind() {
		case reflect.Pointer:
			if !v.IsNil() {
				return walk(v.Elem())
			}
		case reflect.String:
			if v.Len() > (max-total)/6 {
				return false
			}
			total += 6 * v.Len()
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if !walk(v.Field(i)) {
					return false
				}
			}
		case reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				if !walk(v.Index(i)) {
					return false
				}
			}
		}
		return true
	}
	if !walk(reflect.ValueOf(m)) {
		return 0
	}
	return total
}

func oldValidHost(s string) bool {
	if len(s) == 0 || len(s) > 253 || strings.ContainsAny(s, "/:?#@\\ \t\r\n") {
		return false
	}
	s = strings.TrimSuffix(s, ".")
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

func TestManifestBudgetEquivalent(t *testing.T) {
	text := "\x01\t\n\"\\汉字🙂"
	digest := strings.Repeat("a", 64)
	m := &Manifest{SchemaVersion: 1, Binding: fixtureBinding(), SelectionGeneration: fixtureBinding().Generation, RuntimeSHA256: digest,
		CapturedSources: []CapturedSource{{SourceConfig, 0, true, &digest}, {SourceSelection, 0, false, nil}},
		Rules:           []RuleOrigin{}, FinalOrigin: RouteProjection{Evidence: ProvenanceUnknown, Kind: RuleUnknown, TerminalKind: TerminalUnknown, OutboundTag: text},
		Outbounds: []OutboundOrigin{{Tag: text, Type: "direct", TerminalKind: TerminalDirect}}}
	for _, candidate := range []*Manifest{nil, {}, {Rules: []RuleOrigin{}, Outbounds: []OutboundOrigin{}, CapturedSources: []CapturedSource{}}, m} {
		if got, want := ManifestBudget(candidate), oldManifestBudget(candidate); got != want {
			t.Fatalf("budget %d != %d", got, want)
		}
	}
	for _, n := range []int{0, 1, 7, 257} {
		m.Outbounds = make([]OutboundOrigin, n)
		for i := range m.Outbounds {
			m.Outbounds[i] = OutboundOrigin{Tag: text, Type: "direct", TerminalKind: TerminalDirect}
		}
		budget := ManifestBudget(m)
		if budget != oldManifestBudget(m) {
			t.Fatal("slice budget differs")
		}
		got, e := EncodeBounded(*m, budget)
		want, w := EncodeBounded(*m, oldManifestBudget(m))
		// Duplicate tags are intentionally rejected by both strict paths.
		if (e == nil) != (w == nil) || !bytes.Equal(got, want) {
			t.Fatal("encoding differs")
		}
		if n <= 1 && e != nil {
			t.Fatal(e)
		}
		if e == nil {
			var decoded Manifest
			if e = DecodeStrict(got, &decoded, budget); e != nil {
				t.Fatal(e)
			}
		}
	}
}

func TestValidHostDifferential(t *testing.T) {
	check := func(s string) {
		t.Helper()
		if got, want := ValidHost(s), oldValidHost(s); got != want {
			t.Fatalf("host %q: %v != %v", s, got, want)
		}
	}
	check("")
	for a := 0; a < 256; a++ {
		check(string([]byte{byte(a)}))
		for b := 0; b < 256; b++ {
			check(string([]byte{byte(a), byte(b)}))
		}
	}
	alphabet := []byte("aZ0_-.\x00/:?#@\\ \t\r\n\xff")
	var walk func([]byte, int)
	walk = func(s []byte, n int) {
		check(string(s))
		if n == 0 {
			return
		}
		for _, c := range alphabet {
			walk(append(s, c), n-1)
		}
	}
	walk(nil, 3)
	rng := rand.New(rand.NewSource(218901))
	for i := 0; i < 20000; i++ {
		b := make([]byte, rng.Intn(270))
		for j := range b {
			if i%2 == 0 {
				b[j] = alphabet[rng.Intn(len(alphabet))]
			} else {
				b[j] = byte(rng.Intn(256))
			}
		}
		check(string(b))
	}
	for _, n := range []int{1, 62, 63, 64, 252, 253, 254, 255} {
		s := strings.Repeat("a", n)
		check(s)
		check(s + ".")
		check(s + ".b")
		check("-" + s)
		check(s + "-")
	}
	for _, s := range []string{"_", "a_b", "a-b", "a..b", "a.", "a..", "汉字", "é", "🙂", strings.Repeat("a.", 126) + "a", strings.Repeat("a.", 127) + "a"} {
		check(s)
	}
	// Mutate every byte position of valid maximum-length and label-boundary names.
	for _, s := range []string{"example.com.", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)} {
		for i := range s {
			for c := 0; c < 256; c++ {
				b := []byte(s)
				b[i] = byte(c)
				check(string(b))
			}
		}
	}
}

func TestValidHostNoAlloc(t *testing.T) {
	for _, s := range []string{"example.com.", "a_b.example", "bad/host", strings.Repeat("a.", 126) + "a"} {
		if n := testing.AllocsPerRun(1000, func() { _ = ValidHost(s) }); n != 0 {
			t.Fatalf("host %q: %g allocations", s, n)
		}
	}
}
