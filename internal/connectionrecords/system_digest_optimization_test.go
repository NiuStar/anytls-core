package connectionrecords

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/rand"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// systemOriginalManifestDigest is the ManifestDigest body from codec.go at
// f3c3979df6b503efd5c68d4d7775d60874b362ec, with only its name changed.
// Keep this independent of candidate digest/encoding helpers: in particular,
// EncodeBounded(view, budget) must retain its original validation and encoding.
func systemOriginalManifestDigest(m Manifest, budget int) (string, error) {
	m.ManifestID = strings.Repeat("0", 64)
	if err := Validate(m); err != nil {
		return "", err
	}
	view := struct {
		SchemaVersion       int              `json:"schema_version"`
		InstanceID          string           `json:"instance_id"`
		Generation          string           `json:"generation"`
		SelectionGeneration string           `json:"selection_generation"`
		RuntimeSHA256       string           `json:"runtime_sha256"`
		CapturedSources     []CapturedSource `json:"captured_sources"`
		Rules               []RuleOrigin     `json:"rules"`
		FinalOrigin         RouteProjection  `json:"final_origin"`
		Outbounds           []OutboundOrigin `json:"outbounds"`
	}{m.SchemaVersion, m.InstanceID, m.Generation, m.SelectionGeneration, m.RuntimeSHA256, m.CapturedSources, m.Rules, m.FinalOrigin, m.Outbounds}
	b, err := EncodeBounded(view, budget)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// This separately declared fixed view witnesses the actual bounded canonical
// bytes, not encoding/json's different HTML/U+2028/U+2029 escaping policy.
func systemDigestCanonicalBytes(m Manifest, budget int) ([]byte, error) {
	view := struct {
		SchemaVersion       int              `json:"schema_version"`
		InstanceID          string           `json:"instance_id"`
		Generation          string           `json:"generation"`
		SelectionGeneration string           `json:"selection_generation"`
		RuntimeSHA256       string           `json:"runtime_sha256"`
		CapturedSources     []CapturedSource `json:"captured_sources"`
		Rules               []RuleOrigin     `json:"rules"`
		FinalOrigin         RouteProjection  `json:"final_origin"`
		Outbounds           []OutboundOrigin `json:"outbounds"`
	}{m.SchemaVersion, m.InstanceID, m.Generation, m.SelectionGeneration, m.RuntimeSHA256, m.CapturedSources, m.Rules, m.FinalOrigin, m.Outbounds}
	return EncodeBounded(view, budget)
}

// Adapted from TestManifestDigestExcludesSelfAndBindsSources in types_test.go.
func systemDigestFixture() Manifest {
	b := fixtureBinding()
	digest := strings.Repeat("e", 64)
	final := RouteProjection{Evidence: ProvenanceVerified, Kind: RuleDefault, ConfiguredTarget: ptr("DIRECT"), GroupPath: []GroupEdge{}, TerminalKind: TerminalDirect, OutboundTag: "direct", OutboundType: "direct", SelectionGeneration: &b.Generation}
	return Manifest{SchemaVersion: 1, Binding: b, SelectionGeneration: b.Generation, RuntimeSHA256: digest, CapturedSources: []CapturedSource{{SourceConfig, 0, true, &digest}, {SourceSelection, 0, false, nil}}, Rules: []RuleOrigin{}, FinalOrigin: final, Outbounds: []OutboundOrigin{{Tag: "direct", Type: "direct", TerminalKind: TerminalDirect}}}
}

func systemDigestMixedFixture() Manifest {
	m := systemDigestFixture()
	digest := strings.Repeat("d", 64)
	m.CapturedSources = append(m.CapturedSources, CapturedSource{SourceRuleSet, 0, true, &digest}, CapturedSource{SourceCA, 0, true, &digest}, CapturedSource{SourceCA, 1, true, &digest})
	nodeID := m.Generation + ":node:7"
	m.Outbounds = append(m.Outbounds, OutboundOrigin{Tag: "node-7", Type: "anytls", TerminalKind: TerminalNode, NodeID: &nodeID, NodeLabel: ptr("节点😀")})
	for i, kind := range []RuleKind{RuleDomain, RuleDomainSuffix, RuleIPCIDR, RuleGeoIP, RuleSet, RuleMatch} {
		route := RouteProjection{Evidence: ProvenanceVerified, SourceID: ptr(m.Generation + ":rule:" + strconv.Itoa(i)), SourceIndex: ptr(i), Kind: kind, ConfiguredTarget: ptr("group"), GroupPath: []GroupEdge{{Group: "group", Selected: "节点😀"}}, TerminalKind: TerminalNode, FinalNodeID: &nodeID, FinalNodeLabel: ptr("节点😀"), OutboundTag: "node-7", OutboundType: "anytls", SelectionGeneration: ptr(m.Generation)}
		switch kind {
		case RuleDomain, RuleDomainSuffix:
			route.Condition = &Condition{Kind: kind, Value: "example.com"}
		case RuleIPCIDR:
			route.Condition = &Condition{Kind: kind, Value: "192.0.2.0/24"}
		case RuleGeoIP:
			route.Condition = &Condition{Kind: kind, Value: "CN"}
		case RuleSet:
			route.Condition = &Condition{Kind: kind, Value: "rules"}
			route.RuleSet = &RuleSetProjection{Label: "rules", SHA256: digest}
		}
		m.Rules = append(m.Rules, RuleOrigin{Type: "field", ActionType: "route", ExpectedOutbound: "node-7", Synthetic: SyntheticNone, Route: route})
	}
	for _, synthetic := range []SyntheticKind{SyntheticSniff, SyntheticResolve, SyntheticHijack} {
		m.Rules = append(m.Rules, RuleOrigin{Type: "field", ActionType: "synthetic", Synthetic: synthetic, Route: RouteProjection{Evidence: ProvenanceUnknown, Kind: RuleUnknown, TerminalKind: TerminalUnknown}})
	}
	return m
}

// Clone typed values recursively, retaining nil versus empty and arbitrary bad
// strings. A JSON round trip would silently repair invalid UTF-8 in negatives.
func systemDigestCloneValue(v reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		x := reflect.New(v.Type().Elem())
		x.Elem().Set(systemDigestCloneValue(v.Elem()))
		return x
	case reflect.Slice:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		x := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			x.Index(i).Set(systemDigestCloneValue(v.Index(i)))
		}
		return x
	case reflect.Struct:
		x := reflect.New(v.Type()).Elem()
		for i := 0; i < v.NumField(); i++ {
			x.Field(i).Set(systemDigestCloneValue(v.Field(i)))
		}
		return x
	default:
		return v
	}
}

func systemDigestClone(m Manifest) Manifest {
	return systemDigestCloneValue(reflect.ValueOf(m)).Interface().(Manifest)
}

func systemDigestCompare(t *testing.T, m Manifest, budget int, wantErr error) string {
	t.Helper()
	before := systemDigestClone(m)
	want, oldErr := systemOriginalManifestDigest(m, budget)
	if !reflect.DeepEqual(m, before) {
		t.Fatal("original digest mutated caller-owned input")
	}
	got, gotErr := ManifestDigest(m, budget)
	if !reflect.DeepEqual(m, before) {
		t.Fatal("digest mutated caller-owned input")
	}
	if got != want || gotErr != oldErr {
		t.Fatalf("budget=%d: digest/error differs: candidate=%q,%v original=%q,%v", budget, got, gotErr, want, oldErr)
	}
	for _, sentinel := range []error{ErrInvalid, ErrTooLarge} {
		if errors.Is(gotErr, sentinel) != errors.Is(oldErr, sentinel) {
			t.Fatalf("budget=%d: sentinel identity differs for %v", budget, sentinel)
		}
	}
	if gotErr != wantErr {
		t.Fatalf("budget=%d: expected error %v, got %v", budget, wantErr, gotErr)
	}
	if gotErr != nil && got != "" {
		t.Fatal("failed digest returned partial output")
	}
	if gotErr == nil && len(got) != 64 {
		t.Fatalf("digest length=%d, want 64", len(got))
	}
	return got
}

func systemDigestCheckValid(t *testing.T, m Manifest) string {
	t.Helper()
	// A positive fixture must be accepted by the frozen old function first.
	if _, err := systemOriginalManifestDigest(m, MaxResponseBytes); err != nil {
		t.Fatalf("invalid positive fixture: %v", err)
	}
	canonical, err := systemDigestCanonicalBytes(m, MaxResponseBytes)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	want := hex.EncodeToString(sum[:])
	for _, budget := range []int{len(canonical), len(canonical) - 1, 1, 0, -1} {
		var wantErr error
		if budget < len(canonical) {
			wantErr = ErrTooLarge
		}
		got := systemDigestCompare(t, m, budget, wantErr)
		encoded, encodeErr := systemDigestCanonicalBytes(m, budget)
		if encodeErr != wantErr || wantErr != nil && encoded != nil {
			t.Fatalf("budget=%d: canonical encoding error/partial bytes: %v", budget, encodeErr)
		}
		if wantErr == nil && (!bytes.Equal(encoded, canonical) || got != want) {
			t.Fatal("canonical bytes/hash changed at exact budget")
		}
	}
	return want
}

func TestSystemManifestDigestCanonicalAndEquivalent(t *testing.T) {
	m := systemDigestFixture()
	canonical, err := systemDigestCanonicalBytes(m, MaxResponseBytes)
	if err != nil {
		t.Fatal(err)
	}
	// Literal independently locks every baseline field, order and explicit null.
	want := `{"schema_version":1,"instance_id":"` + m.InstanceID + `","generation":"` + m.Generation + `","selection_generation":"` + m.SelectionGeneration + `","runtime_sha256":"` + m.RuntimeSHA256 + `","captured_sources":[{"kind":"CONFIG","ordinal":0,"present":true,"sha256":"` + m.RuntimeSHA256 + `"},{"kind":"SELECTION","ordinal":0,"present":false,"sha256":null}],"rules":[],"final_origin":{"evidence":"VERIFIED","source_id":null,"source_index":null,"kind":"DEFAULT_SELECTED","condition":null,"rule_set":null,"configured_target":"DIRECT","group_path":[],"terminal_kind":"DIRECT","final_node_id":null,"final_node_label":null,"outbound_tag":"direct","outbound_type":"direct","selection_generation":"` + m.Generation + `"},"outbounds":[{"tag":"direct","type":"direct","terminal_kind":"DIRECT","node_id":null,"node_label":null}]}`
	if string(canonical) != want {
		t.Fatal("baseline fixed-order canonical bytes changed")
	}
	t.Run("empty", func(t *testing.T) { systemDigestCheckValid(t, m) })
	t.Run("empty-outbounds", func(t *testing.T) {
		x := systemDigestFixture()
		x.Outbounds = []OutboundOrigin{}
		systemDigestCheckValid(t, x)
	})
	t.Run("mixed-origins", func(t *testing.T) { systemDigestCheckValid(t, systemDigestMixedFixture()) })
	t.Run("escaped-labels", func(t *testing.T) {
		x := systemDigestMixedFixture()
		label := "中文😀\"\\\b\f\n\r\t\x01\x1f<> &\u2028\u2029"
		x.Rules[0].Route.FinalNodeLabel = &label
		x.Rules[0].Route.GroupPath[0] = GroupEdge{Group: label, Selected: label}
		x.Rules[4].Route.RuleSet.Label = label
		x.Rules[4].Route.Condition.Value = label
		x.Outbounds[1].NodeLabel = &label
		systemDigestCheckValid(t, x)
		raw, err := systemDigestCanonicalBytes(x, MaxResponseBytes)
		if err != nil || !bytes.Contains(raw, []byte(`\"\\\b\f\n\r\t\u0001\u001f<> &`+"\u2028\u2029")) {
			t.Fatalf("bounded encoder escaping contract changed: %v", err)
		}
	})
}

func TestSystemManifestDigestSelfAndSourceBinding(t *testing.T) {
	m := systemDigestMixedFixture()
	base := systemDigestCheckValid(t, m)
	for _, self := range []string{"", "short", "not-hex", strings.Repeat("f", 64), "\x00", string([]byte{255})} {
		x := systemDigestClone(m)
		x.ManifestID = self
		if got := systemDigestCheckValid(t, x); got != base {
			t.Fatal("digest includes ignored self field")
		}
	}
	for i := range m.CapturedSources {
		x := systemDigestClone(m)
		x.CapturedSources[i].Present = true
		// SHA256(empty) is a present empty file, never an absent selection.
		empty := sha256.Sum256(nil)
		x.CapturedSources[i].SHA256 = ptr(hex.EncodeToString(empty[:]))
		if got := systemDigestCheckValid(t, x); got == base {
			t.Fatalf("source %d change not bound", i)
		}
	}
	x := systemDigestClone(m)
	x.RuntimeSHA256 = strings.Repeat("a", 64)
	if systemDigestCheckValid(t, x) == base {
		t.Fatal("runtime SHA change not bound")
	}
	x = systemDigestClone(m)
	x.CapturedSources[3], x.CapturedSources[4] = x.CapturedSources[4], x.CapturedSources[3]
	if systemDigestCheckValid(t, x) == base {
		t.Fatal("ordered duplicate-SHA CA captures lost")
	}
	x = systemDigestClone(m)
	x.Rules[0], x.Rules[1] = x.Rules[1], x.Rules[0]
	if systemDigestCheckValid(t, x) == base {
		t.Fatal("compiler rule order lost")
	}
	x = systemDigestClone(m)
	x.Outbounds[0], x.Outbounds[1] = x.Outbounds[1], x.Outbounds[0]
	if systemDigestCheckValid(t, x) == base {
		t.Fatal("compiler outbound order lost")
	}
}

func TestSystemManifestDigestInvalidPriority(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{"schema", func(m *Manifest) { m.SchemaVersion = 2 }},
		{"instance", func(m *Manifest) { m.InstanceID = "bad" }},
		{"generation", func(m *Manifest) { m.Generation = strings.Repeat("A", 32) }},
		{"selection-generation", func(m *Manifest) { m.SelectionGeneration = strings.Repeat("a", 32) }},
		{"runtime-short", func(m *Manifest) { m.RuntimeSHA256 = "bad" }},
		{"runtime-uppercase", func(m *Manifest) { m.RuntimeSHA256 = strings.Repeat("E", 64) }},
		{"runtime-not-hex", func(m *Manifest) { m.RuntimeSHA256 = strings.Repeat("g", 64) }},
		{"nil-rules", func(m *Manifest) { m.Rules = nil }},
		{"nil-outbounds", func(m *Manifest) { m.Outbounds = nil }},
		{"missing-sources", func(m *Manifest) { m.CapturedSources = m.CapturedSources[:1] }},
		{"first-source-kind", func(m *Manifest) { m.CapturedSources[0].Kind = SourceCA }},
		{"second-source-kind", func(m *Manifest) { m.CapturedSources[1].Kind = SourceConfig }},
		{"config-absent", func(m *Manifest) {
			m.CapturedSources[0].Present = false
			m.CapturedSources[0].SHA256 = nil
		}},
		{"source-ordinal", func(m *Manifest) { m.CapturedSources[0].Ordinal = 1 }},
		{"source-negative-ordinal", func(m *Manifest) { m.CapturedSources[4].Ordinal = -1 }},
		{"late-selection", func(m *Manifest) { m.CapturedSources[4].Kind = SourceSelection }},
		{"present-no-sha", func(m *Manifest) { m.CapturedSources[1].Present = true }},
		{"absent-with-sha", func(m *Manifest) { m.CapturedSources[1].SHA256 = ptr(strings.Repeat("a", 64)) }},
		{"source-sha", func(m *Manifest) { m.CapturedSources[4].SHA256 = ptr("bad") }},
		{"source-enum", func(m *Manifest) { m.CapturedSources[4].Kind = "BAD" }},
		{"last-type", func(m *Manifest) { m.Rules[len(m.Rules)-1].Type = "" }},
		{"last-action", func(m *Manifest) { m.Rules[len(m.Rules)-1].ActionType = "" }},
		{"synthetic-enum", func(m *Manifest) { m.Rules[len(m.Rules)-1].Synthetic = "BAD" }},
		{"unknown-claim", func(m *Manifest) { m.Rules[len(m.Rules)-1].Route.ConfiguredTarget = ptr("DIRECT") }},
		{"unknown-empty-path", func(m *Manifest) { m.Rules[len(m.Rules)-1].Route.GroupPath = []GroupEdge{} }},
		{"verified-no-condition", func(m *Manifest) { m.Rules[0].Route.Condition = nil }},
		{"verified-no-target", func(m *Manifest) { m.Rules[0].Route.ConfiguredTarget = nil }},
		{"verified-nil-path", func(m *Manifest) { m.Rules[0].Route.GroupPath = nil }},
		{"verified-no-generation", func(m *Manifest) { m.Rules[0].Route.SelectionGeneration = nil }},
		{"verified-no-source-id", func(m *Manifest) { m.Rules[0].Route.SourceID = nil }},
		{"verified-no-index", func(m *Manifest) { m.Rules[0].Route.SourceIndex = nil }},
		{"source-index-negative", func(m *Manifest) { m.Rules[0].Route.SourceIndex = ptr(-1) }},
		{"source-id-leading-zero", func(m *Manifest) { m.Rules[0].Route.SourceID = ptr(m.Generation + ":rule:00") }},
		{"source-id-generation", func(m *Manifest) { m.Rules[0].Route.SourceID = ptr(strings.Repeat("a", 32) + ":rule:0") }},
		{"node-no-id", func(m *Manifest) { m.Rules[0].Route.FinalNodeID = nil }},
		{"node-no-label", func(m *Manifest) { m.Rules[0].Route.FinalNodeLabel = nil }},
		{"node-leading-zero", func(m *Manifest) { m.Rules[0].Route.FinalNodeID = ptr(m.Generation + ":node:07") }},
		{"domain", func(m *Manifest) { m.Rules[0].Route.Condition.Value = "https://bad/" }},
		{"suffix", func(m *Manifest) { m.Rules[1].Route.Condition.Value = "bad host" }},
		{"cidr", func(m *Manifest) { m.Rules[2].Route.Condition.Value = "192.0.2.0/99" }},
		{"geoip", func(m *Manifest) { m.Rules[3].Route.Condition.Value = "US" }},
		{"ruleset-label", func(m *Manifest) { m.Rules[4].Route.RuleSet.Label = "" }},
		{"ruleset-hash", func(m *Manifest) { m.Rules[4].Route.RuleSet.SHA256 = "bad" }},
		{"ruleset-condition", func(m *Manifest) { m.Rules[4].Route.Condition.Value = "" }},
		{"match-condition", func(m *Manifest) { m.Rules[5].Route.Condition = &Condition{Kind: RuleDomain, Value: "example.com"} }},
		{"final-generation", func(m *Manifest) { m.FinalOrigin.SelectionGeneration = ptr(strings.Repeat("a", 32)) }},
		{"final-kind", func(m *Manifest) { m.FinalOrigin.Kind = "BAD" }},
		{"duplicate-outbound", func(m *Manifest) { m.Outbounds[1].Tag = m.Outbounds[0].Tag }},
		{"outbound-empty-type", func(m *Manifest) { m.Outbounds[1].Type = "" }},
		{"outbound-no-node-id", func(m *Manifest) { m.Outbounds[1].NodeID = nil }},
		{"outbound-node-leading-zero", func(m *Manifest) { m.Outbounds[1].NodeID = ptr(m.Generation + ":node:07") }},
		{"nested-utf8", func(m *Manifest) { m.Rules[0].Route.GroupPath[0].Selected = string([]byte{255}) }},
		{"nested-nul", func(m *Manifest) { m.Rules[4].Route.RuleSet.Label = "bad\x00label" }},
		{"late-utf8", func(m *Manifest) { m.Outbounds[1].NodeLabel = ptr(string([]byte{255})) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := systemDigestMixedFixture()
			tc.mutate(&m)
			for _, budget := range []int{MaxResponseBytes, 1, 0, -1} {
				// Invalid manifest must win even when the byte budget is invalid.
				systemDigestCompare(t, m, budget, ErrInvalid)
			}
		})
	}
}

func TestSystemManifestDigestFixedSeed(t *testing.T) {
	rng := rand.New(rand.NewSource(20261029))
	labels := []string{"plain", "中文😀", "quote\"slash\\", "\b\f\n\r\t\x01", "<>&\u2028\u2029"}
	for i := 0; i < 24; i++ {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			m := systemDigestMixedFixture()
			for j := range m.Rules {
				m.Rules[j].Type = labels[rng.Intn(len(labels))]
				m.Rules[j].ActionType = labels[rng.Intn(len(labels))]
				if m.Rules[j].Route.Evidence == ProvenanceVerified {
					m.Rules[j].Route.FinalNodeLabel = ptr(labels[rng.Intn(len(labels))])
				}
			}
			rng.Shuffle(len(m.Rules), func(a, b int) { m.Rules[a], m.Rules[b] = m.Rules[b], m.Rules[a] })
			systemDigestCheckValid(t, m)
			m.Rules[rng.Intn(len(m.Rules))].ActionType = "bad\x00action"
			for _, budget := range []int{MaxResponseBytes, 0, -1} {
				systemDigestCompare(t, m, budget, ErrInvalid)
			}
		})
	}
}

// Synthetic in-memory route counts only, NOT compiler output or user-config
// equivalence. UNKNOWN origins intentionally avoid measuring compiler setup.
// Execute with -test.benchtime=1x -test.count=5 for five repetitions (not
// five fresh processes); the largest fixture can allocate heavily, so do not
// let the default adaptive runner scale.
func BenchmarkSystemManifestDigest(b *testing.B) {
	for _, size := range []int{0, 1000, 10000, 91982} {
		b.Run("routes_"+strconv.Itoa(size), func(b *testing.B) {
			b.StopTimer()
			m := systemDigestFixture()
			m.Rules = make([]RuleOrigin, size)
			kinds := []SyntheticKind{SyntheticNone, SyntheticSniff, SyntheticResolve, SyntheticHijack}
			for i := range m.Rules {
				m.Rules[i] = RuleOrigin{Type: "field", ActionType: "synthetic", Synthetic: kinds[i%len(kinds)], Route: RouteProjection{Evidence: ProvenanceUnknown, Kind: RuleUnknown, TerminalKind: TerminalUnknown}}
			}
			budget := ManifestBudget(&m)
			if err := Validate(m); err != nil {
				b.Fatalf("synthetic fixture invalid: %v", err)
			}
			canonical, err := systemDigestCanonicalBytes(m, budget)
			if err != nil {
				b.Fatal(err)
			}
			sum := sha256.Sum256(canonical)
			want := hex.EncodeToString(sum[:])
			b.Logf("fixture=synthetic_UNKNOWN rules=%d outbounds=%d sources=%d canonical_bytes=%d manifest_budget=%d canonical_sha256=%s", len(m.Rules), len(m.Outbounds), len(m.CapturedSources), len(canonical), budget, want)
			b.SetBytes(int64(len(canonical)))
			canonical = nil
			b.ReportAllocs()
			b.ResetTimer()
			b.StartTimer()
			for i := 0; i < b.N; i++ {
				got, err := ManifestDigest(m, budget)
				if err != nil || got != want {
					b.Fatalf("digest mismatch: %v", err)
				}
			}
			b.StopTimer()
		})
	}
}
