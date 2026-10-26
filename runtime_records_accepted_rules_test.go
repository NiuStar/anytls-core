//go:build embedded_core && with_utls

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	"github.com/NiuStar/anytls-core/internal/engine"
)

func TestRecordsCompilerAcceptedConditionIsolation(t *testing.T) {
	for _, tc := range []struct {
		name, kind, value, target string
		known                     bool
	}{
		{"unicode_domain", "DOMAIN", "例子.com", "DIRECT", false},
		{"unicode_suffix", "DOMAIN-SUFFIX", "例子.com", "outer", false},
		{"asterisk", "DOMAIN", "*.invalid", "DIRECT", false},
		{"empty_label", "DOMAIN-SUFFIX", "a..invalid", "DIRECT", false},
		{"long_label", "DOMAIN", strings.Repeat("x", 64) + ".invalid", "outer", false},
		{"long_host", "DOMAIN-SUFFIX", strings.Repeat("a.", 127) + "a", "DIRECT", false},
		{"ascii_domain", "DOMAIN", "safe.invalid", "DIRECT", true},
		{"ascii_suffix", "DOMAIN-SUFFIX", "safe.invalid", "outer", true},
		{"ipv4", "IP-CIDR", "127.0.0.1/32", "DIRECT", true},
		{"ipv6", "IP-CIDR", "::1/128", "DIRECT", true},
		{"ruleset", "RULE-SET", "local", "DIRECT", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, _, _ := recordsCompilerFixture(t, fmt.Sprintf(" - %s,%s,%s\n - DOMAIN,unrelated.invalid,DIRECT\n - MATCH,a\n", tc.kind, tc.value, tc.target))
			legacy, err := prepareRuntime(&o)
			if err != nil {
				t.Fatal(err)
			}
			want, err := json.MarshalIndent(legacy, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			compiled, err := prepareRuntimeWithRecords(&o)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(want, compiled.JSON) {
				t.Fatal("telemetry changed exact runtime JSON")
			}
			// Real SDK construction must accept the unchanged routing input.
			if err := engine.Check(context.Background(), compiled.JSON); err != nil {
				t.Fatalf("SDK rejected accepted fixture: %v", err)
			}
			m := compiled.Manifest
			if m == nil {
				t.Fatal("accepted condition disabled the entire records manifest")
			}
			digest, err := cr.ManifestDigest(*m, cr.ManifestBudget(m))
			if err != nil || digest != m.ManifestID {
				t.Fatalf("invalid manifest: %v", err)
			}
			var affected, unrelated *cr.RouteProjection
			for i := range m.Rules {
				r := &m.Rules[i]
				if r.Synthetic != cr.SyntheticNone {
					continue
				}
				if affected == nil {
					affected = &r.Route
				} else {
					unrelated = &r.Route
				}
			}
			if affected == nil || unrelated == nil || unrelated.Evidence != cr.ProvenanceVerified || unrelated.SourceIndex == nil || *unrelated.SourceIndex != 1 || m.FinalOrigin.Evidence != cr.ProvenanceVerified {
				t.Fatal("unrelated attribution lost")
			}
			if tc.known {
				if affected.Evidence != cr.ProvenanceVerified || affected.Condition == nil || affected.Condition.Value != tc.value {
					t.Fatal("representable condition lost")
				}
			} else {
				if cr.Validate(cr.Condition{Kind: cr.RuleKind(tc.kind), Value: tc.value}) == nil {
					t.Fatal("strict codec accepted unrepresentable condition")
				}
				tag, typ := "direct", "direct"
				if tc.target == "outer" {
					tag, typ = "node-1", "anytls"
				}
				if !reflect.DeepEqual(*affected, unknownCompileRoute(tag, typ)) {
					t.Fatalf("unsupported attribution not fully UNKNOWN: %#v", affected)
				}
				wire, err := json.Marshal(affected)
				if err != nil || bytes.Contains(wire, []byte(tc.value)) {
					t.Fatal("unsupported condition leaked into projection")
				}
			}
		})
	}
}
