package familypolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	"strings"
	"testing"
)

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func TestSnapshotBindsCapturedBytesAndInlineRules(t *testing.T) {
	source := []byte(`{"version":3,"rules":[{"ip_cidr":["192.0.2.0/24","2001:db8::/32"]}]}`)
	sum := digest(source)
	raw := []byte(`{"route":{"rule_set":[{"type":"inline","tag":"local","rules":[{"ip_cidr":["192.0.2.0/24","2001:db8::/32"]}]}]}}`)
	m := cr.Manifest{SchemaVersion: cr.SchemaVersion, Binding: cr.Binding{InstanceID: strings.Repeat("1", 32), Generation: strings.Repeat("2", 32)}, SelectionGeneration: strings.Repeat("2", 32), RuntimeSHA256: digest(raw), CapturedSources: []cr.CapturedSource{{Kind: cr.SourceConfig, Present: true, SHA256: &sum}, {Kind: cr.SourceSelection}, {Kind: cr.SourceRuleSet, Present: true, SHA256: &sum}}, Rules: []cr.RuleOrigin{}, Outbounds: []cr.OutboundOrigin{}, FinalOrigin: cr.RouteProjection{Evidence: cr.ProvenanceUnknown, Kind: cr.RuleUnknown, TerminalKind: cr.TerminalUnknown}}
	seal := func() {
		t.Helper()
		var err error
		m.ManifestID, err = cr.ManifestDigest(m, cr.ManifestBudget(&m))
		if err != nil {
			t.Fatal(err)
		}
	}
	seal()
	sources := []Source{{Tag: "local", JSON: append([]byte(nil), source...)}}
	snap := Capture(raw, &m, sources)
	if snap == nil || !snap.Matches(raw) {
		t.Fatal("captured inline policy missing")
	}
	sources[0].JSON[0] = ' '
	if !snap.Matches(raw) {
		t.Fatal("snapshot retained caller bytes")
	}
	if Capture(raw, &m, sources) != nil {
		t.Fatal("changed source SHA accepted")
	}
	if snap.Matches(append(raw, ' ')) {
		t.Fatal("changed runtime accepted")
	}
	var changed map[string]any
	if err := json.Unmarshal(raw, &changed); err != nil {
		t.Fatal(err)
	}
	changed["route"].(map[string]any)["rule_set"].([]any)[0].(map[string]any)["type"] = "local"
	other, _ := json.Marshal(changed)
	m.RuntimeSHA256 = digest(other)
	seal()
	sources[0].JSON = source
	if Capture(other, &m, sources) != nil {
		t.Fatal("watched local set accepted")
	}
}
