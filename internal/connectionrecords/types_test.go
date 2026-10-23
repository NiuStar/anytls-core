package connectionrecords

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestNamespaceCanonicalDigest(t *testing.T) {
	scope := Scope{UID: 501, ConfigIdentity: strings.Repeat("d", 64)}
	got, e := NamespaceDigest(scope)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256([]byte(`{"schema_version":1,"uid":501,"config_identity":"` + scope.ConfigIdentity + `"}`))
	if got != hex.EncodeToString(sum[:]) {
		t.Fatal("namespace encoding changed")
	}
	scope.UID = 0
	if _, e := NamespaceDigest(scope); e == nil {
		t.Fatal("root registration accepted")
	}
}
func TestManifestDigestExcludesSelfAndBindsSources(t *testing.T) {
	b := fixtureBinding()
	digest := strings.Repeat("e", 64)
	final := RouteProjection{Evidence: ProvenanceVerified, Kind: RuleDefault, ConfiguredTarget: ptr("DIRECT"), GroupPath: []GroupEdge{}, TerminalKind: TerminalDirect, OutboundTag: "direct", OutboundType: "direct", SelectionGeneration: &b.Generation}
	m := Manifest{SchemaVersion: 1, Binding: b, SelectionGeneration: b.Generation, RuntimeSHA256: digest, CapturedSources: []CapturedSource{{SourceConfig, 0, true, &digest}, {SourceSelection, 0, false, nil}}, Rules: []RuleOrigin{}, FinalOrigin: final, Outbounds: []OutboundOrigin{{Tag: "direct", Type: "direct", TerminalKind: TerminalDirect}}}
	first, e := ManifestDigest(m, MaxResponseBytes)
	if e != nil {
		t.Fatal(e)
	}
	m.ManifestID = strings.Repeat("f", 64)
	second, e := ManifestDigest(m, MaxResponseBytes)
	if e != nil || second != first {
		t.Fatal("digest recursively includes itself", e)
	}
	m.CapturedSources[1].Present = true
	m.CapturedSources[1].SHA256 = &digest
	third, e := ManifestDigest(m, MaxResponseBytes)
	if e != nil || third == first {
		t.Fatal("ABSENT lost", e)
	}
	m.CapturedSources[1].SHA256 = nil
	if Validate(m) == nil {
		t.Fatal("present without digest accepted")
	}
}
func TestOnlyApprovedWireFields(t *testing.T) {
	r := fixtureRecord()
	b, e := EncodeBounded(r, MaxRecordBytes)
	if e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{"password", "payload", "subscription", "process_info", "dns_response", "sniff_context", "url"} {
		if strings.Contains(string(b), `"`+secret+`"`) {
			t.Fatal(secret)
		}
	}
	// Observation has no field for connection/context/metadata or receipt IDs;
	// adding one must be accompanied by an explicit API freeze revision.
}
