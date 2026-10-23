package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
)

func recordsRuntimeFixture(t *testing.T) (string, compiledRuntime, controlHelperRegistration) {
	t.Helper()
	root := t.TempDir()
	config := filepath.Join(root, "config.yaml")
	if e := os.WriteFile(config, []byte("private original"), 0600); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(root, "service")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	staged := filepath.Join(dir, "config.yaml")
	if e := os.WriteFile(staged, []byte("captured staged"), 0600); e != nil {
		t.Fatal(e)
	}
	raw := []byte(`{"runtime":"same-capture"}`)
	sum := sha256.Sum256(raw)
	runtimeDigest := hex.EncodeToString(sum[:])
	sourceDigest := strings.Repeat("a", 64)
	m := &cr.Manifest{SchemaVersion: 1, Binding: cr.Binding{InstanceID: strings.Repeat("1", 32), Generation: strings.Repeat("2", 32), ManifestID: strings.Repeat("3", 64)}, SelectionGeneration: strings.Repeat("2", 32), RuntimeSHA256: runtimeDigest, CapturedSources: []cr.CapturedSource{{Kind: cr.SourceConfig, Ordinal: 0, Present: true, SHA256: &sourceDigest}, {Kind: cr.SourceSelection, Ordinal: 0, Present: false}}, Rules: []cr.RuleOrigin{}, FinalOrigin: cr.RouteProjection{Evidence: cr.ProvenanceUnknown, Kind: cr.RuleUnknown, TerminalKind: cr.TerminalUnknown}, Outbounds: []cr.OutboundOrigin{}}
	digest, e := cr.ManifestDigest(*m, manifestBudget(m))
	if e != nil {
		t.Fatal(e)
	}
	m.ManifestID = digest
	return staged, compiledRuntime{JSON: raw, Manifest: m}, controlHelperRegistration{UID: 501, Config: config, Home: root}
}
func TestRecordsRuntimeExactAssociationAndDigest(t *testing.T) {
	staged, compiled, reg := recordsRuntimeFixture(t)
	scope, h, e := runRecordsBinding(staged, compiled, reg, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	expected, e := controlHelperConfigIdentity(reg.Config)
	if e != nil {
		t.Fatal(e)
	}
	if scope.UID != reg.UID || scope.ConfigIdentity != expected || h.Binding != compiled.Manifest.Binding || h.RuntimeSHA256 != compiled.Manifest.RuntimeSHA256 || h.PreviousBinding != nil {
		t.Fatal("wrong originating identity")
	}
	// This is path identity, not current source contents or a second compiler.
	if e = os.WriteFile(reg.Config, []byte("replacement disk YAML never compiled here"), 0600); e != nil {
		t.Fatal(e)
	}
	if next, _, e := runRecordsBinding(staged, compiled, reg, time.Now()); e != nil || next != scope {
		t.Fatal("history relabeled by current YAML")
	}
	for _, kind := range []string{"foreign", "unregistered", "root-user", "digest", "manifest", "self-digest", "symlink", "mode", "parent"} {
		t.Run(kind, func(t *testing.T) {
			path, c, r := staged, compiled, reg
			switch kind {
			case "foreign":
				path = filepath.Join(filepath.Dir(reg.Config), "foreign", "config.yaml")
			case "unregistered":
				r.Config = filepath.Join(filepath.Dir(reg.Config), "other.yaml")
			case "root-user":
				r.UID = 0
			case "digest":
				c.JSON = []byte(`{"different":true}`)
			case "manifest":
				c.Manifest = nil
			case "self-digest":
				copy := *c.Manifest
				copy.ManifestID = strings.Repeat("f", 64)
				c.Manifest = &copy
			case "symlink":
				if e := os.Rename(staged, staged+".saved"); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(staged+".saved", staged); e != nil {
					t.Fatal(e)
				}
				defer func() { _ = os.Remove(staged); _ = os.Rename(staged+".saved", staged) }()
			case "mode":
				if e := os.Chmod(staged, 0644); e != nil {
					t.Fatal(e)
				}
				defer os.Chmod(staged, 0600)
			case "parent":
				if e := os.Chmod(filepath.Dir(staged), 0755); e != nil {
					t.Fatal(e)
				}
				defer os.Chmod(filepath.Dir(staged), 0700)
			}
			if _, _, e := runRecordsBinding(path, c, r, time.Now()); e != cr.TelemetryUnavailable {
				t.Fatalf("invalid association accepted: %v", e)
			}
		})
	}
}
func TestRecordsServicePlistExplicitMarker(t *testing.T) {
	p, e := servicePlist("/private/service/anytls-macos", "/private/service/config.yaml", "/private/service/sing-box", "/private/service/anytls.log", false)
	if e != nil {
		t.Fatal(e)
	}
	count := strings.Count(p, "<string>-record-service</string>")
	if !externalCoreRequired() && count != 1 {
		t.Fatal("embedded authorized launch did not carry marker")
	}
	if externalCoreRequired() && count != 0 {
		t.Fatal("external launch claimed recording eligibility")
	}
	if strings.Contains(p, "records/") {
		t.Fatal("plist exposed a storage path override")
	}
}
func TestRecordsRuntimeNonrootNeverOpensProductionStore(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("nonroot eligibility guard requires ordinary UID")
	}
	staged, compiled, _ := recordsRuntimeFixture(t)
	if w, e := openRunRecords(staged, compiled); w != nil || e != cr.TelemetryUnavailable {
		t.Fatal("ordinary standalone run opened root store")
	}
}
