package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
)

func recordsCompilerFixture(t *testing.T, rules string) (runtimeOptions, []byte, []byte) {
	t.Helper()
	dir := t.TempDir()
	ca, _ := runtimeCertificate(t)
	caPath := filepath.Join(dir, "ca.pem")
	runtimeWrite(t, caPath, ca, 0600)
	set := []byte(`{"version":3,"rules":[{"ip_cidr":["127.0.0.0/8"]}]}`)
	runtimeWrite(t, filepath.Join(dir, "set.json"), set, 0600)
	data := []byte(fmt.Sprintf("proxies:\n - {name: a, type: anytls, server: 127.0.0.1, port: 443, password: compiler-secret, ca: %s}\n - {name: b, type: anytls, server: 127.0.0.2, port: 443, password: compiler-secret, ca: %s}\nproxy-groups:\n - {name: outer, type: select, proxies: [inner], selected: inner}\n - {name: inner, type: select, proxies: [b], selected: b}\n - {name: shared, type: select, proxies: [b], selected: b}\nrule-sets:\n local: {path: set.json, sha256: %s, resolve-ip: true}\nrules:\n%s", caPath, caPath, shaHex(set), rules))
	path := filepath.Join(dir, "config.yaml")
	runtimeWrite(t, path, data, 0600)
	return runtimeOptions{Command: "check", Config: path, NodeName: "a", Mode: "proxy", LocalPort: 21180}, data, set
}

func TestRecordsCompilerExactJSONAndOrigins(t *testing.T) {
	o, config, set := recordsCompilerFixture(t, " - DOMAIN,first.invalid,outer\n - DOMAIN,first.invalid,shared\n - RULE-SET,local,DIRECT\n - MATCH,outer\n")
	old, err := prepareRuntime(&o)
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.MarshalIndent(old, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := prepareRuntimeWithRecords(&o)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(compiled.JSON, want) {
		t.Fatal("exact legacy encoder bytes changed")
	}
	m := compiled.Manifest
	if m == nil {
		t.Fatal("missing manifest")
	}
	if m.RuntimeSHA256 != shaHex(want) {
		t.Fatal("runtime digest")
	}
	digest, err := cr.ManifestDigest(*m, manifestBudget(m))
	if err != nil || digest != m.ManifestID {
		t.Fatalf("manifest digest: %v", err)
	}
	if len(m.Rules) != 6 || m.Rules[0].Synthetic != cr.SyntheticSniff || m.Rules[1].Synthetic != cr.SyntheticHijack || m.Rules[4].Synthetic != cr.SyntheticResolve {
		t.Fatalf("final slot order: %#v", m.Rules)
	}
	first, second := m.Rules[2].Route, m.Rules[3].Route
	if *first.SourceIndex != 0 || *second.SourceIndex != 1 || *first.SourceID == *second.SourceID {
		t.Fatal("duplicate source identity lost")
	}
	if !reflect.DeepEqual(first.GroupPath, []cr.GroupEdge{{Group: "outer", Selected: "inner"}, {Group: "inner", Selected: "b"}}) || !reflect.DeepEqual(second.GroupPath, []cr.GroupEdge{{Group: "shared", Selected: "b"}}) {
		t.Fatal("resolver edges lost")
	}
	if first.OutboundTag != second.OutboundTag || first.OutboundTag != "node-1" {
		t.Fatal("shared tag not reused")
	}
	if m.FinalOrigin.Kind != cr.RuleMatch || *m.FinalOrigin.SourceIndex != 3 || m.FinalOrigin.OutboundTag != "node-1" {
		t.Fatal("MATCH is separate final origin")
	}
	if m.Rules[5].Route.RuleSet == nil || m.Rules[5].Route.RuleSet.SHA256 != shaHex(set) {
		t.Fatal("top-level set digest")
	}
	if len(m.Outbounds) != 3 || m.Outbounds[0].Tag != "anytls-out" || m.Outbounds[1].Tag != "node-1" || m.Outbounds[2].Tag != "direct" {
		t.Fatal("emission registry order")
	}
	if *m.CapturedSources[0].SHA256 != shaHex(config) || m.CapturedSources[1].Present || m.CapturedSources[1].SHA256 != nil {
		t.Fatal("config/ABSENT capture")
	}
	if m.CapturedSources[2].Kind != cr.SourceRuleSet || *m.CapturedSources[2].SHA256 != shaHex(set) {
		t.Fatal("set captured input")
	}
	// Compilation owns its projections; current disk no longer supplies history.
	if err := os.Remove(o.Config); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(filepath.Dir(o.Config), "set.json")); err != nil {
		t.Fatal(err)
	}
	again, err := cr.ManifestDigest(*m, manifestBudget(m))
	if err != nil || again != digest || !bytes.Equal(compiled.JSON, want) {
		t.Fatal("disk-current backfill")
	}
}

func TestRecordsCompilerDefaultSelectionAndGenerations(t *testing.T) {
	o, _, _ := recordsCompilerFixture(t, "")
	o.NodeName = ""
	if _, err := prepareRuntimeWithRecords(&o); err == nil || err.Error() != "no node selected; use select or -node" {
		t.Fatal("absent selection policy changed")
	}
	runtimeWrite(t, selectedPath(o.Config), []byte("b\n"), 0600)
	a, err := prepareRuntimeWithRecords(&o)
	if err != nil {
		t.Fatal(err)
	}
	b, err := prepareRuntimeWithRecords(&o)
	if err != nil {
		t.Fatal(err)
	}
	if a.Manifest == nil || b.Manifest == nil {
		t.Fatal("missing provenance")
	}
	if a.Manifest.Generation == b.Manifest.Generation || a.Manifest.InstanceID == b.Manifest.InstanceID || !bytes.Equal(a.JSON, b.JSON) {
		t.Fatal("fresh identity/exact runtime")
	}
	r := a.Manifest.FinalOrigin
	if r.Kind != cr.RuleDefault || r.SourceID != nil || r.SourceIndex != nil || r.Condition != nil || len(r.GroupPath) != 0 || *r.FinalNodeLabel != "b" || *r.FinalNodeID != a.Manifest.Generation+":node:1" {
		t.Fatal("ruleless default is not actual selected node")
	}
	if !a.Manifest.CapturedSources[1].Present || *a.Manifest.CapturedSources[1].SHA256 != shaHex([]byte("b\n")) || len(a.Manifest.Rules) != 0 {
		t.Fatal("selected source/empty SDK slots")
	}
}

func TestRecordsCompilerCaptureDoesNotRepairInvalidSelection(t *testing.T) {
	o, _, _ := recordsCompilerFixture(t, "")
	runtimeWrite(t, selectedPath(o.Config), []byte{}, 0600)
	if _, err := prepareRuntimeWithRecords(&o); err == nil {
		t.Fatal("empty present selection changed to ABSENT despite explicit -node")
	}
}

func TestRecordsCompilerManifestBudgetScalesWithAcceptedLabels(t *testing.T) {
	o, _, _ := recordsCompilerFixture(t, " - DOMAIN,first.invalid,outer\n - MATCH,a\n")
	c, err := prepareRuntimeWithRecords(&o)
	if err != nil || c.Manifest == nil {
		t.Fatal("compile")
	}
	m := c.Manifest
	label := strings.Repeat("x", 40000)
	m.FinalOrigin.ConfiguredTarget = &label
	if _, err := cr.ManifestDigest(*m, manifestBudget(m)); err != nil {
		t.Fatal("manifest budget introduced unrelated history/config quota", err)
	}
}
