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
	for _, mode := range []string{"proxy", "tun"} {
		t.Run(mode, func(t *testing.T) { testRecordsCompilerExactJSONAndOrigins(t, mode) })
	}
}

func testRecordsCompilerExactJSONAndOrigins(t *testing.T, mode string) {
	o, config, set := recordsCompilerFixture(t, " - DOMAIN,first.invalid,outer\n - DOMAIN,first.invalid,shared\n - RULE-SET,local,DIRECT\n - MATCH,outer\n")
	o.Mode = mode
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
	digest, err := cr.ManifestDigest(*m, cr.ManifestBudget(m))
	if err != nil || digest != m.ManifestID {
		t.Fatalf("manifest digest: %v", err)
	}
	slots := m.Rules
	if mode == "tun" {
		if len(tunBusinessRules(t, old)) != 4 || len(slots) != 7 || slots[0].Synthetic != cr.SyntheticHijack || slots[0].ActionType != "hijack-dns" {
			t.Fatalf("TUN port-53 capture slot: %#v", slots)
		}
		if slots[0].Route.SourceID != nil || slots[0].Route.SourceIndex != nil || slots[0].Route.Evidence != cr.ProvenanceUnknown {
			t.Fatal("TUN capture acquired user source identity")
		}
		// Only the explicit leading port-53 capture is new for this fixture;
		// retain all old sniff/protocol-capture/user/resolve slot assertions.
		slots = slots[1:]
	}
	if len(slots) != 6 || slots[0].Synthetic != cr.SyntheticSniff || slots[1].Synthetic != cr.SyntheticHijack || slots[4].Synthetic != cr.SyntheticResolve {
		t.Fatalf("final slot order: %#v", m.Rules)
	}
	first, second := slots[2].Route, slots[3].Route
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
	if slots[5].Route.RuleSet == nil || slots[5].Route.RuleSet.SHA256 != shaHex(set) || slots[5].Route.SourceIndex == nil || *slots[5].Route.SourceIndex != 2 || slots[5].Route.SourceID == nil || *slots[5].Route.SourceID != m.Generation+":rule:2" {
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
	again, err := cr.ManifestDigest(*m, cr.ManifestBudget(m))
	if err != nil || again != digest || !bytes.Equal(compiled.JSON, want) {
		t.Fatal("disk-current backfill")
	}
}

func TestRecordsCompilerDefaultSelectionAndGenerations(t *testing.T) {
	for _, mode := range []string{"proxy", "tun"} {
		t.Run(mode, func(t *testing.T) { testRecordsCompilerDefaultSelectionAndGenerations(t, mode) })
	}
}

func testRecordsCompilerDefaultSelectionAndGenerations(t *testing.T, mode string) {
	o, _, _ := recordsCompilerFixture(t, "")
	o.Mode = mode
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
	wantSlots := 0
	if mode == "tun" {
		wantSlots = 3
		if len(tunBusinessRules(t, normalizedRuntime(t, a.JSON))) != 0 || len(a.Manifest.Rules) != 3 {
			t.Fatal("ruleless TUN must retain exactly the DNS capture prefix")
		}
		for i, want := range []cr.SyntheticKind{cr.SyntheticHijack, cr.SyntheticSniff, cr.SyntheticHijack} {
			slot := a.Manifest.Rules[i]
			if slot.Synthetic != want || slot.Route.SourceID != nil || slot.Route.SourceIndex != nil || slot.Route.Evidence != cr.ProvenanceUnknown {
				t.Fatalf("ruleless TUN synthetic attribution at %d: %#v", i, slot)
			}
		}
	}
	if !a.Manifest.CapturedSources[1].Present || *a.Manifest.CapturedSources[1].SHA256 != shaHex([]byte("b\n")) || len(a.Manifest.Rules) != wantSlots {
		t.Fatal("selected source/mode-specific SDK slots")
	}
}

func TestRecordsCompilerCaptureDoesNotRepairInvalidSelection(t *testing.T) {
	o, _, _ := recordsCompilerFixture(t, "")
	runtimeWrite(t, selectedPath(o.Config), []byte{}, 0600)
	if _, err := prepareRuntimeWithRecords(&o); err == nil {
		t.Fatal("empty present selection changed to ABSENT despite explicit -node")
	}
}

func TestRecordsCompilerCAOrdinalsAndDuplicateSources(t *testing.T) {
	o, _, _ := recordsCompilerFixture(t, " - DOMAIN,one.invalid,b\n - DOMAIN,two.invalid,a\n - DOMAIN,three.invalid,b\n - MATCH,a\n")
	for _, selection := range []bool{false, true} {
		if selection {
			runtimeWrite(t, selectedPath(o.Config), []byte("b\n"), 0600)
		}
		compiled, err := prepareRuntimeWithRecords(&o)
		if err != nil || compiled.Manifest == nil {
			t.Fatalf("compile: %v", err)
		}
		m := compiled.Manifest
		if m.CapturedSources[0].Kind != cr.SourceConfig || m.CapturedSources[0].Ordinal != 0 || m.CapturedSources[1].Kind != cr.SourceSelection || m.CapturedSources[1].Ordinal != 0 || m.CapturedSources[1].Present != selection {
			t.Fatal("config/selection compatibility")
		}
		var cfg struct {
			Outbounds []struct {
				TLS struct {
					CertificatePath string `json:"certificate_path"`
				} `json:"tls"`
			} `json:"outbounds"`
		}
		if err = json.Unmarshal(compiled.JSON, &cfg); err != nil {
			t.Fatal(err)
		}
		var want []cr.CapturedSource
		for _, out := range cfg.Outbounds {
			if out.TLS.CertificatePath != "" {
				b, e := os.ReadFile(out.TLS.CertificatePath)
				if e != nil {
					t.Fatal(e)
				}
				sum := shaHex(b)
				want = append(want, cr.CapturedSource{Kind: cr.SourceCA, Ordinal: len(want), Present: true, SHA256: &sum})
			}
		}
		var got []cr.CapturedSource
		for _, s := range m.CapturedSources {
			if s.Kind == cr.SourceCA {
				got = append(got, s)
			}
		}
		if len(got) != 2 || !reflect.DeepEqual(got, want) || *got[0].SHA256 != *got[1].SHA256 {
			t.Fatalf("ordered duplicate CA sources: %#v != %#v", got, want)
		}
	}
	addCapturedSource(nil, cr.SourceCA, 0, nil, true)
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
	if _, err := cr.ManifestDigest(*m, cr.ManifestBudget(m)); err != nil {
		t.Fatal("manifest budget introduced unrelated history/config quota", err)
	}
}
