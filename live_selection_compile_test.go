package main

import (
	"context"
	"encoding/json"
	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	"github.com/NiuStar/anytls-core/internal/engine"
	fp "github.com/NiuStar/anytls-core/internal/familypolicy"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLiveSelectionCompilerScope(t *testing.T) {
	raw := []byte(`proxies:
  - {name: A, type: anytls, server: 192.0.2.1, port: 443, password: p, sni: example.com}
  - {name: B, type: anytls, server: 192.0.2.2, port: 443, password: q, sni: example.com}
proxy-groups:
  - {name: Default, type: select, proxies: [A, B], selected: A}
  - {name: Dedicated, type: select, proxies: [A, B], selected: A}
rules: ["DOMAIN,fixed.example,A", "DOMAIN,special.example,Dedicated", "DOMAIN,group.example,Default", "MATCH,Default"]
`)
	ca, _ := runtimeCertificate(t)
	path := filepath.Join(t.TempDir(), "ca.pem")
	if e := os.WriteFile(path, ca, 0600); e != nil {
		t.Fatal(e)
	}
	raw = []byte(strings.ReplaceAll(string(raw), "sni: example.com", "sni: example.com, ca: "+path))
	nodes, e := loadNodesBytes(raw)
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := buildNode(nodes[0], "tun", 0, false)
	if e != nil {
		t.Fatal(e)
	}
	if e = applyRoutingBytes("fixture.yaml", raw, nodes, nodes[0], cfg, false); e != nil {
		t.Fatal(e)
	}
	addWarmCandidates(raw, nodes, nodes[0], cfg, false, nil)
	plan, e := compileLiveSelection(raw, nodes, nodes[0], cfg, false)
	if e != nil {
		t.Fatal(e)
	}
	if len(plan.Nodes) != 2 {
		t.Fatalf("candidates=%d", len(plan.Nodes))
	}
	route := cfg["route"].(map[string]any)
	rules := route["rules"].([]any)
	var tags []string
	for _, v := range rules {
		r := v.(map[string]any)
		if r["outbound"] != nil {
			tags = append(tags, r["outbound"].(string))
		}
	}
	if len(tags) != 3 || tags[0] == "live" || tags[1] == "live" || tags[2] != "live" || route["final"] != "live" {
		t.Fatalf("routing scope=%v final=%v", tags, route["final"])
	}
	if cfg["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["detour"] != "live" {
		t.Fatal("DNS selection not linked")
	}
	if len(cfg["inbounds"].([]any)[0].(map[string]any)["route_exclude_address"].([]string)) < 2 {
		t.Fatal("missing candidate exclusions")
	}
	next, _ := groupChoiceBytes(raw, "Default", "B")
	if _, e = selectionOnlyChange(raw, []byte("A\n"), next, []byte("B\n")); e != nil {
		t.Fatal(e)
	}
	var doc map[string]any
	yaml.Unmarshal(next, &doc)
	doc["ipv6"] = true
	changed, _ := yaml.Marshal(doc)
	if _, e = selectionOnlyChange(raw, []byte("A\n"), changed, []byte("B\n")); e == nil {
		t.Fatal("nonselection edit admitted")
	}
	// Rebuild so finalization is exercised before the single final encode.
	cfg, e = buildNode(nodes[0], "tun", 0, false)
	if e != nil {
		t.Fatal(e)
	}
	m := &cr.Manifest{SchemaVersion: 1, Binding: cr.Binding{InstanceID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32)}, SelectionGeneration: strings.Repeat("b", 32), Rules: []cr.RuleOrigin{}, Outbounds: []cr.OutboundOrigin{}}
	addCapturedSource(m, cr.SourceConfig, 0, raw, true)
	addCapturedSource(m, cr.SourceSelection, 0, []byte("A"), true)
	if e = applyRoutingRecords("fixture.yaml", raw, nodes, nodes[0], cfg, false, m); e != nil {
		t.Fatal(e)
	}
	finalizeLiveSelection(raw, nodes, nodes[0], cfg, false, m)
	encoded, _ := json.Marshal(cfg)
	m.RuntimeSHA256 = shaHex(encoded)
	m.ManifestID, e = cr.ManifestDigest(*m, cr.ManifestBudget(m))
	if e != nil {
		t.Fatal("final manifest", e)
	}
	if len(m.Outbounds) != len(cfg["outbounds"].([]any)) {
		t.Fatal("unrepresented SDK outbounds")
	}
	if m.FinalOrigin.OutboundType != "anytls-selection" || m.Rules[len(m.Rules)-1].ExpectedOutbound != "live" {
		t.Fatal("dynamic graph manifest mismatch")
	}
	if err := engine.CheckControlled(context.Background(), encoded); err != nil {
		t.Fatal("actual final SDK graph", err)
	}
	snapshot := fp.Capture(encoded, m, nil)
	if snapshot == nil || !snapshot.Matches(encoded) || snapshot.Matches(append(encoded, ' ')) {
		t.Fatal("final runtime family binding")
	}
	if !liveSourceEligible(append(raw, []byte("rule-sets: {local: {path: local.json, sha256: abc}}\n")...)) {
		t.Fatal("local rule sets disabled")
	}

}

func TestLiveCompilerLocalRuleSetFinalFamilyCapture(t *testing.T) {
	o, raw, source := recordsCompilerFixture(t, " - RULE-SET,local,shared\n - MATCH,shared\n")
	raw = []byte(strings.Replace(string(raw), "proxies: [b], selected: b", "proxies: [a, b], selected: a", -1))
	// Remove unrelated nested groups: the default is the direct finite shared set.
	if err := os.WriteFile(o.Config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := buildNode(mustLiveNodes(t, raw)[0], "proxy", 11080, false)
	if err != nil {
		t.Fatal(err)
	}
	nodes := mustLiveNodes(t, raw)
	m := &cr.Manifest{SchemaVersion: 1, Binding: cr.Binding{InstanceID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32)}, SelectionGeneration: strings.Repeat("b", 32), Rules: []cr.RuleOrigin{}, Outbounds: []cr.OutboundOrigin{}}
	addCapturedSource(m, cr.SourceConfig, 0, raw, true)
	addCapturedSource(m, cr.SourceSelection, 0, []byte("a"), true)
	var sources []fp.Source
	if err := applyRoutingCaptured(o.Config, raw, nodes, nodes[0], cfg, false, m, &sources); err != nil {
		t.Fatal(err)
	}
	// Proxy mode does not need warm TUN server routes, so the second leaf uses
	// the same pre-established local endpoint server scope for this fixture.
	finalizeLiveSelection(raw, nodes, nodes[0], cfg, false, m)
	encoded, _ := json.Marshal(cfg)
	m.RuntimeSHA256 = shaHex(encoded)
	m.ManifestID, err = cr.ManifestDigest(*m, cr.ManifestBudget(m))
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 || string(sources[0].JSON) != string(source) {
		t.Fatal("same read source lost")
	}
	snapshot := fp.Capture(encoded, m, sources)
	if snapshot == nil || !snapshot.Matches(encoded) {
		t.Fatal("final local ruleset family capture unavailable")
	}
	if err := engine.CheckControlled(context.Background(), encoded); err != nil {
		t.Fatal("actual final inline SDK graph", err)
	}
	sources[0].JSON = []byte(`{"version":3,"rules":[{"ip_cidr":["192.0.2.0/24"]}]}`)
	if fp.Capture(encoded, m, sources) != nil {
		t.Fatal("untrusted source mutation admitted")
	}
	var poisoned map[string]any
	json.Unmarshal(encoded, &poisoned)
	poisoned["route"].(map[string]any)["rule_set"].([]any)[0].(map[string]any)["rules"] = []any{map[string]any{"ip_cidr": []string{"192.0.2.0/24"}}}
	bad, _ := json.Marshal(poisoned)
	m.RuntimeSHA256 = shaHex(bad)
	m.ManifestID, _ = cr.ManifestDigest(*m, cr.ManifestBudget(m))
	if fp.Capture(bad, m, []fp.Source{{Tag: "local", JSON: source}}) != nil {
		t.Fatal("rehashed inline mutation admitted")
	}
}
func mustLiveNodes(t *testing.T, raw []byte) []node {
	t.Helper()
	nodes, err := loadNodesBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	return nodes
}
