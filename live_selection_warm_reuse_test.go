package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	"github.com/NiuStar/anytls-core/internal/engine"
	fp "github.com/NiuStar/anytls-core/internal/familypolicy"
)

// No listeners or WAN: the SDK check only constructs and closes a Box.
func warmReuseFixture(tb testing.TB, count int, grouped bool) ([]byte, []node, map[string]any, *cr.Manifest) {
	tb.Helper()
	var raw strings.Builder
	raw.WriteString("proxies:\n")
	names := make([]string, count)
	for i := range names {
		names[i] = fmt.Sprintf("n%d", i)
		fmt.Fprintf(&raw, " - {name: %s, type: anytls, server: 198.18.%d.%d, port: 443, password: fixture, client-fingerprint: golang, fingerprint: '%s'}\n", names[i], i/254, i%254+1, strings.Repeat("a", 64))
	}
	if grouped {
		fmt.Fprintf(&raw, "proxy-groups:\n - {name: Default, type: select, proxies: [%s], selected: n0}\n - {name: Dedicated, type: select, proxies: [n0], selected: n0}\nrules: [\"DOMAIN,fixed.invalid,n0\", \"DOMAIN,dedicated.invalid,Dedicated\", \"DOMAIN,dynamic.invalid,Default\", \"IP-CIDR,10.0.0.0/8,DIRECT\", \"MATCH,Default\"]\n", strings.Join(names, ", "))
	}
	b := []byte(raw.String())
	nodes, err := loadNodesBytes(b)
	if err != nil {
		tb.Fatal(err)
	}
	cfg, err := buildNode(nodes[0], "tun", 0, false)
	if err != nil {
		tb.Fatal(err)
	}
	m := &cr.Manifest{SchemaVersion: cr.SchemaVersion, Binding: cr.Binding{InstanceID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32)}, SelectionGeneration: strings.Repeat("b", 32), Rules: []cr.RuleOrigin{}, Outbounds: []cr.OutboundOrigin{}}
	addCapturedSource(m, cr.SourceConfig, 0, b, true)
	addCapturedSource(m, cr.SourceSelection, 0, []byte("n0\n"), true)
	if err := applyRoutingRecords(filepath.Join(tb.TempDir(), "fixture.yaml"), b, nodes, nodes[0], cfg, false, m); err != nil {
		tb.Fatal(err)
	}
	return b, nodes, cfg, m
}

func TestWarmReuseObjectCounts(t *testing.T) {
	for _, count := range []int{1, 20, 128, 200, 256} {
		for _, grouped := range []bool{false, true} {
			t.Run(fmt.Sprintf("nodes=%d/group=%t", count, grouped), func(t *testing.T) {
				raw, nodes, cfg, m := warmReuseFixture(t, count, grouped)
				originals := append([]any(nil), cfg["outbounds"].([]any)...)
				originalRules, _ := json.Marshal(cfg["route"].(map[string]any)["rules"])
				addWarmCandidates(raw, nodes, nodes[0], cfg, false, m)
				exclusions := append([]string(nil), cfg["inbounds"].([]any)[0].(map[string]any)["route_exclude_address"].([]string)...)
				// finalize adds warm candidates itself, so compile directly for the count seam.
				plan, err := compileLiveSelection(raw, nodes, nodes[0], cfg, false)
				if err != nil {
					t.Fatal(err)
				}
				outs := cfg["outbounds"].([]any)
				if len(outs) != len(originals)+count+1 {
					t.Fatalf("constructed graph objects=%d want=%d", len(outs), len(originals)+count+1)
				}
				for i, original := range originals {
					if !reflect.DeepEqual(outs[i], original) {
						t.Fatal("fixed semantic outbound changed")
					}
				}
				if len(plan.Nodes) != count || plan.Initial != "warm-0" {
					t.Fatalf("plan=%+v", plan)
				}
				for i, n := range nodes {
					if plan.Nodes[n.Name] != fmt.Sprintf("warm-%d", i) {
						t.Fatalf("unreused leaf %s", n.Name)
					}
				}
				if !reflect.DeepEqual(exclusions, cfg["inbounds"].([]any)[0].(map[string]any)["route_exclude_address"]) {
					t.Fatal("server bypass scope changed")
				}
				if len(exclusions) != count+1 {
					t.Fatalf("server bypass count=%d want=%d", len(exclusions), count+1)
				}
				for i, n := range nodes {
					if exclusions[i+1] != n.Server+"/32" {
						t.Fatal("candidate server missing from baseline scope")
					}
				}
				if cfg["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["detour"] != "live" {
					t.Fatal("DNS not linked")
				}
				if grouped {
					var before []map[string]any
					if err := json.Unmarshal(originalRules, &before); err != nil {
						t.Fatal(err)
					}
					after := cfg["route"].(map[string]any)["rules"].([]any)
					for i, r := range before {
						if r["outbound"] != nil && r["domain"] != nil && r["domain"].([]any)[0] != "dynamic.invalid" && !reflect.DeepEqual(r["outbound"], after[i].(map[string]any)["outbound"]) {
							t.Fatal("fixed/dedicated rule changed")
						}
					}
				}
				// Rebuild through the real finalizer to require complete ordered origins.
				raw, nodes, cfg, m = warmReuseFixture(t, count, grouped)
				finalizeLiveSelection(raw, nodes, nodes[0], cfg, false, m)
				outs = cfg["outbounds"].([]any)
				if len(m.Outbounds) != len(outs) {
					t.Fatal("manifest/SDK count mismatch")
				}
				for i, o := range outs {
					v := o.(map[string]any)
					if m.Outbounds[i].Tag != v["tag"] || m.Outbounds[i].Type != v["type"] {
						t.Fatal("ordered SDK identity mismatch")
					}
				}
				derived := liveSelectionPlanFromManifest(cfg, m)
				if !reflect.DeepEqual(derived, plan) {
					t.Fatalf("derived plan=%+v expected=%+v", derived, plan)
				}
				encoded, err := json.Marshal(cfg)
				if err != nil {
					t.Fatal(err)
				}
				m.RuntimeSHA256 = shaHex(encoded)
				m.ManifestID, err = cr.ManifestDigest(*m, cr.ManifestBudget(m))
				if err != nil {
					t.Fatal(err)
				}
				snapshot := fp.Capture(encoded, m, nil)
				if snapshot == nil || !snapshot.Matches(encoded) {
					t.Fatal("final runtime family binding")
				}
				if err := engine.CheckControlled(context.Background(), encoded); err != nil {
					t.Fatal("SDK construction", err)
				}
				t.Logf("runtime_outbounds=%d anytls=%d selector=1 static=%d", len(outs), count+1, len(originals))
			})
		}
	}
}

func TestWarmReuseRequiresExactPrivateLeaf(t *testing.T) {
	for _, mutate := range []string{"password", "server_port", "tls", "missing"} {
		t.Run(mutate, func(t *testing.T) {
			raw, nodes, cfg, m := warmReuseFixture(t, 2, true)
			addWarmCandidates(raw, nodes, nodes[0], cfg, false, m)
			outs := cfg["outbounds"].([]any)
			for _, item := range outs {
				o := item.(map[string]any)
				if o["tag"] != "warm-1" {
					continue
				}
				switch mutate {
				case "password":
					o["password"] = "different"
				case "server_port":
					o["server_port"] = 8443
				case "tls":
					o["tls"].(map[string]any)["disable_sni"] = true
				case "missing":
					// Keep the established server/CA scope while removing the
					// private member tag; it must fall back, not reuse another tag.
					o["tag"] = "non-warm-scope"
				}
				break
			}
			cfg["outbounds"] = outs
			plan, err := compileLiveSelection(raw, nodes, nodes[0], cfg, false)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Nodes["n0"] != "warm-0" || !strings.HasPrefix(plan.Nodes["n1"], "live-leaf-") {
				t.Fatalf("unsafe reuse=%+v", plan)
			}
		})
	}
}

func TestWarmReuseEligibilityAndLimits(t *testing.T) {
	t.Run("over256", func(t *testing.T) {
		raw, nodes, cfg, m := warmReuseFixture(t, 257, true)
		before, _ := json.Marshal(cfg)
		addWarmCandidates(raw, nodes, nodes[0], cfg, false, m)
		after, _ := json.Marshal(cfg)
		if string(before) != string(after) {
			t.Fatal("warm scope exceeded 256")
		}
	})
	t.Run("unsafe", func(t *testing.T) {
		raw, nodes, cfg, m := warmReuseFixture(t, 2, true)
		raw = []byte(strings.Replace(string(raw), "password: fixture", "skip-cert-verify: true, password: fixture", 1))
		before, _ := json.Marshal(cfg)
		finalizeLiveSelection(raw, nodes, nodes[0], cfg, false, m)
		after, _ := json.Marshal(cfg)
		if string(before) != string(after) {
			t.Fatal("unsafe source admitted")
		}
	})
	t.Run("proxy_scope", func(t *testing.T) {
		raw, nodes, _, m := warmReuseFixture(t, 2, true)
		cfg, err := buildNode(nodes[0], "proxy", 11080, false)
		if err != nil {
			t.Fatal(err)
		}
		addWarmCandidates(raw, nodes, nodes[0], cfg, false, m)
		plan, err := compileLiveSelection(raw, nodes, nodes[0], cfg, false)
		if err != nil || len(plan.Nodes) != 1 || plan.Nodes["n1"] != "" {
			t.Fatalf("server scope expanded: %+v %v", plan, err)
		}
	})
	t.Run("empty_group", func(t *testing.T) {
		raw, nodes, cfg, _ := warmReuseFixture(t, 1, true)
		raw = []byte(strings.Replace(string(raw), "proxies: [n0], selected: n0", "proxies: [], selected: n0", 1))
		if _, err := compileLiveSelection(raw, nodes, nodes[0], cfg, false); err == nil {
			t.Fatal("empty group admitted")
		}
	})
}

func TestWarmReuseSameCAAndCN(t *testing.T) {
	raw, nodes, _, _ := warmReuseFixture(t, 2, true)
	ca, _ := runtimeCertificate(t)
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, ca, 0600); err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.ReplaceAll(string(raw), "fingerprint: '"+strings.Repeat("a", 64)+"'", "ca: "+path))
	raw = []byte(strings.Replace(string(raw), "\"MATCH,Default\"", "\"GEOIP,CN,DIRECT\", \"MATCH,Default\"", 1))
	var err error
	nodes, err = loadNodesBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := buildNode(nodes[0], "tun", 0, false)
	if err != nil {
		t.Fatal(err)
	}
	m := &cr.Manifest{SchemaVersion: cr.SchemaVersion, Binding: cr.Binding{InstanceID: strings.Repeat("a", 32), Generation: strings.Repeat("b", 32)}, SelectionGeneration: strings.Repeat("b", 32), Rules: []cr.RuleOrigin{}, Outbounds: []cr.OutboundOrigin{}}
	addCapturedSource(m, cr.SourceConfig, 0, raw, true)
	addCapturedSource(m, cr.SourceSelection, 0, []byte("n0"), true)
	if err := applyRoutingRecords(filepath.Join(t.TempDir(), "fixture.yaml"), raw, nodes, nodes[0], cfg, false, m); err != nil {
		t.Fatal(err)
	}
	finalizeLiveSelection(raw, nodes, nodes[0], cfg, false, m)
	ordinal := 0
	for _, item := range cfg["outbounds"].([]any) {
		o := item.(map[string]any)
		tls, _ := o["tls"].(map[string]any)
		if tls["certificate_path"] != nil {
			addCapturedSource(m, cr.SourceCA, ordinal, ca, true)
			ordinal++
		}
	}
	if ordinal != 3 {
		t.Fatalf("CA captures=%d want=3 (static + two reused warm)", ordinal)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	m.RuntimeSHA256 = shaHex(encoded)
	m.ManifestID, err = cr.ManifestDigest(*m, cr.ManifestBudget(m))
	if err != nil {
		t.Fatal(err)
	}
	if fp.Capture(encoded, m, nil) == nil {
		t.Fatal("CN/family contract")
	}
	if err := engine.CheckControlled(context.Background(), encoded); err != nil {
		t.Fatal(err)
	}
}

func TestWarmReuseFixedSameNodeIsIndependent(t *testing.T) {
	raw, nodes, _, _ := warmReuseFixture(t, 2, true)
	raw = []byte(strings.Replace(string(raw), "proxies: [n0], selected: n0", "proxies: [n1], selected: n1", 1))
	raw = []byte(strings.Replace(string(raw), "DOMAIN,fixed.invalid,n0", "DOMAIN,fixed.invalid,n1", 1))
	cfg, err := buildNode(nodes[0], "tun", 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyRoutingRecords(filepath.Join(t.TempDir(), "fixture.yaml"), raw, nodes, nodes[0], cfg, false, nil); err != nil {
		t.Fatal(err)
	}
	original, _ := json.Marshal(cfg["outbounds"])
	finalizeLiveSelection(raw, nodes, nodes[0], cfg, false, nil)
	outs := cfg["outbounds"].([]any)
	if len(outs) != 6 {
		t.Fatalf("static anytls + fixed n1 + direct + two warm + selector: %d", len(outs))
	}
	var before []json.RawMessage
	if err := json.Unmarshal(original, &before); err != nil {
		t.Fatal(err)
	}
	for i, want := range before {
		got, _ := json.Marshal(outs[i])
		if string(got) != string(want) {
			t.Fatal("fixed object identity/options changed")
		}
	}
	fixed := outs[1].(map[string]any)
	warm := outs[4].(map[string]any)
	if fixed["tag"] != "node-1" || warm["tag"] != "warm-1" || fixed["server"] != warm["server"] {
		t.Fatal("independent fixed leaf missing")
	}
}

func TestWarmReusePlanExplicitMembership(t *testing.T) {
	raw, nodes, cfg, m := warmReuseFixture(t, 2, true)
	finalizeLiveSelection(raw, nodes, nodes[0], cfg, false, m)
	if liveSelectionPlanFromManifest(cfg, m) == nil {
		t.Fatal("positive plan missing")
	}
	// A non-member AnyTLS origin must not gain switch authority from its spelling.
	fake := nodeOrigin(m, nodes, "n1", "live-leaf-foreign")
	m.Outbounds = append(m.Outbounds, fake)
	plan := liveSelectionPlanFromManifest(cfg, m)
	if plan == nil || plan.Nodes["n1"] != "warm-1" {
		t.Fatal("prefix granted authority")
	}
	for i := range m.Outbounds {
		if m.Outbounds[i].Tag == "warm-1" {
			m.Outbounds[i].NodeLabel = nil
		}
	}
	if liveSelectionPlanFromManifest(cfg, m) != nil {
		t.Fatal("missing member origin admitted")
	}
}

func TestWarmReuseOrdinaryRuntimeStaysStatic(t *testing.T) {
	raw, _, _, _ := warmReuseFixture(t, 2, true)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	o := runtimeOptions{Command: "check", Config: path, NodeName: "n0", Mode: "tun"}
	compiled, err := prepareRuntimeWithRecords(&o)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.livePlan != nil || compiled.Manifest == nil {
		t.Fatal("ordinary runtime control metadata changed")
	}
	var cfg struct {
		Outbounds []struct {
			Tag string `json:"tag"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(compiled.JSON, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Outbounds) != 2 || cfg.Outbounds[0].Tag != "anytls-out" || cfg.Outbounds[1].Tag != "direct" {
		t.Fatal("nonstaged graph expanded")
	}
}

func BenchmarkWarmReuse(b *testing.B) {
	for _, count := range []int{1, 20, 200} {
		for _, sdk := range []bool{false, true} {
			b.Run(fmt.Sprintf("nodes=%d/sdk=%t", count, sdk), func(b *testing.B) {
				raw, nodes, _, _ := warmReuseFixture(b, count, true)
				objects := 0
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					cfg, err := buildNode(nodes[0], "tun", 0, false)
					if err != nil {
						b.Fatal(err)
					}
					if err := applyRoutingRecords("nonstaged-fixture.yaml", raw, nodes, nodes[0], cfg, false, nil); err != nil {
						b.Fatal(err)
					}
					finalizeLiveSelection(raw, nodes, nodes[0], cfg, false, nil)
					objects = len(cfg["outbounds"].([]any))
					// Accept historical and optimized graphs for paired measurements;
					// TestWarmReuseObjectCounts enforces the optimized count separately.
					if objects != count+3 && objects != 2*count+3 {
						b.Fatalf("unexpected objects=%d", objects)
					}
					encoded, err := json.Marshal(cfg)
					if err != nil {
						b.Fatal(err)
					}
					if sdk {
						if err := engine.CheckControlled(context.Background(), encoded); err != nil {
							b.Fatal(err)
						}
					}
				}
				b.ReportMetric(float64(objects), "outbounds/op")
			})
		}
	}
}
