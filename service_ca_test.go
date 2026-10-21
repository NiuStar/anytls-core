package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/NiuStar/anytls-core/internal/engine"
	"gopkg.in/yaml.v3"
)

func caSnapshotFixture(t *testing.T, ca string) (string, string, string, string) {
	t.Helper()
	d := t.TempDir()
	source := filepath.Join(d, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	binary, config, core := filepath.Join(source, "app"), filepath.Join(source, "config.yaml"), filepath.Join(source, "core")
	runtimeWrite(t, binary, []byte("application"), 0700)
	runtimeWrite(t, core, []byte("external core"), 0700)
	runtimeWrite(t, config, []byte(fmt.Sprintf("proxies:\n - {name: a, type: anytls, server: 127.0.0.1, port: 443, password: synthetic, sni: g21.invalid, ca: %q}\n", ca)), 0644)
	runtimeWrite(t, selectedPath(config), []byte("a\n"), 0600)
	return binary, config, core, filepath.Join(d, "snapshot")
}

func caSnapshotRuntime(t *testing.T, config string) map[string]any {
	t.Helper()
	nodes, err := loadNodes(config)
	if err != nil {
		t.Fatal(err)
	}
	n, err := selectedServiceNode(config)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := buildNode(n, "proxy", 11081, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyRouting(config, nodes, n, cfg, false); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestServiceCAFreezeSourceIndependent(t *testing.T) {
	ca, _ := runtimeCertificate(t)
	path := filepath.Join(t.TempDir(), "external.pem")
	runtimeWrite(t, path, ca, 0644)
	binary, config, core, root := caSnapshotFixture(t, path)
	before := caSnapshotRuntime(t, config)
	if err := stagePrivateRun(binary, config, core, root); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(root, "config.yaml")
	nodes, err := loadNodes(staged)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "certs", shaHex(ca)+".pem")
	if nodes[0].CA != want {
		t.Fatal("required CA was not frozen into content-addressed snapshot")
	}
	for name, mode := range map[string]os.FileMode{"certs": 0700, filepath.Join("certs", shaHex(ca)+".pem"): 0600} {
		st, err := os.Stat(filepath.Join(root, name))
		if err != nil || st.Mode().Perm() != mode {
			t.Fatalf("CA mode mismatch: %v", err)
		}
	}
	got, err := os.ReadFile(want)
	if err != nil || !bytes.Equal(got, ca) || shaHex(got) != shaHex(ca) {
		t.Fatal("CA bytes/SHA changed")
	}
	runtimeWrite(t, path, []byte("source changed"), 0644)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	after := caSnapshotRuntime(t, staged)
	oldOut := before["outbounds"].([]any)[0].(map[string]any)
	newOut := after["outbounds"].([]any)[0].(map[string]any)
	if oldOut["tls"].(map[string]any)["certificate_path"] != path || newOut["tls"].(map[string]any)["certificate_path"] != want {
		t.Fatal("compiler CA path mismatch")
	}
	b, err := json.Marshal(after)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Check(context.Background(), b); err != nil {
		t.Fatalf("strict snapshot engine.Check: %v", err)
	}
}

func TestServiceCAReferencedNodesAndRules(t *testing.T) {
	ca, _ := runtimeCertificate(t)
	d := t.TempDir()
	first, second := filepath.Join(d, "a.pem"), filepath.Join(d, "b.pem")
	runtimeWrite(t, first, ca, 0644)
	runtimeWrite(t, second, ca, 0644)
	binary, config, core, root := caSnapshotFixture(t, first)
	data, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	rule := []byte(`{"version":3,"rules":[{"domain_suffix":["example.invalid"]}]}`)
	runtimeWrite(t, filepath.Join(filepath.Dir(config), "source.json"), rule, 0644)
	data = append(data, []byte(fmt.Sprintf(" - {name: unused, type: anytls, ca: /missing/unused.pem, opaque: [keep, order]}\n - {name: unsupported, type: ss, ca: /missing/ss.pem}\nnodes:\n - {name: b, type: anytls, server: 127.0.0.2, port: 444, password: synthetic, ca: %q, extra: preserved}\nproxy-groups:\n - {name: inner, type: select, proxies: [a, b, unused], selected: b}\n - {name: outer, type: select, proxies: [inner, DIRECT], selected: inner}\nrule-sets:\n domains: {path: source.json, sha256: %s}\nrules:\n - RULE-SET,domains,outer\n - DOMAIN,other.invalid,b\n - MATCH,DIRECT\nunknown: {keep: [2, 1]}\n", second, shaHex(rule)))...)
	runtimeWrite(t, config, data, 0644)
	before := caSnapshotRuntime(t, config)
	var original map[string]any
	if err := readYAML(config, &original); err != nil {
		t.Fatal(err)
	}
	if err := stagePrivateRun(binary, config, core, root); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(root, "config.yaml")
	var doc map[string]any
	if err := readYAML(staged, &doc); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "certs", shaHex(ca)+".pem")
	original["proxies"].([]any)[0].(map[string]any)["ca"] = want
	original["nodes"].([]any)[0].(map[string]any)["ca"] = want
	original["rule-sets"].(map[string]any)["domains"].(map[string]any)["path"] = "rules/domains.json"
	if !reflect.DeepEqual(doc, original) {
		t.Fatal("unrelated YAML fields/order/unknowns changed")
	}
	entries, err := os.ReadDir(filepath.Join(root, "certs"))
	if err != nil || len(entries) != 1 {
		t.Fatal("equal-content CA files were not deduplicated")
	}
	if err := os.RemoveAll(filepath.Dir(config)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(first); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(second); err != nil {
		t.Fatal(err)
	}
	after := caSnapshotRuntime(t, staged)
	for _, entry := range before["outbounds"].([]any) {
		out := entry.(map[string]any)
		if out["type"] == "anytls" {
			out["tls"].(map[string]any)["certificate_path"] = want
		}
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("routing runtime changed beyond CA paths")
	}
	b, err := json.Marshal(after)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Check(context.Background(), b); err != nil {
		t.Fatalf("group/rule snapshot engine.Check: %v", err)
	}
	var typed struct {
		Sets map[string]fileRuleSet `yaml:"rule-sets"`
	}
	if err := readYAML(staged, &typed); err != nil {
		t.Fatal(err)
	}
	spec := typed.Sets["domains"]
	if spec.Path != "rules/domains.json" || spec.SHA256 != shaHex(rule) {
		t.Fatal("CA rewrite reverted rule path/SHA")
	}
	runtimeWrite(t, filepath.Join(root, spec.Path), []byte("tampered"), 0600)
	if _, err := loadRuleSet(staged, "domains", spec); err == nil {
		t.Fatal("rule integrity check lost")
	}
}

func TestServiceCARelativeUsesCallerCWD(t *testing.T) {
	// No Parallel: t.Chdir restores process CWD; config-directory CA is a decoy.
	cwd := t.TempDir()
	t.Chdir(cwd)
	ca, _ := runtimeCertificate(t)
	runtimeWrite(t, "relative.pem", ca, 0644)
	binary, config, core, root := caSnapshotFixture(t, "relative.pem")
	decoy, _ := runtimeCertificate(t)
	runtimeWrite(t, filepath.Join(filepath.Dir(config), "relative.pem"), decoy, 0644)
	before := caSnapshotRuntime(t, config)
	if before["outbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)["certificate_path"] != filepath.Join(cwd, "relative.pem") {
		t.Fatal("baseline not caller-CWD resolved")
	}
	if err := stagePrivateRun(binary, config, core, root); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "certs", shaHex(ca)+".pem")
	got, err := os.ReadFile(want)
	if err != nil || !bytes.Equal(got, ca) {
		t.Fatal("relative CA bytes came from config directory")
	}
	if err := os.Remove("relative.pem"); err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	after := caSnapshotRuntime(t, filepath.Join(root, "config.yaml"))
	if after["outbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)["certificate_path"] != want {
		t.Fatal("staged absolute CA depends on cwd")
	}
}

func TestServiceCAValidation(t *testing.T) {
	ca, _ := runtimeCertificate(t)
	for _, kind := range []string{"invalid", "missing", "empty", "directory", "oversize", "private-key", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ca.pem")
			switch kind {
			case "missing":
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(t.TempDir(), "target.pem")
				runtimeWrite(t, target, ca, 0644)
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			default:
				data := []byte("not a certificate")
				if kind == "empty" {
					data = nil
				}
				if kind == "oversize" {
					data = []byte(strings.Repeat("x", (1<<20)+1))
				}
				if kind == "private-key" {
					data = append(append([]byte{}, ca...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("synthetic-key")})...)
				}
				runtimeWrite(t, path, data, 0644)
			}
			binary, config, core, root := caSnapshotFixture(t, path)
			err := stagePrivateRun(binary, config, core, root)
			if kind == "symlink" {
				if err != nil {
					t.Fatalf("existing source symlink semantics rejected: %v", err)
				}
				st, err := os.Lstat(filepath.Join(root, "certs", shaHex(ca)+".pem"))
				if err != nil || !st.Mode().IsRegular() {
					t.Fatal("CA snapshot not regular")
				}
			} else if err == nil {
				t.Fatal("invalid required CA accepted")
			}
		})
	}
}

func TestServiceCARejectUnconsumedPEM(t *testing.T) {
	ca, pair := runtimeCertificate(t)
	key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	truncated := private[:bytes.Index(private, []byte("-----END"))]
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	for name, data := range map[string][]byte{
		"truncated-private-key":            join(ca, truncated),
		"certificate-labelled-private-key": join(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: key})),
		"leading-text":                     join([]byte("malformed\n"), ca),
		"intermediate-text":                join(ca, []byte("malformed\n"), ca),
		"trailing-text":                    join(ca, []byte("malformed\n")),
		"leading-malformed-block":          join(truncated, ca),
		"intermediate-malformed-block":     join(ca, truncated, ca),
		"invalid-certificate-der":          join(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid DER")})),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ca.pem")
			runtimeWrite(t, path, data, 0600)
			if _, err := readSnapshotCA(path); err == nil {
				t.Fatal("malformed or unconsumed PEM accepted")
			}
		})
	}
	t.Run("multiple-valid-certificates-original-bytes", func(t *testing.T) {
		second, _ := runtimeCertificate(t)
		data := join([]byte(" \r\n\t"), ca, []byte("\n\t"), second, []byte(" \r\n"))
		path := filepath.Join(t.TempDir(), "bundle.pem")
		runtimeWrite(t, path, data, 0600)
		got, err := readSnapshotCA(path)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("valid bundle bytes changed or rejected: %v", err)
		}
	})
}

// Record tag/value/order, not presentation (indentation, comments and line numbers).
func snapshotYAMLScalars(n *yaml.Node) []string {
	out := []string{fmt.Sprintf("%d:%s:%s", n.Kind, n.Tag, n.Value)}
	for _, child := range n.Content {
		out = append(out, snapshotYAMLScalars(child)...)
	}
	return out
}

func TestServiceCAScalarPreservation(t *testing.T) {
	for _, rules := range []bool{false, true} {
		t.Run(fmt.Sprint(rules), func(t *testing.T) {
			d := t.TempDir()
			t.Chdir(d)
			ca, _ := runtimeCertificate(t)
			runtimeWrite(t, "00123", ca, 0600)
			binary, config, core, root := caSnapshotFixture(t, "00123")
			data := "proxies:\n - {name: 123, type: anytls, server: 127.0.0.1, port: 443, password: 00123, sni: g21.invalid, ca: 00123}\n - {name: unused, type: anytls, ca: 00999, password: 00012}\nnodes:\n - {name: unsupported, type: ss, ca: 00123, password: 00123}\nproxy-groups:\n - {name: 456, type: select, proxies: [123, DIRECT], selected: 123}\nunknown: {integer: 00123, float: 1.20, string: !!str 00123, nested: [123, 00123, null]}\n"
			rule := []byte(`{"version":3,"rules":[{"domain_suffix":["example.invalid"]}]}`)
			if rules {
				runtimeWrite(t, filepath.Join(filepath.Dir(config), "source.json"), rule, 0600)
				data += "rule-sets:\n 123: {path: source.json, sha256: " + shaHex(rule) + ", unknown: 00123}\nrules:\n - RULE-SET,123,456\n - MATCH,456\n"
			} else {
				data += "rules:\n - MATCH,456\n"
			}
			runtimeWrite(t, config, []byte(data), 0644)
			runtimeWrite(t, selectedPath(config), []byte("123\n"), 0600)
			beforeNodes, err := loadNodes(config)
			if err != nil || beforeNodes[0].Name != "123" || beforeNodes[0].Password != "00123" || beforeNodes[0].CA != "00123" {
				t.Fatalf("fixture typed semantics invalid: %v", err)
			}
			before := caSnapshotRuntime(t, config)
			var expected yaml.Node
			if err := yaml.Unmarshal([]byte(data), &expected); err != nil {
				t.Fatal(err)
			}
			want := filepath.Join(root, "certs", shaHex(ca)+".pem")
			// Adjust only the two permitted path leaves in the expected tree.
			mapping := expected.Content[0]
			for i := 0; i < len(mapping.Content); i += 2 {
				value := mapping.Content[i+1]
				switch mapping.Content[i].Value {
				case "proxies":
					entry := value.Content[0]
					for j := 0; j < len(entry.Content); j += 2 {
						if entry.Content[j].Value == "ca" {
							entry.Content[j+1].Tag, entry.Content[j+1].Value = "!!str", want
						}
					}
				case "rule-sets":
					entry := value.Content[1]
					entry.Content[1].Tag, entry.Content[1].Value = "!!str", "rules/123.json"
				}
			}
			if err := stagePrivateRun(binary, config, core, root); err != nil {
				t.Fatal(err)
			}
			staged := filepath.Join(root, "config.yaml")
			var actual yaml.Node
			if err := readYAML(staged, &actual); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(snapshotYAMLScalars(&actual), snapshotYAMLScalars(&expected)) {
				t.Error("unrelated YAML scalar tag/value/order changed or required path not rewritten")
			}
			beforeNodes[0].CA = want
			afterNodes, err := loadNodes(staged)
			if err != nil || !reflect.DeepEqual(beforeNodes, afterNodes) {
				t.Errorf("typed node/name/password semantics changed: %v", err)
			}
			if err := os.Remove("00123"); err != nil {
				t.Fatal(err)
			}
			if err := os.RemoveAll(filepath.Dir(config)); err != nil {
				t.Fatal(err)
			}
			after := caSnapshotRuntime(t, staged)
			for _, entry := range before["outbounds"].([]any) {
				out := entry.(map[string]any)
				if out["type"] == "anytls" {
					out["tls"].(map[string]any)["certificate_path"] = want
				}
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("runtime semantics changed beyond CA/rule paths")
			}
			b, err := json.Marshal(after)
			if err != nil {
				t.Fatal(err)
			}
			if err := engine.Check(context.Background(), b); err != nil {
				t.Fatalf("scalar snapshot engine.Check: %v", err)
			}
		})
	}
}

// Count required CA-bearing nodes, not rule references or distinct source paths.
func TestServiceCARequiredReferenceBoundary(t *testing.T) {
	for _, tc := range []struct {
		name  string
		count int
		mixed bool
	}{
		{"128-shared-CA-and-MATCH-DIRECT", 128, false},
		{"128-shared-CA-mixed-duplicate-unused", 128, true},
		{"129-shared-CA-rejected", 129, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca, _ := runtimeCertificate(t)
			path := filepath.Join(t.TempDir(), "shared.pem")
			runtimeWrite(t, path, ca, 0644)
			binary, config, core, root := caSnapshotFixture(t, path)
			var data strings.Builder
			data.WriteString("proxies:\n")
			for i := 0; i < tc.count; i++ {
				fmt.Fprintf(&data, " - {name: ca%d, type: anytls, server: 127.0.0.1, port: 443, password: synthetic, ca: %q}\n", i, path)
			}
			if tc.mixed {
				data.WriteString(" - {name: ca-less, type: anytls, server: 127.0.0.1, port: 443, password: synthetic, skip-cert-verify: true}\n")
				for i := 0; i < 129; i++ {
					fmt.Fprintf(&data, " - {name: unused%d, type: anytls, ca: /missing/unused.pem}\n", i)
				}
			}
			data.WriteString("rules:\n")
			for i := 0; i < tc.count; i++ {
				fmt.Fprintf(&data, " - DOMAIN,node%d.invalid,ca%d\n", i, i)
				if tc.mixed {
					fmt.Fprintf(&data, " - DOMAIN,duplicate%d.invalid,ca%d\n", i, i)
				}
			}
			if tc.mixed {
				data.WriteString(" - DOMAIN,ca-less.invalid,ca-less\n - DOMAIN,reject.invalid,REJECT\n - DOMAIN,direct.invalid,DIRECT\n")
			}
			data.WriteString(" - MATCH,DIRECT\n")
			runtimeWrite(t, config, []byte(data.String()), 0644)
			runtimeWrite(t, selectedPath(config), []byte("ca0\n"), 0600)
			err := stagePrivateRun(binary, config, core, root)
			if tc.count == 129 {
				if err == nil || !strings.Contains(err.Error(), "too many CA references") {
					t.Fatalf("129 required CA nodes sharing one source must hit node-reference cap: %v", err)
				}
				if _, err := os.Lstat(filepath.Join(root, "certs")); !os.IsNotExist(err) {
					t.Fatal("CA reference cap was not enforced before copying")
				}
				return
			}
			if err != nil {
				t.Fatalf("128 required CA nodes plus non-CA targets must be accepted: %v", err)
			}
			staged, err := loadNodes(filepath.Join(root, "config.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			want := filepath.Join(root, "certs", shaHex(ca)+".pem")
			for i, n := range staged {
				switch {
				case i < tc.count:
					if n.CA != want {
						t.Fatalf("required CA node %d not rewritten", i)
					}
				case n.Name == "ca-less":
					if n.CA != "" {
						t.Fatal("CA-less target changed")
					}
				default:
					if n.CA != "/missing/unused.pem" {
						t.Fatal("unused CA changed")
					}
				}
			}
			entries, err := os.ReadDir(filepath.Join(root, "certs"))
			if err != nil || len(entries) != 1 {
				t.Fatalf("shared CA must produce exactly one leaf: %v", err)
			}
			got, err := os.ReadFile(want)
			if err != nil || !bytes.Equal(got, ca) {
				t.Fatalf("shared CA bytes changed: %v", err)
			}
		})
	}
}

func TestServiceCANoRequiredCAIsNoop(t *testing.T) {
	for _, unused := range []bool{false, true} {
		t.Run(fmt.Sprint(unused), func(t *testing.T) {
			binary, config, core, root := caSnapshotFixture(t, "")
			data := []byte("proxies:\n - {name: a, type: anytls, server: 127.0.0.1, port: 443, password: synthetic, skip-cert-verify: true}\n")
			if unused {
				data = append(data, []byte(" - {name: unused, type: anytls, ca: /missing/unused.pem}\n")...)
			}
			runtimeWrite(t, config, data, 0644)
			if err := stagePrivateRun(binary, config, core, root); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filepath.Join(root, "config.yaml"))
			if err != nil || !bytes.Equal(got, data) {
				t.Fatal("no required CA caused extraneous config rewrite")
			}
			if _, err := os.Lstat(filepath.Join(root, "certs")); !os.IsNotExist(err) {
				t.Fatal("no required CA created certs")
			}
			got, err = os.ReadFile(selectedPath(filepath.Join(root, "config.yaml")))
			if err != nil || string(got) != "a\n" {
				t.Fatal("selection bytes changed")
			}
		})
	}
}
