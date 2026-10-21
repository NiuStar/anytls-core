package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestStageRuleSetsScalarPreservation(t *testing.T) {
	d := t.TempDir()
	config, root := filepath.Join(d, "config.yaml"), filepath.Join(d, "snapshot")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	rule := []byte(`{"version":3,"rules":[{"domain_suffix":["example.invalid"]}]}`)
	runtimeWrite(t, filepath.Join(d, "source.json"), rule, 0600)
	data := []byte("proxies:\n - {name: 123, type: anytls, password: 00123, ca: 00123}\nrule-sets:\n 123: {path: source.json, sha256: " + shaHex(rule) + ", unknown: 00123}\nunknown: {number: 00123, string: !!str 00123}\n")
	runtimeWrite(t, config, data, 0600)
	runtimeWrite(t, filepath.Join(root, "config.yaml"), data, 0600)
	if err := stageRuleSets(config, root); err != nil {
		t.Fatal(err)
	}
	var actual, expected yaml.Node
	if err := readYAML(filepath.Join(root, "config.yaml"), &actual); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(bytes.Replace(data, []byte("path: source.json"), []byte("path: rules/123.json"), 1), &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(snapshotYAMLScalars(&actual), snapshotYAMLScalars(&expected)) {
		t.Fatal("rule-set rewrite corrupted unrelated scalar tags/values or unknown fields")
	}
	nodes, err := loadNodes(filepath.Join(root, "config.yaml"))
	if err != nil || nodes[0].Name != "123" || nodes[0].Password != "00123" || nodes[0].CA != "00123" {
		t.Fatalf("rule-set rewrite changed typed string semantics: %v", err)
	}
}

func TestServiceCAAliasMergeFailClosed(t *testing.T) {
	for _, kind := range []string{"entry-alias", "merge", "ca-alias", "top-merge", "rule-set-alias", "rule-set-merge"} {
		t.Run(kind, func(t *testing.T) {
			ca, _ := runtimeCertificate(t)
			path := filepath.Join(t.TempDir(), "ca.pem")
			runtimeWrite(t, path, ca, 0600)
			binary, config, core, root := caSnapshotFixture(t, path)
			data, err := os.ReadFile(config)
			if err != nil {
				t.Fatal(err)
			}
			s := string(data)
			switch kind {
			case "entry-alias":
				s = strings.Replace(s, "proxies:\n - ", "template: &entry ", 1) + "proxies: [*entry]\n"
			case "merge":
				s = strings.Replace(s, "proxies:\n - ", "template: &entry ", 1) + "proxies:\n - {<<: *entry}\n"
			case "ca-alias":
				s = strings.Replace(s, "ca: ", "ca: &ca ", 1) + "unknown: *ca\n"
			case "top-merge":
				s = "template: &top\n " + strings.ReplaceAll(s, "\n", "\n ") + "\n<<: *top\n"
			case "rule-set-alias", "rule-set-merge":
				rule := []byte(`{"version":3,"rules":[{"domain_suffix":["example.invalid"]}]}`)
				runtimeWrite(t, filepath.Join(filepath.Dir(config), "source.json"), rule, 0600)
				s += "template: &spec {path: source.json, sha256: " + shaHex(rule) + "}\nrule-sets:\n domains: "
				if kind == "rule-set-alias" {
					s += "*spec\n"
				} else {
					s += "{<<: *spec}\n"
				}
			}
			runtimeWrite(t, config, []byte(s), 0600)
			// Establish that the existing typed loader accepts this fixture.
			nodes, err := loadNodes(config)
			if err != nil || len(nodes) != 1 || nodes[0].Name != "a" || nodes[0].CA != path {
				t.Fatalf("alias/merge fixture not accepted by loadNodes: %v", err)
			}
			if err := stagePrivateRun(binary, config, core, root); err == nil || !strings.Contains(err.Error(), "aliases or merges") {
				t.Fatalf("alias/merge snapshot must fail closed, got: %v", err)
			}
			got, err := os.ReadFile(filepath.Join(root, "config.yaml"))
			if err != nil || !bytes.Equal(got, []byte(s)) {
				t.Fatal("failed rewrite published changed YAML")
			}
		})
	}
}
