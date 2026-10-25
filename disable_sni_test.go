package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/NiuStar/anytls-core/internal/engine"
	"gopkg.in/yaml.v3"
)

// Existing node/buildNode APIs keep this identical test runnable on the baseline.
func TestDisableSNIBuildNode(t *testing.T) {
	for _, mode := range []string{"proxy", "tun"} {
		for _, setting := range []string{"", ", disable-sni: false", ", disable-sni: true"} {
			t.Run(mode+setting, func(t *testing.T) {
				input := []byte("nodes:\n - {name: P, type: anytls, server: 127.0.0.1, port: 443, password: synthetic-only, sni: reference.invalid, fingerprint: '" + strings.Repeat("ab", 32) + "'" + setting + "}\n")
				nodes, err := loadNodesBytes(input)
				if err != nil {
					t.Fatal(err)
				}
				cfg, err := buildNode(nodes[0], mode, 11080, false)
				if err != nil {
					t.Fatal(err)
				}
				b, err := json.Marshal(cfg)
				if err != nil {
					t.Fatal(err)
				}
				var runtime map[string]any
				if err := json.Unmarshal(b, &runtime); err != nil {
					t.Fatal(err)
				}
				tls := runtime["outbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)
				if tls["server_name"] != "reference.invalid" || tls["insecure"] != nil || tls["certificate_sha256"] == nil {
					t.Fatalf("reference name or strict pin changed: %#v", tls)
				}
				if setting == ", disable-sni: true" {
					if tls["disable_sni"] != true {
						t.Fatalf("explicit disable-sni missing from runtime JSON: %#v", tls)
					}
				} else if _, present := tls["disable_sni"]; present {
					t.Fatal("default/false runtime changed")
				}
			})
		}
	}
}

func TestDisableSNIRejectNonBool(t *testing.T) {
	for _, value := range []string{"null", "", "~", "'true'", "'false'", "1", "0", "[]", "{}", "yes"} {
		t.Run(fmt.Sprintf("%q", value), func(t *testing.T) {
			input := []byte("nodes:\n - {name: P, type: anytls, server: 127.0.0.1, port: 443, password: synthetic-only, skip-cert-verify: true, disable-sni: " + value + "}\n")
			if _, err := loadNodesBytes(input); err == nil {
				t.Fatal("explicit non-bool disable-sni accepted")
			}
		})
	}
	// Ordinary scalar aliases and merge inheritance retain the same bool policy.
	for _, input := range []string{
		"flag: &f true\nnodes:\n - {name: P, disable-sni: *f}\n",
		"base: &b {disable-sni: true}\nnodes:\n - {name: P, <<: *b}\n",
	} {
		nodes, err := loadNodesBytes([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := yaml.Marshal(nodes[0])
		if !bytes.Contains(b, []byte("disable-sni: true")) {
			t.Fatal("bool alias/merge lost")
		}
	}
	for _, input := range []string{
		"flag: &f null\nnodes:\n - {name: P, disable-sni: *f}\n",
		"base: &b {disable-sni: null}\nnodes:\n - {name: P, <<: *b}\n",
	} {
		if _, err := loadNodesBytes([]byte(input)); err == nil {
			t.Fatal("indirect null accepted")
		}
	}
}

func TestDisableSNIConversionEditExport(t *testing.T) {
	for _, key := range []string{"nodes", "proxies"} {
		for _, remote := range []bool{false, true} {
			input := []byte(key + ":\n - {name: P, type: anytls, server: 127.0.0.1, port: 443, password: synthetic-only, sni: reference.invalid, disable-sni: true, fingerprint: '" + strings.Repeat("ab", 32) + "'}\n")
			out, report, err := webConvertConfiguration(context.Background(), input, remote, nil)
			if err != nil || len(report.Skipped) != 0 || len(report.Issues) != 0 {
				t.Fatalf("conversion: %v %+v", err, report)
			}
			if key == "nodes" && !bytes.Equal(out, input) {
				t.Fatal("native no-op changed bytes")
			}
			edited, err := webEditNode(out, webNodeEdit{Name: "P", Server: "127.0.0.2", Port: 443, SNI: "reference.invalid"})
			if err != nil {
				t.Fatal(err)
			}
			nodes, err := loadNodesBytes(edited)
			if err != nil || len(nodes) != 1 {
				t.Fatalf("edit reload: %v", err)
			}
			saved, err := yaml.Marshal(map[string]any{"nodes": nodes})
			if err != nil {
				t.Fatal(err)
			}
			exported, _, err := webConvertConfiguration(context.Background(), saved, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			reloaded, err := loadNodesBytes(exported)
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := buildNode(reloaded[0], "proxy", 11080, false)
			if err != nil {
				t.Fatal(err)
			}
			tls := cfg["outbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)
			if tls["disable_sni"] != true || tls["server_name"] != "reference.invalid" {
				t.Fatal("conversion/edit/save/export erased policy")
			}
		}
		for _, value := range []string{"null", "'true'", "1", "[]", "{}"} {
			input := []byte(key + ":\n - {name: good, type: anytls, server: 127.0.0.1, port: 443, password: synthetic-only, skip-cert-verify: true}\n - {name: bad, type: anytls, server: 127.0.0.2, port: 443, password: synthetic-only, skip-cert-verify: true, disable-sni: " + value + "}\n")
			out, report, err := webConvertConfiguration(context.Background(), input, false, nil)
			if err != nil {
				continue
			}
			nodes, err := loadNodesBytes(out)
			if err != nil || len(nodes) != 1 || nodes[0].Name != "good" || len(report.Skipped) == 0 {
				t.Fatal("invalid disable-sni retained or silently stripped")
			}
		}
	}
}

func TestDisableSNIEngineConstruction(t *testing.T) {
	// Same real Check negative gate with/without with_utls; no wire test is skipped
	// into a claimed success when Chrome is unavailable.
	for _, fp := range []string{"", "chrome", "golang"} {
		n := trustFixtureNode(t, nil, map[string]any{"skip-cert-verify": true, "disable-sni": true, "sni": "reference.invalid", "client-fingerprint": fp})
		cfg, err := buildNode(n, "proxy", 11080, true)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(cfg)
		err = engine.Check(context.Background(), b)
		info, ok := debug.ReadBuildInfo()
		if !ok {
			t.Fatal("build info unavailable")
		}
		withUTLS := false
		for _, s := range info.Settings {
			if s.Key == "-tags" {
				for _, tag := range strings.Split(s.Value, ",") {
					withUTLS = withUTLS || tag == "with_utls"
				}
			}
		}
		if !withUTLS && fp != "golang" {
			if err == nil || !strings.Contains(err.Error(), "uTLS is not included in this build") {
				t.Fatalf("missing uTLS did not fail closed: %v", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		if n.SNI != "reference.invalid" {
			t.Fatal("name mutated")
		}
	}
}
