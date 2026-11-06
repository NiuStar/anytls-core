package main

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	"github.com/NiuStar/anytls-core/internal/engine"
	"gopkg.in/yaml.v3"
)

// Uses only pre-existing compiler APIs so these exact bytes run on the baseline.
func TestInitialAddressFamilyCompiledPolicy(t *testing.T) {
	for _, mode := range []string{"tun", "proxy"} {
		for index, policy := range []string{"", "ipv6: false\n", "ipv6: true\n", "flag: &family true\nipv6: *family\n", "flag: &family false\nipv6: *family\n", "base: &base {ipv6: true}\n<<: *base\n", "base: &base {ipv6: true}\n<<: *base\nipv6: false\n"} {
			t.Run(fmt.Sprintf("%s/policy-%d", mode, index), func(t *testing.T) {
				o, original, _ := recordsCompilerFixture(t, " - RULE-SET,local,DIRECT\n - MATCH,outer\n")
				// Family semantics also work without optional uTLS build support.
				original = []byte(strings.ReplaceAll(string(original), "password: compiler-secret,", "client-fingerprint: golang, password: compiler-secret,"))
				o.Mode = mode
				source := append([]byte(policy), original...)
				runtimeWrite(t, o.Config, source, 0600)
				c, err := prepareRuntimeWithRecords(&o)
				if err != nil {
					t.Fatal(err)
				}
				var cfg map[string]any
				if err = json.Unmarshal(c.JSON, &cfg); err != nil {
					t.Fatal(err)
				}
				if mode == "tun" {
					dual := strings.Contains(policy, "true") && !strings.HasSuffix(policy, "ipv6: false\n")
					want := []any{"172.19.0.1/30"}
					if dual {
						want = append(want, "fdfe:dcba:9876::1/126")
					}
					in := cfg["inbounds"].([]any)[0].(map[string]any)
					if !reflect.DeepEqual(in["address"], want) || in["auto_route"] != true {
						t.Errorf("initial TUN address policy: got %#v want %#v", in, want)
					}
					dns := cfg["dns"].(map[string]any)
					if !dual && dns["strategy"] != "ipv4_only" {
						t.Errorf("initial DNS policy must be ipv4_only: %#v", dns)
					}
					if dual && dns["strategy"] != nil {
						t.Errorf("explicit dual must preserve original DNS strategy: %#v", dns)
					}
					if dns["final"] != "secure-dns" || dns["reverse_mapping"] != true {
						t.Error("lost strict unified DNS")
					}
					for _, raw := range cfg["route"].(map[string]any)["rules"].([]any) {
						rule := raw.(map[string]any)
						if rule["action"] == "resolve" {
							want := "ipv4_only"
							if dual {
								want = "prefer_ipv4"
							}
							if rule["strategy"] != want {
								t.Errorf("resolve action overrides initial policy: %v want %s", rule, want)
							}
						}
					}
				} else if dns, ok := cfg["dns"].(map[string]any); ok && dns["strategy"] != nil {
					t.Error("TUN policy leaked into proxy")
				}
				m := c.Manifest
				if m == nil || m.RuntimeSHA256 != shaHex(c.JSON) || m.CapturedSources[0].SHA256 == nil || *m.CapturedSources[0].SHA256 != shaHex(source) {
					t.Fatal("compiled policy/source binding missing")
				}
				if d, err := cr.ManifestDigest(*m, cr.ManifestBudget(m)); err != nil || d != m.ManifestID {
					t.Fatal("manifest digest", err)
				}
				if err := engine.Check(context.Background(), c.JSON); err != nil {
					t.Fatal("actual SDK Check", err)
				}
			})
		}
	}
}

func TestInitialAddressFamilyStrictYAMLAndConversion(t *testing.T) {
	for _, field := range []string{"ipv6: null\n", "ipv6:\n", "ipv6: off\n", "ipv6: 1\n", "ipv6: 'true'\n", "ipv6: []\n", "ipv6: {}\n", "flag: &f 'false'\nipv6: *f\n", "base: &base {ipv6: null}\n<<: *base\n", "ipv6: true\nipv6: false\n"} {
		t.Run(strings.TrimSpace(field), func(t *testing.T) {
			for _, key := range []string{"nodes", "proxies"} {
				b := []byte(field + key + ":\n - {name: a, type: anytls, server: 127.0.0.1, port: 443, password: fixture, skip-cert-verify: true}\n")
				if _, err := loadNodesBytes(b); err == nil {
					t.Error(key + ": loader silently accepted malformed ipv6")
				}
				if _, _, err := webConvertConfiguration(context.Background(), b, false, nil); err == nil {
					t.Error(key + ": converter silently accepted malformed ipv6")
				}
				if err := webValidateConfig("config.yaml", b); err == nil {
					t.Error(key + ": editor silently accepted malformed ipv6")
				}
			}
		})
	}
	for _, value := range []string{"true", "false"} {
		b := []byte("ipv6: " + value + "\nproxies:\n - {name: a, type: anytls, server: 127.0.0.1, port: 443, password: fixture, skip-cert-verify: true}\n")
		out, _, err := webConvertConfiguration(context.Background(), b, false, nil)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err = yaml.Unmarshal(out, &doc); err != nil {
			t.Fatal(err)
		}
		if got, ok := doc["ipv6"].(bool); !ok || got != (value == "true") {
			t.Errorf("conversion dropped/changed explicit %s: %s", value, out)
		}
	}
}
