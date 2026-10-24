package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Decode fixtures through the pre-existing API so identical tests compile on
// the frozen baseline; RED must be a trust assertion, not a missing field.
func trustFixtureNode(t *testing.T, pin any, extra map[string]any) node {
	t.Helper()
	m := map[string]any{"name": "pinned", "type": "anytls", "server": "203.0.113.7", "port": 8443, "password": "test-only"}
	if pin != nil {
		m["certificate-public-key-sha256"] = pin
	}
	for k, v := range extra {
		m[k] = v
	}
	b, err := yaml.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var n node
	if err := yaml.Unmarshal(b, &n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestNodeSPKITrust(t *testing.T) {
	pin := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{255}, 32))
	for _, fingerprint := range []string{"", "chrome"} {
		for _, mode := range []string{"proxy", "tun"} {
			t.Run(mode+"/"+fingerprint, func(t *testing.T) {
				n := trustFixtureNode(t, pin, map[string]any{"client-fingerprint": fingerprint, "skip-cert-verify": false})
				cfg, err := buildNode(n, mode, 11080, false)
				if err != nil {
					t.Fatalf("valid pin-only trust rejected: %v", err)
				}
				tls := cfg["outbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)
				if !reflect.DeepEqual(tls["certificate_public_key_sha256"], []string{pin}) || tls["enabled"] != true {
					t.Fatalf("pin not passed unchanged to SDK: %#v", tls)
				}
				if tls["insecure"] == true || tls["certificate_path"] != nil || tls["certificate"] != nil {
					t.Fatalf("pin-only trust downgraded or mixed: %#v", tls)
				}
				if fingerprint != "" && tls["utls"].(map[string]any)["fingerprint"] != fingerprint {
					t.Fatal("uTLS fingerprint changed")
				}
				encoded, err := yaml.Marshal(n)
				if err != nil || !bytes.Contains(encoded, []byte("certificate-public-key-sha256: ")) {
					t.Fatal("pin lost in YAML roundtrip")
				}
			})
		}
	}
}

func TestNodeSPKIRejectInvalidAndConflictingTrust(t *testing.T) {
	pin := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{255}, 32))
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, []byte("existing CA path policy"), 0600); err != nil {
		t.Fatal(err)
	}
	bad := []string{"invalid", strings.Repeat("a", 64), base64.StdEncoding.EncodeToString(make([]byte, 31)), base64.StdEncoding.EncodeToString(make([]byte, 33)), strings.TrimSuffix(pin, "="), base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{255}, 32)), pin + "\n", " " + pin, pin[:42] + "9="}
	for i, value := range bad {
		for _, extra := range []map[string]any{nil, {"skip-cert-verify": true}, {"ca": ca}} {
			n := trustFixtureNode(t, value, extra)
			if _, err := buildNode(n, "proxy", 11080, true); err == nil {
				t.Fatalf("invalid pin %d accepted or downgraded", i)
			}
		}
	}
	for _, extra := range []map[string]any{{"skip-cert-verify": true}, {"ca": ca}, {"ca": "/missing"}} {
		for _, allow := range []bool{false, true} {
			if _, err := buildNode(trustFixtureNode(t, pin, extra), "proxy", 11080, allow); err == nil {
				t.Fatal("ambiguous pin trust accepted")
			}
		}
	}
	if _, err := buildNode(trustFixtureNode(t, nil, nil), "proxy", 11080, true); err == nil {
		t.Fatal("missing trust accepted")
	}
	if _, err := buildNode(trustFixtureNode(t, pin, map[string]any{"server": "example.com"}), "tun", 0, false); err == nil {
		t.Fatal("pin bypassed TUN fixed-IP restriction")
	}
}

func TestConversionSPKITrust(t *testing.T) {
	pin := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{255}, 32))
	for _, key := range []string{"nodes", "proxies"} {
		for _, remote := range []bool{false, true} {
			input := []byte(key + ":\n - {name: pinned, type: anytls, server: 203.0.113.7, port: 8443, password: test-only, skip-cert-verify: false, client-fingerprint: chrome, certificate-public-key-sha256: '" + pin + "'}\n")
			out, report, err := webConvertConfiguration(context.Background(), input, remote, nil)
			if err != nil || len(report.Issues) != 0 || len(report.Skipped) != 0 {
				t.Fatalf("%s valid pin conversion failed: %v %+v", key, err, report)
			}
			nodes, err := loadNodesBytes(out)
			if err != nil || len(nodes) != 1 {
				t.Fatalf("lost pinned node: %v", err)
			}
			if _, err := buildNode(nodes[0], "proxy", 11080, false); err != nil {
				t.Fatalf("converted pin unusable: %v", err)
			}
			if key == "nodes" && !bytes.Equal(input, out) {
				t.Fatal("unchanged native pin configuration rewritten")
			}
		}
		for _, trust := range []string{"certificate-public-key-sha256: invalid", "certificate-public-key-sha256: '" + pin + "', skip-cert-verify: true", "certificate-public-key-sha256: '" + pin + "', ca: /missing", "certificate-public-key-sha256: [invalid]", "certificate-public-key-sha256: null, skip-cert-verify: true", "certificate-public-key-sha256: '', skip-cert-verify: true", "certificate-public-key-sha256: 123, skip-cert-verify: true"} {
			input := []byte(key + ":\n - {name: good, type: anytls, server: 203.0.113.8, port: 443, password: test-only, skip-cert-verify: true}\n - {name: bad, type: anytls, server: 203.0.113.7, port: 8443, password: test-only, " + trust + "}\n")
			out, report, err := webConvertConfiguration(context.Background(), input, false, nil)
			if err != nil {
				continue // Explicit whole-conversion refusal is also fail-closed.
			}
			nodes, err := loadNodesBytes(out)
			if err != nil || len(nodes) != 1 || nodes[0].Name != "good" || len(report.Skipped) == 0 {
				t.Fatalf("%s invalid pin retained or silently stripped: %v %+v", key, err, report)
			}
			encoded, _ := json.Marshal(report)
			if bytes.Contains(encoded, []byte(pin)) || bytes.Contains(encoded, []byte("/missing")) {
				t.Fatal("trust values leaked in report")
			}
		}
	}
}
