package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

// Use only the pre-existing YAML/node API: these exact bytes must also compile
// against 5057bee so native RED is a policy failure, not a missing new field.
func tlsSecurityNode(t *testing.T, extra map[string]any) node {
	t.Helper()
	m := map[string]any{"name": "fixture", "type": "anytls", "server": "127.0.0.1", "port": 443, "password": "synthetic-only", "sni": "fixture.invalid"}
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

func TestTLSSecurityMinimumVersion(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, []byte("buildNode file validation fixture; not a handshake certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	pin := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, mode := range []string{"proxy", "tun"} {
		for _, fp := range []string{"", "chrome", "firefox", "golang"} {
			for _, trust := range []string{"ca", "pin", "insecure"} {
				for _, version := range []string{"omitted", "", "1.2", "1.3"} {
					t.Run(mode+"/"+fp+"/"+trust+"/"+version, func(t *testing.T) {
						extra := map[string]any{"client-fingerprint": fp}
						want := map[string]any{"enabled": true, "server_name": "fixture.invalid", "min_version": "1.2"}
						if version != "omitted" {
							extra["tls-min-version"] = version
						}
						if version == "1.3" {
							want["min_version"] = "1.3"
						}
						switch trust {
						case "ca":
							extra["ca"] = ca
							want["certificate_path"] = ca
						case "pin":
							extra["certificate-public-key-sha256"] = pin
							want["certificate_public_key_sha256"] = []any{pin}
						case "insecure":
							extra["skip-cert-verify"] = true
							want["insecure"] = true
						}
						if fp != "golang" {
							fingerprint := fp
							if fingerprint == "" {
								fingerprint = "chrome"
							}
							want["utls"] = map[string]any{"enabled": true, "fingerprint": fingerprint}
						}
						n := tlsSecurityNode(t, extra)
						before := n
						cfg, err := buildNode(n, mode, 11080, trust == "insecure")
						if !reflect.DeepEqual(n, before) {
							t.Fatal("source node mutated")
						}
						if version == "1.3" && fp != "golang" {
							if cfg != nil || err == nil || err.Error() != "tls-min-version 1.3 requires client-fingerprint golang" {
								t.Fatalf("unsupported uTLS floor must reject before runtime config: cfg=%v err=%v", cfg, err)
							}
							return
						}
						if err != nil {
							t.Fatal(err)
						}
						if !reflect.DeepEqual(n, before) {
							t.Fatal("source node mutated")
						}
						raw, err := json.Marshal(cfg)
						if err != nil {
							t.Fatal(err)
						}
						var runtime map[string]any
						if err := json.Unmarshal(raw, &runtime); err != nil {
							t.Fatal(err)
						}
						got := runtime["outbounds"].([]any)[0].(map[string]any)["tls"]
						if !reflect.DeepEqual(got, want) {
							t.Fatalf("runtime TLS = %#v; want %#v", got, want)
						}
						if trust == "insecure" {
							if _, err := buildNode(n, mode, 11080, false); err == nil {
								t.Fatal("minimum version bypassed insecure consent")
							}
						}
					})
				}
			}
		}
	}
}

// Use YAML and the old buildNode API so identical test bytes can show a
// business RED on the initial implementation, without a new-field dependency.
func TestTLSSecurityRejectsUnsupportedUTLS13(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, []byte("file validation fixture; no handshake"), 0600); err != nil {
		t.Fatal(err)
	}
	pin := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, mode := range []string{"proxy", "tun"} {
		for _, fp := range []string{"", "chrome", "firefox", "safari", "random", "unknown", "Golang", " golang", "golang "} {
			for i, trust := range []map[string]any{
				{"ca": ca},
				{"certificate-public-key-sha256": pin},
				{"skip-cert-verify": true},
				{"ca": filepath.Join(t.TempDir(), "missing-ca.pem")},
				{"certificate-public-key-sha256": "invalid"},
				{"certificate-public-key-sha256": pin, "ca": ca},
				{},
			} {
				t.Run(fmt.Sprintf("%s/%s/trust%d", mode, fp, i), func(t *testing.T) {
					trust["tls-min-version"] = "1.3"
					if fp != "" {
						trust["client-fingerprint"] = fp
					}
					n := tlsSecurityNode(t, trust)
					before := n
					cfg, err := buildNode(n, mode, 11080, true)
					if cfg != nil || err == nil || err.Error() != "tls-min-version 1.3 requires client-fingerprint golang" {
						t.Fatalf("uTLS 1.3 must reject before CA/trust/runtime handling: cfg=%v err=%v", cfg, err)
					}
					if !reflect.DeepEqual(n, before) {
						t.Fatal("rejection mutated node")
					}
				})
			}
		}
	}
}

func TestTLSSecurityConversionRejectsUnsupportedUTLS13(t *testing.T) {
	pin := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, key := range []string{"nodes", "proxies"} {
		for _, remote := range []bool{false, true} {
			for _, fingerprint := range []string{"", ", client-fingerprint: chrome", ", client-fingerprint: firefox"} {
				t.Run(fmt.Sprintf("%s/%t/%s", key, remote, fingerprint), func(t *testing.T) {
					input := []byte(key + ":\n - {name: good, type: anytls, server: 127.0.0.1, port: 443, password: synthetic-only, skip-cert-verify: true}\n - {name: inactive, type: anytls, server: 127.0.0.1, port: 443, password: synthetic-only, certificate-public-key-sha256: '" + pin + "', tls-min-version: '1.3'" + fingerprint + "}\nproxy-groups:\n - {name: pick, type: select, proxies: [good, inactive], selected: good}\nrules: ['MATCH,pick']\n")
					before := append([]byte(nil), input...)
					out, report, err := webConvertConfiguration(context.Background(), input, remote, nil)
					if err != nil || len(report.Issues) != 0 {
						t.Fatalf("conversion failed with usable good node: %v %+v", err, report)
					}
					nodes, err := loadNodesBytes(out)
					if err != nil {
						t.Fatal(err)
					}
					if len(nodes) != 1 || nodes[0].Name != "good" || len(report.Skipped) == 0 || bytes.Contains(out, []byte("inactive")) {
						t.Fatalf("unsupported uTLS floor or references retained: %+v", report)
					}
					if !bytes.Equal(input, before) {
						t.Fatal("converter mutated source bytes")
					}
				})
			}
		}
	}
}

func TestTLSSecurityRejectInvalidBeforeTrust(t *testing.T) {
	for _, version := range []string{"1.0", "1.1", "1.4", "TLS1.3", " 1.3", "1.3 ", "1.3\n", "1.30", "invalid"} {
		for _, extra := range []map[string]any{{"ca": "/missing-tls-security-ca"}, {"skip-cert-verify": true}, {"certificate-public-key-sha256": "invalid"}} {
			extra["tls-min-version"] = version
			n := tlsSecurityNode(t, extra)
			before := n
			cfg, err := buildNode(n, "proxy", 11080, true)
			if err == nil || err.Error() != "invalid tls-min-version" || cfg != nil {
				t.Fatalf("invalid version must reject before trust/file handling: cfg=%v err=%v", cfg, err)
			}
			if !reflect.DeepEqual(n, before) {
				t.Fatal("rejection mutated node")
			}
		}
	}
}

func TestTLSSecurityMinimumDoesNotRelaxTrust(t *testing.T) {
	pin := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, version := range []string{"1.2", "1.3"} {
		for _, trust := range []map[string]any{{}, {"skip-cert-verify": true}, {"certificate-public-key-sha256": pin, "skip-cert-verify": true}, {"certificate-public-key-sha256": pin, "ca": "/missing"}, {"certificate-public-key-sha256": "invalid"}} {
			trust["tls-min-version"] = version
			trust["client-fingerprint"] = "golang"
			for _, allow := range []bool{false, true} {
				if trust["skip-cert-verify"] == true && len(trust) == 3 && allow {
					continue // Explicit skip plus consent remains supported.
				}
				if _, err := buildNode(tlsSecurityNode(t, trust), "proxy", 11080, allow); err == nil {
					t.Fatal("minimum version bypassed existing trust rejection")
				}
			}
		}
	}
}

func TestTLSSecurityConversionFailClosed(t *testing.T) {
	pin := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, key := range []string{"nodes", "proxies"} {
		for _, remote := range []bool{false, true} {
			for _, value := range []string{"'1.2'", "'1.3'", "''", "null", "1.3", "true", "[1.3]", "{min: '1.3'}", "'1.1'", "' 1.3'", "'1.3 '", "'1.30'"} {
				t.Run(fmt.Sprintf("%s/%t/%s", key, remote, value), func(t *testing.T) {
					input := []byte(key + ":\n - {name: good, type: anytls, server: 127.0.0.1, port: 443, password: synthetic-only, skip-cert-verify: true}\n - {name: inactive, type: anytls, server: 127.0.0.1, port: 443, password: synthetic-only, client-fingerprint: golang, sni: fixture.invalid, certificate-public-key-sha256: '" + pin + "', tls-min-version: " + value + "}\nproxy-groups:\n - {name: pick, type: select, proxies: [good, inactive], selected: good}\nrules: ['MATCH,pick']\n")
					before := append([]byte(nil), input...)
					out, report, err := webConvertConfiguration(context.Background(), input, remote, nil)
					if err != nil || len(report.Issues) != 0 {
						t.Fatalf("conversion failed with usable good node: %v %+v", err, report)
					}
					if !bytes.Equal(input, before) {
						t.Fatal("converter mutated source bytes")
					}
					nodes, err := loadNodesBytes(out)
					if err != nil {
						t.Fatal(err)
					}
					valid := value == "'1.2'" || value == "'1.3'"
					if valid {
						if len(nodes) != 2 || len(report.Skipped) != 0 {
							t.Fatalf("valid version lost: %+v", report)
						}
						cfg, err := buildNode(nodes[1], "proxy", 11080, false)
						if err != nil {
							t.Fatal(err)
						}
						tls := cfg["outbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)
						if tls["min_version"] != value[1:4] || !reflect.DeepEqual(tls["certificate_public_key_sha256"], []string{pin}) || tls["insecure"] != nil || tls["certificate_path"] != nil || tls["server_name"] != "fixture.invalid" {
							t.Fatalf("converted version/trust changed: %#v", tls)
						}
						if key == "nodes" && !bytes.Equal(input, out) {
							t.Fatal("valid native configuration rewritten")
						}
					} else if len(nodes) != 1 || nodes[0].Name != "good" || len(report.Skipped) == 0 || bytes.Contains(out, []byte("inactive")) {
						t.Fatalf("bad inactive version or references retained, or policy stripped: %+v", report)
					}
				})
			}
		}
	}
}
