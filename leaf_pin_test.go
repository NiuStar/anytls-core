package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Uses only baseline APIs: the same test must fail on the unmodified release
// because leaf fingerprint trust is missing, not because a new symbol is absent.
func TestLeafFingerprintTrust(t *testing.T) {
	pin := strings.Repeat("AB", 32)
	want := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xab}, 32))
	for _, key := range []string{"nodes", "proxies"} {
		for _, profile := range []string{"", "chrome", "golang"} {
			t.Run(key+"/"+profile, func(t *testing.T) {
				input := []byte(key + ":\n - {name: pinned, type: anytls, server: 203.0.113.7, port: 8443, password: synthetic-only, fingerprint: '" + pin + "', client-fingerprint: '" + profile + "'}\n")
				nodes, err := loadNodesBytes(input)
				if err != nil || len(nodes) != 1 {
					t.Fatalf("load leaf pin: %v", err)
				}
				for _, mode := range []string{"proxy", "tun"} {
					cfg, err := buildNode(nodes[0], mode, 11080, false)
					if err != nil {
						t.Fatalf("leaf pin-only trust rejected: %v", err)
					}
					tls := cfg["outbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)
					if !reflect.DeepEqual(tls["certificate_sha256"], []string{want}) {
						t.Fatalf("leaf digest absent or not converted to base64: %#v", tls)
					}
					if tls["certificate_public_key_sha256"] != nil || tls["insecure"] != nil || tls["certificate_path"] != nil {
						t.Fatal("leaf pin mixed with another trust mode")
					}
					if profile == "golang" && tls["utls"] != nil {
						t.Fatal("client fingerprint changed")
					}
				}
				encoded, err := yaml.Marshal(nodes[0])
				if err != nil || !bytes.Contains(encoded, []byte("fingerprint: "+strings.ToLower(pin))) {
					t.Fatalf("leaf fingerprint lost or not canonicalized: %v", err)
				}
				for _, remote := range []bool{false, true} {
					out, report, err := webConvertConfiguration(context.Background(), input, remote, nil)
					if err != nil || len(report.Issues) != 0 || len(report.Skipped) != 0 {
						t.Fatalf("leaf conversion: %v %+v", err, report)
					}
					round, err := loadNodesBytes(out)
					if err != nil || len(round) != 1 {
						t.Fatalf("leaf conversion lost node: %v", err)
					}
					cfg, err := buildNode(round[0], "proxy", 11080, false)
					if err != nil {
						t.Fatal(err)
					}
					tls := cfg["outbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)
					if !reflect.DeepEqual(tls["certificate_sha256"], []string{want}) {
						t.Fatal("conversion changed leaf pin")
					}
				}
			})
		}
	}
}

func TestLeafFingerprintRejectMalformedAndMixedTrust(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	spki := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	bad := []string{"fingerprint: " + strings.Repeat("0", 64), "fingerprint: ''", "fingerprint: null", "fingerprint: 123", "fingerprint: []", "fingerprint: {}", "fingerprint: true", "fingerprint: ' " + pin + "'", "fingerprint: '" + pin + " '", "fingerprint: '" + pin[:62] + "'", "fingerprint: '" + pin + "ab'", "fingerprint: '" + strings.Repeat("zz", 32) + "'", "fingerprint: '" + spki + "'", "fingerprint: '" + pin + "', skip-cert-verify: true", "fingerprint: '" + pin + "', ca: /missing", "fingerprint: '" + pin + "', certificate-public-key-sha256: '" + spki + "'"}
	for _, key := range []string{"nodes", "proxies"} {
		for _, trust := range bad {
			input := []byte(key + ":\n - {name: bad, type: anytls, server: 203.0.113.7, port: 8443, password: synthetic-only, " + trust + "}\n")
			// Raw native loading must not turn an explicitly invalid/empty/null leaf
			// pin into CA trust or opt-in insecure trust.
			nodes, err := loadNodesBytes(input)
			if err == nil {
				for _, n := range nodes {
					if _, err := buildNode(n, "proxy", 11080, true); err == nil {
						t.Fatalf("invalid leaf trust accepted: %s", trust)
					}
				}
			}
			input = append(input, []byte(" - {name: good, type: anytls, server: 203.0.113.8, port: 443, password: synthetic-only, skip-cert-verify: true}\n")...)
			out, report, err := webConvertConfiguration(context.Background(), input, false, nil)
			if err != nil {
				continue
			}
			nodes, err = loadNodesBytes(out)
			if err != nil || len(nodes) != 1 || nodes[0].Name != "good" || len(report.Skipped) == 0 {
				t.Fatalf("invalid leaf retained or silently stripped: %v %+v", err, report)
			}
		}
	}
	// Empty/null leaf fields must not disappear even with an otherwise usable
	// trust setting, including direct yaml.Decode callers.
	for _, value := range []string{"''", "null", "123", "true"} {
		var n node
		err := yaml.Unmarshal([]byte("{name: bad, type: anytls, server: 203.0.113.7, port: 443, password: synthetic-only, skip-cert-verify: true, fingerprint: "+value+"}"), &n)
		if err == nil {
			if _, err = buildNode(n, "proxy", 11080, true); err == nil {
				t.Fatalf("typed decode downgraded invalid leaf %s", value)
			}
		}
	}
}

func TestLeafFingerprintAppendAndEditPreservation(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	incoming := []byte("proxies:\n - {name: pinned, type: anytls, server: 203.0.113.7, port: 443, password: synthetic-only, fingerprint: '" + pin + "'}\n")
	prepared, err := webImportAppendInput(incoming, true)
	if err != nil {
		t.Fatal(err)
	}
	converted, report, err := webConvertConfiguration(context.Background(), prepared, true, nil)
	if err != nil || len(report.Skipped) != 0 || len(report.Issues) != 0 {
		t.Fatalf("append conversion: %v %+v", err, report)
	}
	old := []byte("nodes:\n - {name: old, type: anytls, server: 203.0.113.8, port: 443, password: synthetic-only, skip-cert-verify: true}\nrules: ['MATCH,old']\n")
	appended, count, err := webImportAppend(old, converted)
	if err != nil || count != 1 {
		t.Fatalf("append: count=%d err=%v", count, err)
	}
	edited, err := webEditNode(appended, webNodeEdit{Name: "pinned", Server: "203.0.113.9", Port: 8443})
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := loadNodesBytes(edited)
	if err != nil || len(nodes) != 2 {
		t.Fatalf("edit nodes: %v", err)
	}
	if !bytes.Contains(edited, []byte(pin)) || !bytes.Contains(edited, []byte("MATCH,old")) {
		t.Fatal("append/edit dropped pin or existing routing")
	}
	if _, err := buildNode(nodes[1], "proxy", 11080, false); err != nil {
		t.Fatalf("saved leaf trust unusable: %v", err)
	}
}
