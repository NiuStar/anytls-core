package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func runtimeCertificate(t *testing.T) ([]byte, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "g21.invalid"}, DNSNames: []string{"g21.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(ca, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}))
	if err != nil {
		t.Fatal(err)
	}
	return ca, pair
}
func runtimeWrite(t *testing.T, path string, b []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, b, mode); err != nil {
		t.Fatal(err)
	}
}
func normalizedRuntime(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// Authority is a separately compiled, SHA-frozen pre-refactor CLI, not a second
// caller of prepareRuntime. A fake core ONLY records its input; it is not a
// validation result. G2 native driver builds that CLI from the unchanged G1 tree.
func TestSameRuntimeForExternalAndEmbedded(t *testing.T) {
	old := os.Getenv("ANYTLS_G21_REFERENCE_CLI")
	if old == "" {
		t.Skip("native differential requires frozen pre-refactor CLI via ANYTLS_G21_REFERENCE_CLI")
	}
	cases := []struct {
		name, mode, server, selected, rules string
		insecure, allow, legacy             bool
		bad                                 string
	}{
		{name: "proxy-strict-ipv4", mode: "proxy", server: "203.0.113.1", selected: "a"},
		{name: "tun-ipv6", mode: "tun", server: "2001:db8::1", selected: "a"},
		{name: "proxy-domain", mode: "proxy", server: "node.invalid", selected: "a"},
		{name: "tun-domain-rejected", mode: "tun", server: "node.invalid", selected: "a", bad: "TUN server must be a fixed IP"},
		{name: "insecure-positive", mode: "proxy", server: "203.0.113.1", selected: "a", insecure: true, allow: true},
		{name: "insecure-negative", mode: "proxy", server: "203.0.113.1", selected: "a", insecure: true, bad: "TLS requires ca"},
		{name: "groups-rules-resolve-noresolve", mode: "tun", server: "203.0.113.1", selected: "a", rules: " - DOMAIN,first.invalid,g\n - DOMAIN-SUFFIX,blocked.invalid,REJECT\n - RULE-SET,local,DIRECT,no-resolve\n - RULE-SET,local,g\n - MATCH,a\n"},
		{name: "group-direct", mode: "proxy", server: "203.0.113.1", selected: "a", rules: " - DOMAIN,first.invalid,g\n - MATCH,DIRECT\n"},
		{name: "wrong-sha", mode: "proxy", server: "203.0.113.1", selected: "a", rules: " - RULE-SET,local,DIRECT\n - MATCH,a\n", bad: "SHA mismatch"},
		{name: "unsupported", mode: "proxy", server: "203.0.113.1", selected: "ss", bad: "not AnyTLS"},
		{name: "invalid-port", mode: "proxy", server: "203.0.113.1", selected: "a", bad: "invalid local port"},
		{name: "invalid-mode", mode: "other", server: "203.0.113.1", selected: "a", bad: "mode must be proxy or tun"},
		{name: "legacy-secure", mode: "proxy", server: "203.0.113.1", legacy: true},
		{name: "legacy-insecure-password-file", mode: "proxy", server: "203.0.113.1", legacy: true, bad: "password-file must be regular and private"},
		{name: "no-config", mode: "proxy", bad: "password-file is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := t.TempDir()
			ca, _ := runtimeCertificate(t)
			capath := filepath.Join(d, "ca.pem")
			runtimeWrite(t, capath, ca, 0600)
			spec := []byte(`{"version":3,"rules":[{"ip_cidr":["10.0.0.0/8","2001:db8:abcd::/48"]}]}`)
			runtimeWrite(t, filepath.Join(d, "rules.json"), spec, 0600)
			sum := shaHex(spec)
			if tc.name == "wrong-sha" {
				sum = strings.Repeat("0", 64)
			}
			config := filepath.Join(d, "config.yaml")
			caField := "ca: " + capath
			if tc.insecure {
				caField = "skip-cert-verify: true"
			}
			groupSelection := "b"
			if tc.name == "group-direct" {
				groupSelection = "DIRECT"
			}
			yaml := fmt.Sprintf("proxies:\n - {name: a, type: anytls, server: %q, port: 443, password: synthetic, sni: g21.invalid, client-fingerprint: chrome, idle-session-check-interval: 6, idle-session-timeout: 12, min-idle-session: 1, %s}\n - {name: b, type: anytls, server: '2001:db8::2', port: 444, password: synthetic, sni: g21.invalid, ca: %s}\n - {name: ss, type: ss}\nproxy-groups:\n - {name: g, type: select, proxies: [b, DIRECT, REJECT], selected: %s}\nrule-sets:\n local: {path: rules.json, sha256: %s, resolve-ip: true}\nrules:\n%s", tc.server, caField, capath, groupSelection, sum, tc.rules)
			runtimeWrite(t, config, []byte(yaml), 0644)
			port := 11081
			if tc.name == "invalid-port" {
				port = 0
			}
			o := runtimeOptions{Command: "check", Config: config, NodeName: tc.selected, Mode: tc.mode, LocalPort: port, AllowInsecure: tc.allow}
			args := []string{"-config", config, "-node", tc.selected, "-network", tc.mode, "-local-port", fmt.Sprint(port)}
			if tc.allow {
				args = append(args, "-allow-insecure")
			}
			if tc.legacy || tc.name == "no-config" {
				o.Config = ""
				o.Server = tc.server + ":443"
				o.SNI = "g21.invalid"
				o.CA = capath
				args = []string{"-server", o.Server, "-sni", o.SNI, "-ca", capath}
				if tc.legacy {
					o.PasswordFile = filepath.Join(d, "password")
					mode := os.FileMode(0600)
					if tc.bad != "" {
						mode = 0644
					}
					runtimeWrite(t, o.PasswordFile, []byte("synthetic\r\n"), mode)
					args = append(args, "-password-file", o.PasswordFile)
				}
			}
			capture := filepath.Join(d, "old-runtime.json")
			recorder := filepath.Join(d, "record-core")
			runtimeWrite(t, recorder, []byte("#!/bin/sh\n/bin/cp \"$3\" \"$G21_CAPTURE\"\n"), 0700)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, old, append(append(args, "-core", recorder), "check")...)
			cmd.Dir = d
			cmd.Env = append(os.Environ(), "G21_CAPTURE="+capture)
			oldOut, oldErr := cmd.CombinedOutput()
			got, err := prepareRuntime(&o)
			if tc.bad != "" {
				if err == nil || oldErr == nil || !strings.Contains(err.Error(), tc.bad) || !strings.Contains(string(oldOut), tc.bad) {
					t.Fatalf("rejection mismatch new=%v old=%v expected=%s", err, oldErr, tc.bad)
				}
				if _, e := os.Stat(capture); !os.IsNotExist(e) {
					t.Fatal("rejected input reached recorder")
				}
				return
			}
			if err != nil || oldErr != nil {
				t.Fatalf("compile new=%v old=%v", err, oldErr)
			}
			b, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(capture)
			if err != nil {
				t.Fatal(err)
			}
			// The frozen CLI predates the TUN-only DNS capture contract. Apply
			// exactly that delta to its expected output; retain all ordered user
			// slots, resolver actions, endpoints, and every other field/byte check.
			if tc.mode == "tun" || tc.legacy {
				reference := normalizedRuntime(t, want)
				route := reference["route"].(map[string]any)
				var business []any
				if oldRules, ok := route["rules"].([]any); ok {
					prefix := []any{map[string]any{"action": "sniff"}, map[string]any{"protocol": []any{"dns"}, "action": "hijack-dns"}}
					if len(oldRules) < 2 || !reflect.DeepEqual(oldRules[:2], prefix) {
						t.Fatalf("unexpected frozen RULE-SET capture prefix: %#v", oldRules)
					}
					business = oldRules[2:]
				}
				route["rules"] = append([]any{map[string]any{"port": 53, "action": "hijack-dns"}, map[string]any{"action": "sniff"}, map[string]any{"protocol": []string{"dns"}, "action": "hijack-dns"}}, business...)
				reference["dns"].(map[string]any)["reverse_mapping"] = true
				want, err = json.MarshalIndent(reference, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				// Independent literal prefix validation, not a production helper.
				tunBusinessRules(t, got)
			}
			if !reflect.DeepEqual(normalizedRuntime(t, b), normalizedRuntime(t, want)) {
				t.Fatal("complete normalized runtime JSON differs from frozen compiler (ordered arrays retained)")
			}
			exact, marshalErr := json.MarshalIndent(got, "", "  ")
			if marshalErr != nil || string(exact) != string(want) {
				t.Fatal("exact runtime JSON bytes differ from frozen compiler under unchanged MarshalIndent encoder")
			}
			if ref := os.Getenv("ANYTLS_REFERENCE_CORE"); ref != "" {
				p := filepath.Join(d, "official.json")
				runtimeWrite(t, p, b, 0600)
				c := exec.CommandContext(ctx, ref, "check", "-c", p)
				c.Env = []string{"HOME=" + d, "PATH=/usr/bin:/bin"}
				if _, e := c.CombinedOutput(); e != nil {
					t.Fatalf("real official core rejected reference-equal runtime: %v", e)
				}
			}
		})
	}
}

func TestRuntimeNoConfigAndMenus(t *testing.T) {
	for _, command := range []string{"check", "list", "select"} {
		t.Run(command, func(t *testing.T) {
			_, err := prepareRuntime(&runtimeOptions{Command: command, Server: "203.0.113.1:443"})
			if err == nil {
				t.Fatal("missing config accepted")
			}
		})
	}
}
