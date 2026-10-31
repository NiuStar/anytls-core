package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestProxyListenDefault(t *testing.T) {
	n := node{Name: "fixture", Type: "anytls", Server: "203.0.113.7", Port: 443, Password: "synthetic-only", SkipVerify: true}
	cfg, err := buildNode(n, "proxy", 11080, true)
	if err != nil {
		t.Fatal(err)
	}
	inbounds := cfg["inbounds"].([]any)
	if len(inbounds) != 1 {
		t.Fatalf("inbounds: %v", inbounds)
	}
	in := inbounds[0].(map[string]any)
	if in["type"] != "mixed" || in["listen"] != "0.0.0.0" || in["listen_port"] != 11080 {
		t.Fatalf("default SOCKS/HTTP inbound: %v", in)
	}
}

func TestProxyListenExplicitAddress(t *testing.T) {
	n := node{Name: "fixture", Type: "anytls", Server: "203.0.113.7", Port: 443, Password: "synthetic-only", CertificateSHA256: strings.Repeat("ab", 32)}
	for _, listen := range []string{"0.0.0.0", "127.0.0.1", "192.0.2.7"} {
		t.Run(listen, func(t *testing.T) {
			want, err := buildNode(n, "proxy", 11081, false)
			if err != nil {
				t.Fatal(err)
			}
			want["inbounds"].([]any)[0].(map[string]any)["listen"] = listen
			got, err := buildNodeWithListen(n, "proxy", 11081, false, listen)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("address override changed non-listen configuration: %v", got)
			}
		})
	}
}

func TestProxyListenRejectsInvalidAddress(t *testing.T) {
	n := node{Type: "anytls", Server: "203.0.113.7", Port: 443, Password: "synthetic-only", CertificateSHA256: strings.Repeat("ab", 32)}
	for _, listen := range []string{"", "localhost", "127.1", "127.000.0.1", " 127.0.0.1", "127.0.0.1 ", "127.0.0.1:11080", "::1", "::ffff:127.0.0.1", "0.0.0.0/0", "256.1.1.1", "127.0.0.1%lo0"} {
		t.Run(listen, func(t *testing.T) {
			if _, err := buildNodeWithListen(n, "proxy", 11080, false, listen); err == nil || !strings.Contains(err.Error(), "invalid local-listen") {
				t.Fatalf("invalid listen %q: %v", listen, err)
			}
		})
	}
	for _, port := range []int{0, -1, 65536} {
		if _, err := buildNodeWithListen(n, "proxy", port, false, "127.0.0.1"); err == nil || !strings.Contains(err.Error(), "invalid local port") {
			t.Fatalf("invalid port %d: %v", port, err)
		}
	}
	n.CertificateSHA256 = ""
	n.SkipVerify = true
	if _, err := buildNodeWithListen(n, "proxy", 11080, false, "127.0.0.1"); err == nil {
		t.Fatal("listen override bypassed explicit insecure TLS consent")
	}
}

func TestProxyListenTUNUnchanged(t *testing.T) {
	n := node{Type: "anytls", Server: "203.0.113.7", Port: 443, Password: "synthetic-only", CertificateSHA256: strings.Repeat("ab", 32)}
	want, err := buildNode(n, "tun", 0, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, listen := range []string{"0.0.0.0", "127.0.0.1"} {
		got, err := buildNodeWithListen(n, "tun", 0, false, listen)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("proxy listen affected TUN: %v", got)
		}
		inbounds := got["inbounds"].([]any)
		if len(inbounds) != 1 {
			t.Fatalf("unexpected service inbound: %v", inbounds)
		}
		in := inbounds[0].(map[string]any)
		if in["type"] != "tun" || in["listen"] != nil || in["listen_port"] != nil {
			t.Fatalf("TUN gained TCP listener: %v", in)
		}
	}
}

func TestProxyListenRuntimeCompilation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := "nodes:\n - {name: fixture, type: anytls, server: 203.0.113.7, port: 443, password: synthetic-only, fingerprint: '" + strings.Repeat("ab", 32) + "'}\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	for _, listen := range []string{"", "0.0.0.0", "127.0.0.1", "192.0.2.7"} {
		t.Run(listen, func(t *testing.T) {
			o := runtimeOptions{Command: "check", Config: path, NodeName: "fixture", Mode: "proxy", LocalListen: listen, LocalPort: 11081}
			compiled, err := prepareRuntimeWithRecords(&o)
			if err != nil {
				t.Fatal(err)
			}
			var cfg map[string]any
			if err := json.Unmarshal(compiled.JSON, &cfg); err != nil {
				t.Fatal(err)
			}
			want := listen
			if want == "" {
				want = "0.0.0.0"
			}
			in := cfg["inbounds"].([]any)[0].(map[string]any)
			if in["type"] != "mixed" || in["listen"] != want || in["listen_port"] != float64(11081) {
				t.Fatalf("compiled proxy inbound: %v", in)
			}
			if compiled.Manifest == nil || compiled.Manifest.RuntimeSHA256 != shaHex(compiled.JSON) {
				t.Fatal("compiled runtime digest does not cover listen address")
			}
		})
	}
	if _, err := prepareRuntimeWithRecords(&runtimeOptions{Command: "check", Config: path, NodeName: "fixture", Mode: "proxy", LocalListen: "localhost", LocalPort: 11081}); err == nil || !strings.Contains(err.Error(), "invalid local-listen") {
		t.Fatalf("runtime compiler accepted non-literal listen: %v", err)
	}
}

func TestProxyListenCLIValidation(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	for _, listen := range []string{"", "localhost", "::1", "::ffff:127.0.0.1", "127.0.0.1:11080"} {
		err := execute([]string{"--local-listen=" + listen, "--config", missing, "check"})
		if err == nil || !strings.Contains(err.Error(), "invalid local-listen") {
			t.Fatalf("CLI listen %q reached config loading: %v", listen, err)
		}
	}
	for _, args := range [][]string{
		{"--config", missing, "check"},
		{"--local-listen=0.0.0.0", "--config", missing, "check"},
		{"--local-listen", "127.0.0.1", "--config", missing, "check"},
		{"-local-listen=192.0.2.7", "--config", missing, "check"},
	} {
		if err := execute(args); !os.IsNotExist(err) {
			t.Fatalf("valid listen flag did not reach config loading: %v", err)
		}
	}
}
