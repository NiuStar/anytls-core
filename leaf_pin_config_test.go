package main

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

// Baseline-compatible tracer bullet: missing support must fail a trust assertion.
func TestLeafFingerprintBuildNode(t *testing.T) {
	input := []byte("nodes:\n - {name: leaf, type: anytls, server: 203.0.113.7, port: 443, password: synthetic-only, fingerprint: '" + strings.Repeat("ab", 32) + "'}\n")
	nodes, err := loadNodesBytes(input)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("load: %v", err)
	}
	cfg, err := buildNode(nodes[0], "proxy", 11080, false)
	if err != nil {
		t.Fatalf("leaf pin-only trust rejected: %v", err)
	}
	tls := cfg["outbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)
	want := []string{base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xab}, 32))}
	if !reflect.DeepEqual(tls["certificate_sha256"], want) {
		t.Fatalf("leaf pin not emitted: %#v", tls)
	}
}
