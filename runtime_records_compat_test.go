package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Only pre-feature public-in-package symbols: runnable unchanged on old/new
// sources. This is parity coverage, not a manufactured absent-feature RED.
func TestRuntimeLegacyExplicitNodeValidatesSavedSelection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	config := []byte("nodes:\n - {name: a, type: anytls, server: 127.0.0.1, port: 443, password: synthetic, skip-cert-verify: true}\n")
	if err := os.WriteFile(path, config, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".selected", []byte("missing\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := prepareRuntime(&runtimeOptions{Command: "check", Config: path, NodeName: "a", Mode: "proxy", LocalPort: 21180, AllowInsecure: true})
	if err == nil || err.Error() != `saved selection is stale: node "missing" not found` {
		t.Fatalf("legacy selection validation changed: %v", err)
	}
}
