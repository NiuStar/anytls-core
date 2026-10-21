package engine

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Verification-after coverage of the shared registry subset, not a claim that
// the deliberately narrower embedded registry accepts every official type.
func TestCheckParity(t *testing.T) {
	reference := os.Getenv("ANYTLS_REFERENCE_CORE")
	if reference == "" {
		t.Skip("ANYTLS_REFERENCE_CORE is unset; actual official core required")
	}
	if !filepath.IsAbs(reference) {
		t.Fatal("ANYTLS_REFERENCE_CORE must be an absolute executable path")
	}
	valid := string(loopbackConfig(0))
	anyTLS := strings.Replace(valid, `"type":"direct","tag":"direct"`, `"type":"anytls","tag":"fixture","server":"127.0.0.1","server_port":9,"password":"parity-test-marker","tls":{"enabled":true,"insecure":true,"server_name":"fixture.invalid","utls":{"enabled":true,"fingerprint":"chrome"}}`, 1)
	for _, tt := range []struct {
		name   string
		config string
		wantOK bool
	}{
		{"valid-mixed-direct", valid, true},
		{"valid-anytls-tls", anyTLS, true},
		{"unsupported-outbound", strings.Replace(valid, `"type":"direct"`, `"type":"parity-test-unknown-outbound"`, 1), false},
		{"invalid-fingerprint", strings.Replace(anyTLS, `"fingerprint":"chrome"`, `"fingerprint":"parity-test-invalid-fingerprint"`, 1), false},
		{"malformed-json", `{`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			config := []byte(tt.config)
			path := filepath.Join(dir, "synthetic.json")
			if err := os.WriteFile(path, config, 0600); err != nil {
				t.Fatal("cannot write synthetic config")
			}
			checkOK := Check(context.Background(), config) == nil
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, reference, "check", "-c", path)
			cmd.Dir = dir
			cmd.Env = []string{"HOME=" + dir, "TMPDIR=" + dir, "PATH=/usr/bin:/bin"}
			err := cmd.Run() // Discard upstream diagnostics; never print config values.
			if ctx.Err() != nil {
				t.Fatal("official check exceeded five-second timeout")
			}
			rc := 0
			if err != nil {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() < 0 {
					t.Fatal("official check could not execute normally")
				}
				rc = exitErr.ExitCode()
			}
			referenceOK := err == nil
			t.Logf("embedded_ok=%t official_ok=%t official_rc=%d", checkOK, referenceOK, rc)
			if checkOK != tt.wantOK || referenceOK != tt.wantOK {
				t.Fatalf("acceptance mismatch: embedded=%t official=%t want=%t", checkOK, referenceOK, tt.wantOK)
			}
		})
	}
}
