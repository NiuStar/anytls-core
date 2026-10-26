//go:build embedded_core

package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The evidence driver instruments decodeOptions and box.New in isolated sources;
// production code has no global counter, cache, or testing hook.
func TestEmbeddedSinglePass(t *testing.T) {
	if os.Getenv("ANYTLS_SINGLE_PASS_CHILD") == "1" {
		rules := strings.TrimSuffix(strings.Repeat(`{"domain_suffix":["fixture.invalid"],"outbound":"direct"},`, 12000), ",")
		raw := []byte(`{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[` + rules + `]}}`)
		fmt.Printf("INPUT bytes=%d sha256=%x\n", len(raw), sha256.Sum256(raw))
		if err := dispatchEngine("run", raw, "", ""); err == nil {
			t.Fatal("expected cancellation")
		}
		return
	}
	if os.Getenv("ANYTLS_SINGLE_PASS_INSTRUMENTED") != "1" {
		t.Skip("isolated instrumentation driver only")
	}
	log := filepath.Join(t.TempDir(), "calls")
	cmd := exec.Command(os.Args[0], "-test.run=^TestEmbeddedSinglePass$")
	cmd.Env = append(os.Environ(), "ANYTLS_SINGLE_PASS_CHILD=1", "ANYTLS_SINGLE_PASS_CALLS="+log)
	var output strings.Builder
	cmd.Stdout = &output
	cmd.Stderr = &output
	started := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		b, _ := os.ReadFile(log)
		if strings.Contains(string(b), "start\n") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Start not reached")
		}
		time.Sleep(time.Millisecond)
	}
	startup := time.Since(started)
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"decode", "new", "start", "close"} {
		if got := strings.Count(string(b), stage+"\n"); got != 1 {
			t.Errorf("%s calls = %d, want 1", stage, got)
		}
	}
	t.Logf("startup-to-Start-entry=%s (not readiness); %s; actual call trace: %s", startup, output.String(), b)
}
