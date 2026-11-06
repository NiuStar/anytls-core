package main

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Run the actual app/runtime VM regressions in normal Go CI when Node is installed.
func TestWebBackgroundUpdateFrontend(t *testing.T) {
	node := os.Getenv("ANYTLS_R10_NODE")
	if node == "" {
		var err error
		node, err = exec.LookPath("node")
		if err != nil {
			t.Skip("Node required for frontend VM regression")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "--test", "web_background_update_test.mjs", "web_update_observation_test.mjs", "web_runtime_status_test.mjs", "web_rules_list_only_test.mjs", "scripts/web_update_restart_test.mjs")
	output, err := cmd.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatalf("frontend regressions: %v", err)
	}
}
