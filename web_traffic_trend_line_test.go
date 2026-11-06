package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Synthetic browser qualification, not real handler or native VPN acceptance.
// Opt-in like TestR10RealHTTPBrowser; never downloads browser dependencies.
func TestTrafficTrendLineBrowser(t *testing.T) {
	if os.Getenv("ANYTLS_TRAFFIC_TREND_BROWSER") != "1" {
		t.Skip("opt-in local chart browser qualification")
	}
	node := os.Getenv("ANYTLS_R10_NODE")
	if node == "" {
		t.Fatal("explicit ANYTLS_R10_NODE required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	evidence := t.TempDir()
	cmd := exec.CommandContext(ctx, node, "web_traffic_trend_line_test.mjs")
	cmd.Env = append(os.Environ(), "DASHBOARD_EVIDENCE="+evidence)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("chart browser failed: %v\n%s", err, output)
	}
	var result struct {
		Checks []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"checks"`
		Errors []string `json:"errors"`
	}
	b, err := os.ReadFile(filepath.Join(evidence, "results.json"))
	if err != nil || json.Unmarshal(b, &result) != nil || len(result.Checks) < 89 || len(result.Errors) != 0 {
		t.Fatal("missing complete chart browser result")
	}
	for _, check := range result.Checks {
		if check.Status != "PASS" {
			t.Errorf("chart check failed: %s", check.Name)
		}
	}
	t.Logf("synthetic frontend chart browser checks: %d", len(result.Checks))
}
