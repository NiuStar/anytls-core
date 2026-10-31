package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDNSMetricsCLICommandValidationBeforeIO(t *testing.T) {
	for _, command := range []string{"check", "list", "select"} {
		err := execute([]string{"--dns-metrics", "--config", filepath.Join(t.TempDir(), "missing.yaml"), command})
		if err == nil || !strings.Contains(err.Error(), "--dns-metrics is only supported with run") {
			t.Fatalf("%s must reject before config IO: %v", command, err)
		}
	}
}

func TestDNSMetricsCLIPreservesMissingCommandPriority(t *testing.T) {
	err := execute([]string{"--dns-metrics"})
	if err == nil || !strings.Contains(err.Error(), "usage: anytls-macos [flags] list|select|check|run") {
		t.Fatalf("missing-command priority changed: %v", err)
	}
}

func TestDNSMetricsCLIFalsePreservesValidation(t *testing.T) {
	for _, command := range []string{"run", "check", "list", "select"} {
		args := []string{"--config", filepath.Join(t.TempDir(), "missing.yaml"), command}
		before := execute(args)
		after := execute(append([]string{"--dns-metrics=false"}, args...))
		if before == nil || after == nil || before.Error() != after.Error() {
			t.Fatalf("explicit false changed %s: before=%v after=%v", command, before, after)
		}
	}
}

func TestDNSMetricsCLIExternalCoreRejectsBeforeIO(t *testing.T) {
	if !externalCoreRequired() {
		t.Skip("external-core contract")
	}
	err := execute([]string{"--dns-metrics", "--config", filepath.Join(t.TempDir(), "missing.yaml"), "run"})
	if err == nil || !strings.Contains(err.Error(), "--dns-metrics requires embedded_core") {
		t.Fatalf("external build silently accepted metrics: %v", err)
	}
}
