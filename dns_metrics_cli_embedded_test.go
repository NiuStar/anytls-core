//go:build embedded_core

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/NiuStar/anytls-core/internal/engine"
)

func TestDNSMetricsDispatchProcess(t *testing.T) {
	if os.Getenv("ANYTLS_DNS_METRICS_TEST_CHILD") != "1" {
		return
	}
	ctx := context.Background()
	if os.Getenv("ANYTLS_DNS_METRICS_TEST_ENABLED") == "1" {
		ctx = withDNSMetricsEnabled(ctx)
	}
	if os.Getenv("ANYTLS_DNS_METRICS_TEST_CLOSED_STDERR") == "1" {
		os.Stderr.Close()
	}
	err := dispatchCompiledEngine(os.Getenv("ANYTLS_DNS_METRICS_TEST_COMMAND"), compiledRuntime{JSON: []byte(`{"invalid`), startupContext: ctx}, "", "", false)
	if err == nil {
		os.Exit(98)
	}
	fmt.Fprint(os.Stdout, err.Error())
	os.Exit(0)
}

func TestDNSMetricsDispatchFinalOnFailureOnlyWhenOptedIn(t *testing.T) {
	invoke := func(command string, enabled, closed bool) ([]byte, []byte) {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestDNSMetricsDispatchProcess$")
		cmd.Env = append(os.Environ(), "ANYTLS_DNS_METRICS_TEST_CHILD=1", "ANYTLS_DNS_METRICS_TEST_COMMAND="+command,
			fmt.Sprintf("ANYTLS_DNS_METRICS_TEST_ENABLED=%d", boolDNSMetricsInt(enabled)),
			fmt.Sprintf("ANYTLS_DNS_METRICS_TEST_CLOSED_STDERR=%d", boolDNSMetricsInt(closed)))
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("dispatch child failed: %v, stderr=%s", err, stderr.Bytes())
		}
		return stdout.Bytes(), stderr.Bytes()
	}
	original, quiet := invoke("run", false, false)
	if len(quiet) != 0 {
		t.Fatalf("default metrics wrote stderr: %s", quiet)
	}
	actual, summary := invoke("run", true, false)
	if !bytes.Equal(actual, original) {
		t.Fatalf("metrics changed primary failure: %s != %s", actual, original)
	}
	var event map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(summary))
	if err := dec.Decode(&event); err != nil {
		t.Fatalf("missing final JSON on engine failure: %v, %s", err, summary)
	}
	if len(event) != 2 || string(event["event"]) != `"dns_metrics_final"` {
		t.Fatalf("invalid envelope: %s", summary)
	}
	var metrics map[string]any
	if err := json.Unmarshal(event["metrics"], &metrics); err != nil || len(metrics) == 0 {
		t.Fatalf("expected real metrics snapshot: %v, %s", err, summary)
	}
	wantSnapshot, err := json.Marshal(new(engine.DNSMetrics).Snapshot())
	if err != nil || !bytes.Equal(event["metrics"], wantSnapshot) {
		t.Fatalf("snapshot projection drift: got=%s want=%s err=%v", event["metrics"], wantSnapshot, err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		t.Fatalf("multiple summaries or raw error output: %v", err)
	}
	if strings.Contains(string(summary), string(original)) {
		t.Fatal("raw engine error leaked into summary")
	}
	failedWrite, _ := invoke("run", true, true)
	if !bytes.Equal(failedWrite, original) {
		t.Fatal("stderr write failure changed primary engine failure")
	}
	_, checkStderr := invoke("check", true, false)
	if len(checkStderr) != 0 {
		t.Fatalf("check emitted metrics: %s", checkStderr)
	}
}

func boolDNSMetricsInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
