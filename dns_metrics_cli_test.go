package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestDNSMetricsFlagGate(t *testing.T) {
	for _, command := range []string{"run", "check", "list", "select"} {
		for _, embedded := range []bool{false, true} {
			if err := validateDNSMetricsFlag(false, command, embedded); err != nil {
				t.Fatalf("disabled changed %s (%v): %v", command, embedded, err)
			}
			err := validateDNSMetricsFlag(true, command, embedded)
			if command != "run" {
				if err == nil || !strings.Contains(err.Error(), "only supported with run") {
					t.Fatalf("%s: want run-only rejection, got %v", command, err)
				}
			} else if !embedded {
				if err == nil || !strings.Contains(err.Error(), "requires embedded_core") {
					t.Fatalf("external core must reject metrics: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestDNSMetricsContextPreservesParent(t *testing.T) {
	type parentKey struct{}
	parent, cancel := context.WithCancel(context.WithValue(context.Background(), parentKey{}, "preserved"))
	defer cancel()
	if dnsMetricsEnabled(parent) {
		t.Fatal("metrics enabled by default")
	}
	ctx := withDNSMetricsEnabled(parent)
	if !dnsMetricsEnabled(ctx) || ctx.Value(parentKey{}) != "preserved" {
		t.Fatal("metrics context lost opt-in or parent values")
	}
	cancel()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("metrics context lost cancellation")
	}
}

func TestDNSMetricsFinalEnvelope(t *testing.T) {
	var out bytes.Buffer
	snapshot := struct {
		Count uint64 `json:"count"`
	}{Count: 3}
	if err := writeDNSMetricsFinal(&out, snapshot); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Event   string `json:"event"`
		Metrics struct {
			Count uint64 `json:"count"`
		} `json:"metrics"`
	}
	dec := json.NewDecoder(&out)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&got); err != nil || got.Event != "dns_metrics_final" || got.Metrics.Count != snapshot.Count {
		t.Fatalf("invalid final envelope: %+v, %v", got, err)
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		t.Fatalf("expected exactly one JSON record, got %v", err)
	}
}

type dnsMetricsFailWriter struct{ writes int }

func (w *dnsMetricsFailWriter) Write(p []byte) (int, error) {
	w.writes++
	return 0, errors.New("private raw writer error")
}

func TestDNSMetricsFinalWriteFailureHasNoRetry(t *testing.T) {
	w := new(dnsMetricsFailWriter)
	if err := writeDNSMetricsFinal(w, struct{}{}); err == nil {
		t.Fatal("write failure hidden")
	}
	if w.writes != 1 {
		t.Fatalf("retried summary write %d times", w.writes)
	}
}
