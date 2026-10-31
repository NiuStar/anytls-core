package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
)

type dnsMetricsContextKey struct{}

func withDNSMetricsEnabled(ctx context.Context) context.Context {
	return context.WithValue(ctx, dnsMetricsContextKey{}, true)
}

func dnsMetricsEnabled(ctx context.Context) bool {
	enabled, _ := ctx.Value(dnsMetricsContextKey{}).(bool)
	return enabled
}

func validateDNSMetricsFlag(enabled bool, command string, embedded bool) error {
	if !enabled {
		return nil
	}
	if command != "run" {
		return errors.New("--dns-metrics is only supported with run")
	}
	if !embedded {
		return errors.New("--dns-metrics requires embedded_core")
	}
	return nil
}

func writeDNSMetricsFinal(w io.Writer, snapshot any) error {
	return json.NewEncoder(w).Encode(struct {
		Event   string `json:"event"`
		Metrics any    `json:"metrics"`
	}{Event: "dns_metrics_final", Metrics: snapshot})
}
