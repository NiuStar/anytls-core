package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// Policy regression: unavailable configured node routes must never be a
// startup prerequisite. Local job/TUN, config and recovery remain separate.
func TestStartDoesNotInspectConfiguredNodeRoutes(t *testing.T) {
	d, b, c, k, loaded, calls := lifecycleFixture(t)
	raw, err := os.ReadFile(c)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), "203.0.113.2", "2400:c620:2b:74::a", -1))
	if err = os.WriteFile(c, raw, 0600); err != nil {
		t.Fatal(err)
	}
	route := d.route
	var nodeCalls []string
	d.route = func(address string) (string, error) {
		if address != "1.1.1.1" {
			nodeCalls = append(nodeCalls, address)
			return "", errors.New("fixture node has no route")
		}
		return route(address)
	}
	if err = d.start(b, c, k, true); err != nil {
		t.Fatalf("local start blocked on configured node route: %v; node_calls=%d", err, len(nodeCalls))
	}
	if !*loaded || len(nodeCalls) != 0 {
		t.Fatalf("loaded=%v node_calls=%d", *loaded, len(nodeCalls))
	}
	for _, call := range *calls {
		if strings.HasPrefix(call, "curl:") {
			t.Fatal("startup dispatched a WAN connectivity probe")
		}
	}
	v, _ := readDiagnostic(t, d.root)
	if v["readiness"] != "LOCAL_READY" || v["https"] != "NOT_EXECUTED" {
		t.Fatal("startup misreported local readiness")
	}
}
