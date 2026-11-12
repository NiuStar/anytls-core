package main

import (
	"os"
	"strings"
	"testing"
)

func TestSelectedIPv6RouteIsNotAStartupGate(t *testing.T) {
	d, b, c, k, _, _ := lifecycleFixture(t)
	raw, err := os.ReadFile(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(c, []byte(strings.ReplaceAll(string(raw), "203.0.113.1", "2001:db8::1")), 0600); err != nil {
		t.Fatal(err)
	}
	route := d.route
	d.route = func(address string) (string, error) {
		if address != "1.1.1.1" {
			t.Fatal("selected/unselected node route inspected")
		}
		return route(address)
	}
	if err = d.start(b, c, k, true); err != nil {
		t.Fatal(err)
	}
	if _, err = d.status(); err != nil {
		t.Fatal(err)
	}
	if err = d.stop(); err != nil {
		t.Fatal(err)
	}
}

func TestReloadLegacyStopThenLocalStart(t *testing.T) {
	d, b, c, k, _, _ := lifecycleFixture(t)
	if err := d.start(b, c, k, true); err != nil {
		t.Fatal(err)
	}
	writeLegacyBaseline(t, d, 1)
	route := d.route
	legacyNodeReads := 0
	newStart := false
	d.route = func(address string) (string, error) {
		if address != "1.1.1.1" {
			if newStart {
				t.Fatal("new reload start inspected node route")
			}
			legacyNodeReads++
		}
		return route(address)
	}
	deps := reloadDependencies{state: d.state, preflight: func() (node, error) { return preflightServiceNode(c) }, stop: d.stop, start: func(allow bool) error { newStart = true; return d.start(b, c, k, allow) }}
	if err := reloadWithDependencies(true, deps); err != nil {
		t.Fatal(err)
	}
	if legacyNodeReads != 2 {
		t.Fatalf("historical stop authority changed: node reads=%d", legacyNodeReads)
	}
	baseline, _, err := d.baseline()
	if err != nil || baseline.Version != 2 {
		t.Fatal("reload did not create v2", err)
	}
	if err = d.stop(); err != nil {
		t.Fatal(err)
	}
}
