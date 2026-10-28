package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// UNIT-SIMULATED: only the baseline lifecycle API is used, so these exact
// bytes can be overlaid on the old implementation for a business RED.
// Each fixture pause represents one second; preserve its original callback
// so the shared fixture's virtual clock can advance after the clock seam lands.
// This slice detects the old 16-round cutoff, not elapsed-deadline enforcement.
func TestLifecycleReadinessWithinSixtySeconds(t *testing.T) {
	for _, readyAfter := range []int{20, 59} {
		t.Run(fmt.Sprintf("ready_after_%ds", readyAfter), func(t *testing.T) {
			d, binary, config, core, loaded, _ := lifecycleFixture(t)
			pause, route, tool := d.pause, d.route, d.tool
			seconds, probes, bootouts := 0, 0, 0
			d.pause = func() {
				pause()
				seconds++
			}
			d.route = func(ip string) (string, error) {
				if *loaded && ip == "1.1.1.1" && seconds < readyAfter {
					return "en0", nil
				}
				return route(ip)
			}
			d.tool = func(ctx context.Context, name string, args ...string) (string, error) {
				if name == "/usr/bin/curl" {
					probes++
					if seconds < readyAfter {
						t.Fatal("loaded/running was accepted before the public route entered TUN")
					}
				}
				if name == "/bin/launchctl" && args[0] == "bootout" {
					bootouts++
				}
				return tool(ctx, name, args...)
			}
			output, err := lifecycleOutput(t, func() error {
				return d.start(binary, config, core, true)
			})
			if err != nil {
				t.Fatalf("readiness ended before TUN became available inside the 60s observation window: seconds=%d want=%d probes=%d bootouts=%d: %v", seconds, readyAfter, probes, bootouts, err)
			}
			if seconds != readyAfter || probes != 1 || bootouts != 0 || !*loaded {
				t.Fatalf("delayed readiness not verified immediately: seconds=%d want=%d probes=%d bootouts=%d loaded=%v", seconds, readyAfter, probes, bootouts, *loaded)
			}
			if !strings.Contains(output, "AnyTLS TUN ready;") {
				t.Fatal("successful same-invocation HTTPS readiness was not reported")
			}
			if _, err := os.Stat(d.root); err != nil {
				t.Fatalf("successful readiness lost its active snapshot: %v", err)
			}
			if err := d.stop(); err != nil {
				t.Fatal(err)
			}
			if *loaded || bootouts != 1 {
				t.Fatalf("stop did not unload the fixture job: loaded=%v bootouts=%d", *loaded, bootouts)
			}
			if _, err := os.Stat(d.root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("stop did not clean the fixture snapshot: %v", err)
			}
		})
	}
}
