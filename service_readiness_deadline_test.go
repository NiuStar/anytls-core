package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// UNIT-SIMULATED: exercise start/rollback with a per-invocation clock, not
// sixty real sleeps. Loaded-only and physical-public-route cases must never curl.
func TestLifecycleReadinessElapsedDeadline(t *testing.T) {
	for _, tc := range []struct {
		name                                string
		readyAfter, preflight, stateCost    time.Duration
		publicCost, serverCost, httpsCost   time.Duration
		pauseStep                           time.Duration
		notRunning, neverReady, routeError  bool
		beginExpiry, failHTTPS, failCleanup bool
		wantSuccess                         bool
		wantPauses, wantStates, wantPublic  int
		wantServers, wantHTTPS              int
		wantElapsed                         time.Duration
		wantReason                          string
	}{
		{name: "immediate", wantSuccess: true, wantStates: 1, wantPublic: 1, wantServers: 2, wantHTTPS: 1},
		{name: "ready_at_59s", readyAfter: 59 * time.Second, wantSuccess: true, wantPauses: 59, wantStates: 60, wantPublic: 60, wantServers: 120, wantHTTPS: 1, wantElapsed: 59 * time.Second},
		{name: "ready_at_exactly_60s_rejected", readyAfter: 60 * time.Second, wantPauses: 60, wantStates: 60, wantPublic: 60, wantServers: 120, wantElapsed: 60 * time.Second, wantReason: "TUN_NOT_READY"},
		{name: "never_ready_rollback_cleanup", neverReady: true, wantPauses: 60, wantStates: 60, wantPublic: 60, wantServers: 120, wantElapsed: 60 * time.Second, wantReason: "TUN_NOT_READY"},
		{name: "loaded_not_running", notRunning: true, wantPauses: 60, wantStates: 60, wantPublic: 60, wantServers: 120, wantElapsed: 60 * time.Second, wantReason: "PROCESS_NOT_RUNNING"},
		{name: "tools_consume_window", neverReady: true, publicCost: 19 * time.Second, wantPauses: 3, wantStates: 3, wantPublic: 3, wantServers: 6, wantElapsed: 60 * time.Second, wantReason: "TUN_NOT_READY"},
		{name: "state_consumes_entire_window_without_pause", stateCost: 60 * time.Second, wantStates: 1, wantElapsed: 60 * time.Second, wantReason: "READINESS_UNKNOWN"},
		{name: "public_read_just_before_deadline", publicCost: 60*time.Second - time.Nanosecond, wantSuccess: true, wantStates: 1, wantPublic: 1, wantServers: 2, wantHTTPS: 1, wantElapsed: 60*time.Second - time.Nanosecond},
		{name: "public_read_at_exact_deadline", publicCost: 60 * time.Second, wantStates: 1, wantPublic: 1, wantElapsed: 60 * time.Second, wantReason: "READINESS_UNKNOWN"},
		{name: "public_read_crosses_deadline", publicCost: 61 * time.Second, wantStates: 1, wantPublic: 1, wantElapsed: 61 * time.Second, wantReason: "READINESS_UNKNOWN"},
		{name: "server_routes_cross_deadline", serverCost: 31 * time.Second, wantStates: 1, wantPublic: 1, wantServers: 2, wantElapsed: 62 * time.Second, wantReason: "READINESS_UNKNOWN"},
		{name: "round_begin_crosses_deadline", beginExpiry: true, wantElapsed: 60 * time.Second, wantReason: "READINESS_UNKNOWN"},
		{name: "late_wakeup_starts_no_round", neverReady: true, pauseStep: 61 * time.Second, wantPauses: 1, wantStates: 1, wantPublic: 1, wantServers: 2, wantElapsed: 61 * time.Second, wantReason: "TUN_NOT_READY"},
		{name: "preflight_and_bootstrap_do_not_consume_observation", preflight: 2 * time.Minute, readyAfter: 59 * time.Second, wantSuccess: true, wantPauses: 59, wantStates: 60, wantPublic: 60, wantServers: 120, wantHTTPS: 1, wantElapsed: 59 * time.Second},
		{name: "preexpiry_https_keeps_own_budget", readyAfter: 59 * time.Second, httpsCost: 12 * time.Second, wantSuccess: true, wantPauses: 59, wantStates: 60, wantPublic: 60, wantServers: 120, wantHTTPS: 1, wantElapsed: 71 * time.Second},
		{name: "route_error_fails_immediately", routeError: true, wantStates: 1, wantPublic: 1, wantReason: "READINESS_ROUTE_UNAVAILABLE"},
		{name: "late_route_error_keeps_cause", routeError: true, publicCost: 61 * time.Second, wantStates: 1, wantPublic: 1, wantElapsed: 61 * time.Second, wantReason: "READINESS_ROUTE_UNAVAILABLE"},
		{name: "https_still_required", failHTTPS: true, wantStates: 1, wantPublic: 1, wantServers: 2, wantHTTPS: 1, wantReason: "HTTPS_FAILED"},
		{name: "timeout_cleanup_error_keeps_cause", neverReady: true, failCleanup: true, wantPauses: 60, wantStates: 60, wantPublic: 60, wantServers: 120, wantElapsed: 60 * time.Second, wantReason: "TUN_NOT_READY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, binary, config, core, loaded, _ := lifecycleFixture(t)
			now := time.Unix(0, 0)
			var began time.Time
			observing, afterHTTPS, observationEnded := false, false, false
			pauses, states, public, servers, probes, bootouts, clockReads := 0, 0, 0, 0, 0, 0, 0
			primary, cleanup := errors.New("private readiness cause"), errors.New("private cleanup cause")
			tool, state, route, remove := d.tool, d.state, d.route, d.remove
			d.now = func() time.Time {
				if observing {
					clockReads++
					// deadline origin, loop guard, then entry inside the round.
					if tc.beginExpiry && clockReads == 3 {
						now = now.Add(60 * time.Second)
					}
					// Rollback's state/route reads are not observation rounds.
					if !now.Before(began.Add(60 * time.Second)) {
						observationEnded = true
					}
				}
				return now
			}
			d.pause = func() {
				pauses++
				step := tc.pauseStep
				if step == 0 {
					step = time.Second
				}
				now = now.Add(step)
			}
			d.state = func() (bool, bool, error) {
				if *loaded && !afterHTTPS && !observationEnded {
					states++
					now = now.Add(tc.stateCost)
					if tc.notRunning {
						return true, false, nil
					}
				}
				return state()
			}
			d.route = func(ip string) (string, error) {
				if *loaded && !afterHTTPS && !observationEnded {
					if ip == "1.1.1.1" {
						public++
						now = now.Add(tc.publicCost)
						if tc.routeError {
							observationEnded = true
							return "", primary
						}
						if tc.neverReady || now.Sub(began) < tc.readyAfter {
							return "en0", nil
						}
					} else {
						servers++
						now = now.Add(tc.serverCost)
					}
				}
				return route(ip)
			}
			d.tool = func(ctx context.Context, name string, args ...string) (string, error) {
				if name == "/usr/bin/plutil" {
					now = now.Add(tc.preflight)
				}
				if name == "/bin/launchctl" && args[0] == "bootstrap" {
					now = now.Add(tc.preflight)
					output, err := tool(ctx, name, args...)
					began, observing = now, true
					return output, err
				}
				if name == "/bin/launchctl" && args[0] == "bootout" {
					bootouts++
				}
				if name == "/usr/bin/curl" {
					probes++
					if !now.Before(began.Add(60 * time.Second)) {
						t.Fatal("HTTPS started at/after observation expiry")
					}
					afterHTTPS = true
					now = now.Add(tc.httpsCost)
					if tc.failHTTPS {
						return "", primary
					}
				}
				return tool(ctx, name, args...)
			}
			if tc.failCleanup {
				d.remove = func(string) error { return cleanup }
			}
			output, err := lifecycleOutput(t, func() error { return d.start(binary, config, core, true) })
			if (err == nil) != tc.wantSuccess {
				t.Fatalf("success=%v error=%v", tc.wantSuccess, err)
			}
			if pauses != tc.wantPauses || states != tc.wantStates || public != tc.wantPublic || servers != tc.wantServers || probes != tc.wantHTTPS || now.Sub(began) != tc.wantElapsed {
				t.Fatalf("pauses=%d states=%d public=%d servers=%d HTTPS=%d elapsed=%s; want %d/%d/%d/%d/%d/%s", pauses, states, public, servers, probes, now.Sub(began), tc.wantPauses, tc.wantStates, tc.wantPublic, tc.wantServers, tc.wantHTTPS, tc.wantElapsed)
			}
			v, _ := readDiagnostic(t, d.root)
			if tc.wantSuccess {
				if !*loaded || bootouts != 0 || v["readiness"] != "NETWORK_VERIFIED" || v["https"] != "SUCCEEDED_SAME_INVOCATION" || !strings.Contains(output, "AnyTLS TUN ready;") {
					t.Fatal("success lost independent HTTPS/identity evidence", v)
				}
				if _, err := os.Stat(d.root); err != nil {
					t.Fatal("successful start lost active snapshot", err)
				}
				if err := d.stop(); err != nil {
					t.Fatal(err)
				}
			} else {
				var diagErr *startDiagnosticError
				if !errors.As(err, &diagErr) || diagErr.diagnostic.Stage != map[bool]string{true: "HTTPS", false: "READINESS"}[tc.failHTTPS] || diagErr.diagnostic.Reason != tc.wantReason || !diagErr.diagnostic.valid(false) {
					t.Fatalf("missing valid timeout/failure diagnostics: %v (%#v)", err, diagErr)
				}
				if !tc.routeError && !tc.failHTTPS && !strings.Contains(err.Error(), "60s observation timed out") {
					t.Fatal("timeout not explicit", err)
				}
				if (tc.routeError || tc.failHTTPS) && !errors.Is(err, primary) {
					t.Fatal("probe cause lost", err)
				}
				if *loaded || bootouts != 1 || v["readiness"] == "NETWORK_VERIFIED" || strings.Contains(output, "AnyTLS TUN ready;") {
					t.Fatal("failure accepted readiness or skipped rollback", v, bootouts)
				}
				if tc.failCleanup {
					if !errors.Is(err, cleanup) || v["rollback"] != "FAILED" {
						t.Fatal("cleanup cause lost", err, v)
					}
					if _, err := os.Stat(d.root); err != nil {
						t.Fatal("failed cleanup did not retain snapshot", err)
					}
					d.remove = remove
					if err := d.stop(); err != nil {
						t.Fatal(err)
					}
				} else if v["rollback"] != "SUCCEEDED" || v["restoration"] != "VERIFIED" || v["snapshot"] != "REMOVED" {
					t.Fatal("rollback/restoration/cleanup not verified", v)
				}
			}
			if *loaded || bootouts != 1 {
				t.Fatal("fixture job not unloaded", bootouts)
			}
			if _, err := os.Stat(d.root); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("fixture snapshot not removed", err)
			}
		})
	}
}
