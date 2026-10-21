package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

// UNIT-SIMULATED: the same ExitCode API implemented by *exec.ExitError,
// without spawning curl or requiring a particular OS wait-status layout.
type probeExitError int

func (e probeExitError) Error() string { return "private curl SECRET" }
func (e probeExitError) ExitCode() int { return int(e) }

var _ interface{ ExitCode() int } = (*exec.ExitError)(nil)

func TestLifecycleHTTPSRetryRecovery(t *testing.T) {
	for _, code := range []int{6, 7, 28, 35, 52, 56} {
		for _, failures := range []int{1, 2} {
			t.Run(fmt.Sprintf("exit%d_failures%d", code, failures), func(t *testing.T) {
				d, b, c, k, loaded, _ := lifecycleFixture(t)
				tool, state, route := d.tool, d.state, d.route
				attempts, states := 0, 0
				routes := map[string]bool{}
				d.state = func() (bool, bool, error) { states++; return state() }
				d.route = func(ip string) (string, error) { routes[ip] = true; return route(ip) }
				d.tool = func(ctx context.Context, name string, args ...string) (string, error) {
					if name != "/usr/bin/curl" {
						return tool(ctx, name, args...)
					}
					want := []string{"--noproxy", "*", "-4", "-fsS", "--connect-timeout", "5", "--max-time", "12", "https://api.ipify.org"}
					if !slices.Equal(args, want) {
						t.Fatalf("HTTPS semantics changed: %v", args)
					}
					deadline, ok := ctx.Deadline()
					if !ok || time.Until(deadline) > 15*time.Second {
						t.Fatal("unbounded attempt")
					}
					if attempts > 0 && (states == 0 || !routes["1.1.1.1"] || !routes["203.0.113.1"] || !routes["203.0.113.2"]) {
						t.Fatal("retry without rechecking job, exact public TUN and every server")
					}
					attempts++
					states, routes = 0, map[string]bool{}
					if attempts <= failures {
						return "SECRET", fmt.Errorf("wrapped: %w", probeExitError(code))
					}
					return "198.51.100.1", nil
				}
				if err := d.start(b, c, k, true); err != nil {
					t.Fatalf("transient failure not recovered: %v", err)
				}
				if attempts != failures+1 || !*loaded {
					t.Fatalf("attempts=%d loaded=%v", attempts, *loaded)
				}
				if err := d.stop(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestLifecycleHTTPSRetryFailureRollback(t *testing.T) {
	for _, mode := range []string{"permanent_transient", "bad_CA", "invalid_IP", "permission", "unclassified"} {
		t.Run(mode, func(t *testing.T) {
			d, b, c, k, loaded, _ := lifecycleFixture(t)
			tool := d.tool
			attempts, bootouts := 0, 0
			var cause error = probeExitError(35)
			wantAttempts := 1
			switch mode {
			case "permanent_transient":
				wantAttempts = 3
			case "bad_CA":
				cause = probeExitError(60)
			case "invalid_IP":
				cause = nil
			case "permission":
				cause = os.ErrPermission
			case "unclassified":
				cause = errors.New("SECRET unknown failure")
			}
			d.tool = func(ctx context.Context, name string, args ...string) (string, error) {
				if name == "/usr/bin/curl" {
					attempts++
					return "SECRET invalid IP", cause
				}
				if name == "/bin/launchctl" && args[0] == "bootout" {
					bootouts++
				}
				return tool(ctx, name, args...)
			}
			err := d.start(b, c, k, true)
			if err == nil || attempts != wantAttempts || *loaded || bootouts != 1 {
				t.Fatalf("err=%v attempts=%d bootouts=%d loaded=%v", err, attempts, bootouts, *loaded)
			}
			if cause != nil && !errors.Is(err, cause) {
				t.Fatal("final curl cause lost")
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Fatal("private output/error leaked")
			}
			if mode == "permanent_transient" && !strings.Contains(err.Error(), "curl exit 35") {
				t.Fatalf("missing curl category: %v", err)
			}
			if _, err := os.Stat(d.root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rollback did not restore/clean: %v", err)
			}
		})
	}
}

func TestLifecycleHTTPSRetryCancellation(t *testing.T) {
	for _, mode := range []string{"before", "during", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			d, _, _, _, _, _ := lifecycleFixture(t)
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := error(context.Canceled)
			if mode == "before" {
				cancel()
			}
			if mode == "deadline" {
				var stop context.CancelFunc
				parent, stop = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				defer stop()
				want = context.DeadlineExceeded
			}
			attempts := 0
			d.tool = func(ctx context.Context, _ string, _ ...string) (string, error) {
				attempts++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 15*time.Second {
					t.Fatal("attempt deadline lost")
				}
				cancel()
				return "", probeExitError(28)
			}
			// Runtime assertion keeps this same test file compilable against
			// the pre-fix source for native business RED comparison.
			probe, ok := any(d).(interface {
				httpsExitProbe(context.Context, string, networkBaseline, []string) error
			})
			if !ok {
				t.Fatal("bounded HTTPS probe missing")
			}
			err := probe.httpsExitProbe(parent, "utun8", networkBaseline{}, nil)
			wantAttempts := 0
			if mode == "during" {
				wantAttempts = 1
			}
			if !errors.Is(err, want) || attempts != wantAttempts {
				t.Fatalf("cancellation lost: attempts=%d err=%v", attempts, err)
			}
			if mode == "during" && !errors.Is(err, probeExitError(28)) {
				t.Fatal("cancelled curl cause lost")
			}
		})
	}
}

func TestLifecycleHTTPSExitCodeAPI(t *testing.T) {
	// Exercise errors.As against the real standard-library type as well as
	// the wrapped fake exit status used by the business tests above.
	for _, err := range []error{fmt.Errorf("wrapped: %w", &exec.ExitError{}), fmt.Errorf("wrapped: %w", probeExitError(28))} {
		var exit interface{ ExitCode() int }
		if !errors.As(err, &exit) {
			t.Fatal("ExitCode API not found through wrapping")
		}
		if _, ok := exit.(*exec.ExitError); ok && exit.ExitCode() != -1 {
			t.Fatal("unexpected empty ProcessState exit code")
		}
	}
}

func TestLifecycleHTTPSRetryIdentityDrift(t *testing.T) {
	for _, mode := range []string{"utun", "job_gone", "server", "state_error", "route_error"} {
		for _, failAt := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s_after%d", mode, failAt), func(t *testing.T) {
				d, b, c, k, loaded, _ := lifecycleFixture(t)
				tool, state, route := d.tool, d.state, d.route
				attempts := 0
				sentinel := errors.New("SECRET identity probe")
				d.tool = func(ctx context.Context, name string, args ...string) (string, error) {
					if name == "/usr/bin/curl" {
						attempts++
						return "", probeExitError(28)
					}
					return tool(ctx, name, args...)
				}
				d.state = func() (bool, bool, error) {
					if *loaded && attempts >= failAt {
						if mode == "job_gone" {
							return false, false, nil
						}
						if mode == "state_error" {
							return false, false, sentinel
						}
					}
					return state()
				}
				d.route = func(ip string) (string, error) {
					if *loaded && attempts >= failAt {
						if mode == "utun" && ip == "1.1.1.1" {
							return "utun9", nil
						}
						if mode == "server" && ip == "203.0.113.2" {
							return "en1", nil
						}
						if mode == "route_error" && ip == "1.1.1.1" {
							return "", sentinel
						}
					}
					return route(ip)
				}
				err := d.start(b, c, k, true)
				if err == nil || attempts != failAt || !errors.Is(err, probeExitError(28)) {
					t.Fatalf("identity drift lost or retried: attempts=%d err=%v", attempts, err)
				}
				if (mode == "state_error" || mode == "route_error") && !errors.Is(err, sentinel) {
					t.Fatal("identity error chain lost")
				}
			})
		}
	}
}
