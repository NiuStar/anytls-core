package main

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

// UNIT-SIMULATED: exercise the real reload orchestrator, never live launchd.
func TestReloadWithDependencies(t *testing.T) {
	secret := errors.New("password=must-not-be-printed")
	recovery := errors.New("restoration sentinel")
	for _, tc := range []struct {
		name                                      string
		loaded, running, insecure, allow          bool
		stateErr, preflightErr, stopErr, startErr error
		want                                      []string
		cause                                     error
	}{
		{name: "secure", loaded: true, running: true, want: []string{"state", "preflight", "stop", "start:false"}},
		{name: "loaded_not_running", loaded: true, want: []string{"state", "preflight", "stop", "start:false"}},
		{name: "allow_insecure_propagated", loaded: true, insecure: true, allow: true, want: []string{"state", "preflight", "stop", "start:true"}},
		{name: "consent_missing", loaded: true, insecure: true, want: []string{"state", "preflight"}},
		{name: "not_loaded", want: []string{"state"}},
		{name: "inconsistent_state", running: true, want: []string{"state"}},
		{name: "state_failure", stateErr: secret, want: []string{"state"}, cause: secret},
		{name: "preflight_failure", loaded: true, preflightErr: secret, want: []string{"state", "preflight"}, cause: secret},
		{name: "stop_failure", loaded: true, stopErr: secret, want: []string{"state", "preflight", "stop"}, cause: secret},
		{name: "start_failure", loaded: true, startErr: errors.Join(secret, recovery), want: []string{"state", "preflight", "stop", "start:false"}, cause: secret},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			d := reloadDependencies{
				state: func() (bool, bool, error) { calls = append(calls, "state"); return tc.loaded, tc.running, tc.stateErr },
				preflight: func() (node, error) {
					calls = append(calls, "preflight")
					return node{SkipVerify: tc.insecure}, tc.preflightErr
				},
				stop: func() error { calls = append(calls, "stop"); return tc.stopErr },
				start: func(allow bool) error {
					calls = append(calls, "start:"+map[bool]string{true: "true", false: "false"}[allow])
					return tc.startErr
				},
			}
			err := reloadWithDependencies(tc.allow, d)
			if !reflect.DeepEqual(calls, tc.want) {
				t.Fatalf("calls=%v want=%v", calls, tc.want)
			}
			wantError := tc.cause != nil || tc.name == "consent_missing" || !tc.loaded
			if (err != nil) != wantError {
				t.Fatalf("err=%v wantError=%v", err, wantError)
			}
			if tc.cause != nil && !errors.Is(err, tc.cause) {
				t.Fatal("lost original cause")
			}
			if tc.name == "start_failure" && !errors.Is(err, recovery) {
				t.Fatal("lost restoration failure")
			}
			if err != nil && strings.Contains(err.Error(), secret.Error()) {
				t.Fatal("secret leaked")
			}
			if tc.name == "not_loaded" && !strings.Contains(err.Error(), "anytls start") {
				t.Fatal("missing start suggestion")
			}
		})
	}
}

func TestReloadCommandConsent(t *testing.T) {
	for _, mode := range []string{"secure", "insecure", "declined", "preflight_failure", "not_loaded", "elevation_failure"} {
		t.Run(mode, func(t *testing.T) {
			var calls []string
			sentinel := errors.New("private confirmation/elevation cause")
			d := reloadDependencies{
				state: func() (bool, bool, error) { calls = append(calls, "state"); return mode != "not_loaded", true, nil },
				preflight: func() (node, error) {
					calls = append(calls, "preflight")
					if mode == "preflight_failure" {
						return node{}, sentinel
					}
					return node{SkipVerify: mode == "insecure" || mode == "declined"}, nil
				},
			}
			err := reloadCommandWithDependencies(d, func() error {
				calls = append(calls, "confirm")
				if mode == "declined" {
					return sentinel
				}
				return nil
			}, func(allow bool) error {
				calls = append(calls, "elevate:"+map[bool]string{true: "true", false: "false"}[allow])
				if mode == "elevation_failure" {
					return sentinel
				}
				return nil
			})
			want := []string{"state", "preflight", "elevate:false"}
			switch mode {
			case "insecure":
				want = []string{"state", "preflight", "confirm", "elevate:true"}
			case "declined":
				want = []string{"state", "preflight", "confirm"}
			case "preflight_failure":
				want = []string{"state", "preflight"}
			case "not_loaded":
				want = []string{"state"}
			}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("calls=%v want=%v", calls, want)
			}
			wantError := mode == "declined" || mode == "preflight_failure" || mode == "not_loaded" || mode == "elevation_failure"
			if (err != nil) != wantError {
				t.Fatalf("err=%v", err)
			}
			if wantError && mode != "not_loaded" && !errors.Is(err, sentinel) {
				t.Fatal("lost cause")
			}
			if err != nil && strings.Contains(err.Error(), sentinel.Error()) {
				t.Fatal("secret leaked")
			}
		})
	}
}

func TestReloadDiskPreflightPreservesLoadedService(t *testing.T) {
	d, _, config, _, loaded, calls := lifecycleFixture(t)
	*loaded = true
	if err := os.WriteFile(config, []byte("proxies: [broken"), 0600); err != nil {
		t.Fatal(err)
	}
	r := reloadDependencies{state: d.state, preflight: func() (node, error) { return preflightServiceNode(config) },
		stop:  func() error { t.Fatal("stop after rejected disk config"); return nil },
		start: func(bool) error { t.Fatal("start after rejected disk config"); return nil },
	}
	if err := reloadWithDependencies(true, r); err == nil {
		t.Fatal("accepted invalid current disk config")
	}
	if !*loaded || len(*calls) != 0 {
		t.Fatalf("service changed: loaded=%v calls=%v", *loaded, *calls)
	}
}

func TestReloadUsesExistingLifecycleReadiness(t *testing.T) {
	d, binary, config, core, loaded, calls := lifecycleFixture(t)
	if err := d.start(binary, config, core, true); err != nil {
		t.Fatal(err)
	}
	*calls = nil
	r := reloadDependencies{state: d.state, preflight: func() (node, error) { return preflightServiceNode(config) },
		stop: d.stop, start: func(allow bool) error { return d.start(binary, config, core, allow) },
	}
	if err := reloadWithDependencies(true, r); err != nil {
		t.Fatal(err)
	}
	var control []string
	for _, call := range *calls {
		if strings.HasPrefix(call, "launchctl:bootout") {
			control = append(control, "stop")
		}
		if strings.HasPrefix(call, "launchctl:bootstrap") {
			control = append(control, "start")
		}
		if strings.HasPrefix(call, "curl:") {
			control = append(control, "https")
		}
	}
	if !*loaded || !reflect.DeepEqual(control, []string{"stop", "start", "https"}) {
		t.Fatalf("loaded=%v control=%v", *loaded, control)
	}
}

func TestReloadStartFailureKeepsLifecycleRecoveryCauses(t *testing.T) {
	d, binary, config, core, loaded, _ := lifecycleFixture(t)
	if err := d.start(binary, config, core, true); err != nil {
		t.Fatal(err)
	}
	probeFailure := errors.New("private HTTPS password sentinel")
	recoveryFailure := errors.New("private restoration password sentinel")
	tool := d.tool
	stops := 0
	d.tool = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "/usr/bin/curl" {
			return "", probeFailure
		}
		if name == "/bin/launchctl" && args[0] == "bootout" {
			stops++
			if stops == 2 {
				return "", recoveryFailure
			}
		}
		return tool(ctx, name, args...)
	}
	r := reloadDependencies{state: d.state, preflight: func() (node, error) { return preflightServiceNode(config) },
		stop: d.stop, start: func(allow bool) error { return d.start(binary, config, core, allow) },
	}
	err := reloadWithDependencies(true, r)
	if !errors.Is(err, probeFailure) || !errors.Is(err, recoveryFailure) {
		t.Fatalf("original start/recovery causes lost: %v", err)
	}
	if stops != 2 || !*loaded {
		t.Fatalf("unexpected recovery state: stops=%d loaded=%v", stops, *loaded)
	}
	if strings.Contains(err.Error(), "password sentinel") {
		t.Fatal("private start/recovery details leaked")
	}
}
