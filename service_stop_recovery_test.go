package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Same bytes compile on d8ada5f: real private snapshot/files, simulated OS tools.
func TestStopRecoveryRestart(t *testing.T) {
	for _, mode := range []string{"dns_changed", "public_changed", "server_changed", "missing_baseline", "bad_baseline", "dns_probe", "route_probe"} {
		t.Run(mode, func(t *testing.T) {
			d, b, c, k, loaded, _ := lifecycleFixture(t)
			if err := d.start(b, c, k, true); err != nil {
				t.Fatal(err)
			}
			route, dns := d.route, d.dns
			baseline := filepath.Join(d.root, serviceBaselineName)
			switch mode {
			case "missing_baseline":
				if err := os.Remove(baseline); err != nil {
					t.Fatal(err)
				}
			case "bad_baseline":
				if err := os.WriteFile(baseline, []byte("broken"), 0600); err != nil {
					t.Fatal(err)
				}
			case "dns_changed":
				d.dns = func() ([]string, error) { return []string{"nameserver[0] : 192.0.2.99"}, nil }
			case "dns_probe":
				d.dns = func() ([]string, error) { return nil, errors.New("private DNS") }
			default:
				d.route = func(ip string) (string, error) {
					if mode == "route_probe" {
						return "", errors.New("private route")
					}
					if mode == "public_changed" && ip == "1.1.1.1" || mode == "server_changed" && ip != "1.1.1.1" {
						return "en9", nil
					}
					return route(ip)
				}
			}
			if err := d.stop(); err != nil {
				t.Fatalf("confirmed unloaded STOP blocked by recovery warning: %v", err)
			}
			if *loaded {
				t.Fatal("stop left loaded")
			}
			v, _ := readDiagnostic(t, d.root)
			if v["stopped"] != "VERIFIED" || v["outcome"] != "SUCCEEDED" || v["restoration"] == "VERIFIED" || v["snapshot"] != "ARCHIVED" {
				t.Fatalf("false/missing evidence: %v", v)
			}
			archives, err := filepath.Glob(filepath.Join(filepath.Dir(d.root), ".service-recovery-*", "snapshot"))
			if err != nil || len(archives) != 1 {
				t.Fatalf("archive missing: %v %v", archives, err)
			}
			if info, err := os.Stat(filepath.Dir(archives[0])); err != nil || info.Mode().Perm() != 0700 {
				t.Fatal("archive not private", err)
			}
			if _, err := os.Stat(filepath.Join(archives[0], "config.yaml")); err != nil {
				t.Fatal("snapshot evidence lost", err)
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(archives[0]), "service-diagnostic.json")); err != nil {
				t.Fatal("warning receipt lost", err)
			}
			d.route, d.dns = route, dns
			if err := d.start(b, c, k, true); err != nil || !*loaded {
				t.Fatalf("restart locked by old snapshot: %v", err)
			}
		})
	}
}

func TestStartLegacyRecoverySnapshot(t *testing.T) {
	d, b, c, k, loaded, _ := lifecycleFixture(t)
	if err := os.Mkdir(d.root, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(d.root, "legacy-evidence")
	if err := os.WriteFile(marker, []byte("old evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := d.start(b, c, k, true); err != nil || !*loaded {
		t.Fatalf("legacy snapshot blocks start: %v", err)
	}
	paths, _ := filepath.Glob(filepath.Join(filepath.Dir(d.root), ".service-recovery-*", "snapshot", "legacy-evidence"))
	if len(paths) != 1 {
		t.Fatal("legacy evidence not archived", paths)
	}
	if raw, err := os.ReadFile(paths[0]); err != nil || string(raw) != "old evidence" {
		t.Fatal("legacy evidence changed", err)
	}
}

func TestRecoverySnapshotFailClosed(t *testing.T) {
	for _, mode := range []string{"loaded", "running", "unknown", "late_loaded", "late_unknown", "symlink", "identity", "unsafe_mode", "archive_failure"} {
		t.Run(mode, func(t *testing.T) {
			d, b, c, k, _, calls := lifecycleFixture(t)
			if err := os.Mkdir(d.root, 0700); err != nil {
				t.Fatal(err)
			}
			reads := 0
			d.state = func() (bool, bool, error) {
				reads++
				if mode == "loaded" || mode == "late_loaded" && reads > 1 {
					return true, false, nil
				}
				if mode == "running" {
					return false, true, nil
				}
				if mode == "unknown" || mode == "late_unknown" && reads > 1 {
					return false, false, errors.New("unknown job")
				}
				if reads == 2 && mode == "identity" {
					if err := os.Rename(d.root, d.root+".original"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(d.root, 0700); err != nil {
						t.Fatal(err)
					}
				}
				if reads == 2 && mode == "archive_failure" {
					if err := os.Rename(filepath.Dir(d.root), filepath.Dir(d.root)+".moved"); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = os.Rename(filepath.Dir(d.root)+".moved", filepath.Dir(d.root)) })
				}
				return false, false, nil
			}
			if mode == "symlink" {
				if err := os.Remove(d.root); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), d.root); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "unsafe_mode" {
				if err := os.Chmod(d.root, 0777); err != nil {
					t.Fatal(err)
				}
			}
			if err := d.start(b, c, k, true); err == nil {
				t.Fatal("unsafe recovery accepted")
			}
			for _, call := range *calls {
				if strings.HasPrefix(call, "launchctl:") {
					t.Fatal("unsafe recovery controlled job", call)
				}
			}
		})
	}
}

func TestStopRecoveryHelperSuccess(t *testing.T) {
	for _, action := range []string{"stop", "reload"} {
		t.Run(action, func(t *testing.T) {
			d, b, c, k, loaded, _ := lifecycleFixture(t)
			if err := d.start(b, c, k, true); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(d.root, serviceBaselineName)); err != nil {
				t.Fatal(err)
			}
			s := unitControlServer()
			s.state = d.state
			s.stop = func(ctx context.Context) error { return d.withStartup(ctx, s).stop() }
			s.start = func(ctx context.Context, allow bool) error { return d.withStartup(ctx, s).start(b, c, k, allow) }
			r := s.execute(controlHelperWireRequest{action, action != "stop"})
			raw, _ := json.Marshal(r)
			var body map[string]any
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatal(err)
			}
			diag, ok := body["diagnostics"].(map[string]any)
			if !r.OK || !ok || diag["outcome"] != "SUCCEEDED" || diag["restoration"] != "UNKNOWN" || diag["operation"] != strings.ToUpper(action) {
				t.Fatalf("warning not delivered on success: %s", raw)
			}
			if *loaded != (action == "reload") {
				t.Fatal("wrong final job state")
			}
		})
	}
}
