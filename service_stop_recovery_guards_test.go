package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoveryCleanupSafety(t *testing.T) {
	for _, mode := range []string{"stop_unsafe_mode", "start_held_identity"} {
		t.Run(mode, func(t *testing.T) {
			d, b, c, k, loaded, _ := lifecycleFixture(t)
			if err := d.start(b, c, k, true); err != nil {
				t.Fatal(err)
			}
			if mode == "stop_unsafe_mode" {
				if err := os.Chmod(d.root, 0777); err != nil {
					t.Fatal(err)
				}
				if err := d.stop(); err == nil {
					t.Fatal("unsafe restored snapshot deleted")
				}
				if *loaded {
					t.Fatal("unsafe snapshot prevented unload")
				}
			} else {
				*loaded = false
				if err := os.Rename(d.root, d.root+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(d.root, 0700); err != nil {
					t.Fatal(err)
				}
				if err := d.start(b, c, k, true); err == nil {
					t.Fatal("held snapshot identity replaced")
				}
				if *loaded {
					t.Fatal("replacement snapshot started job")
				}
			}
			if _, err := os.Lstat(d.root); err != nil {
				t.Fatal("unsafe evidence removed", err)
			}
			paths, _ := filepath.Glob(filepath.Join(filepath.Dir(d.root), ".service-recovery-*", "snapshot"))
			if len(paths) != 0 {
				t.Fatal("unsafe evidence archived", paths)
			}
		})
	}
}

func TestStopRecoveryFailClosed(t *testing.T) {
	for _, mode := range []string{"bootout", "still_loaded", "post_unload_unknown", "identity", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			d, b, c, k, loaded, _ := lifecycleFixture(t)
			if err := d.start(b, c, k, true); err != nil {
				t.Fatal(err)
			}
			sentinel := errors.New("stop sentinel")
			tool, state, route := d.tool, d.state, d.route
			reads := 0
			d.state = func() (bool, bool, error) {
				reads++
				if mode == "post_unload_unknown" && reads >= 3 {
					return false, false, sentinel
				}
				return state()
			}
			d.tool = func(ctx context.Context, name string, args ...string) (string, error) {
				if name == "/bin/launchctl" && args[0] == "bootout" {
					if mode == "bootout" {
						return "", sentinel
					}
					if mode == "still_loaded" {
						return "", nil
					}
				}
				return tool(ctx, name, args...)
			}
			changed := false
			d.route = func(ip string) (string, error) {
				if !*loaded && !changed && (mode == "identity" || mode == "symlink") {
					changed = true
					if err := os.Rename(d.root, d.root+".original"); err != nil {
						t.Fatal(err)
					}
					if mode == "symlink" {
						if err := os.Symlink(d.root+".original", d.root); err != nil {
							t.Fatal(err)
						}
					} else if err := os.Mkdir(d.root, 0700); err != nil {
						t.Fatal(err)
					}
					return "en9", nil
				}
				return route(ip)
			}
			err := d.stop()
			if err == nil {
				t.Fatal("unconfirmed control or replaced snapshot accepted")
			}
			if (mode == "bootout" || mode == "post_unload_unknown") && !errors.Is(err, sentinel) {
				t.Fatal("control cause lost", err)
			}
			archives, _ := filepath.Glob(filepath.Join(filepath.Dir(d.root), ".service-recovery-*", "snapshot"))
			if len(archives) != 0 {
				t.Fatal("unsafe archive", archives)
			}
			if _, err := os.Lstat(d.root); err != nil {
				t.Fatal("evidence removed", err)
			}
		})
	}
}
