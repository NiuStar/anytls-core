package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"time"

	"golang.org/x/sys/unix"
	"path/filepath"
	"strings"
	"testing"
)

// The actual public start selection boundary, without servicePaths or control.
func TestServicePublicPreflightOversize(t *testing.T) {
	d, _, c, _, _, _ := lifecycleFixture(t)
	_ = d
	raw, err := os.ReadFile(c)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, []byte("#"+strings.Repeat("x", snapshotConfigLimit)+"\n")...)
	if err := os.WriteFile(c, raw, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := selectedServiceNode(c); err == nil {
		t.Fatal("public start preflight accepted oversized config before capture")
	}
}

// UNIT-SIMULATED: a same-IP change must not reuse pre-stage TLS permission.
func TestServiceStageRecompileBeforeBaseline(t *testing.T) {
	d, b, c, k, loaded, calls := lifecycleFixture(t)
	ca := filepath.Join(filepath.Dir(c), "ca.pem")
	pemBytes, _ := runtimeCertificate(t)
	if err := os.WriteFile(ca, pemBytes, 0644); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(c)
	if err != nil {
		t.Fatal(err)
	}
	safe := strings.ReplaceAll(string(raw), "skip-cert-verify: true", "ca: "+ca)
	if err := os.WriteFile(c, []byte(safe), 0644); err != nil {
		t.Fatal(err)
	}
	original := d.stage
	d.stage = func(binary, config, core, root string) error {
		// Ordinary atomic source replacement, no hostile same-UID authority claim.
		next := config + ".replacement"
		if err := os.WriteFile(next, raw, 0644); err != nil {
			return err
		}
		if err := os.Rename(next, config); err != nil {
			return err
		}
		return original(binary, config, core, root)
	}
	if err := d.start(b, c, k, false); err == nil {
		t.Fatal("staged same-IP insecure replacement accepted after secure preflight")
	}
	if *loaded {
		t.Fatal("insecure replacement reached bootstrap")
	}
	for _, call := range *calls {
		if strings.HasPrefix(call, "route:") || strings.HasPrefix(call, "launchctl:") {
			t.Fatal("rejected staged config reached baseline/control: " + call)
		}
	}
	if _, err := os.Lstat(d.root); !os.IsNotExist(err) {
		t.Fatalf("owned rejected stage not cleaned: %v", err)
	}
}

func TestServicePublicPreflightBoundaries(t *testing.T) {
	for _, leaf := range []string{"config", "selected"} {
		for _, kind := range []string{"0644", "oversize", "directory", "fifo", "symlink"} {
			t.Run(leaf+"/"+kind, func(t *testing.T) {
				_, _, c, _, _, _ := lifecycleFixture(t)
				target := c
				limit := int64(snapshotConfigLimit)
				if leaf == "selected" {
					target = selectedPath(c)
					limit = snapshotSelectedLimit
				}
				if kind == "0644" {
					if err := os.Chmod(target, 0644); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Remove(target); err != nil {
						t.Fatal(err)
					}
					var err error
					switch kind {
					case "oversize":
						err = os.WriteFile(target, bytes.Repeat([]byte("x"), int(limit)+1), 0644)
					case "directory":
						err = os.Mkdir(target, 0700)
					case "fifo":
						err = unix.Mkfifo(target, 0600)
					case "symlink":
						err = os.Symlink(c+".other", target)
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				// Parent owns TMPDIR and reaps helper on timeout: timeout is FAIL.
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestServicePreflightHelper$", "-test.v")
				cmd.Env = append(os.Environ(), "ANYTLS_PREFLIGHT_HELPER="+c, "ANYTLS_PREFLIGHT_ACCEPT="+kind)
				out, err := cmd.CombinedOutput()
				if ctx.Err() != nil || err != nil {
					t.Fatalf("bounded helper failed: %v %v %s", ctx.Err(), err, out)
				}
			})
		}
	}
}
func TestServicePreflightHelper(t *testing.T) {
	c := os.Getenv("ANYTLS_PREFLIGHT_HELPER")
	if c == "" {
		return
	}
	_, err := preflightServiceNode(c)
	if (err == nil) != (os.Getenv("ANYTLS_PREFLIGHT_ACCEPT") == "0644") {
		t.Fatalf("unexpected preflight acceptance: %v", err)
	}
}

func TestServiceCaptureSameBytesAndFullJSON(t *testing.T) {
	_, _, c, _, _, _ := lifecycleFixture(t)
	raw, err := os.ReadFile(c)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.ReplaceAll(raw, []byte("password: fixture"), []byte("password: 00123"))
	if err := os.WriteFile(c, raw, 0644); err != nil {
		t.Fatal(err)
	}
	captured, err := captureServiceConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	// Preserve the historical parser's complete JSON before changing the paths.
	nodes, err := loadNodes(c)
	if err != nil {
		t.Fatal(err)
	}
	name, err := selectedNode(c, nodes)
	if err != nil {
		t.Fatal(err)
	}
	n, err := choose(nodes, name)
	if err != nil {
		t.Fatal(err)
	}
	want, err := buildNode(n, "tun", 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyRouting(c, nodes, n, want, true); err != nil {
		t.Fatal(err)
	}
	before, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	replacement := bytes.ReplaceAll(raw, []byte("password: 00123"), []byte("password: different"))
	replacement = bytes.ReplaceAll(replacement, []byte("MATCH,primary"), []byte("MATCH,secondary"))
	next := c + ".next"
	if err := os.WriteFile(next, replacement, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, c); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(selectedPath(c), []byte("secondary"), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := captured.compile(true)
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("captured nodes/selection/groups/rules/full JSON mixed source versions")
	}
	if got["outbounds"].([]any)[0].(map[string]any)["password"] != "00123" {
		t.Fatal("scalar password changed")
	}
	if !reflect.DeepEqual(captured.config, raw) {
		t.Fatal("capture mutated")
	}
	fresh, err := captureServiceConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := fresh.compile(true)
	if err != nil {
		t.Fatal(err)
	}
	changedJSON, _ := json.Marshal(changed)
	if bytes.Equal(before, changedJSON) {
		t.Fatal("negative control did not change full JSON")
	}
}

func TestServiceStagedVersionDrivesBaseline(t *testing.T) {
	d, b, c, k, _, calls := lifecycleFixture(t)
	stage := d.stage
	d.stage = func(binary, config, core, root string) error {
		raw, err := os.ReadFile(config)
		if err != nil {
			return err
		}
		raw = bytes.ReplaceAll(raw, []byte("203.0.113.2"), []byte("203.0.113.7"))
		raw = bytes.ReplaceAll(raw, []byte("password: fixture"), []byte("password: replacement"))
		if err := os.WriteFile(config+".next", raw, 0644); err != nil {
			return err
		}
		if err := os.Rename(config+".next", config); err != nil {
			return err
		}
		if err := stage(binary, config, core, root); err != nil {
			return err
		}
		// Source no longer exists: all later compilation must use the staged inputs.
		return os.Remove(config)
	}
	if err := d.start(b, c, k, true); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(d.root, serviceBaselineName))
	if err != nil {
		t.Fatal(err)
	}
	var baseline networkBaseline
	if err := json.Unmarshal(raw, &baseline); err != nil {
		t.Fatal(err)
	}
	if baseline.Servers["203.0.113.7"] != "en0" || baseline.Servers["203.0.113.2"] != "" {
		t.Fatal("baseline came from pre-stage source")
	}
	for _, call := range *calls {
		if call == "route:203.0.113.2" {
			t.Fatal("old source route used")
		}
	}
	captured, err := captureServiceConfig(filepath.Join(d.root, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := captured.compile(true)
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range compiled["outbounds"].([]any) {
		o := out.(map[string]any)
		if o["type"] == "anytls" && o["password"] != "replacement" {
			t.Fatal("password mixed across versions")
		}
	}
}

func TestServicePreflightMissingSelectionCause(t *testing.T) {
	_, _, c, _, _, _ := lifecycleFixture(t)
	if err := os.Remove(selectedPath(c)); err != nil {
		t.Fatal(err)
	}
	if _, err := preflightServiceNode(c); err == nil || !strings.Contains(err.Error(), "select a node") {
		t.Fatalf("missing selection contract: %v", err)
	}
	_, err := readSnapshotSource(c+".missing", snapshotConfigLimit, false)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatal("sanitized open cause lost")
	}
}
