package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// All tools, routes, DNS and HTTPS are UNIT-SIMULATED by lifecycleFixture.
// Read the public JSON, so these tests compile against the pre-receipt source.
func readDiagnostic(t *testing.T, root string) (map[string]any, string) {
	t.Helper()
	p := filepath.Join(filepath.Dir(root), "service-diagnostic.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("diagnostic receipt missing: %v", err)
	}
	if len(raw) > 65536 {
		t.Fatal("receipt exceeds 64KiB")
	}
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("receipt is not private")
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v["trust"] != "UNTRUSTED_DIAGNOSTIC" || v["schema_version"] != float64(1) {
		t.Fatal("receipt trust/schema")
	}
	for _, secret := range []string{root, "fixture", "SECRET", "BEGIN CERTIFICATE", "runtime.json", "password", "203.0.113.", "192.0.2.53"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("receipt leaked %q", secret)
		}
	}
	return v, string(raw)
}
func TestReceiptLifecycle(t *testing.T) {
	d, b, c, k, _, _ := lifecycleFixture(t)
	if err := d.start(b, c, k, true); err != nil {
		t.Fatal(err)
	}
	v, _ := readDiagnostic(t, d.root)
	wantMode := "EMBEDDED"
	if externalCoreRequired() {
		wantMode = "EXTERNAL"
	}
	if v["engine_mode"] != wantMode || v["network"] != "TUN" || v["operation"] != "START" || v["outcome"] != "SUCCEEDED" || v["readiness"] != "NETWORK_VERIFIED" || v["https"] != "SUCCEEDED_SAME_INVOCATION" {
		t.Fatalf("wrong start outcome: %v", v)
	}
	sum := sha256.Sum256([]byte("app"))
	identity := v["identity"].(map[string]any)
	if identity["app_sha256"] != hex.EncodeToString(sum[:]) || identity["git_revision"] != "UNKNOWN" || identity["app_version"] != "UNKNOWN" {
		t.Fatal("staged artifact/build identity incorrect")
	}
	staged, err := os.ReadFile(filepath.Join(d.root, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cs := sha256.Sum256(staged)
	if identity["config_sha256"] != hex.EncodeToString(cs[:]) {
		t.Fatal("config digest is not staged bytes")
	}
	if len(v["servers"].([]any)) != 2 {
		t.Fatal("all baseline servers not recorded")
	}
	if err := d.stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(d.root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("snapshot not deleted")
	}
	v, _ = readDiagnostic(t, d.root)
	if v["operation"] != "STOP" || v["outcome"] != "SUCCEEDED" || v["stopped"] != "VERIFIED" || v["restoration"] != "VERIFIED" || v["snapshot"] != "REMOVED" || v["https"] != "NOT_EXECUTED" {
		t.Fatalf("wrong stop outcome: %v", v)
	}
	if v["identity"].(map[string]any)["app_sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatal("digest lost across deletion")
	}
}
func TestReceiptFailedRollback(t *testing.T) {
	d, b, c, k, loaded, _ := lifecycleFixture(t)
	primary := errors.New("SECRET HTTPS")
	rollback := errors.New("SECRET bootout")
	tool := d.tool
	d.tool = func(ctx context.Context, n string, a ...string) (string, error) {
		if n == "/usr/bin/curl" {
			return "SECRET", primary
		}
		if n == "/bin/launchctl" && a[0] == "bootout" {
			return "SECRET", rollback
		}
		return tool(ctx, n, a...)
	}
	err := d.start(b, c, k, true)
	if !errors.Is(err, primary) || !errors.Is(err, rollback) || !*loaded {
		t.Fatal("original failure identities/state lost")
	}
	v, _ := readDiagnostic(t, d.root)
	if v["outcome"] != "FAILED" || v["readiness"] == "NETWORK_VERIFIED" || v["stopped"] == "VERIFIED" || v["rollback"] != "FAILED" || v["https"] != "FAILED" {
		t.Fatalf("false ready/stopped: %v", v)
	}
}
func TestReceiptPoisonIgnored(t *testing.T) {
	d, _, _, _, loaded, calls := lifecycleFixture(t)
	*loaded = true
	p := filepath.Join(filepath.Dir(d.root), "service-diagnostic.json")
	poison := []byte(`{"trust":"UNTRUSTED_DIAGNOSTIC","readiness":"NETWORK_VERIFIED","https":"SUCCEEDED_SAME_INVOCATION","stopped":"VERIFIED"}`)
	if err := os.WriteFile(p, poison, 0600); err != nil {
		t.Fatal(err)
	}
	*calls = nil
	status, err := d.status()
	if err != nil || !strings.Contains(status, "readiness not_verified") {
		t.Fatalf("poison trusted: %s %v", status, err)
	}
	raw, _ := os.ReadFile(p)
	if string(raw) != string(poison) {
		t.Fatal("status wrote receipt")
	}
	for _, call := range *calls {
		if strings.Contains(call, "curl:") || strings.Contains(call, "launchctl:") {
			t.Fatal("status controlled service")
		}
	}
}
func TestReceiptWriteFailure(t *testing.T) {
	for _, mode := range []string{"symlink", "directory", "failed_lifecycle"} {
		t.Run(mode, func(t *testing.T) {
			d, b, c, k, _, _ := lifecycleFixture(t)
			p := filepath.Join(filepath.Dir(d.root), "service-diagnostic.json")
			target := filepath.Join(t.TempDir(), "untouched")
			if err := os.WriteFile(target, []byte("untouched"), 0600); err != nil {
				t.Fatal(err)
			}
			if mode == "directory" {
				if err := os.Mkdir(p, 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Symlink(target, p); err != nil {
					t.Fatal(err)
				}
			}
			sentinel := errors.New("SECRET preflight")
			if mode == "failed_lifecycle" {
				d.proxy = func() error { return sentinel }
			}
			err := d.start(b, c, k, true)
			if err == nil || !strings.Contains(err.Error(), "diagnostic receipt write failed") || strings.Contains(err.Error(), target) || strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("receipt failure silently accepted/unsafe: %v", err)
			}
			if mode == "failed_lifecycle" && !errors.Is(err, sentinel) {
				t.Fatal("lifecycle cause lost")
			}
			raw, _ := os.ReadFile(target)
			if string(raw) != "untouched" {
				t.Fatal("symlink target replaced")
			}
		})
	}
}
func TestReceiptCancelled(t *testing.T) {
	d, b, c, k, _, _ := lifecycleFixture(t)
	tool := d.tool
	d.tool = func(ctx context.Context, n string, a ...string) (string, error) {
		if n == "/usr/bin/curl" {
			return "SECRET", context.Canceled
		}
		return tool(ctx, n, a...)
	}
	if err := d.start(b, c, k, true); !errors.Is(err, context.Canceled) {
		t.Fatal("cancel identity lost")
	}
	v, _ := readDiagnostic(t, d.root)
	if v["https"] != "CANCELLED" || v["outcome"] != "CANCELLED" || v["rollback"] != "SUCCEEDED" || v["readiness"] == "NETWORK_VERIFIED" {
		t.Fatalf("cancel faked success: %v", v)
	}
}

func TestReceiptAuthoritativePatchIdentity(t *testing.T) {
	raw, err := os.ReadFile("patches/sing-box/core-slim.identity.json")
	if err != nil {
		t.Fatal(err)
	}
	var authoritative struct {
		Commit string `json:"commit"`
		Patch  string `json:"patch_sha256"`
	}
	if err := json.Unmarshal(raw, &authoritative); err != nil {
		t.Fatal(err)
	}
	if diagnosticUpstream != authoritative.Commit || diagnosticPatch != authoritative.Patch {
		t.Fatal("receipt source identity diverges from authority")
	}
	patch, err := os.ReadFile("patches/sing-box/core-slim.patch.json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(patch)
	if hex.EncodeToString(sum[:]) != diagnosticPatch {
		t.Fatal("patch SHA is not actual approved patch bytes")
	}
}
func TestReceiptStagedCollectionBounds(t *testing.T) {
	dir := t.TempDir()
	r := newDiagnostic("STOP")
	for name, data := range map[string]string{"anytls-macos": "app", "config.yaml": "password: SECRET", "config.yaml.selected": "SECRET"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, sub := range []string{"rules", "certs"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, sub, "SECRET.pem"), []byte("SECRET"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r.capture(dir)
	sum := sha256.Sum256([]byte("SECRET"))
	if len(r.Identity.Rules) != 1 || r.Identity.Rules[0] != hex.EncodeToString(sum[:]) || r.Identity.CA[0] != hex.EncodeToString(sum[:]) {
		t.Fatal("not hashing actual captured staged bytes")
	}
	if err := os.Symlink(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "certs", "link")); err != nil {
		t.Fatal(err)
	}
	r.capture(dir)
	if r.Identity.CA[0] != "UNAVAILABLE" {
		t.Fatal("nonregular staged artifact accepted")
	}
	f, err := os.Create(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(2 << 20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	r.capture(dir)
	if r.Identity.Config != "UNAVAILABLE" {
		t.Fatal("unbounded collection")
	}
}
func TestReceiptStopBranches(t *testing.T) {
	for _, mode := range []string{"absent", "missing_baseline", "dns_changed", "cleanup_failed", "receipt_failed"} {
		t.Run(mode, func(t *testing.T) {
			d, b, c, k, _, _ := lifecycleFixture(t)
			sentinel := errors.New("SECRET cleanup")
			if mode != "absent" {
				if err := d.start(b, c, k, true); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "missing_baseline":
				if err := os.Remove(filepath.Join(d.root, serviceBaselineName)); err != nil {
					t.Fatal(err)
				}
			case "dns_changed":
				d.dns = func() ([]string, error) { return []string{"nameserver[0] : 192.0.2.54"}, nil }
			case "cleanup_failed":
				d.remove = func(string) error { return sentinel }
			case "receipt_failed":
				p := filepath.Join(filepath.Dir(d.root), "service-diagnostic.json")
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(p, 0700); err != nil {
					t.Fatal(err)
				}
			}
			err := d.stop()
			if mode == "absent" && err != nil {
				t.Fatal(err)
			}
			if (mode == "cleanup_failed" || mode == "receipt_failed") && err == nil {
				t.Fatal("failure branch accepted")
			}
			if mode == "cleanup_failed" && !errors.Is(err, sentinel) {
				t.Fatal("cleanup identity lost")
			}
			if mode == "receipt_failed" {
				if !strings.Contains(err.Error(), "lifecycle succeeded; diagnostic receipt write failed") {
					t.Fatal("operation outcome missing")
				}
				if _, e := os.Stat(d.root); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("verified stop was not completed")
				}
				return
			}
			v, _ := readDiagnostic(t, d.root)
			if v["https"] != "NOT_EXECUTED" || v["readiness"] == "NETWORK_VERIFIED" {
				t.Fatal("stop fabricated readiness")
			}
			if mode == "absent" && v["restoration"] != "UNAVAILABLE_NO_BASELINE" {
				t.Fatal("absent baseline fabricated restoration")
			}
			if (mode == "missing_baseline" || mode == "dns_changed") && v["restoration"] == "VERIFIED" {
				t.Fatal("failed restoration claimed verified")
			}
			if mode == "cleanup_failed" && (v["restoration"] != "VERIFIED" || v["snapshot"] != "RETAINED") {
				t.Fatal("restoration/cleanup conflated")
			}
		})
	}
}
func TestReceiptPhaseEvidence(t *testing.T) {
	for _, mode := range []string{"timeout", "secondary", "final_changed"} {
		t.Run(mode, func(t *testing.T) {
			d, b, c, k, loaded, _ := lifecycleFixture(t)
			route, tool := d.route, d.tool
			probed := false
			d.tool = func(ctx context.Context, n string, a ...string) (string, error) {
				out, err := tool(ctx, n, a...)
				if n == "/usr/bin/curl" {
					probed = true
				}
				return out, err
			}
			d.route = func(ip string) (string, error) {
				if *loaded {
					if mode == "timeout" && ip == "1.1.1.1" {
						return "en0", nil
					}
					if mode == "secondary" && ip == "203.0.113.2" {
						return "utun9", nil
					}
					if mode == "final_changed" && probed && ip == "1.1.1.1" {
						return "utun9", nil
					}
				}
				return route(ip)
			}
			if err := d.start(b, c, k, true); err == nil {
				t.Fatal("failure branch accepted")
			}
			v, _ := readDiagnostic(t, d.root)
			if v["outcome"] != "FAILED" || v["rollback"] != "SUCCEEDED" || v["readiness"] == "NETWORK_VERIFIED" {
				t.Fatalf("wrong branch: %v", v)
			}
			if mode == "final_changed" {
				if v["https"] != "SUCCEEDED_SAME_INVOCATION" || v["after_https"].(map[string]any)["public_route"] != "FAILED" {
					t.Fatal("final change evidence incorrect")
				}
			} else if v["https"] != "NOT_EXECUTED" {
				t.Fatal("unexecuted HTTPS claimed success")
			}
			servers := v["servers"].([]any)
			if servers[0].(map[string]any)["baseline"] != "CAPTURED_PHYSICAL" || servers[1].(map[string]any)["restoration"] != "VERIFIED" {
				t.Fatal("phase observations not retained")
			}
			if mode == "secondary" && servers[1].(map[string]any)["readiness"] != "FAILED" {
				t.Fatal("failed secondary route relabeled")
			}
		})
	}
}

func TestReceiptCollectionCaps(t *testing.T) {
	for _, mode := range []string{"count_at", "count_over", "total_at", "total_over", "file_over"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			count, size := 128, int64(0)
			switch mode {
			case "count_over":
				count = 129
			case "total_at":
				count, size = 16, 1<<20
			case "total_over":
				count, size = 17, 1<<20
			case "file_over":
				count, size = 1, (1<<20)+1
			}
			for i := 0; i < count; i++ {
				f, err := os.Create(filepath.Join(dir, fmt.Sprint(i)))
				if err != nil {
					t.Fatal(err)
				}
				err = f.Truncate(size)
				if closeErr := f.Close(); err != nil || closeErr != nil {
					t.Fatal("fixture file creation failed", err, closeErr)
				}
			}
			got := diagnosticHashes(dir)
			if strings.HasSuffix(mode, "over") {
				if len(got) != 1 || got[0] != "UNAVAILABLE" {
					t.Fatal("collection cap not enforced")
				}
			} else if len(got) != count || strings.Contains(strings.Join(got, ""), "UNAVAILABLE") {
				t.Fatal("valid directory at exact cap rejected")
			}
		})
	}
}

// TestReceiptDirectoryGate contains blocking regressions in an owned subprocess.
// Run waits/reaps even after CommandContext kills it; parent-owned TMPDIR also
// removes child fixtures after a timeout. No blocked goroutine survives in Go's
// suite process, and timeout is a business failure, never an accepted rejection.
func TestReceiptDirectoryGate(t *testing.T) {
	const marker = "ANYTLS_RECEIPT_DIRECTORY_HELPER"
	if selected := os.Getenv(marker); selected != "" {
		parts := strings.Split(selected, "/")
		if len(parts) != 3 {
			t.Fatal("invalid selected-test marker")
		}
		receiptDirectoryCase(t, parts[0], parts[1], parts[2])
		return
	}
	for _, operation := range []string{"collect", "stop"} {
		for _, directory := range []string{"rules", "certs"} {
			for _, kind := range []string{"fifo", "symlink", "regular"} {
				selected := operation + "/" + directory + "/" + kind
				t.Run(selected, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReceiptDirectoryGate$", "-test.v")
					cmd.Env = append(os.Environ(), marker+"="+selected, "TMPDIR="+t.TempDir())
					out, err := cmd.CombinedOutput() // joins I/O and waits the owned child
					if ctx.Err() != nil {
						t.Fatalf("directory gate blocked %s; owned child killed/waited=%t: %s", selected, cmd.ProcessState != nil, out)
					}
					if err != nil {
						t.Fatalf("directory gate failed %s: %v: %s", selected, err, out)
					}
					if !strings.Contains(string(out), "DIRECTORY_GATE_VERIFIED "+selected) {
						t.Fatal("helper did not complete business assertions")
					}
				})
			}
		}
	}
}

func receiptDirectoryCase(t *testing.T, operation, directory, kind string) {
	t.Helper()
	d, b, c, k, loaded, calls := lifecycleFixture(t)
	if operation == "stop" {
		if err := d.start(b, c, k, true); err != nil {
			t.Fatal(err)
		}
	} else if err := os.Mkdir(d.root, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d.root, directory)
	if err := os.RemoveAll(p); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	outsideBytes := []byte("outside staged snapshot")
	if err := os.WriteFile(filepath.Join(outside, "outside"), outsideBytes, 0600); err != nil {
		t.Fatal(err)
	}
	switch kind {
	case "fifo":
		if err := syscall.Mkfifo(p, 0600); err != nil {
			t.Fatal(err)
		}
	case "symlink":
		if err := os.Symlink(outside, p); err != nil {
			t.Fatal(err)
		}
	case "regular":
		if err := os.WriteFile(p, []byte("not a directory"), 0600); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unknown directory fixture")
	}
	fmt.Println("DIRECTORY_GATE_INVOKE", operation+"/"+directory+"/"+kind)
	var identity map[string]any
	if operation == "collect" {
		r := newDiagnostic("STOP")
		r.capture(d.root)
		raw, err := json.Marshal(r.Identity)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &identity); err != nil {
			t.Fatal(err)
		}
	} else {
		// Install closures before stop's value receiver copies its dependencies.
		*calls = nil
		state, dns := d.state, d.dns
		d.state = func() (bool, bool, error) {
			*calls = append(*calls, "state")
			return state()
		}
		d.dns = func() ([]string, error) {
			*calls = append(*calls, "dns")
			return dns()
		}
		if err := d.stop(); err != nil {
			t.Fatal(err)
		}
		if *loaded || len(*calls) == 0 || (*calls)[0] != "state" {
			t.Fatal("stop did not reach actual simulated state/bootout")
		}
		bootout, stateAfter, routeAfter, dnsAfter := false, false, false, false
		for _, call := range *calls {
			if strings.HasPrefix(call, "launchctl:bootout ") {
				bootout = true
			}
			stateAfter = stateAfter || bootout && call == "state"
			routeAfter = routeAfter || bootout && strings.HasPrefix(call, "route:")
			dnsAfter = dnsAfter || bootout && call == "dns"
		}
		if !bootout || !stateAfter || !routeAfter || !dnsAfter {
			t.Fatal("malformed collection prevented bootout/restoration probes")
		}
		v, raw := readDiagnostic(t, d.root)
		if v["stopped"] != "VERIFIED" || v["restoration"] != "VERIFIED" || v["snapshot"] != "REMOVED" || v["outcome"] != "SUCCEEDED" {
			t.Fatal("malformed collection displaced actual lifecycle outcome")
		}
		if _, err := os.Lstat(d.root); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("verified stop retained snapshot")
		}
		sum := sha256.Sum256(outsideBytes)
		if strings.Contains(raw, hex.EncodeToString(sum[:])) {
			t.Fatal("outside directory digest included in receipt")
		}
		identity = v["identity"].(map[string]any)
	}
	field := "rules_sha256"
	if directory == "certs" {
		field = "ca_sha256"
	}
	hashes := identity[field].([]any)
	if len(hashes) != 1 || hashes[0] != "UNAVAILABLE" {
		t.Fatal("non-directory staged collection must be UNAVAILABLE; outside digest must not be included")
	}
	fmt.Println("DIRECTORY_GATE_VERIFIED", operation+"/"+directory+"/"+kind)
}

func TestReceiptWriterBoundedAtomicReplacement(t *testing.T) {
	root := filepath.Join(t.TempDir(), "snapshot")
	r := newDiagnostic("START")
	if err := r.write(root); err != nil {
		t.Fatal(err)
	}
	r.Outcome = "FAILED"
	if err := r.write(root); err != nil {
		t.Fatal(err)
	}
	_, raw := readDiagnostic(t, root)
	if !strings.Contains(raw, `"outcome":"FAILED"`) {
		t.Fatal("current receipt not replaced")
	}
	entries, err := os.ReadDir(filepath.Dir(root))
	if err != nil || len(entries) != 1 {
		t.Fatal("temp/history left behind")
	}
	r.Identity.App = strings.Repeat("x", 65536)
	if err := r.write(root); err == nil {
		t.Fatal("oversized receipt accepted")
	}
	_, after := readDiagnostic(t, root)
	if raw != after {
		t.Fatal("failed publication destroyed old receipt")
	}
	r.serverScope(129, "CAPTURED_PHYSICAL")
	if len(r.Servers) != 0 || r.ServerCount != 129 || r.ServerDetails != "UNAVAILABLE_BOUND_EXCEEDED" {
		t.Fatal("server details silently truncated")
	}
}
