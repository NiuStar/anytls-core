package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// UNIT-SIMULATED tools/network; real staging in TempDir, never root wrappers.
func lifecycleFixture(t *testing.T) (serviceLifecycle, string, string, string, *bool, *[]string) {
	t.Helper()
	dir := t.TempDir()
	config := filepath.Join(dir, "config.yaml")
	binary := filepath.Join(dir, "app")
	core := filepath.Join(dir, "core")
	data := `proxies:
 - {name: primary, type: anytls, server: 203.0.113.1, port: 443, password: fixture, skip-cert-verify: true}
 - {name: secondary, type: anytls, server: 203.0.113.2, port: 443, password: fixture, skip-cert-verify: true}
 - {name: duplicate, type: anytls, server: 203.0.113.2, port: 443, password: fixture, skip-cert-verify: true}
 - {name: unused, type: anytls, server: 203.0.113.99, port: 443, password: fixture, skip-cert-verify: true}
rules: ["DOMAIN,example.org,secondary", "DOMAIN,example.net,duplicate", "MATCH,primary"]
`
	for p, b := range map[string]string{config: data, selectedPath(config): "primary", binary: "app", core: "core"} {
		if err := os.WriteFile(p, []byte(b), 0600); err != nil {
			t.Fatal(err)
		}
	}
	loaded := false
	calls := []string{}
	d := newServiceLifecycle(filepath.Join(dir, "snapshot"))
	d.state = func() (bool, bool, error) { return loaded, loaded, nil }
	d.proxy = func() error { return nil }
	// Closures share one clock across value-receiver lifecycle copies.
	now := time.Unix(0, 0)
	d.now = func() time.Time { return now }
	d.pause = func() { now = now.Add(time.Second) }
	d.route = func(ip string) (string, error) {
		calls = append(calls, "route:"+ip)
		if loaded && ip == "1.1.1.1" {
			return "utun8", nil
		}
		return "en0", nil
	}
	d.dns = func() ([]string, error) { return []string{"nameserver[0] : 192.0.2.53"}, nil }
	d.tool = func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, filepath.Base(name)+":"+strings.Join(args, " "))
		if name == "/bin/launchctl" {
			switch args[0] {
			case "bootstrap":
				loaded = true
			case "bootout":
				loaded = false
			default:
				t.Fatal("unexpected control")
			}
		}
		if name == "/usr/bin/curl" {
			return "198.51.100.1", nil
		}
		return "", nil
	}
	return d, binary, config, core, &loaded, &calls
}
func TestServiceStatusEvidence(t *testing.T) {
	for _, mode := range []string{"loaded", "running_private_unavailable", "running_network_ready", "restoration_failed", "not_verified", "stopped"} {
		t.Run(mode, func(t *testing.T) {
			d, b, c, k, loaded, calls := lifecycleFixture(t)
			want := mode
			switch mode {
			case "loaded":
				d.state = func() (bool, bool, error) { return true, false, nil }
			case "running_private_unavailable":
				*loaded = true
				want = "running; readiness not_verified"
			case "running_network_ready":
				if err := d.start(b, c, k, true); err != nil {
					t.Fatal(err)
				}
				want = "running; network ready; HTTPS not_verified"
			case "restoration_failed":
				if err := d.start(b, c, k, true); err != nil {
					t.Fatal(err)
				}
				*loaded = false
				d.route = func(string) (string, error) { return "utun9", nil }
			case "not_verified":
				if err := os.Mkdir(d.root, 0700); err != nil {
					t.Fatal(err)
				}
			}
			*calls = nil
			got, err := d.status()
			if (err != nil && mode != "restoration_failed") || !strings.Contains(got, want) {
				t.Fatalf("status=%q err=%v want %q", got, err, want)
			}
			for _, call := range *calls {
				if strings.HasPrefix(call, "curl:") || strings.HasPrefix(call, "launchctl:") {
					t.Fatal("status invoked control/HTTPS")
				}
			}
		})
	}
}
func TestServiceStatusDisabledNotAbsent(t *testing.T) {
	sentinel := errors.New("tool sentinel")
	l, r, err := serviceStateWithTool(func(context.Context, string, ...string) (string, error) { return "service is disabled", sentinel })
	if err == nil || l || r {
		t.Fatal("disabled error incorrectly accepted as confirmed unloaded")
	}
}

func TestLifecycleAllRoutedServers(t *testing.T) {
	d, b, c, k, loaded, calls := lifecycleFixture(t)
	original := d.route
	d.route = func(ip string) (string, error) {
		if *loaded && ip == "203.0.113.2" {
			return "utun9", nil
		}
		return original(ip)
	}
	err := d.start(b, c, k, true)
	if err == nil {
		t.Fatal("secondary routed server entered TUN but start succeeded")
	}
	if *loaded {
		t.Fatal("failed readiness did not bootout")
	}
	for _, call := range *calls {
		if call == "route:203.0.113.99" {
			t.Fatal("unused node route queried")
		}
	}
}
func TestLifecycleUnloadedMissingBaseline(t *testing.T) {
	d, _, _, _, _, _ := lifecycleFixture(t)
	if err := os.Mkdir(d.root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := d.stop(); err != nil {
		t.Fatal("unloaded snapshot must not block stop", err)
	}
	archives, _ := filepath.Glob(filepath.Join(filepath.Dir(d.root), ".service-recovery-*", "snapshot"))
	if len(archives) != 1 {
		t.Fatal("diagnostic evidence not archived")
	}
}
func TestLifecycleRollbackErrors(t *testing.T) {
	d, b, c, k, _, _ := lifecycleFixture(t)
	primary := errors.New("probe sentinel")
	cleanup := errors.New("bootout sentinel")
	tool := d.tool
	d.tool = func(ctx context.Context, n string, a ...string) (string, error) {
		if n == "/usr/bin/curl" {
			return "", primary
		}
		if n == "/bin/launchctl" && a[0] == "bootout" {
			return "", cleanup
		}
		return tool(ctx, n, a...)
	}
	err := d.start(b, c, k, true)
	if !errors.Is(err, primary) || !errors.Is(err, cleanup) {
		t.Fatalf("primary/rollback causes lost: %v", err)
	}
	if strings.Contains(err.Error(), "rolled back") {
		t.Fatal("unconfirmed rollback claimed")
	}
}
func TestLifecycleStopProbeErrors(t *testing.T) {
	d, b, c, k, _, _ := lifecycleFixture(t)
	if err := d.start(b, c, k, true); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("DNS sentinel")
	d.dns = func() ([]string, error) { return nil, sentinel }
	if err := d.stop(); err != nil {
		t.Fatalf("DNS probe warning blocked confirmed stop: %v", err)
	}
	v, _ := readDiagnostic(t, d.root)
	if v["restoration"] == "VERIFIED" || v["snapshot"] != "ARCHIVED" {
		t.Fatal("DNS uncertainty lost", v)
	}
}
func TestLifecycleCorruptBaseline(t *testing.T) {
	for _, raw := range []string{`{}`, `{"Server":"203.0.113.1","ServerInterface":"","PublicInterface":"","DNS":null}`, `not json`} {
		t.Run(raw, func(t *testing.T) {
			d, _, _, _, loaded, _ := lifecycleFixture(t)
			*loaded = true
			if err := os.Mkdir(d.root, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(d.root, serviceBaselineName), []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			d.route = func(string) (string, error) { return "", nil }
			d.dns = func() ([]string, error) { return nil, nil }
			if err := d.stop(); err != nil {
				t.Fatal("corrupt baseline blocked unload", err)
			}
			v, _ := readDiagnostic(t, d.root)
			if v["restoration"] == "VERIFIED" {
				t.Fatal("empty/corrupt evidence falsely proved restoration")
			}
			if *loaded {
				t.Fatal("missing proof must not prevent bootout")
			}
		})
	}
}
func TestLifecycleBaselineAllServers(t *testing.T) {
	d, b, c, k, _, _ := lifecycleFixture(t)
	if err := d.start(b, c, k, true); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(d.root, serviceBaselineName))
	if err != nil {
		t.Fatal(err)
	}
	var baseline struct {
		Version int
		Servers map[string]string
	}
	if err := json.Unmarshal(raw, &baseline); err != nil {
		t.Fatal(err)
	}
	if baseline.Version != 1 || len(baseline.Servers) != 2 || baseline.Servers["203.0.113.2"] != "en0" {
		t.Fatalf("all actual servers not captured: %s", raw)
	}
}

func TestLifecycleStopTransitions(t *testing.T) {
	for _, mode := range []string{"unloaded_restored", "unloaded_secondary_changed", "loaded_missing_baseline", "bootout_and_baseline_errors", "state_error", "route_error", "cleanup_error", "legacy_single", "legacy_multi"} {
		t.Run(mode, func(t *testing.T) {
			d, b, c, k, loaded, calls := lifecycleFixture(t)
			if mode == "legacy_single" {
				raw, err := os.ReadFile(c)
				if err != nil {
					t.Fatal(err)
				}
				data := strings.Split(string(raw), "rules:")[0] + "rules: [\"MATCH,primary\"]\n"
				if err := os.WriteFile(c, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := d.start(b, c, k, true); err != nil {
				t.Fatal(err)
			}
			*calls = nil
			sentinel := errors.New("transition sentinel")
			wantErr := false
			switch mode {
			case "unloaded_restored":
				*loaded = false
				wantErr = false
			case "unloaded_secondary_changed":
				*loaded = false
				route := d.route
				d.route = func(ip string) (string, error) {
					if ip == "203.0.113.2" {
						return "en1", nil
					}
					return route(ip)
				}
			case "loaded_missing_baseline":
				if err := os.Remove(filepath.Join(d.root, serviceBaselineName)); err != nil {
					t.Fatal(err)
				}
			case "bootout_and_baseline_errors":
				wantErr = true
				if err := os.Remove(filepath.Join(d.root, serviceBaselineName)); err != nil {
					t.Fatal(err)
				}
				d.tool = func(context.Context, string, ...string) (string, error) { return "SECRET", sentinel }
			case "state_error":
				wantErr = true
				d.state = func() (bool, bool, error) { return false, false, sentinel }
			case "route_error":
				d.route = func(string) (string, error) { return "", sentinel }
			case "cleanup_error":
				wantErr = true
				d.remove = func(string) error { return sentinel }
			case "legacy_single", "legacy_multi":
				p := filepath.Join(d.root, serviceBaselineName)
				raw, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				var v map[string]any
				if err := json.Unmarshal(raw, &v); err != nil {
					t.Fatal(err)
				}
				delete(v, "Version")
				delete(v, "Servers")
				raw, err = json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, raw, 0600); err != nil {
					t.Fatal(err)
				}
				wantErr = false
			}
			err := d.stop()
			if (err != nil) != wantErr {
				t.Fatalf("stop error=%v wantErr=%v", err, wantErr)
			}
			if wantErr && (strings.HasSuffix(mode, "error") || mode == "bootout_and_baseline_errors") {
				if !errors.Is(err, sentinel) {
					t.Fatalf("error identity lost: %v", err)
				}
			}
			if err != nil {
				if _, e := os.Stat(d.root); e != nil {
					t.Fatal("evidence removed on failure")
				}
				if strings.Contains(err.Error(), "SECRET") {
					t.Fatal("tool output leaked")
				}
			} else if _, e := os.Stat(d.root); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("successful restoration did not clean snapshot")
			}
			if mode == "loaded_missing_baseline" && *loaded {
				t.Fatal("job not unloaded")
			}
			if mode == "bootout_and_baseline_errors" && !errors.Is(err, os.ErrNotExist) {
				t.Fatal("baseline error lost")
			}
			if mode == "state_error" {
				for _, call := range *calls {
					if strings.Contains(call, "bootout") {
						t.Fatal("state error must fail closed")
					}
				}
			}
		})
	}
}
func TestLifecycleStartProbeTransitions(t *testing.T) {
	for _, mode := range []string{"state", "public", "secondary", "dns", "https", "timeout", "bootstrap", "staging_cleanup_state"} {
		t.Run(mode, func(t *testing.T) {
			d, b, c, k, loaded, _ := lifecycleFixture(t)
			sentinel := errors.New("private upstream SECRET")
			route := d.route
			state := d.state
			dns := d.dns
			tool := d.tool
			d.state = func() (bool, bool, error) {
				if *loaded && mode == "state" {
					return false, false, sentinel
				}
				return state()
			}
			d.route = func(ip string) (string, error) {
				if *loaded && ((mode == "public" && ip == "1.1.1.1") || (mode == "secondary" && ip == "203.0.113.2")) {
					return "", sentinel
				}
				if *loaded && mode == "timeout" && ip == "1.1.1.1" {
					return "en0", nil
				}
				return route(ip)
			}
			d.dns = func() ([]string, error) {
				if *loaded && mode == "dns" {
					return nil, sentinel
				}
				return dns()
			}
			d.tool = func(ctx context.Context, n string, a ...string) (string, error) {
				if mode == "https" && n == "/usr/bin/curl" {
					return "SECRET", sentinel
				}
				out, err := tool(ctx, n, a...)
				if mode == "bootstrap" && n == "/bin/launchctl" && a[0] == "bootstrap" {
					return "SECRET", sentinel
				}
				return out, err
			}
			if mode == "staging_cleanup_state" {
				failed := false
				d.state = func() (bool, bool, error) {
					if failed {
						return false, false, sentinel
					}
					return false, false, nil
				}
				d.stage = func(_, _, _, root string) error {
					if err := os.Mkdir(root, 0700); err != nil {
						t.Fatal(err)
					}
					failed = true
					return sentinel
				}
			}
			err := d.start(b, c, k, true)
			if err == nil {
				t.Fatal("failed readiness/staging accepted")
			}
			if mode != "timeout" && !errors.Is(err, sentinel) {
				t.Fatalf("probe error lost: %v", err)
			}
			if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "rolled back") {
				t.Fatalf("unsafe error display: %v", err)
			}
			if mode == "state" || mode == "staging_cleanup_state" {
				if _, err := os.Stat(d.root); err != nil {
					t.Fatal("uncertain job state deleted snapshot")
				}
			}
		})
	}
}

// Capture only the same production state machine's output; no root entry point.
func lifecycleOutput(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = original; _ = f.Close() }()
	callErr := fn()
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(raw), callErr
}

func TestLifecycleHTTPSExactUTUN(t *testing.T) {
	for _, mode := range []string{"unchanged", "changed_restored", "changed_restoration_error"} {
		t.Run(mode, func(t *testing.T) {
			d, b, c, k, loaded, calls := lifecycleFixture(t)
			tool, route, dns := d.tool, d.route, d.dns
			probed, restoredDNS := false, false
			sentinel := errors.New("restoration DNS sentinel")
			d.tool = func(ctx context.Context, n string, a ...string) (string, error) {
				out, err := tool(ctx, n, a...)
				if n == "/usr/bin/curl" {
					if !*loaded {
						t.Fatal("HTTPS probe without running owned job")
					}
					probed = true // Deterministic interface change across blocking HTTPS.
				}
				return out, err
			}
			d.route = func(ip string) (string, error) {
				iface, err := route(ip)
				if probed && *loaded && ip == "1.1.1.1" && mode != "unchanged" {
					return "utun9", nil
				}
				if ip != "1.1.1.1" && iface != "en0" {
					t.Fatal("fixture server route did not remain physical")
				}
				return iface, err
			}
			d.dns = func() ([]string, error) {
				if probed && !*loaded {
					restoredDNS = true
					if mode == "changed_restoration_error" {
						return nil, sentinel
					}
				}
				return dns()
			}
			output, err := lifecycleOutput(t, func() error { return d.start(b, c, k, true) })
			if !probed {
				t.Fatal("HTTPS probe not exercised")
			}
			if mode == "unchanged" {
				if err != nil || !*loaded || !strings.Contains(output, "AnyTLS TUN ready;") {
					t.Fatalf("unchanged utun8 rejected: output=%q err=%v", output, err)
				}
				if err := d.stop(); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "readiness changed during HTTPS probe") {
				t.Errorf("utun8 -> utun9 must fail readiness: %v", err)
			}
			if strings.Contains(output, "AnyTLS TUN ready;") {
				t.Error("changed utun printed ready")
			}
			bootouts := 0
			for _, call := range *calls {
				if call == "launchctl:bootout system/"+serviceLabel {
					bootouts++
				}
			}
			if *loaded || bootouts != 1 || !restoredDNS {
				t.Errorf("rollback not verified: loaded=%v bootouts=%d DNS=%v", *loaded, bootouts, restoredDNS)
			}
			_, statErr := os.Stat(d.root)
			if mode == "changed_restoration_error" {
				if !errors.Is(err, sentinel) || !errors.Is(statErr, os.ErrNotExist) || strings.Contains(output, "restoration verified") {
					t.Fatalf("rollback error/evidence lost: output=%q err=%v stat=%v", output, err, statErr)
				}
			} else if !errors.Is(statErr, os.ErrNotExist) || !strings.Contains(output, "all server/public routes and DNS restoration verified") {
				t.Fatalf("restoration not proved: output=%q stat=%v", output, statErr)
			}
		})
	}
}

func TestLifecycleDNSBaselineAddresses(t *testing.T) {
	for _, mode := range []string{"scoped_v1", "scoped_legacy_v0", "scoped_changed_zone", "ipv4", "plain_ipv6"} {
		t.Run(mode, func(t *testing.T) {
			d, b, c, k, loaded, calls := lifecycleFixture(t)
			want := []string{"nameserver[0] : fe80::1%en0", "nameserver[1] : 2001:db8::53", "nameserver[0] : 192.0.2.53", "nameserver[1] : fe80::1%en0"}
			if mode == "ipv4" {
				want = []string{"nameserver[0] : 192.0.2.53"}
			} else if mode == "plain_ipv6" {
				want = []string{"nameserver[0] : 2001:db8::53"}
			}
			if mode == "scoped_legacy_v0" {
				raw, err := os.ReadFile(c)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(c, []byte(strings.Split(string(raw), "rules:")[0]+"rules: [\"MATCH,primary\"]\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			d.dns = func() ([]string, error) { return slices.Clone(want), nil }
			if err := d.start(b, c, k, true); err != nil {
				t.Fatalf("valid DNS baseline rejected at start: %v", err)
			}
			p := filepath.Join(d.root, serviceBaselineName)
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			var baseline networkBaseline
			if err := json.Unmarshal(raw, &baseline); err != nil {
				t.Fatal(err)
			}
			if baseline.Version != 1 || !slices.Equal(baseline.DNS, want) {
				t.Fatalf("DNS strings/order/zone changed: %s", raw)
			}
			if mode == "scoped_legacy_v0" {
				baseline.Version, baseline.Servers = 0, nil
				raw, err = json.Marshal(baseline)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			*calls = nil
			status, err := d.status()
			if err != nil || !strings.Contains(status, "network ready; HTTPS not_verified") {
				t.Fatalf("valid baseline status rejected: %q %v", status, err)
			}
			if len(*calls) != 1+len(baseline.Servers) && mode != "scoped_legacy_v0" {
				t.Fatalf("unexpected status route scope: %v", *calls)
			}
			if mode == "scoped_changed_zone" {
				tool := d.tool
				zoneChanged := false
				d.dns = func() ([]string, error) {
					current := slices.Clone(want)
					if zoneChanged {
						current[0] = "nameserver[0] : fe80::1%en1"
					}
					return current, nil
				}
				d.tool = func(ctx context.Context, n string, a ...string) (string, error) {
					out, err := tool(ctx, n, a...)
					if n == "/bin/launchctl" && a[0] == "bootout" {
						zoneChanged = true // Shared closure survives stop's value receiver.
					}
					return out, err
				}
			}
			err = d.stop()
			if *loaded {
				t.Fatal("owned job remained loaded after stop")
			}
			if mode == "scoped_changed_zone" {
				if err != nil {
					t.Fatalf("changed DNS zone blocked stop: %v", err)
				}
				status, err := d.status()
				if err != nil || !strings.Contains(status, "stopped") {
					t.Fatalf("changed-zone job not stopped: %q %v", status, err)
				}
				paths, _ := filepath.Glob(filepath.Join(filepath.Dir(d.root), ".service-recovery-*", "snapshot", serviceBaselineName))
				if len(paths) != 1 {
					t.Fatal("missing original DNS evidence", paths)
				}
				raw, err := os.ReadFile(paths[0])
				if err != nil {
					t.Fatal(err)
				}
				var retained networkBaseline
				if err := json.Unmarshal(raw, &retained); err != nil || !slices.Equal(retained.DNS, want) {
					t.Fatalf("original zone/order diagnostic evidence lost: %s %v", raw, err)
				}
			} else if err != nil {
				t.Fatal(err)
			} else if _, err := os.Stat(d.root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("verified stop left snapshot: %v", err)
			}
		})
	}
}

func TestLifecycleMalformedScopedDNS(t *testing.T) {
	for _, address := range []string{"fe80::1%", "192.0.2.53%en0", "%en0", "fe80::gg%en0", "[fe80::1%en0]", "fe80::1%en0 : garbage", " fe80::1%en0"} {
		t.Run(address, func(t *testing.T) {
			d, b, c, k, loaded, calls := lifecycleFixture(t)
			d.dns = func() ([]string, error) { return []string{"nameserver[0] : " + address}, nil }
			if err := d.start(b, c, k, true); err == nil {
				t.Fatal("malformed scoped DNS accepted")
			}
			if *loaded {
				t.Fatal("invalid baseline loaded job")
			}
			if _, err := os.Stat(d.root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid baseline staged snapshot: %v", err)
			}
			for _, call := range *calls {
				if strings.HasPrefix(call, "launchctl:") || strings.HasPrefix(call, "curl:") {
					t.Fatal("invalid baseline invoked control/probe")
				}
			}
		})
	}
}

func TestLifecycleInsecureAggregate(t *testing.T) {
	d, _, c, _, _, _ := lifecycleFixture(t)
	_ = d
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, []byte("compiler checks regular nonempty"), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(c)
	if err != nil {
		t.Fatal(err)
	}
	data := strings.Replace(string(raw), "name: primary, type: anytls,", "name: primary, ca: "+ca+", type: anytls,", 1)
	if err := os.WriteFile(c, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	servers, insecure, err := serviceOutbounds(c, true)
	if err != nil || !insecure || len(servers) != 2 {
		t.Fatalf("secondary TLS not aggregated: %v %v %v", servers, insecure, err)
	}
	if _, _, err := serviceOutbounds(c, false); err == nil {
		t.Fatal("secondary insecure outbound accepted without explicit approval")
	}
}
