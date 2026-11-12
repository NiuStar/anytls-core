package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Historical producer fixture: never derive legacy server authority from v2.
func writeLegacyBaseline(t *testing.T, d serviceLifecycle, version int) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(d.root, serviceBaselineName))
	if err != nil {
		t.Fatal(err)
	}
	var local networkBaseline
	if err = json.Unmarshal(raw, &local); err != nil {
		t.Fatal(err)
	}
	servers, _, err := serviceOutbounds(filepath.Join(d.root, "config.yaml"), true)
	if err != nil {
		t.Fatal(err)
	}
	legacy := networkBaseline{Version: version, Server: servers[0], ServerInterface: "en0", PublicInterface: local.PublicInterface, DNS: local.DNS}
	if version == 1 {
		legacy.Servers = map[string]string{}
		for _, server := range servers {
			legacy.Servers[server] = "en0"
		}
	}
	raw, err = json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(d.root, serviceBaselineName), raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestLocalBaselineNoNodeRoutesAcrossLifecycle(t *testing.T) {
	for _, mode := range []string{"success", "final_dns_error", "no_job", "no_tun", "empty_dns"} {
		t.Run(mode, func(t *testing.T) {
			d, b, c, k, loaded, _ := lifecycleFixture(t)
			route := d.route
			nodeCalls := 0
			d.route = func(address string) (string, error) {
				if address != "1.1.1.1" {
					nodeCalls++
					return "", errors.New("node route must not run")
				}
				if mode == "no_tun" && *loaded {
					return "en0", nil
				}
				return route(address)
			}
			if mode == "no_job" {
				state := d.state
				d.state = func() (bool, bool, error) {
					if *loaded {
						return true, false, nil
					}
					return state()
				}
			}
			if mode == "final_dns_error" || mode == "empty_dns" {
				dns := d.dns
				d.dns = func() ([]string, error) {
					if *loaded {
						if mode == "empty_dns" {
							return nil, nil
						}
						return nil, errors.New("fixture final DNS failure")
					}
					return dns()
				}
			}
			err := d.start(b, c, k, true)
			if (err == nil) != (mode == "success") {
				t.Fatalf("mode=%s start=%v", mode, err)
			}
			v, _ := readDiagnostic(t, d.root)
			if v["schema_version"] != float64(3) || v["node_route_verification"] != "NOT_RUN" || v["restoration_scope"] != "LOCAL_INTERFACE_DNS" {
				t.Fatal("missing explicit local scope", v)
			}
			for _, phase := range []string{"baseline", "before_https", "after_https", "restore"} {
				if v[phase].(map[string]any)["server_routes"] != "NOT_EXECUTED" {
					t.Fatalf("fabricated server evidence in %s", phase)
				}
			}
			if mode == "success" {
				if _, err = d.status(); err != nil {
					t.Fatal(err)
				}
				// v2 status/STOP do not need recompiling the stored node scope.
				if err = os.Remove(filepath.Join(d.root, "config.yaml")); err != nil {
					t.Fatal(err)
				}
				if _, _, err = d.baseline(); err != nil {
					t.Fatal("v2 unexpectedly recompiled", err)
				}
				if err = d.stop(); err != nil {
					t.Fatal(err)
				}
			} else if *loaded {
				t.Fatal("failed start left job loaded")
			}
			if nodeCalls != 0 {
				t.Fatalf("node route calls=%d", nodeCalls)
			}
		})
	}
}

func TestLocalBaselineRejectsMixedAndUnknownEvidence(t *testing.T) {
	d, b, c, k, _, _ := lifecycleFixture(t)
	if err := d.start(b, c, k, true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(d.root, serviceBaselineName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, poison := range []string{
		strings.Replace(string(raw), `"Version":2`, `"Version":2,"version":2`, 1),
		strings.Replace(string(raw), `"Version":2`, `"version":2`, 1),
		strings.Replace(string(raw), `"Version":2`, `"Version":2,"Version":2`, 1),
		strings.Replace(string(raw), `"Version":2`, `"Version":3`, 1),
		strings.Replace(string(raw), `"Version":2`, `"Version":2.0`, 1),
		strings.Replace(string(raw), `"Version":2`, `"Version":null`, 1),
		strings.Replace(string(raw), `"Version":2`, `"Version":true`, 1),
		strings.Replace(string(raw), `"Version":2`, `"Version":"2"`, 1),
		strings.Replace(string(raw), `"Scope":"LOCAL_INTERFACE_DNS"`, `"Scope":"ALL_SERVERS"`, 1),
		strings.Replace(string(raw), `"Version":2,`, "", 1),
		strings.Replace(string(raw), `"Server":""`, `"Server":"203.0.113.1"`, 1),
		strings.Replace(string(raw), `"ServerInterface":""`, `"ServerInterface":"en0"`, 1),
		strings.Replace(string(raw), `"Version":2`, `"Version":2,"Servers":{}`, 1),
		strings.Replace(string(raw), `"Version":2`, `"Version":2,"Servers":null`, 1),
		strings.Replace(string(raw), `"Server":""`, `"Server":null`, 1),
		strings.Replace(string(raw), `"Scope":"LOCAL_INTERFACE_DNS"`, `"Scope":null`, 1),
	} {
		if err = os.WriteFile(path, []byte(poison), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err = d.baseline(); err == nil {
			t.Fatalf("mixed/unknown baseline accepted: %s", poison)
		}
	}
}

func TestLegacyStopStillChecksAllServers(t *testing.T) {
	for _, version := range []int{0, 1} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			d, b, c, k, _, _ := lifecycleFixture(t)
			if err := d.start(b, c, k, true); err != nil {
				t.Fatal(err)
			}
			writeLegacyBaseline(t, d, version)
			nodeCalls := 0
			route := d.route
			d.route = func(address string) (string, error) {
				if address != "1.1.1.1" {
					nodeCalls++
					return "en1", nil
				}
				return route(address)
			}
			if err := d.stop(); err != nil {
				t.Fatal(err)
			}
			v, _ := readDiagnostic(t, d.root)
			if v["restoration"] == "VERIFIED" || v["snapshot"] != "ARCHIVED" || v["schema_version"] != float64(1) {
				t.Fatal("legacy uncertainty weakened", v)
			}
			if version == 1 && nodeCalls == 0 {
				t.Fatal("legacy server route gate bypassed")
			}
			if version == 0 && nodeCalls != 0 {
				t.Fatal("v0 multi scope must reject before probes")
			}
		})
	}
}
