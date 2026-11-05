package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
)

// Assert the public DTO, not only its helper, so omission/false are distinct.
func linkAssertDTO(t *testing.T, w *webConsole, cookie *http.Cookie, startup, defaultChoice string, linked bool, syncNodes ...string) {
	t.Helper()
	out := webRequest(w, "GET", "/api/v1/nodes", "", cookie, "")
	var dto struct {
		Nodes []struct {
			Name            string `json:"name"`
			Selected        bool   `json:"selected"`
			DefaultSelected *bool  `json:"defaultSelected"`
			NeedsSync       *bool  `json:"selectionNeedsSync"`
		} `json:"nodes"`
		Linked *bool `json:"selection_linked"`
	}
	if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &dto) != nil {
		t.Fatalf("GET: %d %s", out.Code, out.Body.String())
	}
	if dto.Linked == nil || *dto.Linked != linked {
		t.Fatalf("selection_linked: %s", out.Body.String())
	}
	wantSync := map[string]bool{}
	for _, n := range syncNodes {
		wantSync[n] = true
	}
	gotStartup, gotDefault := []string{}, []string{}
	for _, n := range dto.Nodes {
		if n.Selected {
			gotStartup = append(gotStartup, n.Name)
		}
		if n.DefaultSelected == nil || n.NeedsSync == nil {
			t.Fatalf("missing flags: %s", out.Body.String())
		}
		if *n.DefaultSelected {
			gotDefault = append(gotDefault, n.Name)
		}
		if *n.NeedsSync != wantSync[n.Name] {
			t.Fatalf("node %s repair=%v want=%v: %s", n.Name, *n.NeedsSync, wantSync[n.Name], out.Body.String())
		}
	}
	wantStartup, wantDefault := []string{}, []string{}
	if startup != "" {
		wantStartup = append(wantStartup, startup)
	}
	if defaultChoice != "" {
		wantDefault = append(wantDefault, defaultChoice)
	}
	if !reflect.DeepEqual(gotStartup, wantStartup) || !reflect.DeepEqual(gotDefault, wantDefault) {
		t.Fatalf("startup=%v default=%v want %v/%v: %s", gotStartup, gotDefault, wantStartup, wantDefault, out.Body.String())
	}
}

func linkAssertRuntimeDNS(t *testing.T, w *webConsole, dnsServer, finalServer string) {
	t.Helper()
	cfg, err := prepareRuntimeMap(&runtimeOptions{Command: "check", Config: w.configPath, Mode: "tun", LocalPort: 11080, AllowInsecure: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	dns := cfg["dns"].(map[string]any)
	servers := dns["servers"].([]any)
	if len(servers) != 1 || servers[0].(map[string]any)["detour"] != "anytls-out" {
		t.Fatalf("unexpected DNS: %v", dns)
	}
	final := cfg["route"].(map[string]any)["final"]
	gotDNS, gotFinal := "", ""
	for _, raw := range cfg["outbounds"].([]any) {
		out := raw.(map[string]any)
		if out["tag"] == "anytls-out" {
			gotDNS, _ = out["server"].(string)
		}
		if out["tag"] == final {
			gotFinal, _ = out["server"].(string)
		}
	}
	if gotDNS != dnsServer || gotFinal != finalServer {
		t.Fatalf("compiled DNS=%q final=%q want=%q/%q", gotDNS, gotFinal, dnsServer, finalServer)
	}
}

func TestWebSelectionLinkStartupDNSMismatchRepair(t *testing.T) {
	config := strings.Replace(selectionLinkConfig, "selected: DIRECT}", "selected: b}", 1)
	for _, choice := range []string{"a", "b"} {
		t.Run(choice, func(t *testing.T) {
			w, cookie, csrf := linkFixture(t, config, "a")
			before, _ := w.profileFiles()
			linkAssertDTO(t, w, cookie, "a", "b", false, "a", "b")
			linkAssertRuntimeDNS(t, w, "127.0.0.1", "127.0.0.2")
			after, _ := w.profileFiles()
			if !webProfileEqual(before, after) {
				t.Fatal("read/compile normalized retained state")
			}
			linkPost(t, w, cookie, csrf, "/api/v1/nodes/selection", `{"name":"`+choice+`"}`)
			server := "127.0.0.1"
			if choice == "b" {
				server = "127.0.0.2"
			}
			linkAssertDTO(t, w, cookie, choice, choice, true)
			linkAssertRuntimeDNS(t, w, server, server)
		})
	}
}

func TestWebSelectionLinkDTOBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, config, saved, defaultChoice string
		linked                             bool
		sync                               []string
	}{
		{"group-direct", selectionLinkConfig, "a", "", false, []string{"a", "b"}},
		{"clean", strings.Replace(selectionLinkConfig, "selected: DIRECT}", "selected: a}", 1), "a", "a", true, nil},
		{"nested", strings.Replace(selectionLinkConfig, "proxies: [a, b, DIRECT], selected: DIRECT}", "proxies: [a, b, DIRECT, dedicated], selected: dedicated}", 1), "a", "", false, nil},
		{"explicit-direct", strings.Replace(selectionLinkConfig, "MATCH,default", "MATCH,DIRECT", 1), "a", "", false, nil},
		{"explicit-node", strings.Replace(selectionLinkConfig, "MATCH,default", "MATCH,b", 1), "a", "", false, nil},
		{"missing-startup", strings.Replace(selectionLinkConfig, "selected: DIRECT}", "selected: b}", 1), "", "b", false, []string{"a", "b"}},
		{"nonmember", strings.Replace(selectionLinkConfig, "proxies: [a, b, DIRECT], selected: DIRECT}", "proxies: [b, DIRECT], selected: b}", 1), "a", "b", false, []string{"b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, cookie, _ := linkFixture(t, tc.config, tc.saved)
			before, _ := os.ReadFile(w.configPath)
			selection, selectionErr := os.ReadFile(selectedPath(w.configPath))
			linkAssertDTO(t, w, cookie, tc.saved, tc.defaultChoice, tc.linked, tc.sync...)
			after, _ := os.ReadFile(w.configPath)
			next, nextErr := os.ReadFile(selectedPath(w.configPath))
			if !bytes.Equal(before, after) || !bytes.Equal(selection, next) || (selectionErr == nil) != (nextErr == nil) {
				t.Fatal("GET changed files")
			}
		})
	}
}
