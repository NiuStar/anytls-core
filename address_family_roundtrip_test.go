package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestInitialAddressFamilyBuildersAndOuterAddress(t *testing.T) {
	o, _, _ := recordsCompilerFixture(t, "")
	nodes, err := loadNodes(o.Config)
	if err != nil {
		t.Fatal(err)
	}
	for _, server := range []string{"127.0.0.1", "2001:db8::10"} {
		n := nodes[0]
		n.Server = server
		cfg, err := buildNode(n, "tun", 0, false)
		if err != nil {
			t.Fatal(err)
		}
		in := cfg["inbounds"].([]any)[0].(map[string]any)
		if !reflect.DeepEqual(in["address"], []string{"172.19.0.1/30"}) || cfg["dns"].(map[string]any)["strategy"] != "ipv4_only" {
			t.Fatal("node builder did not default IPv4")
		}
		prefix := "/32"
		if strings.Contains(server, ":") {
			prefix = "/128"
		}
		if !reflect.DeepEqual(in["route_exclude_address"], []string{server + prefix}) {
			t.Fatal("outer exclusion changed")
		}
		legacy, err := build(options{Server: net.JoinHostPort(server, "443"), SNI: "g21.invalid", Password: "fixture", CA: n.CA})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(legacy["inbounds"].([]any)[0].(map[string]any)["address"], in["address"]) || legacy["dns"].(map[string]any)["strategy"] != "ipv4_only" {
			t.Fatal("legacy CLI builder differs")
		}
		if err = applyRoutingBytes(o.Config, []byte("ipv6: true\n"), nodes, n, cfg, false); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(in["address"], []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}) || cfg["dns"].(map[string]any)["strategy"] != nil {
			t.Fatal("explicit dual ignored")
		}
	}
	// Proxy, including its existing routed DNS, is byte-identical for both policies.
	for _, rules := range []string{"", " - RULE-SET,local,DIRECT\n - MATCH,outer\n"} {
		var first []byte
		o, b, _ := recordsCompilerFixture(t, rules)
		for _, policy := range []string{"", "ipv6: false\n", "ipv6: true\n"} {
			runtimeWrite(t, o.Config, append([]byte(policy), b...), 0600)
			cfg, err := prepareRuntime(&o)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if first == nil {
				first = raw
			} else if !bytes.Equal(first, raw) {
				t.Fatal("TUN family policy changed proxy runtime")
			}
		}
	}
}

func TestInitialAddressFamilyImportExportRetainsFalseAndTrue(t *testing.T) {
	for _, value := range []string{"false", "true"} {
		t.Run(value, func(t *testing.T) {
			w, password := webFixture(t)
			cookie, csrf := webLogin(t, w, password)
			input := "ipv6: " + value + "\n" + clashExportFixture
			before, err := os.ReadFile(w.configPath)
			if err != nil {
				t.Fatal(err)
			}
			p := importPreview(t, w, cookie, csrf, map[string]any{"yaml": input})
			rec := importRequest(t, w, cookie, csrf, "import/export", map[string]any{"token": p["token"]}, p["etag"].(string))
			if rec.Code != 200 {
				t.Fatal(rec.Code, rec.Body.String())
			}
			var result struct {
				YAML string `json:"yaml"`
			}
			if err = json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err = yaml.Unmarshal([]byte(result.YAML), &doc); err != nil {
				t.Fatal(err)
			}
			if got, ok := doc["ipv6"].(bool); !ok || got != (value == "true") {
				t.Fatal("export dropped boolean", result.YAML)
			}
			after, _ := os.ReadFile(w.configPath)
			if !bytes.Equal(before, after) {
				t.Fatal("preview export mutated source")
			}
			rec = importRequest(t, w, cookie, csrf, "import/commit", map[string]any{"token": p["token"], "confirm_replace": true, "confirm_insecure": true, "accept_conversion": true}, p["etag"].(string))
			if rec.Code != 200 {
				t.Fatal(rec.Code, rec.Body.String())
			}
			after, _ = os.ReadFile(w.configPath)
			if string(after) != result.YAML {
				t.Fatal("import/save not exact exported bytes")
			}
			rec = webRequest(w, http.MethodGet, "/api/v1/config/export", "", cookie, "")
			if rec.Code != 200 {
				t.Fatal(rec.Code)
			}
			var current struct {
				YAML string `json:"yaml"`
			}
			if err = json.Unmarshal(rec.Body.Bytes(), &current); err != nil || current.YAML != result.YAML {
				t.Fatal("native re-export changed policy", err)
			}
		})
	}
}
