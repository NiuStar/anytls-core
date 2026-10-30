package main

import (
	"context"
	"encoding/json"
	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	"github.com/NiuStar/anytls-core/internal/engine"
	"strings"
	"testing"
)

func TestGeoIPCNCompilerRecords(t *testing.T) {
	for _, mode := range []string{"proxy", "tun"} {
		t.Run(mode, func(t *testing.T) { testGeoIPCNCompilerRecords(t, mode) })
	}
}

func testGeoIPCNCompilerRecords(t *testing.T, mode string) {
	for _, suffix := range []string{"", ",no-resolve"} {
		p := routingFixture(t, " - DOMAIN,earlier.invalid,REJECT\n - GEOIP,CN,DIRECT"+suffix+"\n - MATCH,main\n")
		c, e := prepareRuntimeWithRecords(&runtimeOptions{Config: p, NodeName: "main", Mode: mode, LocalPort: 11080, AllowInsecure: true})
		if e != nil {
			t.Fatal(e)
		}
		if c.Manifest == nil {
			t.Fatal("GEOIP disabled records")
		}
		found := false
		for _, r := range c.Manifest.Rules {
			if string(r.Route.Kind) == "GEOIP" {
				found = true
				if r.Route.Evidence != cr.ProvenanceVerified || r.Route.Condition.Value != "CN" || r.Route.TerminalKind != cr.TerminalDirect {
					t.Fatal("incorrect attribution")
				}
			}
		}
		if !found {
			t.Fatal("GEOIP not first-class")
		}
		var cfg map[string]any
		if e = json.Unmarshal(c.JSON, &cfg); e != nil {
			t.Fatal(e)
		}
		rules := cfg["route"].(map[string]any)["rules"].([]any)
		first := 1
		if suffix == "" {
			first++
		}
		if mode == "tun" {
			tunBusinessRules(t, cfg)
			first = 3
		}
		wantSlots := first + 2
		if suffix == "" {
			wantSlots++
			if rules[first+1].(map[string]any)["action"] != "resolve" || rules[first+1].(map[string]any)["server"] != "secure-dns" {
				t.Fatal("resolve must remain immediately before GEOIP")
			}
		}
		if len(rules) != wantSlots {
			t.Fatal("unexpected GEOIP slot count")
		}
		if rules[first].(map[string]any)["action"] != "reject" {
			t.Fatal("resolution reordered before earlier rule")
		}
		resolves := 0
		for _, r := range rules {
			if r.(map[string]any)["action"] == "resolve" {
				resolves++
			}
		}
		if (suffix == "") != (resolves == 1) {
			t.Fatal("no-resolve contract")
		}
		if suffix != "" && mode == "proxy" {
			if _, ok := cfg["dns"]; ok {
				t.Fatal("no-resolve unexpectedly added DNS in proxy mode")
			}
		}
		if mode == "tun" {
			dns, ok := cfg["dns"].(map[string]any)
			if !ok || dns["final"] != "secure-dns" || dns["reverse_mapping"] != true {
				t.Fatal("TUN no-resolve must not disable unified DNS capture")
			}
		}
		if e = engine.Check(context.Background(), c.JSON); e != nil {
			t.Fatal(e)
		}
	}
}

func TestGeoIPCNConversion(t *testing.T) {
	for _, s := range []string{"", ",no-resolve"} {
		raw := []byte("proxies: [{name: main, type: anytls, server: 192.0.2.1, port: 443, password: pass, skip-cert-verify: true}]\nrules: ['GEOIP,CN,DIRECT" + s + "', 'MATCH,main']\n")
		b, r, e := webConvertConfiguration(context.Background(), raw, true, nil)
		if e != nil || len(r.Skipped) != 0 || !strings.Contains(string(b), "GEOIP,CN,DIRECT"+s) {
			t.Fatalf("CN dropped: %v skipped=%d", e, len(r.Skipped))
		}
	}
}
