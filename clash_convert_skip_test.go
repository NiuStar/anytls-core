package main

import (
	"context"
	"gopkg.in/yaml.v3"
	"strings"
	"testing"
)

func TestConversionSkipNativeCritical(t *testing.T) {
	good := "{name: good, type: anytls, server: 192.0.2.1, port: 443, password: pass}"
	raw := []byte("# comment\nnodes: [" + good + "]\n")
	b, r, e := webConvertConfiguration(context.Background(), raw, false, nil)
	if e != nil || string(b) != string(raw) || r.Converted || len(r.Skipped) != 0 || len(r.Issues) != 0 {
		t.Fatalf("native changed: %v %+v", e, r)
	}
	for _, field := range []string{"alpn: [h2]", "tls: false", "network: ws", "ca: /private/SECRET"} {
		raw = []byte("nodes: [" + good + ", {name: SECRETNAME, type: anytls, server: 192.0.2.2, port: 443, password: SECRET, " + field + "}]\nrules: ['MATCH,SECRETNAME']\n")
		b, r, e = webConvertConfiguration(context.Background(), raw, true, nil)
		if e != nil || len(r.Issues) != 0 || len(r.Skipped) == 0 || !r.Converted || strings.Contains(string(b), "SECRET") || !strings.Contains(string(b), "MATCH,good") {
			t.Fatalf("critical node not removed: %s %v %+v", b, e, r)
		}
		for _, s := range append(append([]string{}, r.Skipped...), r.Warnings...) {
			if strings.Contains(s, "SECRET") {
				t.Fatal("secret leak")
			}
		}
	}
	raw = []byte("nodes: [" + strings.TrimSuffix(good, "}") + ", ca: /private/handwritten}]\n")
	b, r, e = webConvertConfiguration(context.Background(), raw, false, nil)
	if e != nil || string(b) != string(raw) || len(r.Skipped) != 0 {
		t.Fatalf("local CA altered: %v %+v", e, r)
	}
}

func TestConversionSkipProvidersCycles(t *testing.T) {
	raw := `proxies: [{name: good, type: anytls, server: 192.0.2.1, port: 443, password: pass}]
proxy-providers:
 bad: {type: file, path: /SECRET}
 remote: {type: http, url: https://remote.example/SECRET}
proxy-groups:
 - {name: usable, type: select, proxies: [good], use: [bad, remote]}
 - {name: cycle1, type: select, proxies: [cycle2]}
 - {name: cycle2, type: select, proxies: [cycle1, good]}
 - {name: parent, type: select, proxies: [cycle1]}
 - {name: balance, type: load-balance, proxies: [good]}
 - {name: semantics, type: select, proxies: [good], dialer-proxy: good}
rule-providers: {bad: {type: file, path: /SECRET}}
rules: ['DOMAIN,before.example,good','RULE-SET,bad,good','IP-CIDR,999.2.0.0/12,good','DOMAIN,after.example,good','MATCH,cycle1']
`
	b, r, e := webConvertConfiguration(context.Background(), []byte(raw), false, func(context.Context, string) ([]byte, error) {
		return []byte("proxies: [{name: privateca, type: anytls, server: 192.0.2.2, port: 443, password: SECRET, ca: /SECRET}]"), nil
	})
	if e != nil || len(r.Issues) != 0 || len(r.Skipped) < 7 {
		t.Fatalf("skip failed: %v %+v", e, r)
	}
	var d struct {
		Nodes  []node       `yaml:"nodes"`
		Groups []proxyGroup `yaml:"proxy-groups"`
		Rules  []string     `yaml:"rules"`
	}
	if e := yaml.Unmarshal(b, &d); e != nil {
		t.Fatal(e)
	}
	if len(d.Nodes) != 1 || len(d.Groups) != 1 || len(d.Rules) != 3 || d.Rules[2] != "MATCH,usable" {
		t.Fatalf("bad dependencies survived: %s", b)
	}
}

func TestConversionSkipAllUnsupported(t *testing.T) {
	_, r, e := webConvertConfiguration(context.Background(), []byte("proxies: [{name: ss, type: ss}]"), true, nil)
	if e != nil || len(r.Issues) == 0 || len(r.Skipped) == 0 {
		t.Fatalf("all unsupported must block: %v %+v", e, r)
	}
	b, r, e := webConvertConfiguration(context.Background(), []byte("proxies: [{name: good, type: anytls, server: 192.0.2.1, port: 443, password: pass}]\nrules: ['GEOIP,CN,DIRECT']"), true, nil)
	if e != nil || len(r.Issues) != 0 || strings.Contains(string(b), "rules:") || len(r.Warnings) == 0 {
		t.Fatalf("all rules handling: %s %v %+v", b, e, r)
	}
}

func TestConversionSkipRoutingFinalAndDisabled(t *testing.T) {
	raw := []byte("proxies: [{name: first, type: anytls, server: 192.0.2.1, port: 443, password: pass, skip-cert-verify: true}, {name: final, type: anytls, server: 192.0.2.2, port: 443, password: pass, skip-cert-verify: true}, {name: ss, type: ss}]\nrules: ['GEOIP,CN,DIRECT', 'MATCH,final']\n")
	b, r, e := webConvertConfiguration(context.Background(), raw, true, nil)
	if e != nil || len(r.Issues) != 0 {
		t.Fatal(e, r)
	}
	nodes, e := loadNodesBytes(b)
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := buildNode(nodes[0], "proxy", 11080, true)
	if e != nil {
		t.Fatal(e)
	}
	if e := applyRoutingBytes("config.yaml", b, nodes, nodes[0], cfg, true); e != nil {
		t.Fatal(e)
	}
	if cfg["route"].(map[string]any)["final"] != "node-1" {
		t.Fatal("final MATCH not honored")
	}
	disabled := []byte("# disabled routing\nnodes: [{name: first, type: anytls, server: 192.0.2.1, port: 443, password: pass}]\nrules: []\nrule-sets: {inactive: {path: /handwritten/local, sha256: abc}}\n")
	b, r, e = webConvertConfiguration(context.Background(), disabled, false, nil)
	if e != nil || string(b) != string(disabled) || r.Converted {
		t.Fatalf("disabled native semantics changed: %v %+v", e, r)
	}
}

func TestConversionSkipMixed(t *testing.T) {
	raw := "proxies:\n"
	for i := 0; i < 17; i++ {
		raw += " - {name: n" + string(rune('a'+i)) + ", type: anytls, server: 192.0.2.1, port: 443, password: pass}\n"
	}
	raw += " - {name: secret, type: ss, password: SECRET}\nproxy-groups: [{name: outer, type: select, proxies: [inner], selected: inner}, {name: inner, type: select, proxies: [secret, na], selected: secret}, {name: empty, type: select, proxies: [secret]}]\nrules: ['GEOIP,CN,DIRECT', 'DOMAIN,example.com,secret', 'MATCH,outer']\n"
	b, r, e := webConvertConfiguration(context.Background(), []byte(raw), true, nil)
	if e != nil || len(r.Issues) != 0 {
		t.Fatalf("mixed blocked: %v %+v", e, r)
	}
	var d struct {
		Nodes  []node       `yaml:"nodes"`
		Groups []proxyGroup `yaml:"proxy-groups"`
		Rules  []string     `yaml:"rules"`
	}
	if e := yaml.Unmarshal(b, &d); e != nil {
		t.Fatal(e)
	}
	if len(d.Nodes) != 17 || len(d.Groups) != 2 || d.Groups[1].Selected != "na" || strings.Join(d.Rules, ";") != "MATCH,outer" {
		t.Fatalf("not sanitized: %s", b)
	}
}
