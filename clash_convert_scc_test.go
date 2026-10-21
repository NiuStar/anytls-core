package main

import (
	"context"
	"gopkg.in/yaml.v3"
	"strings"
	"testing"
)

func TestConversionSCCCrossEdgesAllPermutations(t *testing.T) {
	groups := []string{"{name: a, type: select, proxies: [b,c]}", "{name: b, type: select, proxies: [a]}", "{name: c, type: select, proxies: [b,good]}"}
	permutations := [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	for _, order := range permutations {
		for repeat := 0; repeat < 20; repeat++ {
			input := "proxies: [{name: good, type: anytls, server: 192.0.2.1, port: 443, password: p, skip-cert-verify: true}]\nproxy-groups:\n"
			for _, i := range order {
				input += " - " + groups[i] + "\n"
			}
			input += " - {name: self, type: select, proxies: [self,good]}\n - {name: ok, type: select, proxies: [good]}\nrules: ['MATCH,c']\n"
			b, r, e := webConvertConfiguration(context.Background(), []byte(input), false, nil)
			if e != nil || len(r.Issues) > 0 {
				t.Fatal(e, r)
			}
			var out struct {
				Groups []proxyGroup `yaml:"proxy-groups"`
				Rules  []string     `yaml:"rules"`
			}
			if yaml.Unmarshal(b, &out) != nil {
				t.Fatal("decode")
			}
			if len(out.Groups) != 1 || out.Groups[0].Name != "ok" || len(out.Rules) != 1 || out.Rules[0] != "MATCH,ok" {
				t.Fatal("incomplete SCC deletion", string(b))
			}
			if !strings.Contains(strings.Join(r.Warnings, ""), "MATCH") {
				t.Fatal("missing fallback warning")
			}
		}
	}
}
