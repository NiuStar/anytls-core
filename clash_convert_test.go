package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func convertFixture(t *testing.T, text string, fetch func(context.Context, string) ([]byte, error)) ([]byte, webConversionReport) {
	t.Helper()
	b, r, e := webConvertConfiguration(context.Background(), []byte(text), true, fetch)
	if e != nil {
		t.Fatalf("conversion: %v", e)
	}
	return b, r
}

func TestClashConvertAnyTLS(t *testing.T) {
	b, r := convertFixture(t, `proxies:
  - {name: first, type: anytls, server: 192.0.2.1, port: 443, password: "00123", servername: example.com, skip-cert-verify: false, min-idle-session: 2}
proxy-groups:
  - {name: choice, type: select, proxies: [first, DIRECT]}
rules: ["MATCH,choice"]
dns: {enable: true}
`, nil)
	if r.Format != "clash" || !r.Converted || len(r.Issues) != 0 || len(r.Warnings) == 0 {
		t.Fatalf("report: %+v", r)
	}
	var d struct {
		Nodes  []node       `yaml:"nodes"`
		Groups []proxyGroup `yaml:"proxy-groups"`
	}
	if e := yaml.Unmarshal(b, &d); e != nil {
		t.Fatal(e)
	}
	if len(d.Nodes) != 1 || d.Nodes[0].Password != "00123" || d.Nodes[0].SNI != "example.com" || d.Nodes[0].SkipVerify || d.Nodes[0].MinIdle != 2 || d.Groups[0].Selected != "first" {
		t.Fatal("lost node/group semantics")
	}
	if bytes.Contains(b, []byte("dns:")) || bytes.Contains(b, []byte("servername:")) {
		t.Fatal("unconverted fields")
	}
}

func TestClashConvertNativePreservation(t *testing.T) {
	raw := []byte("# keep comment\nnodes: []\nx-private: {number: !!str 00123, '<<': literal}\n")
	b, r, e := webConvertConfiguration(context.Background(), raw, true, nil)
	if e != nil || r.Converted || r.Format != "native" || !bytes.Equal(raw, b) {
		t.Fatalf("native changed: %v %+v", e, r)
	}
	b, r = convertFixture(t, `x-base: &base {password: !!str 00123, server: 192.0.2.1, port: 443, type: anytls}
x-key: &key name
nodes:
 - <<: [*base, {port: 8443}]
   *key: first
   port: 9443
x-literal: {'<<': yes}
`, nil)
	if !r.Converted || len(r.Issues) != 0 {
		t.Fatal(r)
	}
	var root yaml.Node
	if e := yaml.Unmarshal(b, &root); e != nil {
		t.Fatal(e)
	}
	var d struct {
		Nodes []node `yaml:"nodes"`
	}
	if e := root.Decode(&d); e != nil || d.Nodes[0].Password != "00123" || d.Nodes[0].Port != 9443 {
		t.Fatalf("flatten: %v", e)
	}
	if bytes.Contains(b, []byte("*base")) || bytes.Contains(b, []byte("&base")) || !bytes.Contains(b, []byte("'<<'")) {
		t.Fatalf("aliases/literal: %s", b)
	}
}

func TestClashConvertRejectInvalid(t *testing.T) {
	for _, s := range []string{"nodes: [", "nodes: []\nnodes: []", "x: &x {self: *x}\nnodes: []", "nodes: []\n---\nnodes: []", "? [a,b]\n: c\nnodes: []"} {
		_, _, e := webConvertConfiguration(context.Background(), []byte(s), true, nil)
		if e == nil || e.Error() != "CONFIG_CONVERSION_INVALID" {
			t.Fatalf("expected redacted invalid error, got %v", e)
		}
	}
}

func TestClashConvertUnsupportedAndManualGroups(t *testing.T) {
	_, r := convertFixture(t, `proxies: [{name: SECRETNAME, type: ss, password: SECRETPASSWORD}, {name: other, type: vmess}]
proxy-groups: [{name: manual, type: url-test, proxies: [SECRETNAME]}, {name: broken, type: relay, proxies: [other]}]
rules: ["GEOIP,SECRETCOUNTRY,DIRECT", "MATCH,DIRECT"]
`, nil)
	if len(r.Issues) != 4 || len(r.Warnings) == 0 {
		t.Fatalf("missing issues: %+v", r)
	}
	j, _ := json.Marshal(r)
	for _, secret := range []string{"SECRETNAME", "SECRETPASSWORD", "SECRETCOUNTRY"} {
		if bytes.Contains(j, []byte(secret)) {
			t.Fatal("secret leaked")
		}
	}
}

func TestClashConvertHTTPProviders(t *testing.T) {
	fetched := []string{}
	fetch := func(_ context.Context, url string) ([]byte, error) {
		fetched = append(fetched, url)
		switch url {
		case "https://example.com/nodes?secret=token":
			return []byte("proxies: [{name: imported, type: anytls, server: 192.0.2.1, port: 443, password: pass}]"), nil
		case "https://example.com/domains":
			return []byte("payload: ['+.example.com', exact.example, '*.wild.example']"), nil
		case "https://example.com/ip":
			return []byte("payload: ['2001:db8::/32']"), nil
		case "https://example.com/classical":
			return []byte("payload: ['DOMAIN,class.example', 'IP-CIDR,192.0.2.0/24,no-resolve']"), nil
		}
		return nil, errors.New("SECRET fetch failure")
	}
	b, r := convertFixture(t, `proxy-providers:
  n: {type: http, url: 'https://example.com/nodes?secret=token', path: /SECRET/cache, health-check: {enable: true}}
proxies: []
proxy-groups: [{name: pick, type: select, use: [n], filter: imported}]
rule-providers:
  d: {type: http, behavior: domain, url: https://example.com/domains}
  i: {type: http, behavior: ipcidr, url: https://example.com/ip}
  c: {type: http, behavior: classical, url: https://example.com/classical}
rules: ['DOMAIN,before.example,DIRECT', 'RULE-SET,d,pick', 'RULE-SET,i,DIRECT,no-resolve', 'RULE-SET,c,DIRECT', 'MATCH,pick']
`, fetch)
	if len(r.Issues) != 0 || len(fetched) != 4 {
		t.Fatalf("providers: %+v %v", r, fetched)
	}
	var d struct {
		Nodes  []node       `yaml:"nodes"`
		Groups []proxyGroup `yaml:"proxy-groups"`
		Rules  []string     `yaml:"rules"`
	}
	if e := yaml.Unmarshal(b, &d); e != nil {
		t.Fatal(e)
	}
	if len(d.Nodes) != 1 || d.Groups[0].Selected != "imported" {
		t.Fatal("provider nodes/group missing")
	}
	expected := []string{"DOMAIN,before.example,DIRECT", "DOMAIN-SUFFIX,example.com,pick", "DOMAIN,exact.example,pick", "DOMAIN-SUFFIX,wild.example,pick", "IP-CIDR,2001:db8::/32,DIRECT", "DOMAIN,class.example,DIRECT", "IP-CIDR,192.0.2.0/24,DIRECT", "MATCH,pick"}
	if strings.Join(d.Rules, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("rule order: %#v", d.Rules)
	}
	j, _ := json.Marshal(r)
	if bytes.Contains(j, []byte("SECRET")) || bytes.Contains(j, []byte("token")) {
		t.Fatal("report leaked provider data")
	}
}

func TestClashConvertFilterPreservesExplicitMembers(t *testing.T) {
	b, r := convertFixture(t, `proxies: [{name: first, type: anytls}, {name: second, type: anytls}]
proxy-groups: [{name: pick, type: select, proxies: [DIRECT], include-all-proxies: true, filter: first}]
`, nil)
	if len(r.Issues) != 0 {
		t.Fatal(r)
	}
	var d struct {
		Groups []proxyGroup `yaml:"proxy-groups"`
	}
	if e := yaml.Unmarshal(b, &d); e != nil {
		t.Fatal(e)
	}
	if strings.Join(d.Groups[0].Proxies, ",") != "DIRECT,first" || d.Groups[0].Selected != "DIRECT" {
		t.Fatalf("explicit proxies filtered: %+v", d.Groups)
	}
}

func TestClashConvertRemoteResourceGate(t *testing.T) {
	raw := []byte("nodes: [{name: first, type: anytls, ca: /SECRET/ca}]\nrule-sets: {private: {path: /SECRET/rules, sha256: abc}}\nx-meta: {path: /SECRET/unused}\n")
	b, r, e := webConvertConfiguration(context.Background(), raw, true, nil)
	if e != nil || len(r.Issues) != 2 || !bytes.Equal(raw, b) {
		t.Fatalf("resource gate: %v %+v", e, r)
	}
	_, local, e := webConvertConfiguration(context.Background(), raw, false, nil)
	if e != nil || len(local.Issues) != 0 {
		t.Fatalf("local resource changed: %v %+v", e, local)
	}
	j, _ := json.Marshal(r)
	if bytes.Contains(j, []byte("SECRET")) || bytes.Contains(j, []byte("private")) {
		t.Fatal("resource value leaked")
	}
	_, r = convertFixture(t, "nodes: []\nx-meta: {path: /SECRET/unused}\n", nil)
	if len(r.Issues) != 0 {
		t.Fatal("unrelated path rejected")
	}
}

func TestClashConvertMergePrecedenceAndAliasKeys(t *testing.T) {
	b, r := convertFixture(t, `x-first: &first {password: !!str 00123, port: 443}
x-second: &second {password: later, server: 192.0.2.1}
x-key: &key type
nodes: [{<<: [*first, *second], name: node, *key: anytls}]
`, nil)
	if len(r.Issues) != 0 {
		t.Fatal(r)
	}
	var d struct {
		Nodes []node `yaml:"nodes"`
	}
	if e := yaml.Unmarshal(b, &d); e != nil {
		t.Fatal(e)
	}
	if d.Nodes[0].Password != "00123" || d.Nodes[0].Server != "192.0.2.1" || d.Nodes[0].Type != "anytls" {
		t.Fatal("merge precedence or scalar alias key lost")
	}
	for _, raw := range []string{"x: &k name\nnodes: [{name: first, *k: second}]", "x: &k [name]\nnodes: [{*k: value}]"} {
		_, _, e := webConvertConfiguration(context.Background(), []byte(raw), true, nil)
		if e == nil || e.Error() != "CONFIG_CONVERSION_INVALID" {
			t.Fatalf("alias key should reject: %v", e)
		}
	}
}

func TestClashConvertNativeUnsupportedProtocols(t *testing.T) {
	raw := []byte("nodes: [{name: private, type: ss, password: SECRET}, {name: first, type: anytls}]\n")
	b, r, e := webConvertConfiguration(context.Background(), raw, true, nil)
	if e != nil || len(r.Issues) != 1 || !bytes.Equal(raw, b) {
		t.Fatalf("unsupported native node not blocked: %v %+v", e, r)
	}
}

func TestClashConvertLiteralMergeKeyCoexists(t *testing.T) {
	b, r := convertFixture(t, "x: &base {value: original}\nnodes: []\nx-other: {<<: *base, '<<': literal}\n", nil)
	if len(r.Issues) != 0 {
		t.Fatal(r)
	}
	var d map[string]any
	if e := yaml.Unmarshal(b, &d); e != nil {
		t.Fatal(e)
	}
	other := d["x-other"].(map[string]any)
	if other["<<"] != "literal" || other["value"] != "original" {
		t.Fatal("literal merge key changed")
	}
}

func TestClashConvertUnsupportedProviderPayloads(t *testing.T) {
	for _, payload := range []string{"payload: ['GEOIP,SECRET']", "payload: ['DOMAIN-KEYWORD,SECRET']", "payload: ["} {
		_, r := convertFixture(t, "proxies: []\nrule-providers: {p: {type: http, url: 'https://example.com/?SECRET', behavior: classical}}\nrules: ['RULE-SET,p,DIRECT','MATCH,DIRECT']\n", func(context.Context, string) ([]byte, error) { return []byte(payload), nil })
		if len(r.Issues) == 0 {
			t.Fatal("unsupported provider payload accepted")
		}
		j, _ := json.Marshal(r)
		if bytes.Contains(j, []byte("SECRET")) {
			t.Fatal("provider payload leaked")
		}
	}
	_, r := convertFixture(t, "proxies: []\nrule-providers: {p: {type: http, url: 'https://example.com/?SECRET', behavior: domain, format: mrs}}\n", func(context.Context, string) ([]byte, error) { t.Fatal("MRS must not be fetched"); return nil, nil })
	if len(r.Issues) != 1 {
		t.Fatal(r)
	}
}

func TestClashConvertProviderFailures(t *testing.T) {
	for _, spec := range []string{"{type: file, path: /SECRET/file}", "{type: http, url: 'https://example.com/?SECRET=token'}"} {
		_, r := convertFixture(t, "proxies: []\nproxy-providers: {private: "+spec+"}\n", func(context.Context, string) ([]byte, error) { return nil, errors.New("SECRET") })
		if len(r.Issues) != 1 {
			t.Fatalf("missing resource issue: %+v", r)
		}
		j, _ := json.Marshal(r)
		if bytes.Contains(j, []byte("SECRET")) || bytes.Contains(j, []byte("token")) {
			t.Fatal("secret leaked")
		}
	}
}
