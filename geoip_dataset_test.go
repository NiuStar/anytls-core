package main

import (
	"bytes"
	"context"
	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	"github.com/NiuStar/anytls-core/internal/engine"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	S "github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeoIPCNTargets(t *testing.T) {
	for _, target := range []string{"DIRECT", "backup", "pick", "REJECT"} {
		p := routingFixture(t, " - GEOIP,CN,"+target+",no-resolve\n - MATCH,main\n")
		b, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		if target == "pick" {
			b = append(b, []byte("proxy-groups:\n - {name: pick, type: select, proxies: [backup], selected: backup}\n")...)
			if e = os.WriteFile(p, b, 0600); e != nil {
				t.Fatal(e)
			}
		}
		c, e := prepareRuntimeWithRecords(&runtimeOptions{Config: p, NodeName: "main", Mode: "proxy", LocalPort: 11080, AllowInsecure: true})
		if e != nil || c.Manifest == nil {
			t.Fatalf("target %s: %v", target, e)
		}
		if e = engine.Check(context.Background(), c.JSON); e != nil {
			t.Fatal(e)
		}
	}
}

func TestGeoIPCNFullDatasetSDKMatch(t *testing.T) {
	cidrs, e := geoIPCNCIDRs()
	if e != nil {
		t.Fatal(e)
	}
	if len(cidrs) != 10014 {
		t.Fatal("incomplete upstream dataset")
	}
	r, e := S.NewHeadlessRule(context.Background(), option.HeadlessRule{DefaultOptions: option.DefaultHeadlessRule{IPCIDR: cidrs}})
	if e != nil {
		t.Fatal(e)
	}
	for ip, want := range map[string]bool{"119.6.64.69": true, "125.71.32.2": true, "240e::1": true, "1.1.1.1": false, "127.0.0.1": false, "2001:db8::1": false} {
		m := &adapter.InboundContext{Destination: M.Socksaddr{Addr: netip.MustParseAddr(ip), Port: 443}}
		if r.Match(m) != want {
			t.Errorf("SDK dataset membership %s", ip)
		}
	}
	if r.Match(&adapter.InboundContext{Destination: M.Socksaddr{Fqdn: "unresolved.invalid", Port: 443}}) {
		t.Fatal("unresolved hostname matched CN")
	}
}

func TestGeoIPCNFailClosed(t *testing.T) {
	for _, rule := range []string{"GEOIP,US,DIRECT", "GEOIP,gcn,DIRECT", "GEOIP,cn,DIRECT", "geoip,CN,DIRECT", "GEOIP,ＣＮ,DIRECT", "GEOIP,CN,DIRECT,NO-RESOLVE", "GEOIP,CN,DIRECT,no-resolve,extra", "GEOIP,CN", "GEOIP,CN,DIRECT,", "GEOIP,CN,DIRECT,no-resolve,no-resolve"} {
		p := routingFixture(t, " - "+rule+"\n - MATCH,main\n")
		_, e := prepareRuntimeWithRecords(&runtimeOptions{Config: p, NodeName: "main", Mode: "proxy", LocalPort: 11080, AllowInsecure: true})
		if e == nil {
			t.Errorf("accepted unsupported rule %q", rule)
		}
		if e != nil && strings.Contains(e.Error(), "password") {
			t.Fatal("credential error leak")
		}
	}
	for _, country := range []string{"CN", "cn", "gcn", "US", "ＣＮ"} {
		e := cr.Validate(cr.Condition{Kind: cr.RuleGeoIP, Value: country})
		if (e == nil) != (country == "CN") {
			t.Fatal("records country validation")
		}
	}
}

func TestGeoIPCNStagingSaveExport(t *testing.T) {
	p := routingFixture(t, " - GEOIP,CN,DIRECT,no-resolve\n - MATCH,main\n")
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	b = bytes.Replace(b, []byte("proxies:"), []byte("nodes:"), 1)
	if e = webValidateConfig(p, b); e != nil {
		t.Fatal(e)
	}
	exported, r, e := webConvertConfiguration(context.Background(), b, false, nil)
	if e != nil || r.Converted || !bytes.Equal(b, exported) {
		t.Fatal("native save/export rewrote GEOIP")
	}
	root := t.TempDir()
	q := filepath.Join(root, "config.yaml")
	if e = os.WriteFile(q, b, 0600); e != nil {
		t.Fatal(e)
	}
	if e = stageRuleSets(p, root); e != nil {
		t.Fatal(e)
	}
	staged, e := os.ReadFile(q)
	if e != nil || !bytes.Equal(staged, b) {
		t.Fatal("staging changed embedded rule")
	}
	if e = os.Remove(p); e != nil {
		t.Fatal(e)
	}
	c, e := prepareRuntimeWithRecords(&runtimeOptions{Config: q, NodeName: "main", Mode: "proxy", LocalPort: 11080, AllowInsecure: true})
	if e != nil || c.Manifest == nil {
		t.Fatalf("staging depended on original path: err=%v manifest=%v", e, c.Manifest != nil)
	}
	if e = engine.Check(context.Background(), c.JSON); e != nil {
		t.Fatal(e)
	}
}
