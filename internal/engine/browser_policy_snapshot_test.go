package engine

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	fp "github.com/NiuStar/anytls-core/internal/familypolicy"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func browserSnapshotFixture(t *testing.T, raw, source []byte) *fp.Snapshot {
	t.Helper()
	m := recordsTestManifest(t, raw, "P", "direct")
	sum := recordsSHA(source)
	m.CapturedSources = append(m.CapturedSources, cr.CapturedSource{Kind: cr.SourceRuleSet, Present: true, SHA256: &sum})
	recordsSeal(t, m)
	s := fp.Capture(raw, m, []fp.Source{{Tag: "local", JSON: source}})
	if s == nil {
		t.Fatal("source capture")
	}
	return s
}
func TestBrowserCapturedRuleSetActualCompiledIdentity(t *testing.T) {
	source := []byte(`{"version":3,"rules":[{"ip_cidr":["192.0.2.0/24","2001:db8::/32"]}]}`)
	raw := []byte(`{"outbounds":[{"type":"direct","tag":"P"}],"dns":{"servers":[{"type":"https","tag":"secure-dns","server":"127.0.0.1","server_port":9}]},"route":{"rule_set":[{"type":"inline","tag":"local","rules":[{"ip_cidr":["192.0.2.0/24","2001:db8::/32"]}]}],"rules":[{"action":"resolve","server":"secure-dns","strategy":"prefer_ipv4"},{"rule_set":["local"],"action":"route","outbound":"P"}],"final":"P"}}`)
	s := browserSnapshotFixture(t, raw, source)
	if browserCapturedPolicy(raw, nil) || !browserCapturedPolicy(raw, s) {
		t.Fatal("unauthenticated or missing policy admission")
	}
	ctx, _, err := decodeOptions(fp.WithSnapshot(context.Background(), s), raw)
	if err != nil {
		t.Fatal(err)
	}
	if !service.FromContext[browserDNSObserver](ctx).(*browserProvenance).static {
		t.Fatal("snapshot not consumed by SDK decode registry")
	}
	instance := recordsBox(t, raw)
	// Start only actual compiled rules to bind RuleSetItem.setList; no Box.Start,
	// listeners, resolver calls, native devices or network operations.
	for _, r := range instance.Router().Rules() {
		if err := r.Start(); err != nil {
			t.Fatal(err)
		}
	}
	m := adapter.InboundContext{Network: "tcp", Protocol: "tls", Domain: "a.test", IPVersion: 6, Destination: M.Socksaddr{Addr: netip.MustParseAddr("2001:db8::1"), Port: 443}}
	original := m
	a, ai, ok := browserPureMatch(instance.Router(), m)
	if !ok || ai != 1 {
		t.Fatal("compiled v6 ruleset did not match", ai, ok)
	}
	m.IPVersion = 4
	m.Destination.Addr = netip.MustParseAddr("192.0.2.1")
	b, bi, ok := browserPureMatch(instance.Router(), m)
	if !ok || a != b || ai != bi {
		t.Fatal("actual rule identity changed for accepted pair")
	}
	if original.Destination.Addr != netip.MustParseAddr("2001:db8::1") {
		t.Fatal("original metadata changed")
	}
	m.Destination = M.Socksaddr{Fqdn: "a.test", Port: 443}
	if _, _, ok := browserPureMatch(instance.Router(), m); ok {
		t.Fatal("effectful domain resolve treated as no-op")
	}
	for _, change := range []string{"remote", "process_name", "missing", "resolve-option"} {
		var root map[string]any
		if err := json.Unmarshal(raw, &root); err != nil {
			t.Fatal(err)
		}
		route := root["route"].(map[string]any)
		set := route["rule_set"].([]any)[0].(map[string]any)
		switch change {
		case "remote":
			set["type"] = "remote"
		case "process_name":
			set["rules"].([]any)[0].(map[string]any)["process_name"] = []string{"browser"}
		case "missing":
			route["rules"].([]any)[1].(map[string]any)["rule_set"] = []string{"missing"}
		case "resolve-option":
			route["rules"].([]any)[0].(map[string]any)["disable_cache"] = true
		}
		bad, _ := json.Marshal(root)
		if browserCapturedPolicy(bad, s) {
			t.Fatal("changed runtime accepted", change)
		}
		if change != "remote" {
			captured := source
			if change == "process_name" {
				captured = []byte(`{"version":3,"rules":[{"ip_cidr":["192.0.2.0/24","2001:db8::/32"],"process_name":["browser"]}]}`)
			}
			// Refresh all source/runtime/manifest digests, so rejection exercises the
			// unsupported policy surface rather than merely a stale SHA guard.
			refreshed := browserSnapshotFixture(t, bad, captured)
			if browserCapturedPolicy(bad, refreshed) {
				t.Fatal("unsupported reauthenticated policy", change)
			}
		}
	}
}
func TestBrowserCapturedRuleSetRejectCandidate(t *testing.T) {
	source := []byte(`{"version":3,"rules":[{"ip_cidr":["192.0.2.0/24"]}]}`)
	raw := []byte(`{"outbounds":[{"type":"direct","tag":"P"}],"route":{"rule_set":[{"type":"inline","tag":"local","rules":[{"ip_cidr":["192.0.2.0/24"]}]}],"rules":[{"rule_set":["local"],"action":"reject"}],"final":"P"}}`)
	s := browserSnapshotFixture(t, raw, source)
	if !browserCapturedPolicy(raw, s) {
		t.Fatal("reject policy not admitted")
	}
	instance := recordsBox(t, raw)
	for _, r := range instance.Router().Rules() {
		if err := r.Start(); err != nil {
			t.Fatal(err)
		}
	}
	m := adapter.InboundContext{Destination: M.Socksaddr{Addr: netip.MustParseAddr("2001:db8::1"), Port: 443}, IPVersion: 6}
	if r, i, ok := browserPureMatch(instance.Router(), m); !ok || r != nil || i != -1 {
		t.Fatal("v6 final")
	}
	m.Destination.Addr = netip.MustParseAddr("192.0.2.1")
	m.IPVersion = 4
	if _, _, ok := browserPureMatch(instance.Router(), m); ok {
		t.Fatal("candidate bypassed actual named ruleset REJECT")
	}
}
