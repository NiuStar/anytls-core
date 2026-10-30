package main

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	"github.com/NiuStar/anytls-core/internal/engine"
)

// This contract is deliberately TUN-only. A normal mixed/proxy configuration
// may use a hostname for the AnyTLS server and retain its existing bootstrap.
// Check validates SDK construction; this test neither starts TUN nor claims
// that an arbitrary application using the system resolver is captured.
func TestUnifiedDNSCaptureIndependentOfUserRules(t *testing.T) {
	// Evaluate only the synthetic predicate vocabulary, not user routing.
	// Unknown predicates fail closed; no new production API is required.
	var captureMatches func(map[string]any, int, string, string) bool
	captureMatches = func(rule map[string]any, port int, protocol, network string) bool {
		matched := true
		for key, value := range rule {
			switch key {
			case "action", "type", "mode":
			case "rules":
				children, _ := value.([]any)
				all, anyMatch := len(children) > 0, false
				for _, child := range children {
					m, ok := child.(map[string]any)
					hit := ok && captureMatches(m, port, protocol, network)
					all, anyMatch = all && hit, anyMatch || hit
				}
				if rule["mode"] == "or" {
					matched = matched && anyMatch
				} else {
					matched = matched && all
				}
			case "port", "protocol", "network":
				values, ok := value.([]any)
				if !ok {
					values = []any{value}
				}
				hit := false
				for _, item := range values {
					hit = hit || key == "port" && item == float64(port) || key == "protocol" && item == protocol || key == "network" && item == network
				}
				matched = matched && hit
			case "invert":
			default:
				return false
			}
		}
		if rule["invert"] == true {
			return !matched
		}
		return matched
	}
	for _, tc := range []struct {
		name, rules string
	}{
		{"no_rules", ""},
		{"domain_only", " - DOMAIN,direct.invalid,DIRECT\n - MATCH,a\n"},
		{"match_direct", " - MATCH,DIRECT\n"},
		{"resolver_ip_direct", " - IP-CIDR,8.8.8.8/32,DIRECT\n - MATCH,DIRECT\n"},
		{"geoip_no_resolve", " - GEOIP,CN,DIRECT,no-resolve\n - MATCH,a\n"},
		{"ruleset_resolve", " - RULE-SET,local,DIRECT\n - MATCH,a\n"},
		{"ruleset_no_resolve", " - RULE-SET,local,DIRECT,no-resolve\n - MATCH,a\n"},
		{"duplicate_domain_group", " - DOMAIN,first.invalid,outer\n - DOMAIN,first.invalid,shared\n - MATCH,DIRECT\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, config, set := recordsCompilerFixture(t, tc.rules)
			o.Mode = "tun"
			compiled, err := prepareRuntimeWithRecords(&o)
			if err != nil {
				t.Fatal(err)
			}
			var cfg map[string]any
			if err := json.Unmarshal(compiled.JSON, &cfg); err != nil {
				t.Fatal(err)
			}

			// Resolve both A and AAAA through the secure server. Do not confuse
			// an individual business-route prefer_ipv4 action with DNS policy.
			dns, ok := cfg["dns"].(map[string]any)
			if !ok {
				t.Fatal("TUN has no unified DNS policy")
			}
			if dns["final"] != "secure-dns" || dns["reverse_mapping"] != true {
				t.Errorf("DNS must select secure-dns and retain domain attribution: %#v", dns)
			}
			if strategy, _ := dns["strategy"].(string); strategy == "ipv4_only" || strategy == "ipv6_only" {
				t.Errorf("unified DNS must support both A and AAAA, got %q", strategy)
			}
			// A single endpoint is intentional: failure must not silently fall
			// back to a local/UDP/TCP resolver. Registered SDK transports are
			// not configured fallbacks and are outside this assertion.
			servers, _ := dns["servers"].([]any)
			if len(servers) != 1 {
				t.Fatalf("want the single approved fail-closed DoH endpoint, got %#v", servers)
			}
			server, _ := servers[0].(map[string]any)
			tls, _ := server["tls"].(map[string]any)
			if server["tag"] != "secure-dns" || server["type"] != "https" || server["server"] != "1.1.1.1" || server["detour"] != "anytls-out" || tls["server_name"] != "cloudflare-dns.com" || tls["insecure"] == true || tls["disable_sni"] == true {
				t.Errorf("DoH endpoint must use authenticated Cloudflare TLS through AnyTLS: %#v", server)
			}
			if enabled, present := tls["enabled"]; present && enabled != true {
				t.Error("DoH TLS explicitly disabled")
			}
			if port, present := server["server_port"]; present && port != float64(443) {
				t.Errorf("unexpected DoH port: %v", port)
			}
			if path, present := server["path"]; present && path != "/dns-query" {
				t.Errorf("unexpected DoH path: %v", path)
			}
			if rules, _ := dns["rules"].([]any); len(rules) != 0 {
				t.Errorf("user routing must not introduce alternate DNS selection: %#v", rules)
			}

			route := cfg["route"].(map[string]any)
			rules, _ := route["rules"].([]any)
			m := compiled.Manifest
			if m == nil {
				t.Fatal("missing TUN provenance manifest")
			}
			if len(m.Rules) != len(rules) {
				t.Fatalf("SDK/manifest slot mismatch: %d != %d", len(rules), len(m.Rules))
			}
			if m.RuntimeSHA256 != shaHex(compiled.JSON) {
				t.Error("manifest not bound to emitted runtime bytes")
			}
			if digest, err := cr.ManifestDigest(*m, cr.ManifestBudget(m)); err != nil || digest != m.ManifestID {
				t.Errorf("invalid manifest digest: %v", err)
			}
			if len(m.CapturedSources) < 2 || m.CapturedSources[0].SHA256 == nil || *m.CapturedSources[0].SHA256 != shaHex(config) {
				t.Error("config source identity changed")
			}

			firstPolicy := len(rules)
			var userOrigins []cr.RouteProjection
			for i, raw := range rules {
				rule := raw.(map[string]any)
				origin := m.Rules[i]
				action, _ := rule["action"].(string)
				if origin.ActionType != action {
					t.Errorf("SDK/manifest action mismatch at %d: %q != %q", i, action, origin.ActionType)
				}
				typ, _ := rule["type"].(string)
				if typ == "" {
					typ = "default"
				}
				if origin.Type != typ {
					t.Errorf("SDK/manifest rule type mismatch at %d: %q != %q", i, typ, origin.Type)
				}
				switch action {
				case "sniff", "resolve", "hijack-dns":
					want := map[string]cr.SyntheticKind{"sniff": cr.SyntheticSniff, "resolve": cr.SyntheticResolve, "hijack-dns": cr.SyntheticHijack}[action]
					if origin.Synthetic != want || origin.Route.SourceID != nil || origin.Route.SourceIndex != nil || origin.Route.Evidence != cr.ProvenanceUnknown {
						t.Errorf("synthetic slot %d incorrectly attributed to a user rule: %#v", i, origin)
					}
					if action == "hijack-dns" && i >= firstPolicy {
						t.Errorf("DNS capture at %d follows ordinary policy at %d", i, firstPolicy)
					}
					if action == "resolve" {
						if firstPolicy == len(rules) {
							firstPolicy = i
						}
						if rule["server"] != "secure-dns" {
							t.Errorf("resolve action bypasses unified DoH: %#v", rule)
						}
					}
				default:
					if firstPolicy == len(rules) {
						firstPolicy = i
					}
					if origin.Synthetic != cr.SyntheticNone || origin.ExpectedOutbound != rule["outbound"] {
						t.Errorf("ordinary SDK/manifest slot mismatch at %d: %#v", i, origin)
					}
					if origin.Route.Condition != nil {
						field := map[cr.RuleKind]string{cr.RuleDomain: "domain", cr.RuleIPCIDR: "ip_cidr", cr.RuleSet: "rule_set"}[origin.Route.Kind]
						if field != "" && !reflect.DeepEqual(rule[field], []any{origin.Route.Condition.Value}) {
							t.Errorf("SDK condition/source slot mismatch at %d: %#v", i, origin.Route)
						}
					}
					userOrigins = append(userOrigins, origin.Route)
				}
			}

			// Evaluate only the DNS capture predicates, not a substitute route
			// engine. Both an explicit port-53 request (even before sniffing)
			// and already-detected DNS on another port must be captured. The
			// implementation may use two rules or one logical OR rule.
			for _, probe := range []struct {
				name, protocol, network string
				port                    int
			}{
				{"udp53_before_sniff", "", "udp", 53},
				{"tcp53_before_sniff", "", "tcp", 53},
				{"detected_dns_udp", "dns", "udp", 5353},
				{"detected_dns_tcp", "dns", "tcp", 5353},
			} {
				found := false
				for i := 0; i < firstPolicy; i++ {
					rule := rules[i].(map[string]any)
					if rule["action"] == "hijack-dns" && captureMatches(rule, probe.port, probe.protocol, probe.network) {
						found = true
					}
				}
				if !found {
					t.Errorf("%s: no DNS capture before ordinary policy/final; DNS must not escape via DIRECT", probe.name)
				}
			}
			for _, raw := range rules {
				rule := raw.(map[string]any)
				if rule["action"] == "hijack-dns" && captureMatches(rule, 443, "tls", "tcp") {
					t.Errorf("DNS capture incorrectly hijacks ordinary HTTPS: %#v", rule)
				}
			}

			lines := strings.Split(strings.TrimSpace(tc.rules), "\n")
			if tc.rules == "" {
				lines = nil
			}
			ordinary := 0
			for index, line := range lines {
				parts := strings.Split(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- ")), ",")
				kind, value, target := parts[0], "", parts[len(parts)-1]
				if target == "no-resolve" {
					target = parts[len(parts)-2]
				}
				var got cr.RouteProjection
				if kind == "MATCH" {
					got = m.FinalOrigin
				} else {
					value = parts[1]
					if ordinary >= len(userOrigins) {
						t.Fatalf("missing ordinary source index %d", index)
					}
					got = userOrigins[ordinary]
					ordinary++
				}
				if got.SourceIndex == nil || *got.SourceIndex != index || got.SourceID == nil || *got.SourceID != fmt.Sprintf("%s:rule:%d", m.Generation, index) || got.Kind != cr.RuleKind(kind) || got.Evidence != cr.ProvenanceVerified || got.ConfiguredTarget == nil || *got.ConfiguredTarget != target {
					t.Errorf("user identity/order changed at %d: %#v", index, got)
				}
				if kind != "MATCH" && (got.Condition == nil || got.Condition.Value != value) {
					t.Errorf("user condition changed at %d: %#v", index, got.Condition)
				}
				if kind == "RULE-SET" {
					if got.RuleSet == nil || got.RuleSet.SHA256 != shaHex(set) {
						t.Error("audited real rule-set bytes lost their SHA")
					}
					captured := false
					for _, source := range m.CapturedSources {
						captured = captured || source.Kind == cr.SourceRuleSet && source.Present && source.SHA256 != nil && *source.SHA256 == shaHex(set)
					}
					if !captured {
						t.Error("rule-set source bytes missing from manifest")
					}
				}
				if target == "DIRECT" && (got.TerminalKind != cr.TerminalDirect || got.OutboundTag != "direct") {
					t.Errorf("ordinary DIRECT target changed: %#v", got)
				}
			}
			if ordinary != len(userOrigins) {
				t.Errorf("unexpected ordinary rule origins: %d != %d", len(userOrigins), ordinary)
			}
			resolves := 0
			for _, raw := range rules {
				if raw.(map[string]any)["action"] == "resolve" {
					resolves++
				}
			}
			wantResolves := 0
			if tc.name == "ruleset_resolve" {
				wantResolves = 1
			}
			if resolves != wantResolves {
				t.Errorf("capture must not change business no-resolve semantics: resolves=%d want=%d", resolves, wantResolves)
			}
			if route["final"] != m.FinalOrigin.OutboundTag {
				t.Error("SDK/manifest final target mismatch")
			}
			if tc.rules == "" && (m.FinalOrigin.Kind != cr.RuleDefault || m.FinalOrigin.SourceID != nil || m.FinalOrigin.SourceIndex != nil || route["final"] != "anytls-out") {
				t.Error("ruleless final selection changed")
			}
			if tc.name == "duplicate_domain_group" && len(userOrigins) == 2 {
				if !reflect.DeepEqual(userOrigins[0].GroupPath, []cr.GroupEdge{{Group: "outer", Selected: "inner"}, {Group: "inner", Selected: "b"}}) || !reflect.DeepEqual(userOrigins[1].GroupPath, []cr.GroupEdge{{Group: "shared", Selected: "b"}}) || userOrigins[0].OutboundTag != userOrigins[1].OutboundTag {
					t.Error("synthetic insertion changed group paths/shared terminal")
				}
			}
			// Always check the actual compiled bytes, even when a semantic
			// assertion above fails. No network connection or TUN start occurs.
			if err := engine.Check(context.Background(), compiled.JSON); err != nil {
				t.Errorf("SDK rejects compiled TUN policy: %v", err)
			}
		})
	}
}
