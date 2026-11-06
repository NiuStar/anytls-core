package main

import (
	"errors"

	"gopkg.in/yaml.v3"
)

// ipv6 is an intentional initial TUN policy, never inferred from the outer
// server address or local interfaces. Preserve explicit false and reject null.
func configuredIPv6(n *yaml.Node) (bool, error) {
	if n == nil || n.Kind == 0 {
		return false, nil
	}
	seen := map[*yaml.Node]bool{}
	for n != nil && n.Kind == yaml.AliasNode && !seen[n] {
		seen[n] = true
		n = n.Alias
	}
	if n == nil || n.Kind != yaml.ScalarNode || n.Tag != "!!bool" {
		return false, errors.New("invalid ipv6: expected bool")
	}
	var enabled bool
	if err := n.Decode(&enabled); err != nil {
		return false, errors.New("invalid ipv6: expected bool")
	}
	return enabled, nil
}

// Shared by both builders and YAML routing using the already captured bytes.
// Mixed/proxy DNS and routing retain their existing independent semantics.
func applyTUNAddressFamily(cfg map[string]any, ipv6 bool) {
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	if in["type"] != "tun" {
		return
	}
	addresses := []string{"172.19.0.1/30"}
	dns := cfg["dns"].(map[string]any)
	if ipv6 {
		addresses = append(addresses, "fdfe:dcba:9876::1/126")
		delete(dns, "strategy")
	} else {
		dns["strategy"] = "ipv4_only"
	}
	in["address"] = addresses
	// Generated business resolve actions otherwise override the DNS default.
	for _, raw := range cfg["route"].(map[string]any)["rules"].([]any) {
		rule := raw.(map[string]any)
		if rule["action"] == "resolve" {
			if ipv6 {
				rule["strategy"] = "prefer_ipv4"
			} else {
				rule["strategy"] = "ipv4_only"
			}
		}
	}
}

// Each runtime owns fresh maps. The literal endpoint avoids resolver bootstrap;
// detour is the global selected AnyTLS node, not the business MATCH target.
func unifiedTUNDNS() map[string]any {
	return map[string]any{
		"servers": []any{map[string]any{"type": "https", "tag": "secure-dns", "server": "1.1.1.1", "tls": map[string]any{"server_name": "cloudflare-dns.com"}, "detour": "anytls-out"}},
		"final":   "secure-dns", "reverse_mapping": true,
	}
}

func unifiedTUNDNSRules() []any {
	return []any{
		map[string]any{"port": 53, "action": "hijack-dns"},
		map[string]any{"action": "sniff"},
		map[string]any{"protocol": []string{"dns"}, "action": "hijack-dns"},
	}
}
