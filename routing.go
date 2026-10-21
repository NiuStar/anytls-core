package main

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"gopkg.in/yaml.v3"
)

// applyRouting accepts only the small, explicit Clash rule subset documented in README.
// ponytail: no provider/group/GEOIP emulation; add each only with a separate verified contract.
func applyRouting(path string, nodes []node, selected node, cfg map[string]any, allowInsecure bool) error {
	b, err := readSnapshotSource(path, snapshotConfigLimit, true)
	if err != nil {
		return err
	}
	return applyRoutingBytes(path, b, nodes, selected, cfg, allowInsecure)
}

func applyRoutingBytes(path string, b []byte, nodes []node, selected node, cfg map[string]any, allowInsecure bool) error {
	var doc struct {
		Rules     []string               `yaml:"rules"`
		Groups    []proxyGroup           `yaml:"proxy-groups"`
		Providers map[string]any         `yaml:"rule-providers"`
		Sets      map[string]fileRuleSet `yaml:"rule-sets"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return err
	}
	if len(doc.Providers) > 0 {
		return errors.New("remote rule-providers require audited conversion to rule-sets; refusing silent fallback")
	}
	for _, g := range doc.Groups {
		if _, err := resolveGroup(g.Name, nodes, doc.Groups); err != nil {
			return err
		}
	}
	if len(doc.Rules) == 0 {
		return nil
	}
	route := cfg["route"].(map[string]any)
	inbound := cfg["inbounds"].([]any)[0].(map[string]any)
	if inbound["type"] != "tun" && inbound["type"] != "mixed" {
		return errors.New("routing requires tun or mixed inbound")
	}
	outbounds := cfg["outbounds"].([]any)
	active := map[string]string{selected.Name: "anytls-out"}
	excluded := []string{}
	if inbound["type"] == "tun" {
		excluded = append(excluded, inbound["route_exclude_address"].([]string)...)
	}
	rules := []any{map[string]any{"action": "sniff"}}
	matched := false
	addDirect := false
	loadedSets := map[string]bool{}
	sets := []any{}
	for i, raw := range doc.Rules {
		parts := strings.Split(raw, ",")
		if len(parts) < 2 {
			return fmt.Errorf("rules[%d]: invalid rule", i)
		}
		kind := strings.TrimSpace(parts[0])
		value := ""
		target := ""
		if kind == "MATCH" {
			if len(parts) != 2 {
				return fmt.Errorf("rules[%d]: invalid MATCH", i)
			}
			target = strings.TrimSpace(parts[1])
			if i != len(doc.Rules)-1 || matched {
				return fmt.Errorf("rules[%d]: MATCH must occur once at end", i)
			}
			matched = true
		} else {
			if len(parts) != 3 && !(len(parts) == 4 && parts[0] == "RULE-SET" && parts[3] == "no-resolve") {
				return fmt.Errorf("rules[%d]: expected TYPE,value,target", i)
			}
			value = strings.TrimSpace(parts[1])
			target = strings.TrimSpace(parts[2])
			if value == "" {
				return fmt.Errorf("rules[%d]: empty match", i)
			}
		}
		switch kind {
		case "DOMAIN", "DOMAIN-SUFFIX":
			if value == "" || strings.ContainsAny(value, " /\t\r\n") || strings.HasPrefix(value, ".") {
				return fmt.Errorf("rules[%d]: invalid domain", i)
			}
		case "IP-CIDR":
			if _, _, e := net.ParseCIDR(value); e != nil {
				return fmt.Errorf("rules[%d]: invalid CIDR: %w", i, e)
			}
		case "RULE-SET":
			spec, ok := doc.Sets[value]
			if !ok {
				return fmt.Errorf("rules[%d]: missing audited rule-set %q", i, value)
			}
			if !loadedSets[value] {
				set, err := loadRuleSet(path, value, spec)
				if err != nil {
					return fmt.Errorf("rules[%d]: %w", i, err)
				}
				sets = append(sets, set)
				loadedSets[value] = true
			}
		case "MATCH":
		default:
			return fmt.Errorf("rules[%d]: unsupported rule %q", i, kind)
		}
		if kind == "RULE-SET" && doc.Sets[value].ResolveIP && len(parts) == 3 {
			if _, ok := cfg["dns"]; !ok {
				cfg["dns"] = map[string]any{"servers": []any{map[string]any{"type": "https", "tag": "secure-dns", "server": "1.1.1.1", "tls": map[string]any{"server_name": "cloudflare-dns.com"}, "detour": "anytls-out"}}, "final": "secure-dns"}
			}
			rules = append(rules, map[string]any{"action": "resolve", "server": "secure-dns", "strategy": "prefer_ipv4"})
		}
		tag := ""
		resolved, err := resolveGroup(target, nodes, doc.Groups)
		if err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
		target = resolved
		switch target {
		case "DIRECT":
			tag = "direct"
			if !addDirect {
				outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct"})
				addDirect = true
			}
		case "REJECT":
			if kind == "MATCH" {
				return fmt.Errorf("rules[%d]: MATCH REJECT not supported", i)
			}
		default:
			if target == "" {
				return fmt.Errorf("rules[%d]: empty target", i)
			}
			if existing, ok := active[target]; ok {
				tag = existing
			} else {
				n, e := choose(nodes, target)
				if e != nil {
					return fmt.Errorf("rules[%d]: %w", i, e)
				}
				if !selectable(n) {
					return fmt.Errorf("rules[%d]: node %q incomplete", i, target)
				}
				// Every routed server must be an IP in TUN mode so its host route can bypass TUN.
				mode := "proxy"
				if inbound["type"] == "tun" {
					mode = "tun"
				}
				built, e := buildNode(n, mode, 11080, allowInsecure)
				if e != nil {
					return fmt.Errorf("rules[%d]: %w", i, e)
				}
				tag = fmt.Sprintf("node-%d", len(active))
				out := built["outbounds"].([]any)[0].(map[string]any)
				out["tag"] = tag
				outbounds = append(outbounds, out)
				if inbound["type"] == "tun" {
					excluded = append(excluded, built["inbounds"].([]any)[0].(map[string]any)["route_exclude_address"].([]string)...)
				}
				active[target] = tag
			}
		}
		if kind == "MATCH" {
			route["final"] = tag
			continue
		}
		rule := map[string]any{}
		switch kind {
		case "DOMAIN":
			rule["domain"] = []string{value}
		case "DOMAIN-SUFFIX":
			rule["domain_suffix"] = []string{value}
		case "IP-CIDR":
			rule["ip_cidr"] = []string{value}
		case "RULE-SET":
			rule["rule_set"] = []string{value}
		}
		if target == "REJECT" {
			rule["action"] = "reject"
		} else {
			rule["action"] = "route"
			rule["outbound"] = tag
		}
		rules = append(rules, rule)
	}
	if !matched {
		return errors.New("routing rules require a final MATCH target")
	}
	if len(sets) > 0 {
		rules = append(rules[:1], append([]any{map[string]any{"protocol": []string{"dns"}, "action": "hijack-dns"}}, rules[1:]...)...)
		if dns, ok := cfg["dns"].(map[string]any); ok {
			dns["reverse_mapping"] = true
		}
	}
	route["rules"] = rules
	if len(sets) > 0 {
		route["rule_set"] = sets
	}
	cfg["outbounds"] = outbounds
	if inbound["type"] == "tun" {
		inbound["route_exclude_address"] = excluded
	}
	return nil
}
