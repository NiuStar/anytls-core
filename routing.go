package main

import (
	"errors"
	"fmt"
	"net"
	"strings"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"

	"gopkg.in/yaml.v3"
)

// applyRouting accepts only the small, explicit Clash rule subset documented in README.
// GEOIP is limited to the embedded, pinned CN IPv4/IPv6 dataset.
func applyRouting(path string, nodes []node, selected node, cfg map[string]any, allowInsecure bool) error {
	b, err := readSnapshotSource(path, snapshotConfigLimit, true)
	if err != nil {
		return err
	}
	return applyRoutingBytes(path, b, nodes, selected, cfg, allowInsecure)
}

func applyRoutingBytes(path string, b []byte, nodes []node, selected node, cfg map[string]any, allowInsecure bool) error {
	return applyRoutingRecords(path, b, nodes, selected, cfg, allowInsecure, nil)
}

func applyRoutingRecords(path string, b []byte, nodes []node, selected node, cfg map[string]any, allowInsecure bool, manifest *cr.Manifest) error {
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
	if manifest != nil {
		manifest.Outbounds = append(manifest.Outbounds, nodeOrigin(manifest, nodes, selected.Name, "anytls-out"))
		manifest.FinalOrigin = routeOrigin(manifest, nodes, -1, string(cr.RuleDefault), "", selected.Name, selected.Name, "anytls-out", []cr.GroupEdge{})
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
	if manifest != nil {
		manifest.Rules = append(manifest.Rules, syntheticOrigin("sniff", cr.SyntheticSniff))
	}
	matched := false
	addDirect := false
	loadedSets := map[string]bool{}
	sets := []any{}
	geoIPResolve := false
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
			if len(parts) != 3 && !(len(parts) == 4 && (parts[0] == "RULE-SET" || parts[0] == "GEOIP") && parts[3] == "no-resolve") {
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
		case "GEOIP":
			if !supportedGeoIPRule(parts) {
				return fmt.Errorf("rules[%d]: GEOIP supports only exact CN with optional no-resolve", i)
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
				// loadRuleSet validated SHA against the same handle used for inline rules.
				if manifest != nil {
					sum := spec.SHA256
					manifest.CapturedSources = append(manifest.CapturedSources, cr.CapturedSource{Kind: cr.SourceRuleSet, Ordinal: len(sets) - 1, Present: true, SHA256: &sum})
				}
			}
		case "MATCH":
		default:
			return fmt.Errorf("rules[%d]: unsupported rule %q", i, kind)
		}
		if (kind == "RULE-SET" && doc.Sets[value].ResolveIP || kind == "GEOIP") && len(parts) == 3 {
			geoIPResolve = geoIPResolve || kind == "GEOIP"
			if _, ok := cfg["dns"]; !ok {
				cfg["dns"] = map[string]any{"servers": []any{map[string]any{"type": "https", "tag": "secure-dns", "server": "1.1.1.1", "tls": map[string]any{"server_name": "cloudflare-dns.com"}, "detour": "anytls-out"}}, "final": "secure-dns"}
			}
			rules = append(rules, map[string]any{"action": "resolve", "server": "secure-dns", "strategy": "prefer_ipv4"})
			if manifest != nil {
				manifest.Rules = append(manifest.Rules, syntheticOrigin("resolve", cr.SyntheticResolve))
			}
		}
		tag := ""
		configuredTarget := target
		resolved, edges, err := resolveGroupPath(target, nodes, doc.Groups)
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
				if manifest != nil {
					manifest.Outbounds = append(manifest.Outbounds, nodeOrigin(manifest, nodes, "DIRECT", tag))
				}
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
				if manifest != nil {
					manifest.Outbounds = append(manifest.Outbounds, nodeOrigin(manifest, nodes, target, tag))
				}
			}
		}
		var origin cr.RouteProjection
		if manifest != nil {
			origin = routeOrigin(manifest, nodes, i, kind, value, configuredTarget, target, tag, edges)
			if kind == "RULE-SET" && target != "REJECT" {
				origin.RuleSet = &cr.RuleSetProjection{Label: value, SHA256: doc.Sets[value].SHA256}
			}
		}
		if kind == "MATCH" {
			if manifest != nil {
				manifest.FinalOrigin = origin
			}
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
		case "GEOIP":
			cidrs, err := geoIPCNCIDRs()
			if err != nil {
				return err
			}
			rule["ip_cidr"] = cidrs
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
		if manifest != nil {
			action := "route"
			if target == "REJECT" {
				action = "reject"
			}
			manifest.Rules = append(manifest.Rules, cr.RuleOrigin{Type: "default", ActionType: action, ExpectedOutbound: tag, Synthetic: cr.SyntheticNone, Route: origin})
		}
	}
	if !matched {
		return errors.New("routing rules require a final MATCH target")
	}
	if len(sets) > 0 || geoIPResolve {
		rules = append(rules[:1], append([]any{map[string]any{"protocol": []string{"dns"}, "action": "hijack-dns"}}, rules[1:]...)...)
		if manifest != nil {
			manifest.Rules = append(manifest.Rules[:1], append([]cr.RuleOrigin{syntheticOrigin("hijack-dns", cr.SyntheticHijack)}, manifest.Rules[1:]...)...)
		}
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
