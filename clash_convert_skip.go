package main

import (
	"fmt"
	"net"
	"strings"

	"gopkg.in/yaml.v3"
)

// Sanitize references only after all providers and independently supported units
// have been captured. Never invent DIRECT to repair a removed proxy.
func conversionSanitize(root *yaml.Node, r *webConversionReport, remote bool) {
	skip := func(path, reason string) { r.Skipped = append(r.Skipped, "已跳过 "+path+": "+reason) }
	nodes := conversionField(root, "nodes")
	valid := map[string]bool{"DIRECT": true, "REJECT": true}
	kept := []*yaml.Node{}
	for i, n := range nodes.Content {
		path := fmt.Sprintf("nodes[%d]", i)
		var typed node
		if n.Decode(&typed) != nil || !selectable(typed) || typed.Name == "" || valid[typed.Name] || typed.IdleCheck < 0 || typed.IdleTimeout < 0 || typed.MinIdle < 0 || typed.UDP != nil && !*typed.UDP || strings.ContainsAny(typed.Server, "%\r") || typed.EgressIP != "" && net.ParseIP(typed.EgressIP) == nil {
			skip(path, "invalid/incomplete or duplicate AnyTLS node")
			continue
		}
		if remote && typed.CA != "" {
			skip(path+".ca", "remote local-file dependency; entire node removed")
			continue
		}
		if version := conversionField(n, "tls-min-version"); version != nil && (version.Kind != yaml.ScalarNode || version.Tag != "!!str" || version.Value == "") {
			skip(path+".tls-min-version", "invalid TLS minimum version field; entire node removed")
			continue
		}
		if err := validateNodeTLSMinVersion(typed); err != nil {
			skip(path+".tls-min-version", "invalid TLS minimum version; entire node removed")
			continue
		}
		if pin := conversionField(n, "certificate-public-key-sha256"); pin != nil && (pin.Kind != yaml.ScalarNode || pin.Tag != "!!str" || pin.Value == "") {
			skip(path+".certificate-public-key-sha256", "invalid SPKI trust field; entire node removed")
			continue
		}
		if err := validateNodeSPKITrust(typed); err != nil {
			skip(path+".certificate-public-key-sha256", "invalid or conflicting SPKI trust; entire node removed")
			continue
		}
		valid[typed.Name] = true
		kept = append(kept, n)
	}
	nodes.Content = kept
	if len(kept) == 0 {
		r.Issues = append(r.Issues, "nodes: no usable AnyTLS nodes remain")
	}
	sets := conversionField(root, "rule-sets")
	if remote && sets != nil && sets.Kind == yaml.MappingNode {
		next := []*yaml.Node{}
		for i := 0; i < len(sets.Content); i += 2 {
			if p := conversionField(sets.Content[i+1], "path"); p != nil && conversionText(p) != "" {
				skip(fmt.Sprintf("rule-sets[%d].path", i/2), "remote local-file dependency; entire rule-set removed")
				continue
			}
			next = append(next, sets.Content[i], sets.Content[i+1])
		}
		sets.Content = next
	}
	groups := conversionField(root, "proxy-groups")
	gs := map[string]*yaml.Node{}
	groupPaths := map[string]string{}
	if groups != nil && groups.Kind == yaml.SequenceNode {
		for i, g := range groups.Content {
			path := fmt.Sprintf("proxy-groups[%d]", i)
			name := conversionText(conversionField(g, "name"))
			bad := g.Kind != yaml.MappingNode || name == "" || valid[name] || gs[name] != nil || conversionText(conversionField(g, "type")) != "select"
			for j := 0; j < len(g.Content) && g.Kind == yaml.MappingNode; j += 2 {
				switch g.Content[j].Value {
				case "name", "type", "proxies", "selected":
				default:
					bad = true
				}
			}
			if m := conversionField(g, "proxies"); m == nil || m.Kind != yaml.SequenceNode {
				bad = true
			}
			if bad {
				skip(path, "unsupported/invalid group; entire group removed")
				continue
			}
			gs[name] = g
			groupPaths[name] = path
		}
		// Tarjan SCC marks every cycle member, including cross/back edges.
		cyclic := conversionCyclicGroups(gs, groups.Content)
		// Iterate input order so reports and retained units are deterministic.
		for _, g := range groups.Content {
			name := conversionText(conversionField(g, "name"))
			if cyclic[name] && gs[name] == g {
				skip(groupPaths[name], "cyclic group removed")
				delete(gs, name)
			}
		}
		for changed := true; changed; {
			changed = false
			for _, g := range groups.Content {
				name := conversionText(conversionField(g, "name"))
				if gs[name] != g {
					continue
				}
				members := conversionField(g, "proxies")
				next := []*yaml.Node{}
				for j, m := range members.Content {
					if m.Kind == yaml.ScalarNode && (valid[m.Value] || gs[m.Value] != nil) {
						next = append(next, m)
					} else {
						skip(fmt.Sprintf("%s.proxies[%d]", groupPaths[name], j), "unavailable member reference")
					}
				}
				members.Content = next
				if len(next) == 0 {
					skip(groupPaths[name], "empty group removed; no DIRECT replacement")
					delete(gs, name)
					changed = true
				}
			}
		}
		next := []*yaml.Node{}
		for _, g := range groups.Content {
			name := conversionText(conversionField(g, "name"))
			if gs[name] != g {
				continue
			}
			m := conversionField(g, "proxies")
			selected := conversionText(conversionField(g, "selected"))
			found := false
			for _, member := range m.Content {
				if member.Value == selected {
					found = true
				}
			}
			if !found {
				conversionSet(g, "selected", conversionString(m.Content[0].Value))
				r.Warnings = append(r.Warnings, groupPaths[name]+".selected: selection changed to first surviving member; confirmation required")
			}
			next = append(next, g)
			valid[name] = true
		}
		groups.Content = next
	}
	rules := conversionField(root, "rules")
	if rules != nil && rules.Kind == yaml.SequenceNode && len(rules.Content) > 0 {
		fallback := ""
		// Prefer an existing group whose selected chain actually ends at an AnyTLS node.
		if groups != nil {
			for _, g := range groups.Content {
				name := conversionText(conversionField(g, "name"))
				target := name
				for gs[target] != nil {
					target = conversionText(conversionField(gs[target], "selected"))
				}
				if target != "DIRECT" && target != "REJECT" && valid[target] {
					fallback = name
					break
				}
			}
		}
		if fallback == "" && len(kept) > 0 {
			fallback = conversionText(conversionField(kept[0], "name"))
		}
		next := []*yaml.Node{}
		var final *yaml.Node
		for i, n := range rules.Content {
			path := fmt.Sprintf("rules[%d]", i)
			p := conversionParts(n.Value)
			if n.Kind != yaml.ScalarNode {
				skip(path, "invalid rule")
				continue
			}
			isMatch := len(p) == 2 && p[0] == "MATCH"
			supported := isMatch || len(p) == 3 && (p[0] == "DOMAIN" || p[0] == "DOMAIN-SUFFIX" || p[0] == "IP-CIDR" || p[0] == "RULE-SET") || len(p) == 4 && p[0] == "RULE-SET" && p[3] == "no-resolve"
			if !supported {
				skip(path, "unsupported rule type or shape")
				continue
			}
			target := p[1]
			if !isMatch {
				target = p[2]
			}
			if isMatch {
				if final != nil {
					skip(path, "duplicate MATCH replaced earlier MATCH; last final target retained")
				}
				if i != len(rules.Content)-1 {
					r.Warnings = append(r.Warnings, path+": MATCH moved to final position; confirmation required")
				}
				resolved := target
				for gs[resolved] != nil {
					resolved = conversionText(conversionField(gs[resolved], "selected"))
				}
				if !valid[target] || resolved == "REJECT" {
					skip(path, "MATCH target unavailable")
					if fallback == "" {
						continue
					}
					p[1] = fallback
					r.Warnings = append(r.Warnings, path+": 原 MATCH 目标已移除，改用可用代理（绝非自动 DIRECT）；必须确认 fallback")
				}
				final = conversionString(strings.Join(p, ","))
				continue
			}
			if !valid[target] {
				skip(path, "unavailable rule target")
				continue
			}
			if (p[0] == "DOMAIN" || p[0] == "DOMAIN-SUFFIX") && (p[1] == "" || strings.ContainsAny(p[1], "*?+\r\n\t /,") || strings.HasPrefix(p[1], ".")) {
				skip(path, "unsupported domain pattern")
				continue
			}
			if p[0] == "IP-CIDR" {
				if _, _, e := net.ParseCIDR(p[1]); e != nil {
					skip(path, "invalid CIDR")
					continue
				}
			}
			if p[0] == "RULE-SET" && conversionField(sets, p[1]) == nil {
				skip(path, "unavailable rule-set reference")
				continue
			}
			next = append(next, n)
		}
		if final == nil && len(next) > 0 && fallback != "" {
			final = conversionString("MATCH," + fallback)
			r.Warnings = append(r.Warnings, "rules: missing usable final MATCH; fallback to available proxy; confirmation required")
		}
		if final != nil {
			next = append(next, final)
		}
		rules.Content = next
		if len(next) == 0 {
			conversionDelete(root, "rules")
			r.Warnings = append(r.Warnings, "rules: 所有规则已跳过；省略 rules，使用现有默认全代理 bootstrap；必须确认")
		}
	} else if rules != nil && r.Format == "clash" && len(r.Skipped) > 0 {
		conversionDelete(root, "rules")
		r.Warnings = append(r.Warnings, "rules: 所有规则已跳过；使用现有默认全代理 bootstrap；必须确认")
	}
	if len(r.Skipped) > 0 {
		r.Warnings = append(r.Warnings, "部分不支持的配置已跳过；仅保留可用 AnyTLS 内容，必须确认后才应用")
	}
}

func conversionDelete(root *yaml.Node, key string) {
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value == key {
			root.Content = append(root.Content[:i], root.Content[i+2:]...)
			return
		}
	}
}
