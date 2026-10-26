package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Issues block publication; warnings require confirmation in the caller. Reports
// contain schema paths/indices and fixed descriptions, never configuration values.
type webConversionReport struct {
	Format    string   `json:"format"`
	Converted bool     `json:"converted"`
	Warnings  []string `json:"warnings"`
	Issues    []string `json:"issues"`
	Skipped   []string `json:"skipped"`
}

var errWebConversionInvalid = errors.New("CONFIG_CONVERSION_INVALID")
var errWebConversionTooLarge = errors.New("CONFIG_CONVERSION_TOO_LARGE")

func webConversionErrorCode(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "CONFIG_CONVERSION_TIMEOUT"
	}
	if errors.Is(err, context.Canceled) {
		return "CONFIG_CONVERSION_CANCELED"
	}
	if errors.Is(err, errWebConversionTooLarge) {
		return errWebConversionTooLarge.Error()
	}
	return errWebConversionInvalid.Error()
}

func webConvertConfiguration(ctx context.Context, input []byte, remote bool, fetch func(context.Context, string) ([]byte, error)) ([]byte, webConversionReport, error) {
	r := webConversionReport{Warnings: []string{}, Issues: []string{}, Skipped: []string{}}
	root, changed, err := conversionParseContext(ctx, input)
	if err != nil {
		return nil, r, err
	}
	native, clash := conversionField(root, "nodes") != nil, conversionField(root, "proxies") != nil || conversionField(root, "proxy-providers") != nil
	if native && clash {
		return nil, r, errWebConversionInvalid
	}
	if !native && !clash {
		return nil, r, errWebConversionInvalid
	}
	if native {
		r.Format = "native"
		r.Converted = changed
		nodes := conversionField(root, "nodes")
		if nodes.Kind != yaml.SequenceNode {
			return nil, r, errWebConversionInvalid
		}
		c := conversionState{ctx: ctx, report: &r, nodes: conversionSeq()}
		c.addNodes(nodes, "nodes")
		for _, n := range nodes.Content {
			if conversionField(n, "servername") != nil {
				changed = true
				c.warn("nodes: servername normalized to native sni; confirmation required")
			}
		}
		if changed || len(r.Skipped) > 0 {
			conversionSet(root, "nodes", c.nodes)
		}
		beforeWarnings := len(r.Warnings)
		if err := ctx.Err(); err != nil {
			return nil, r, err
		}
		conversionSanitize(root, &r, remote)
		if err := ctx.Err(); err != nil {
			return nil, r, err
		}
		r.Converted = changed || len(r.Skipped) > 0 || len(r.Warnings) > beforeWarnings
		if !r.Converted {
			return input, r, nil
		}
		b, e := conversionMarshal(ctx, root)
		if e != nil {
			return nil, r, e
		}
		return b, r, nil
	}
	r.Format = "clash"
	r.Converted = true
	out := conversionMap()
	c := conversionState{ctx: ctx, fetch: fetch, report: &r, nodes: conversionSeq(), providers: map[string][]string{}, ruleProviders: map[string]conversionRuleProvider{}}
	if n := conversionField(root, "proxies"); n != nil {
		c.addNodes(n, "proxies")
	}
	if p := conversionField(root, "proxy-providers"); p != nil {
		if p.Kind != yaml.MappingNode {
			return nil, r, errWebConversionInvalid
		}
		for i := 0; i < len(p.Content); i += 2 {
			path := fmt.Sprintf("proxy-providers[%d]", i/2)
			data := c.resource(p.Content[i+1], path)
			if data == nil {
				continue
			}
			child, _, e := conversionParseContext(ctx, data)
			if e != nil {
				c.issue(path + ": invalid provider YAML")
				continue
			}
			if conversionField(child, "proxy-providers") != nil {
				c.issue(path + ": nested providers are unsupported")
				continue
			}
			start := len(c.nodes.Content)
			c.addNodes(conversionField(child, "proxies"), path+".proxies")
			names := []string{}
			kept := append([]*yaml.Node{}, c.nodes.Content[:start]...)
			for index, n := range c.nodes.Content[start:] {
				if ca := conversionField(n, "ca"); ca != nil && conversionText(ca) != "" {
					c.issue(fmt.Sprintf("%s.proxies[%d].ca: remote provider requires a local file", path, index))
					continue
				}
				kept = append(kept, n)
				names = append(names, conversionText(conversionField(n, "name")))
			}
			c.nodes.Content = kept
			c.providers[p.Content[i].Value] = names
		}
	}
	conversionSet(out, "nodes", c.nodes)
	if groups := conversionField(root, "proxy-groups"); groups != nil {
		if groups.Kind != yaml.SequenceNode {
			return nil, r, errWebConversionInvalid
		}
		next := conversionSeq()
		for i, g := range groups.Content {
			if converted := c.group(g, fmt.Sprintf("proxy-groups[%d]", i)); converted != nil {
				next.Content = append(next.Content, converted)
			}
		}
		conversionSet(out, "proxy-groups", next)
	}
	if p := conversionField(root, "rule-providers"); p != nil {
		if p.Kind != yaml.MappingNode {
			return nil, r, errWebConversionInvalid
		}
		for i := 0; i < len(p.Content); i += 2 {
			path := fmt.Sprintf("rule-providers[%d]", i/2)
			spec := p.Content[i+1]
			format := conversionText(conversionField(spec, "format"))
			if format != "" && format != "yaml" {
				c.issue(path + ".format: unsupported provider format")
				continue
			}
			behavior := conversionText(conversionField(spec, "behavior"))
			if behavior != "domain" && behavior != "ipcidr" && behavior != "classical" {
				c.issue(path + ".behavior: unsupported provider behavior")
				continue
			}
			data := c.resource(spec, path)
			if data == nil {
				continue
			}
			child, _, e := conversionParseContext(ctx, data)
			if e != nil {
				c.issue(path + ": invalid provider YAML")
				continue
			}
			payload := conversionField(child, "payload")
			if payload == nil || payload.Kind != yaml.SequenceNode {
				c.issue(path + ".payload: expected sequence")
				continue
			}
			c.ruleProviders[p.Content[i].Value] = conversionRuleProvider{behavior, payload, path}
		}
	}
	if sets := conversionField(root, "rule-sets"); sets != nil {
		conversionSet(out, "rule-sets", sets)
	}
	if rules := conversionField(root, "rules"); rules != nil {
		if rules.Kind != yaml.SequenceNode {
			return nil, r, errWebConversionInvalid
		}
		result := conversionSeq()
		for i, n := range rules.Content {
			path := fmt.Sprintf("rules[%d]", i)
			if n.Kind != yaml.ScalarNode {
				c.issue(path + ": expected scalar rule")
				continue
			}
			parts := conversionParts(n.Value)
			if len(parts) > 0 && parts[0] == "RULE-SET" && (len(parts) == 3 || len(parts) == 4 && parts[3] == "no-resolve") {
				p, ok := c.ruleProviders[parts[1]]
				if !ok {
					if conversionField(conversionField(out, "rule-sets"), parts[1]) != nil {
						result.Content = append(result.Content, n)
						continue
					}
					c.issue(path + ": unresolved rule provider")
					continue
				}
				if len(parts) == 4 {
					c.warn(path + ".no-resolve: native inline IP rules do not initiate resolution")
				}
				for j, item := range p.payload.Content {
					itemPath := fmt.Sprintf("%s.payload[%d]", p.path, j)
					if item.Kind != yaml.ScalarNode {
						c.issue(itemPath + ": expected scalar rule")
						continue
					}
					raw := item.Value
					switch p.behavior {
					case "domain":
						kind := "DOMAIN"
						if strings.HasPrefix(raw, "+.") {
							kind = "DOMAIN-SUFFIX"
							raw = strings.TrimPrefix(raw, "+.")
						} else if strings.HasPrefix(raw, "*.") {
							kind = "DOMAIN-SUFFIX"
							raw = strings.TrimPrefix(raw, "*.")
							c.warn(itemPath + ": wildcard becomes suffix including the apex; confirmation required")
						} else if strings.HasPrefix(raw, ".") {
							kind = "DOMAIN-SUFFIX"
							raw = strings.TrimPrefix(raw, ".")
							c.warn(itemPath + ": leading-dot suffix includes the apex; confirmation required")
						}
						raw = kind + "," + raw + "," + parts[2]
					case "ipcidr":
						raw = "IP-CIDR," + raw + "," + parts[2]
					case "classical":
						sub := conversionParts(raw)
						if len(sub) == 3 && sub[2] == "no-resolve" {
							sub = sub[:2]
							c.warn(itemPath + ".no-resolve: native inline IP rules do not initiate resolution")
						}
						if len(sub) != 2 {
							c.issue(itemPath + ": expected TYPE,value without target")
							continue
						}
						raw = strings.Join(sub, ",") + "," + parts[2]
					}
					c.rule(result, raw, itemPath)
				}
			} else {
				c.rule(result, n.Value, path)
			}
		}
		conversionSet(out, "rules", result)
	}
	for i := 0; i < len(root.Content); i += 2 {
		key := root.Content[i].Value
		switch key {
		case "proxies", "proxy-providers", "proxy-groups", "rules", "rule-providers", "rule-sets":
		default:
			c.warn(conversionPublicField(key, i/2) + ": Clash control field is not applicable to native configuration")
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, r, err
	}
	conversionSanitize(out, &r, remote)
	b, e := conversionMarshal(ctx, out)
	if e != nil {
		return nil, r, e
	}
	return b, r, nil
}

// Parse one document, reject duplicate explicit keys, and remove aliases and
// merges by deep-copying nodes, preserving scalar tags and original lexemes.
func conversionParse(input []byte) (*yaml.Node, bool, error) {
	return conversionParseContext(context.Background(), input)
}

func conversionParseContext(ctx context.Context, input []byte) (*yaml.Node, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if int64(len(input)) > snapshotConfigLimit {
		return nil, false, errWebConversionTooLarge
	}
	dec := yaml.NewDecoder(bytes.NewReader(input))
	var doc, extra yaml.Node
	if e := dec.Decode(&doc); e != nil {
		return nil, false, errWebConversionInvalid
	}
	if e := dec.Decode(&extra); e != io.EOF {
		return nil, false, errWebConversionInvalid
	}
	if conversionExpansionCost(ctx, &doc, map[*yaml.Node]bool{}, map[*yaml.Node]int64{}) < 0 {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		return nil, false, errWebConversionInvalid
	}
	changed := false
	n, e := conversionExpand(&doc, map[*yaml.Node]bool{}, &changed)
	if e != nil || len(n.Content) != 1 || n.Content[0].Kind != yaml.MappingNode {
		return nil, false, errWebConversionInvalid
	}
	return n.Content[0], changed, nil
}

func conversionExpand(n *yaml.Node, active map[*yaml.Node]bool, changed *bool) (*yaml.Node, error) {
	if n == nil || active[n] {
		return nil, errWebConversionInvalid
	}
	active[n] = true
	defer delete(active, n)
	if n.Kind == yaml.AliasNode {
		*changed = true
		return conversionExpand(n.Alias, active, changed)
	}
	cp := *n
	cp.Anchor = ""
	cp.Alias = nil
	cp.Content = nil
	if n.Anchor != "" {
		*changed = true
	}
	if n.Kind != yaml.MappingNode {
		for _, child := range n.Content {
			v, e := conversionExpand(child, active, changed)
			if e != nil {
				return nil, e
			}
			cp.Content = append(cp.Content, v)
		}
		return &cp, nil
	}
	explicit := map[string]bool{}
	merged := map[string]bool{}
	var merge *yaml.Node
	for i := 0; i < len(n.Content); i += 2 {
		k, e := conversionExpand(n.Content[i], active, changed)
		if e != nil || k.Kind != yaml.ScalarNode {
			return nil, errWebConversionInvalid
		}
		id := k.Tag + "\x00" + k.Value
		if explicit[id] {
			return nil, errWebConversionInvalid
		}
		explicit[id] = true
		v, e := conversionExpand(n.Content[i+1], active, changed)
		if e != nil {
			return nil, e
		}
		if k.Tag == "!!merge" {
			merge = v
			*changed = true
			continue
		}
		cp.Content = append(cp.Content, k, v)
	}
	if merge != nil {
		sources := []*yaml.Node{merge}
		if merge.Kind == yaml.SequenceNode {
			sources = merge.Content
		}
		for _, src := range sources {
			if src.Kind != yaml.MappingNode {
				return nil, errWebConversionInvalid
			}
			for i := 0; i < len(src.Content); i += 2 {
				k := src.Content[i]
				id := k.Tag + "\x00" + k.Value
				if explicit[id] || merged[id] {
					continue
				}
				merged[id] = true
				cp.Content = append(cp.Content, k, src.Content[i+1])
			}
		}
	}
	return &cp, nil
}

type conversionRuleProvider struct {
	behavior string
	payload  *yaml.Node
	path     string
}
type conversionState struct {
	ctx           context.Context
	fetch         func(context.Context, string) ([]byte, error)
	report        *webConversionReport
	nodes         *yaml.Node
	providers     map[string][]string
	ruleProviders map[string]conversionRuleProvider
}

func (c *conversionState) issue(s string) {
	c.report.Skipped = append(c.report.Skipped, "已跳过 "+s)
}
func (c *conversionState) warn(s string) { c.report.Warnings = append(c.report.Warnings, s) }

func (c *conversionState) addNodes(seq *yaml.Node, path string) {
	if seq == nil || seq.Kind != yaml.SequenceNode {
		c.issue(path + ": expected proxy sequence")
		return
	}
	for i, n := range seq.Content {
		p := fmt.Sprintf("%s[%d]", path, i)
		if n.Kind != yaml.MappingNode {
			c.issue(p + ": expected proxy mapping")
			continue
		}
		typ := conversionText(conversionField(n, "type"))
		if typ != "anytls" {
			c.issue(p + ".type: " + conversionUnsupportedProtocol(typ))
			continue
		}
		start := len(c.report.Skipped)
		next := conversionMap()
		for j := 0; j < len(n.Content); j += 2 {
			key := n.Content[j].Value
			switch key {
			case "name", "type", "server", "port", "password", "udp", "client-fingerprint", "idle-session-check-interval", "idle-session-timeout", "min-idle-session", "skip-cert-verify", "egress-ip", "sni", "disable-sni", "ca", "certificate-public-key-sha256", "fingerprint", "tls-min-version":
				conversionSet(next, key, n.Content[j+1])
			case "servername":
				if conversionField(n, "sni") != nil {
					c.issue(p + ".servername: conflicts with sni")
				} else {
					conversionSet(next, "sni", n.Content[j+1])
				}
			case "icon", "hidden":
				c.warn(p + ": display metadata not retained")
			default:
				c.issue(p + "." + conversionPublicField(key, j/2) + ": unsupported AnyTLS field; entire node removed")
			}
		}
		if len(c.report.Skipped) == start {
			c.nodes.Content = append(c.nodes.Content, next)
		}
	}
}

func (c *conversionState) resource(spec *yaml.Node, path string) []byte {
	start := len(c.report.Skipped)
	if spec == nil || spec.Kind != yaml.MappingNode {
		c.issue(path + ": expected provider mapping")
		return nil
	}
	if conversionText(conversionField(spec, "type")) != "http" {
		c.issue(path + ".type: conversion requires a URL; local resources are not read")
		return nil
	}
	if conversionField(spec, "path") != nil {
		c.warn(path + ".path: HTTP cache path ignored; no local file is read")
	}
	if conversionField(spec, "health-check") != nil {
		c.warn(path + ".health-check: automatic health checks are not retained")
	}
	if conversionField(spec, "interval") != nil {
		c.warn(path + ".interval: provider is captured once; automatic refresh is not retained")
	}
	for i := 0; i < len(spec.Content); i += 2 {
		switch spec.Content[i].Value {
		case "type", "url", "path", "health-check", "interval", "behavior", "format":
		default:
			c.issue(path + "." + conversionPublicField(spec.Content[i].Value, i/2) + ": unsupported provider option")
		}
	}
	if len(c.report.Skipped) != start {
		return nil
	}
	url := conversionText(conversionField(spec, "url"))
	if url == "" || c.fetch == nil {
		c.issue(path + ".url: provider URL unavailable")
		return nil
	}
	data, e := c.fetch(c.ctx, url)
	if e != nil {
		c.issue(path + ".url: provider fetch failed")
		return nil
	}
	return data
}

func (c *conversionState) group(g *yaml.Node, path string) *yaml.Node {
	start := len(c.report.Skipped)
	out := conversionMap()
	if g.Kind != yaml.MappingNode {
		c.issue(path + ": expected group mapping")
		return nil
	}
	kind := conversionText(conversionField(g, "type"))
	switch kind {
	case "select":
	case "url-test", "fallback":
		c.warn(path + ".type: 自动测速/故障切换变为手动选择；需确认")
	default:
		c.issue(path + ".type: unsupported group semantics")
	}
	if n := conversionField(g, "name"); n != nil {
		conversionSet(out, "name", n)
	}
	conversionSet(out, "type", conversionString("select"))
	members := []string{}
	if p := conversionField(g, "proxies"); p != nil {
		if p.Kind != yaml.SequenceNode {
			c.issue(path + ".proxies: expected sequence")
		} else {
			for _, n := range p.Content {
				if n.Kind != yaml.ScalarNode {
					c.issue(path + ".proxies: expected scalar member")
				} else {
					members = append(members, n.Value)
				}
			}
		}
	}
	explicitCount := len(members)
	if use := conversionField(g, "use"); use != nil {
		if use.Kind != yaml.SequenceNode {
			c.issue(path + ".use: expected sequence")
		} else {
			for i, n := range use.Content {
				names, ok := c.providers[n.Value]
				if n.Kind != yaml.ScalarNode || !ok {
					c.issue(fmt.Sprintf("%s.use[%d]: unavailable provider reference", path, i))
					start++ // This drops the reference, not the otherwise valid group.
					continue
				}
				members = append(members, names...)
			}
		}
	}
	for _, key := range []string{"include-all", "include-all-proxies"} {
		if conversionText(conversionField(g, key)) == "true" {
			for _, n := range c.nodes.Content {
				members = append(members, conversionText(conversionField(n, "name")))
			}
		}
	}
	filter := conversionText(conversionField(g, "filter"))
	var re *regexp.Regexp
	if filter != "" {
		var e error
		re, e = regexp.Compile(filter)
		if e != nil {
			c.issue(path + ".filter: invalid regular expression")
		}
	}
	seq := conversionSeq()
	seen := map[string]bool{}
	for i, m := range members {
		if seen[m] || i >= explicitCount && re != nil && !re.MatchString(m) {
			continue
		}
		seen[m] = true
		seq.Content = append(seq.Content, conversionString(m))
	}
	conversionSet(out, "proxies", seq)
	selected := conversionField(g, "selected")
	if selected != nil {
		conversionSet(out, "selected", selected)
	} else if len(seq.Content) > 0 {
		conversionSet(out, "selected", conversionString(seq.Content[0].Value))
	} else {
		c.issue(path + ".proxies: no selectable members")
	}
	for i := 0; i < len(g.Content); i += 2 {
		key := g.Content[i].Value
		switch key {
		case "name", "type", "proxies", "selected", "use", "filter", "include-all", "include-all-proxies":
		case "url", "interval", "lazy", "tolerance", "timeout", "max-failed-times", "hidden", "icon":
			c.warn(path + "." + key + ": selector metadata/automatic behavior not retained")
		default:
			c.issue(path + "." + conversionPublicField(key, i/2) + ": unsupported group option")
		}
	}
	if len(c.report.Skipped) != start {
		return nil
	}
	return out
}

func (c *conversionState) rule(out *yaml.Node, raw, path string) {
	p := conversionParts(raw)
	if supportedGeoIPRule(p) {
		out.Content = append(out.Content, conversionString(strings.Join(p, ",")))
		return
	}
	if len(p) == 4 && p[3] == "no-resolve" && (p[0] == "IP-CIDR" || p[0] == "IP-CIDR6") {
		p = p[:3]
		c.warn(path + ".no-resolve: native inline IP rules do not initiate resolution")
	}
	if len(p) > 0 && p[0] == "IP-CIDR6" {
		p[0] = "IP-CIDR"
	}
	if len(p) == 2 && p[0] == "MATCH" {
		out.Content = append(out.Content, conversionString(strings.Join(p, ",")))
		return
	}
	if len(p) == 3 {
		switch p[0] {
		case "DOMAIN", "DOMAIN-SUFFIX":
			if strings.ContainsAny(p[1], "*?+\r\n	 /,") || p[1] == "" || strings.HasPrefix(p[1], ".") {
				c.issue(path + ": unsupported domain pattern")
				return
			}
			out.Content = append(out.Content, conversionString(strings.Join(p, ",")))
			return
		case "IP-CIDR":
			out.Content = append(out.Content, conversionString(strings.Join(p, ",")))
			return
		}
	}
	c.issue(path + ": unsupported rule type or shape")
}

func conversionRemoteFiles(root *yaml.Node, r *webConversionReport) {
	if n := conversionField(root, "nodes"); n != nil && n.Kind == yaml.SequenceNode {
		for i, item := range n.Content {
			if ca := conversionField(item, "ca"); ca != nil && ca.Value != "" {
				r.Issues = append(r.Issues, fmt.Sprintf("nodes[%d].ca: remote configuration requires a local resource", i))
			}
		}
	}
	if sets := conversionField(root, "rule-sets"); sets != nil && sets.Kind == yaml.MappingNode {
		for i := 0; i < len(sets.Content); i += 2 {
			if path := conversionField(sets.Content[i+1], "path"); path != nil && path.Value != "" {
				r.Issues = append(r.Issues, fmt.Sprintf("rule-sets[%d].path: remote configuration requires a local resource", i/2))
			}
		}
	}
}
func conversionMap() *yaml.Node { return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"} }
func conversionSeq() *yaml.Node { return &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"} }
func conversionString(s string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
}
func conversionText(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}
func conversionField(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}
func conversionSet(n *yaml.Node, key string, v *yaml.Node) {
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			n.Content[i+1] = v
			return
		}
	}
	n.Content = append(n.Content, conversionString(key), v)
}
func conversionParts(s string) []string {
	p := strings.Split(s, ",")
	for i := range p {
		p[i] = strings.TrimSpace(p[i])
	}
	return p
}

// Known protocol labels are public; arbitrary type strings can be credentials.
func conversionUnsupportedProtocol(typ string) string {
	switch typ {
	case "ss", "ssr", "vmess", "vless", "trojan", "hysteria", "hysteria2", "tuic", "wireguard", "socks5", "http", "snell", "direct", "reject":
		return "unsupported protocol " + typ + " (only anytls is supported)"
	}
	return "unsupported protocol (only anytls is supported)"
}

// Unknown keys are potentially credentials too: report only known schema fields.
func conversionPublicField(key string, index int) string {
	switch key {
	case "dns", "tun", "port", "mixed-port", "socks-port", "redir-port", "tproxy-port", "allow-lan", "bind-address", "mode", "log-level", "ipv6", "external-controller", "secret", "external-ui", "profile", "hosts", "sniffer", "routing-mark", "interface-name", "listeners", "exclude-filter", "exclude-type", "include-all-providers", "dialer-proxy", "network", "tls", "alpn", "reality-opts", "fingerprint", "headers", "override", "proxy", "udp-over-tcp", "smux", "tfo", "mptcp":
		return key
	}
	return fmt.Sprintf("fields[%d]", index)
}
