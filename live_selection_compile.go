package main

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

type livePlan struct {
	Nodes   map[string]string
	Initial string
}

// compileLiveSelection never expands the pre-established server route scope.
// A member outside that scope is cold (RELOAD_REQUIRED). All immutable leaves
// are constructed before Box.Start; fixed node/dedicated routes are untouched.
func compileLiveSelection(raw []byte, nodes []node, selected node, cfg map[string]any, allow bool) (*livePlan, error) {
	group, groups, e := defaultSelectionGroup(raw)
	if e != nil {
		return nil, e
	}
	members := make([]string, 0, len(nodes))
	for _, n := range nodes {
		members = append(members, n.Name)
	}
	if group != nil {
		if group.Type != "select" || group.Selected != selected.Name {
			return nil, errors.New("selection not linked")
		}
		members = group.Proxies
	}
	for _, g := range groups {
		if g.Name == selected.Name {
			return nil, errors.New("nested selection")
		}
	}
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	mode := "proxy"
	if in["type"] == "tun" {
		mode = "tun"
	}
	originals := cfg["outbounds"].([]any)
	// Reuse only the private warm leaf for this member, never a fixed-rule
	// outbound even when its dial options happen to be identical.
	byTag := make(map[string]map[string]any, len(originals))
	servers := map[string]bool{}
	cas := map[string]bool{"": true}
	for _, r := range originals {
		o := r.(map[string]any)
		byTag[o["tag"].(string)] = o
		if o["type"] == "anytls" {
			servers[o["server"].(string)] = true
			tls := o["tls"].(map[string]any)
			path, _ := tls["certificate_path"].(string)
			cas[path] = true
		}
	}
	plan := &livePlan{Nodes: map[string]string{}}
	outbounds := append([]any(nil), originals...)
	tags := []string{}
	for i, name := range members {
		n, e := choose(nodes, name)
		if e != nil || !selectable(n) || n.SkipVerify || !servers[n.Server] {
			continue
		}
		built, e := buildNode(n, mode, 11080, allow)
		if e != nil {
			continue
		}
		out := built["outbounds"].([]any)[0].(map[string]any)
		path, _ := out["tls"].(map[string]any)["certificate_path"].(string)
		if !cas[path] {
			continue
		}
		tag := fmt.Sprintf("warm-%d", i)
		out["tag"] = tag
		if mode != "tun" || !reflect.DeepEqual(byTag[tag], out) {
			// Proxy mode and non-warm callers retain their existing leaf path.
			tag = fmt.Sprintf("live-leaf-%d", len(tags))
			out["tag"] = tag
			outbounds = append(outbounds, out)
		}
		tags = append(tags, tag)
		plan.Nodes[name] = tag
		if name == selected.Name {
			plan.Initial = tag
		}
	}
	if plan.Initial == "" || len(tags) > 256 {
		return nil, errors.New("selection not admitted")
	}
	// Route indexes include synthetic sniff/hijack/resolve rules. Associate only
	// actual action=route entries with their configured source rule in order.
	var doc struct {
		Rules []string `yaml:"rules"`
	}
	if yaml.Unmarshal(raw, &doc) != nil {
		return nil, errors.New("invalid routing")
	}
	routes := cfg["route"].(map[string]any)
	compiled, _ := routes["rules"].([]any)
	cursor := 0
	for _, rawRule := range doc.Rules {
		parts := strings.Split(rawRule, ",")
		kind := strings.TrimSpace(parts[0])
		target := strings.TrimSpace(parts[len(parts)-1])
		if target == "no-resolve" {
			target = strings.TrimSpace(parts[len(parts)-2])
		}
		dynamic := group != nil && target == group.Name
		if kind == "MATCH" {
			if dynamic {
				routes["final"] = "live"
			}
			continue
		}
		for cursor < len(compiled) {
			r := compiled[cursor].(map[string]any)
			cursor++
			if r["action"] == "route" || r["action"] == "reject" {
				if dynamic && r["action"] == "route" {
					r["outbound"] = "live"
				}
				break
			}
		}
	}
	if len(doc.Rules) == 0 {
		routes["final"] = "live"
	}
	if dns, ok := cfg["dns"].(map[string]any); ok {
		// Cache namespaces are isolated by the live transport's Environment epoch;
		// pre-switch operations cannot repopulate the post-switch namespace.
		for _, v := range dns["servers"].([]any) {
			s := v.(map[string]any)
			if s["detour"] == "anytls-out" {
				s["detour"] = "live"
			}
		}
	}
	cfg["outbounds"] = append(outbounds, map[string]any{"type": "anytls-selection", "tag": "live", "outbounds": tags, "default": plan.Initial})
	return plan, nil
}

// Comparison is semantic and closed to every change except the startup node
// and the one direct final MATCH group's selected field. Dedicated policies,
// node/TLS/password fields and rules remain byte-decoded equivalent.
func selectionOnlyChange(old, oldSelected, next, nextSelected []byte) (string, error) {
	var a, b map[string]any
	if yaml.Unmarshal(old, &a) != nil || yaml.Unmarshal(next, &b) != nil {
		return "", errors.New("invalid config")
	}
	nodes, e := loadNodesBytes(old)
	if e != nil {
		return "", e
	}
	oldName, e := selectedBytes(oldSelected, nodes)
	if e != nil {
		return "", e
	}
	name, e := selectedBytes(nextSelected, nodes)
	if e != nil {
		return "", e
	}
	group, _, e := defaultSelectionGroup(old)
	if e != nil {
		return "", e
	}
	if group != nil {
		if group.Type != "select" || !slices.Contains(group.Proxies, name) {
			return "", errors.New("not a direct member")
		}
		for _, v := range []map[string]any{a, b} {
			list, ok := v["proxy-groups"].([]any)
			if !ok {
				return "", errors.New("invalid groups")
			}
			found := false
			for _, entry := range list {
				g, ok := entry.(map[string]any)
				if !ok {
					return "", errors.New("invalid group")
				}
				if g["name"] == group.Name {
					if found {
						return "", errors.New("duplicate group")
					}
					found = true
					if v == nil {
						return "", errors.New("invalid config")
					}
					delete(g, "selected")
				}
			}
			if !found {
				return "", errors.New("missing group")
			}
		}
		ng, _, e := defaultSelectionGroup(next)
		if e != nil || ng == nil || ng.Selected != name {
			return "", errors.New("selection not linked")
		}
	}
	if oldName == "" || !reflect.DeepEqual(a, b) {
		return "", errors.New("reload required: nonselection change")
	}
	return name, nil
}
func liveSourceEligible(raw []byte) bool {
	var doc struct {
		Sets      map[string]any `yaml:"rule-sets"`
		Providers map[string]any `yaml:"rule-providers"`
	}
	if yaml.Unmarshal(raw, &doc) != nil || len(doc.Providers) > 0 {
		return false
	}
	nodes, e := loadNodesBytes(raw)
	if e != nil {
		return false
	}
	for _, n := range nodes {
		if n.SkipVerify {
			return false
		}
	}
	return true
}
