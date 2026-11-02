package engine

import (
	"encoding/json"
	fp "github.com/NiuStar/anytls-core/internal/familypolicy"
)

// browserCapturedPolicy checks an admission-only projection. It does not change
// the runtime JSON/options or expand/replace a compiled rule. The SDK still owns
// first-match ordering and nested rule-set semantics. Only compiler-owned inline
// data has no watcher/reload path (v1.14.3 NewLocalRuleSet's inline branch).
func browserCapturedPolicy(raw []byte, snapshot *fp.Snapshot) bool {
	if browserStaticPolicy(raw) {
		return true
	}
	if !snapshot.Matches(raw) {
		return false
	}
	var root map[string]json.RawMessage
	var route map[string]json.RawMessage
	if json.Unmarshal(raw, &root) != nil || json.Unmarshal(root["route"], &route) != nil {
		return false
	}
	var sets []map[string]json.RawMessage
	if v := route["rule_set"]; v != nil && json.Unmarshal(v, &sets) != nil {
		return false
	}
	tags := map[string]bool{}
	for _, set := range sets {
		if len(set) != 3 {
			return false
		}
		var typ, tag string
		if json.Unmarshal(set["type"], &typ) != nil || typ != "inline" || json.Unmarshal(set["tag"], &tag) != nil || tag == "" || tags[tag] {
			return false
		}
		var rules []map[string]json.RawMessage
		if json.Unmarshal(set["rules"], &rules) != nil || len(rules) == 0 {
			return false
		}
		for _, r := range rules {
			if !browserPureHeadless(r, 0) {
				return false
			}
		}
		tags[tag] = true
	}
	delete(route, "rule_set")
	var rules []map[string]json.RawMessage
	if json.Unmarshal(route["rules"], &rules) != nil {
		return false
	}
	for _, r := range rules {
		encoded, _ := json.Marshal(r)
		if string(encoded) == `{"action":"resolve","server":"secure-dns","strategy":"prefer_ipv4"}` {
			// An exact compiler-owned literal no-op, not arbitrary resolver options.
			for key := range r {
				delete(r, key)
			}
			continue
		}
		if v := r["rule_set"]; v != nil {
			var names []string
			if json.Unmarshal(v, &names) != nil || len(names) == 0 {
				return false
			}
			for _, name := range names {
				if !tags[name] {
					return false
				}
			}
			delete(r, "rule_set")
		}
	}
	route["rules"], _ = json.Marshal(rules)
	root["route"], _ = json.Marshal(route)
	admission, _ := json.Marshal(root)
	return browserStaticPolicy(admission)
}

func browserPureHeadless(r map[string]json.RawMessage, depth int) bool {
	if depth > 16 || len(r) == 0 {
		return false
	}
	var typ string
	if v := r["type"]; v != nil && json.Unmarshal(v, &typ) != nil {
		return false
	}
	if typ == "logical" {
		for k := range r {
			if k != "type" && k != "mode" && k != "rules" && k != "invert" {
				return false
			}
		}
		var mode string
		var rules []map[string]json.RawMessage
		if json.Unmarshal(r["mode"], &mode) != nil || (mode != "and" && mode != "or") || json.Unmarshal(r["rules"], &rules) != nil || len(rules) == 0 {
			return false
		}
		for _, child := range rules {
			if !browserPureHeadless(child, depth+1) {
				return false
			}
		}
		return true
	}
	if typ != "" && typ != "default" {
		return false
	}
	for k := range r {
		switch k {
		case "type", "domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr", "source_ip_cidr", "port", "source_port", "network", "ip_version", "invert":
		default:
			return false
		}
	}
	return true
}
