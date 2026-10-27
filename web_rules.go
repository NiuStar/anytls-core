package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/NiuStar/anytls-core/internal/engine"
	"gopkg.in/yaml.v3"
)

// A single captured config supplies the public inventory and its version.
type webRuleDoc struct {
	Rules  []string               `yaml:"rules"`
	Groups []proxyGroup           `yaml:"proxy-groups"`
	Sets   map[string]fileRuleSet `yaml:"rule-sets"`
}

func webRuleToken(s string) bool {
	return s != "" && s == strings.TrimSpace(s) && !strings.ContainsAny(s, ",\r\n\x00")
}
func webRuleTargets(b []byte, doc webRuleDoc) []string {
	targets := []string{"DIRECT", "REJECT"}
	nodes, err := loadNodesBytes(b)
	if err != nil {
		return targets
	}
	names := []string{}
	for _, n := range nodes {
		names = append(names, n.Name)
	}
	for _, g := range doc.Groups {
		names = append(names, g.Name)
	}
	seen := map[string]bool{"DIRECT": true, "REJECT": true}
	for _, name := range names {
		if seen[name] || !webRuleToken(name) {
			continue
		}
		terminal, _, err := resolveGroupPath(name, nodes, doc.Groups)
		if err != nil {
			continue
		}
		if terminal != "DIRECT" && terminal != "REJECT" {
			n, e := choose(nodes, terminal)
			if e != nil {
				continue
			}
			if _, e = buildNode(n, "proxy", 11080, true); e != nil {
				continue
			}
		}
		seen[name] = true
		targets = append(targets, name)
	}
	return targets
}

// A matching digest only authenticates bytes, not SDK rule semantics. Construct
// and close a real, listener-free Box before advertising or activating a set.
func webCheckRuleSet(ctx context.Context, path, label string, spec fileRuleSet) error {
	set, err := loadRuleSet(path, label, spec)
	if err != nil {
		return err
	}
	config := map[string]any{
		"log":       map[string]any{"disabled": true},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"rule_set": []any{set}, "rules": []any{map[string]any{"rule_set": []string{label}, "outbound": "direct"}}, "final": "direct"},
	}
	raw, err := json.Marshal(config)
	if err != nil {
		return err
	}
	return engine.Check(ctx, raw)
}
func (w *webConsole) getRules(rw http.ResponseWriter, r *http.Request) {
	b, err := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
	if err != nil {
		webError(rw, 500, "CONFIG_UNAVAILABLE")
		return
	}
	var doc webRuleDoc
	if yaml.Unmarshal(b, &doc) != nil {
		webError(rw, 422, "CONFIG_INVALID")
		return
	}
	if doc.Rules == nil {
		doc.Rules = []string{}
	}
	sets := []string{}
	for label, spec := range doc.Sets {
		if webRuleToken(label) {
			if e := webCheckRuleSet(r.Context(), w.configPath, label, spec); e == nil {
				sets = append(sets, label)
			}
		}
	}
	sort.Strings(sets)
	_, editErr := webRuleLayout(b)
	etag := `"` + shaHex(b) + `"`
	rw.Header().Set("ETag", etag)
	webJSON(rw, 200, map[string]any{"rules": doc.Rules, "etag": etag, "targets": webRuleTargets(b, doc), "rule_sets": sets, "editable": editErr == nil, "edit_error": func() string {
		if editErr != nil {
			return "RULE_EDIT_UNSUPPORTED"
		}
		return ""
	}()})
}

var webRuleLine = regexp.MustCompile(`^( *)-[ \t]+`)

// No YAML round trip: edits are one byte insertion at a verified block item.
// Unrelated anchors, comments, unknown fields and scalar spelling stay untouched.
func webRuleLayout(b []byte) ([]*yaml.Node, error) {
	unsupported := errors.New("RULE_EDIT_UNSUPPORTED")
	var root yaml.Node
	if yaml.Unmarshal(b, &root) != nil || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, unsupported
	}
	var rules *yaml.Node
	top := root.Content[0]
	for i := 0; i < len(top.Content); i += 2 {
		k, v := top.Content[i], top.Content[i+1]
		if k.Kind != yaml.ScalarNode || k.Tag == "!!merge" {
			return nil, unsupported
		}
		if k.Value == "rules" {
			if rules != nil {
				return nil, unsupported
			}
			rules = v
		}
	}
	if rules == nil || rules.Kind != yaml.SequenceNode || rules.Style&yaml.FlowStyle != 0 || rules.Anchor != "" || len(rules.Content) == 0 {
		return nil, unsupported
	}
	lines := bytes.Split(b, []byte("\n"))
	indent := ""
	for i, n := range rules.Content {
		if n.Kind != yaml.ScalarNode || n.Tag != "!!str" || n.Anchor != "" || n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 || strings.ContainsAny(n.Value, "\r\n\x00") || n.Line < 1 || n.Line > len(lines) {
			return nil, unsupported
		}
		match := webRuleLine.FindSubmatch(lines[n.Line-1])
		if match == nil {
			return nil, unsupported
		}
		if i == 0 {
			indent = string(match[1])
		} else if indent != string(match[1]) {
			return nil, unsupported
		}
		parts := strings.Split(n.Value, ",")
		if strings.TrimSpace(parts[0]) == "MATCH" && (i != len(rules.Content)-1 || len(parts) != 2) {
			return nil, unsupported
		}
	}
	last := strings.Split(rules.Content[len(rules.Content)-1].Value, ",")
	if len(last) != 2 || strings.TrimSpace(last[0]) != "MATCH" {
		return nil, unsupported
	}
	return rules.Content, nil
}
func canonicalWebRule(s string) string {
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return strings.Join(parts, ",")
}
func (w *webConsole) addRule(rw http.ResponseWriter, r *http.Request) {
	var fields map[string]json.RawMessage
	if webDecode(rw, r, &fields) != nil || fields == nil {
		webError(rw, 422, "RULE_INVALID_INPUT")
		return
	}
	allowed := map[string]bool{"type": true, "value": true, "target": true, "no_resolve": true, "position": true, "index": true, "confirm_insecure": true}
	for k := range fields {
		if !allowed[k] {
			webError(rw, 422, "RULE_INVALID_INPUT")
			return
		}
	}
	var kind, value, target, position string
	var noResolve, consent bool
	var index *int
	decode := func(key string, dst any, required bool) bool {
		raw, ok := fields[key]
		if !ok {
			return !required
		}
		return string(raw) != "null" && json.Unmarshal(raw, dst) == nil
	}
	if !decode("type", &kind, true) || !decode("value", &value, true) || !decode("target", &target, true) || !decode("no_resolve", &noResolve, true) || !decode("position", &position, true) || !decode("confirm_insecure", &consent, false) {
		webError(rw, 422, "RULE_INVALID_INPUT")
		return
	}
	if raw, ok := fields["index"]; ok && string(raw) != "null" {
		if json.Unmarshal(raw, &index) != nil {
			webError(rw, 422, "RULE_POSITION_INVALID")
			return
		}
	}
	if position != "first" && position != "before_match" && position != "index" || (position == "index") != (index != nil) {
		webError(rw, 422, "RULE_POSITION_INVALID")
		return
	}
	if !webRuleToken(value) || !webRuleToken(target) || !map[string]bool{"DOMAIN": true, "DOMAIN-SUFFIX": true, "IP-CIDR": true, "GEOIP": true, "RULE-SET": true}[kind] || noResolve && kind != "GEOIP" && kind != "RULE-SET" || kind == "GEOIP" && value != "CN" {
		webError(rw, 422, "RULE_INVALID_INPUT")
		return
	}
	if len(r.Header.Values("If-Match")) != 1 || r.Header.Get("If-Match") == "" {
		webError(rw, 428, "IF_MATCH_REQUIRED")
		return
	}
	old, err := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
	if err != nil {
		webError(rw, 500, "CONFIG_UNAVAILABLE")
		return
	}
	if r.Header.Get("If-Match") != `"`+shaHex(old)+`"` {
		webError(rw, 412, "CONFIG_CONFLICT")
		return
	}
	items, err := webRuleLayout(old)
	if err != nil {
		webError(rw, 422, "RULE_EDIT_UNSUPPORTED")
		return
	}
	at := len(items) - 1
	if position == "first" {
		at = 0
	}
	if index != nil {
		at = *index
	}
	if at < 0 || at >= len(items) {
		webError(rw, 422, "RULE_POSITION_INVALID")
		return
	}
	var doc webRuleDoc
	if yaml.Unmarshal(old, &doc) != nil {
		webError(rw, 422, "CONFIG_INVALID")
		return
	}
	validTarget := false
	for _, name := range webRuleTargets(old, doc) {
		validTarget = validTarget || name == target
	}
	if !validTarget {
		webError(rw, 422, "RULE_TARGET_INVALID")
		return
	}
	if kind == "RULE-SET" {
		spec, ok := doc.Sets[value]
		if !ok {
			webError(rw, 422, "RULE_VALUE_INVALID")
			return
		}
		if e := webCheckRuleSet(r.Context(), w.configPath, value, spec); e != nil {
			webError(rw, 422, "RULE_VALUE_INVALID")
			return
		}
	}
	rule := kind + "," + value + "," + target
	if noResolve {
		rule += ",no-resolve"
	}
	changed := true
	for i, n := range items {
		if canonicalWebRule(n.Value) == rule {
			changed = false
			at = i
			break
		}
	}
	candidate := old
	if changed {
		offset := 0
		for line := 1; line < items[at].Line; line++ {
			j := bytes.IndexByte(old[offset:], '\n')
			if j < 0 {
				webError(rw, 422, "RULE_EDIT_UNSUPPORTED")
				return
			}
			offset += j + 1
		}
		end := bytes.IndexByte(old[offset:], '\n')
		newline := "\n"
		if (end >= 0 && end > 0 && old[offset+end-1] == '\r') || (end < 0 && offset >= 2 && bytes.Equal(old[offset-2:offset], []byte("\r\n"))) {
			newline = "\r\n"
		}
		prefix := webRuleLine.FindSubmatch(old[offset:])[1]
		insert := string(prefix) + "- '" + strings.ReplaceAll(rule, "'", "''") + "'" + newline
		candidate = append(bytes.Clone(old[:offset]), []byte(insert)...)
		candidate = append(candidate, old[offset:]...)
	}
	if webValidateConfig(w.configPath, candidate) != nil {
		webError(rw, 422, "RULE_VALUE_INVALID")
		return
	}
	// Existing activated sets must pass the same native gate even when this new
	// rule is not a RULE-SET. Never publish a config that activates invalid SDK data.
	checked := map[string]bool{}
	if kind == "RULE-SET" {
		checked[value] = true
	}
	for _, existing := range doc.Rules {
		parts := strings.Split(existing, ",")
		if len(parts) >= 3 && strings.TrimSpace(parts[0]) == "RULE-SET" {
			label := strings.TrimSpace(parts[1])
			if !checked[label] {
				if e := webCheckRuleSet(r.Context(), w.configPath, label, doc.Sets[label]); e != nil {
					webError(rw, 422, "RULE_VALUE_INVALID")
					return
				}
				checked[label] = true
			}
		}
	}
	latest, err := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
	if err != nil || !bytes.Equal(latest, old) {
		webError(rw, 412, "CONFIG_CONFLICT")
		return
	}
	if changed && webAtomicWrite(w.configPath, candidate) != nil {
		webError(rw, 500, "CONFIG_WRITE_FAILED")
		return
	}
	readback, err := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
	if err != nil || !bytes.Equal(readback, candidate) {
		webError(rw, 500, "CONFIG_READBACK_FAILED")
		return
	}
	w.finishConfigSave(rw, r, changed, `"`+shaHex(readback)+`"`, consent, map[string]any{"inserted": changed, "index": at, "rule": rule})
}
