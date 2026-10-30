package main

import (
	"bytes"
	"errors"
	"strings"

	"gopkg.in/yaml.v3"
)

// Frozen at 5be5a6441858dd286a4e857affeae8858211ec3f from web_rules.go.
// Exact copies with function names only changed, including the internal layout
// call. Never route this independent old oracle through a candidate AST helper.
func oldWebRulesASTProjection(b []byte, listOnly bool, supplyOptions func(webRuleDoc) ([]string, []string)) (map[string]any, error) {
	var doc webRuleDoc
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	if doc.Rules == nil {
		doc.Rules = []string{}
	}
	_, editErr := oldWebRulesASTLayout(b)
	etag := `"` + shaHex(b) + `"`
	projection := map[string]any{"rules": doc.Rules, "etag": etag, "editable": editErr == nil, "edit_error": func() string {
		if editErr != nil {
			return "RULE_EDIT_UNSUPPORTED"
		}
		return ""
	}()}
	if listOnly {
		projection["view"], projection["options_loaded"] = "list", false
		return projection, nil
	}
	projection["targets"], projection["rule_sets"] = supplyOptions(doc)
	return projection, nil
}

func oldWebRulesASTLayout(b []byte) ([]*yaml.Node, error) {
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
