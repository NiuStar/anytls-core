package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"
)

// Deletion needs a stronger proof than insertion: each item must be wholly
// contained in its physical line, not a quoted/plain continuation that merely
// decodes to a string without newlines. Never consume YAML comment attachments.
func webRuleDeleteCandidate(old []byte, items []*yaml.Node, at int) ([]byte, error) {
	unsupported := errors.New("RULE_EDIT_UNSUPPORTED")
	lines := bytes.SplitAfter(old, []byte("\n"))
	start, end, offset := 0, 0, 0
	lineOffsets := make([]int, len(lines))
	for i, line := range lines {
		lineOffsets[i] = offset
		offset += len(line)
	}
	for i, item := range items {
		if item.Line < 1 || item.Line > len(lines) {
			return nil, unsupported
		}
		line := lines[item.Line-1]
		var physical yaml.Node
		if yaml.Unmarshal(line, &physical) != nil || len(physical.Content) != 1 {
			return nil, unsupported
		}
		seq := physical.Content[0]
		if seq.Kind != yaml.SequenceNode || seq.Style&yaml.FlowStyle != 0 || len(seq.Content) != 1 {
			return nil, unsupported
		}
		n := seq.Content[0]
		if n.Kind != yaml.ScalarNode || n.Tag != "!!str" || n.Anchor != "" || n.Value != item.Value || n.Style != item.Style {
			return nil, unsupported
		}
		if i == at {
			start = lineOffsets[item.Line-1]
			end = start + len(line)
		}
	}
	candidate := append(bytes.Clone(old[:start]), old[end:]...)
	var doc webRuleDoc
	if yaml.Unmarshal(candidate, &doc) != nil || len(doc.Rules) != len(items)-1 {
		return nil, unsupported
	}
	for i, rule := range doc.Rules {
		original := i
		if i >= at {
			original++
		}
		if rule != items[original].Value {
			return nil, unsupported
		}
	}
	return candidate, nil
}

func (w *webConsole) deleteRule(rw http.ResponseWriter, r *http.Request) {
	// Keep strict duplicate-key handling local; do not change older endpoints'
	// JSON policy. webDecode supplies the existing media type/size/single-value gate.
	var raw json.RawMessage
	if webDecode(rw, r, &raw) != nil {
		webError(rw, 422, "RULE_DELETE_INVALID")
		return
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		webError(rw, 422, "RULE_DELETE_INVALID")
		return
	}
	fields := map[string]json.RawMessage{}
	for dec.More() {
		token, err := dec.Token()
		key, ok := token.(string)
		if err != nil || !ok || fields[key] != nil || key != "index" && key != "rule" && key != "confirm_insecure" {
			webError(rw, 422, "RULE_DELETE_INVALID")
			return
		}
		var value json.RawMessage
		if dec.Decode(&value) != nil || bytes.Equal(value, []byte("null")) {
			webError(rw, 422, "RULE_DELETE_INVALID")
			return
		}
		fields[key] = value
	}
	var index int
	var rule string
	var consent bool
	if json.Unmarshal(fields["index"], &index) != nil || index < 0 || json.Unmarshal(fields["rule"], &rule) != nil || fields["confirm_insecure"] != nil && json.Unmarshal(fields["confirm_insecure"], &consent) != nil {
		webError(rw, 422, "RULE_DELETE_INVALID")
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
	if index >= len(items) || items[index].Value != rule {
		webError(rw, 422, "RULE_DELETE_INVALID")
		return
	}
	if strings.TrimSpace(strings.Split(rule, ",")[0]) == "MATCH" {
		webError(rw, 422, "RULE_DELETE_PROTECTED")
		return
	}
	candidate, err := webRuleDeleteCandidate(old, items, index)
	if err != nil {
		webError(rw, 422, "RULE_EDIT_UNSUPPORTED")
		return
	}
	if webValidateConfig(w.configPath, candidate) != nil {
		webError(rw, 422, "CONFIG_VALIDATION_FAILED")
		return
	}
	// Validate only remaining active sets: deleting a broken RULE-SET is a
	// supported repair, and inactive definitions must not block it.
	var doc webRuleDoc
	if yaml.Unmarshal(candidate, &doc) != nil {
		webError(rw, 422, "CONFIG_VALIDATION_FAILED")
		return
	}
	checked := map[string]bool{}
	for _, remaining := range doc.Rules {
		parts := strings.Split(remaining, ",")
		if len(parts) >= 3 && strings.TrimSpace(parts[0]) == "RULE-SET" {
			label := strings.TrimSpace(parts[1])
			if !checked[label] {
				if webCheckRuleSet(r.Context(), w.configPath, label, doc.Sets[label]) != nil {
					webError(rw, 422, "CONFIG_VALIDATION_FAILED")
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
	if webAtomicWrite(w.configPath, candidate) != nil {
		webError(rw, 500, "CONFIG_WRITE_FAILED")
		return
	}
	readback, err := readSnapshotSource(w.configPath, snapshotConfigLimit, false)
	if err != nil || !bytes.Equal(readback, candidate) {
		webError(rw, 500, "CONFIG_READBACK_FAILED")
		return
	}
	w.finishConfigSave(rw, r, true, `"`+shaHex(readback)+`"`, consent, map[string]any{"deleted": true, "index": index, "rule": rule})
}
