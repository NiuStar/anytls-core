package main

import (
	"errors"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Narrow node form editor: only explicit, unshared node mappings are editable.
// The raw YAML editor remains available for additions/advanced fields. Empty
// password in the form means preserve the secret, never erase it implicitly.
type webNodeEdit struct {
	Name     string `json:"name"`
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	SNI      string `json:"sni"`
}

func webEditNode(b []byte, in webNodeEdit) ([]byte, error) {
	nodes, err := loadNodesBytes(b)
	if err != nil {
		return nil, err
	}
	var current node
	found := false
	for _, n := range nodes {
		if n.Name == in.Name {
			found, current = true, n
			n.Server, n.Port = in.Server, in.Port
			if in.Password != "" {
				n.Password = in.Password
			}
			if !selectable(n) {
				return nil, errors.New("node incomplete")
			}
		}
	}
	if !found {
		return nil, errors.New("node missing")
	}
	var doc yaml.Node
	if yaml.Unmarshal(b, &doc) != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("explicit config mapping required")
	}
	root := doc.Content[0]
	for _, key := range []string{"proxies", "nodes"} {
		sequence := snapshotYAMLField(root, key)
		if sequence == nil {
			continue
		}
		if sequence.Kind != yaml.SequenceNode {
			return nil, errors.New("explicit node sequence required")
		}
		for _, target := range sequence.Content {
			if target.Kind != yaml.MappingNode {
				continue
			}
			name := snapshotYAMLField(target, "name")
			if name == nil || name.Value != in.Name {
				continue
			}
			for i := 0; i < len(target.Content); i += 2 {
				if target.Content[i].Kind != yaml.ScalarNode || target.Content[i].Tag == "!!merge" {
					return nil, errors.New("explicit node keys required")
				}
			}
			if groupChoiceSharedTarget(&doc, root, sequence, target) {
				return nil, errors.New("shared node mapping")
			}
			// Validate every present editable leaf before comparing values: a no-op
			// must not bypass the rejection of aliases or shared scalar anchors.
			values := []struct{ key, old, value, tag string }{
				{"server", current.Server, in.Server, "!!str"},
				{"port", strconv.Itoa(current.Port), strconv.Itoa(in.Port), "!!int"},
				{"sni", current.SNI, in.SNI, "!!str"},
				{"password", current.Password, current.Password, "!!str"},
			}
			if in.Password != "" {
				values[3].value = in.Password
			}
			for _, v := range values {
				leaf := snapshotYAMLField(target, v.key)
				if leaf != nil && (leaf.Kind != yaml.ScalarNode || groupChoiceSharedTarget(&doc, leaf)) {
					return nil, errors.New("shared or indirect node field")
				}
			}
			changed := false
			for _, v := range values {
				if v.old == v.value {
					continue
				}
				leaf := snapshotYAMLField(target, v.key)
				if leaf == nil {
					leaf = &yaml.Node{Kind: yaml.ScalarNode}
					target.Content = append(target.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v.key}, leaf)
				}
				leaf.Tag, leaf.Value = v.tag, v.value
				changed = true
			}
			if !changed {
				return b, nil
			}
			return yaml.Marshal(&doc)
		}
	}
	return nil, errors.New("explicit node not found")
}
