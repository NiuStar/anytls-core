package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"

	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
)

func readYAML(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(b, v)
}

func stageRuleSets(config, root string) error {
	captured, err := readSnapshotSource(filepath.Join(root, "config.yaml"), snapshotConfigLimit, false)
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(captured, &doc); err != nil {
		return err
	}
	var typed struct {
		Sets map[string]fileRuleSet `yaml:"rule-sets"`
	}
	if err := doc.Decode(&typed); err != nil {
		return err
	}
	if len(typed.Sets) == 0 {
		return nil
	}
	if err := snapshotYAMLPlain(&doc); err != nil {
		return err
	}
	sets := snapshotYAMLField(doc.Content[0], "rule-sets")
	if sets == nil || sets.Kind != yaml.MappingNode {
		return errors.New("snapshot rule-sets mapping missing")
	}
	if len(typed.Sets) > snapshotReferenceLimit {
		return errors.New("snapshot has too many rule sets")
	}
	total := 0
	dir := filepath.Join(root, "rules")
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	next := map[string]fileRuleSet{}
	for name, spec := range typed.Sets {
		if strings.ContainsAny(name, "/\\\\\x00") || name == "." || name == ".." {
			return fmt.Errorf("unsafe rule-set name %q", name)
		}
		path := spec.Path
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(config), path)
		}
		b, err := readSnapshotSource(path, snapshotRuleLimit, true)
		if err != nil {
			return err
		}
		if _, err := validateRuleSetBytes(name, spec, b); err != nil {
			return err
		}
		total += len(b)
		if total > snapshotRuleTotalLimit {
			return errors.New("snapshot aggregate rule bytes exceeded")
		}
		if err := writeSnapshotLeaf(filepath.Join(dir, name+".json"), b, 0600); err != nil {
			return err
		}
		spec.Path = "rules/" + name + ".json"
		next[name] = spec
	}
	seen := map[string]bool{}
	for i := 0; i < len(sets.Content); i += 2 {
		var name string
		if err := sets.Content[i].Decode(&name); err != nil {
			return err
		}
		spec, ok := next[name]
		if !ok {
			return errors.New("snapshot rule-set replacement missing")
		}
		if err := snapshotYAMLSetPath(sets.Content[i+1], "path", spec.Path); err != nil {
			return err
		}
		seen[name] = true
	}
	if len(seen) != len(next) {
		return errors.New("snapshot rule-set replacement missing")
	}
	b, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	return replaceSnapshotConfig(root, b)
}

// Snapshot rewrites deliberately fail closed on aliases/merges: editing an
// anchored leaf could also change an unrelated field through a shared alias.
// Ordinary nodes retain their original scalar tag and spelling via yaml.Node.
func snapshotYAMLPlain(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode || n.Tag == "!!merge" {
		return errors.New("snapshot path rewrite does not support YAML aliases or merges")
	}
	if n.Kind == yaml.DocumentNode && (len(n.Content) != 1 || n.Content[0].Kind != yaml.MappingNode) {
		return errors.New("snapshot requires a YAML mapping")
	}
	for _, child := range n.Content {
		if err := snapshotYAMLPlain(child); err != nil {
			return err
		}
	}
	return nil
}

func snapshotYAMLField(n *yaml.Node, key string) *yaml.Node {
	if n.Kind == yaml.MappingNode {
		for i := 0; i < len(n.Content); i += 2 {
			if n.Content[i].Kind == yaml.ScalarNode && n.Content[i].Value == key {
				return n.Content[i+1]
			}
		}
	}
	return nil
}

func snapshotYAMLSetPath(n *yaml.Node, key, path string) error {
	leaf := snapshotYAMLField(n, key)
	if leaf == nil || leaf.Kind != yaml.ScalarNode {
		return errors.New("snapshot path replacement missing scalar")
	}
	leaf.Tag, leaf.Value = "!!str", path
	return nil
}

type proxyGroup struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`
	Proxies  []string `yaml:"proxies"`
	Selected string   `yaml:"selected"`
}
type fileRuleSet struct {
	Path      string `yaml:"path"`
	SHA256    string `yaml:"sha256"`
	ResolveIP bool   `yaml:"resolve-ip,omitempty"`
}

func shaHex(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }

func resolveGroup(name string, nodes []node, groups []proxyGroup) (string, error) {
	terminal, _, err := resolveGroupPath(name, nodes, groups)
	return terminal, err
}

func resolveGroupPath(name string, nodes []node, groups []proxyGroup) (string, []cr.GroupEdge, error) {
	edges := []cr.GroupEdge{}
	seen := map[string]bool{}
	for {
		if name == "DIRECT" || name == "REJECT" {
			return name, edges, nil
		}
		if seen[name] {
			return "", nil, fmt.Errorf("cyclic group %q", name)
		}
		seen[name] = true
		var group *proxyGroup
		for i := range groups {
			if groups[i].Name == name {
				if group != nil {
					return "", nil, fmt.Errorf("duplicate group %q", name)
				}
				group = &groups[i]
			}
		}
		if group == nil {
			n, err := choose(nodes, name)
			if err != nil {
				return "", nil, err
			}
			return n.Name, edges, nil
		}
		for _, n := range nodes {
			if n.Name == name {
				return "", nil, fmt.Errorf("group/node name collision %q", name)
			}
		}
		if group.Type != "select" {
			return "", nil, fmt.Errorf("unsupported group type %q", group.Type)
		}
		if group.Selected == "" {
			return "", nil, fmt.Errorf("group %q needs explicit selected member", name)
		}
		found := false
		for _, p := range group.Proxies {
			if p == group.Selected {
				found = true
			}
		}
		if !found {
			return "", nil, fmt.Errorf("group %q selected member is not in proxies", name)
		}
		edges = append(edges, cr.GroupEdge{Group: name, Selected: group.Selected})
		name = group.Selected
	}
}

func loadRuleSet(config, name string, spec fileRuleSet) (map[string]any, error) {
	if spec.Path == "" || len(spec.SHA256) != 64 {
		return nil, fmt.Errorf("rule-set %q needs path and sha256", name)
	}
	p := spec.Path
	if !filepath.IsAbs(p) {
		p = filepath.Join(filepath.Dir(config), p)
	}
	b, err := readSnapshotSource(p, snapshotRuleLimit, true)
	if err != nil {
		return nil, err
	}
	return validateRuleSetBytes(name, spec, b)
}

func validateRuleSetBytes(name string, spec fileRuleSet, b []byte) (map[string]any, error) {
	if spec.Path == "" || len(spec.SHA256) != 64 {
		return nil, fmt.Errorf("rule-set %q needs path and sha256", name)
	}
	if shaHex(b) != spec.SHA256 {
		return nil, fmt.Errorf("rule-set %q SHA mismatch", name)
	}
	var doc struct {
		Version int               `json:"version"`
		Rules   []json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	if doc.Version != 3 || len(doc.Rules) == 0 {
		return nil, fmt.Errorf("rule-set %q requires version 3 and nonempty rules", name)
	}
	return map[string]any{"type": "inline", "tag": name, "rules": doc.Rules}, nil
}
