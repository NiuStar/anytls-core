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
)

func readYAML(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(b, v)
}

func stageRuleSets(config, root string) error {
	var doc map[string]any
	if err := readYAML(config, &doc); err != nil {
		return err
	}
	var typed struct {
		Sets map[string]fileRuleSet `yaml:"rule-sets"`
	}
	if err := readYAML(config, &typed); err != nil {
		return err
	}
	if len(typed.Sets) == 0 {
		return nil
	}
	dir := filepath.Join(root, "rules")
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	next := map[string]fileRuleSet{}
	for name, spec := range typed.Sets {
		if strings.ContainsAny(name, "/\\\\\x00") || name == "." || name == ".." {
			return fmt.Errorf("unsafe rule-set name %q", name)
		}
		if _, err := loadRuleSet(config, name, spec); err != nil {
			return err
		}
		path := spec.Path
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(config), path)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if shaHex(b) != spec.SHA256 {
			return fmt.Errorf("rule-set %s changed during staging", name)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".json"), b, 0600); err != nil {
			return err
		}
		spec.Path = "rules/" + name + ".json"
		next[name] = spec
	}
	doc["rule-sets"] = next
	b, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "config.yaml"), b, 0600)
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
	seen := map[string]bool{}
	for {
		if name == "DIRECT" || name == "REJECT" {
			return name, nil
		}
		if seen[name] {
			return "", fmt.Errorf("cyclic group %q", name)
		}
		seen[name] = true
		var group *proxyGroup
		for i := range groups {
			if groups[i].Name == name {
				if group != nil {
					return "", fmt.Errorf("duplicate group %q", name)
				}
				group = &groups[i]
			}
		}
		if group == nil {
			n, err := choose(nodes, name)
			if err != nil {
				return "", err
			}
			return n.Name, nil
		}
		for _, n := range nodes {
			if n.Name == name {
				return "", fmt.Errorf("group/node name collision %q", name)
			}
		}
		if group.Type != "select" {
			return "", fmt.Errorf("unsupported group type %q", group.Type)
		}
		if group.Selected == "" {
			return "", fmt.Errorf("group %q needs explicit selected member", name)
		}
		found := false
		for _, p := range group.Proxies {
			if p == group.Selected {
				found = true
			}
		}
		if !found {
			return "", fmt.Errorf("group %q selected member is not in proxies", name)
		}
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
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 32<<20 {
		return nil, errors.New("rule-set must be regular, at most 32MiB")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
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
