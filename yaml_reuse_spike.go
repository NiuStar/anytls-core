package main

import "gopkg.in/yaml.v3"

// Optional hot selection only: failures decline capability, not cold startup.
func liveSourceEligibleStage(raw []byte) bool {
	var ast yaml.Node
	if yaml.Unmarshal(raw, &ast) != nil {
		return false
	}
	var doc struct {
		Sets      map[string]any `yaml:"rule-sets"`
		Providers map[string]any `yaml:"rule-providers"`
	}
	if ast.Decode(&doc) != nil || len(doc.Providers) > 0 {
		return false
	}
	nodes, e := loadNodesDecode(ast.Decode)
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
