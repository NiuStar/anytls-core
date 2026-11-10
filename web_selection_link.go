package main

import (
	"errors"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"
)

// Only the actual final MATCH target links the startup card. No guessed group
// names, nested traversal or policy/rule rewriting. Dedicated groups stay local.
func defaultSelectionGroup(b []byte) (*proxyGroup, []proxyGroup, error) {
	return defaultSelectionGroupDecode(func(v any) error { return yaml.Unmarshal(b, v) })
}

func defaultSelectionGroupDecode(decode func(any) error) (*proxyGroup, []proxyGroup, error) {
	var doc struct {
		Rules  []string     `yaml:"rules"`
		Groups []proxyGroup `yaml:"proxy-groups"`
	}
	if err := decode(&doc); err != nil {
		return nil, nil, err
	}
	if len(doc.Rules) == 0 {
		return nil, doc.Groups, nil
	}
	parts := strings.Split(doc.Rules[len(doc.Rules)-1], ",")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) != "MATCH" {
		return nil, doc.Groups, nil
	}
	target := strings.TrimSpace(parts[1])
	if target == "DIRECT" || target == "REJECT" {
		return nil, doc.Groups, nil
	}
	var found *proxyGroup
	for i := range doc.Groups {
		if doc.Groups[i].Name == target {
			if found != nil {
				return nil, nil, errors.New("duplicate default group")
			}
			found = &doc.Groups[i]
		}
	}
	return found, doc.Groups, nil
}

func concreteSelection(name string, nodes []node, groups []proxyGroup) bool {
	if name == "" || name == "DIRECT" || name == "REJECT" {
		return false
	}
	for _, g := range groups {
		if g.Name == name {
			return false
		}
	}
	n, err := choose(nodes, name)
	return err == nil && selectable(n)
}

// Startup/DNS identity and the default group's direct choice are independent
// facts. Never hide a retained .selected mismatch or normalize it on a GET.
func effectiveWebSelection(config string, _ []byte, nodes []node) string {
	selected, _ := selectedNode(config, nodes)
	return selected
}

// Only a direct final MATCH select group participates in card linkage. A nested
// current choice is deliberately not flattened, and explicit MATCH node/DIRECT
// rules remain outside this contract. Reuse the actual editor to avoid offering
// repairs for nonmembers, alias/merge targets or unsupported group edits.
func webSelectionLinkState(b []byte, nodes []node, startup string) (defaultSelected string, linked bool, needsSync map[string]bool) {
	return webSelectionLinkStateDecode(b, nodes, startup, func(v any) error { return yaml.Unmarshal(b, v) })
}

func webSelectionLinkStateDecode(b []byte, nodes []node, startup string, decode func(any) error) (defaultSelected string, linked bool, needsSync map[string]bool) {
	needsSync = make(map[string]bool)
	group, groups, err := defaultSelectionGroupDecode(decode)
	if err != nil || group == nil || group.Type != "select" {
		return
	}
	for _, g := range groups {
		if g.Name == group.Selected {
			return
		}
	}
	if concreteSelection(group.Selected, nodes, groups) {
		for _, member := range group.Proxies {
			if member == group.Selected {
				defaultSelected = group.Selected
				linked = startup == defaultSelected
				break
			}
		}
	}
	if linked {
		return
	}
	// Structural editability is shared by every concrete member; validate once,
	// not by reparsing/marshalling the full profile once per card.
	editable := false
	for _, member := range group.Proxies {
		if !concreteSelection(member, nodes, groups) {
			continue
		}
		if !editable {
			if _, err := groupChoiceBytes(b, group.Name, member); err != nil {
				return
			}
			editable = true
		}
		needsSync[member] = true
	}
	return
}

// The authenticated router holds actionMu through validation, commit and the
// existing finishConfigSave. Legacy clients may omit If-Match; supplied ETags
// always fence the captured config, and commit fences both captured files.
func (w *webConsole) saveLinkedSelection(rw http.ResponseWriter, r *http.Request, group, choice string, consent bool) {
	old, err := w.profileFiles()
	if err != nil {
		if group == "" {
			webError(rw, 422, "NODE_SELECTION_REJECTED")
		} else {
			webError(rw, 503, "SELECTION_STORE_UNAVAILABLE")
		}
		return
	}
	if match := r.Header.Get("If-Match"); match != "" && match != `"`+shaHex(old[0].data)+`"` {
		webError(rw, 412, "CONFIG_CONFLICT")
		return
	}
	candidate := old[0].data
	nodes, err := loadNodesBytes(candidate)
	if err != nil {
		webError(rw, 422, "CONFIG_INVALID")
		return
	}
	defaultGroup, groups, err := defaultSelectionGroup(candidate)
	if err != nil {
		webError(rw, 422, "NODE_SELECTION_REJECTED")
		return
	}
	selection := ""
	if group == "" {
		if !concreteSelection(choice, nodes, groups) {
			webError(rw, 422, "NODE_SELECTION_REJECTED")
			return
		}
		selection = choice
		if defaultGroup != nil {
			// Do not flatten a nested policy or insert arbitrary membership. Explicit
			// DIRECT in this select group may be replaced by this user-chosen member.
			nested := false
			for _, g := range groups {
				if g.Name == defaultGroup.Selected {
					nested = true
				}
			}
			if nested {
				webError(rw, 422, "NODE_SELECTION_REJECTED")
				return
			}
			candidate, err = groupChoiceBytes(candidate, defaultGroup.Name, choice)
		}
	} else {
		candidate, err = groupChoiceBytes(candidate, group, choice)
		if defaultGroup != nil && group == defaultGroup.Name && concreteSelection(choice, nodes, groups) {
			selection = choice
		}
	}
	if err != nil || webValidateConfig(w.configPath, candidate) != nil {
		webError(rw, 422, "SELECTION_REJECTED")
		return
	}
	target := append([]webProfileFile(nil), old...)
	// Target identity is intentionally unbound: commit verifies exact bytes and
	// presence after publishing new inodes, while old keeps its CAS identities.
	for i := range target {
		target[i].info = nil
	}
	target[0].data = candidate
	if selection != "" {
		target[1].data = []byte(selection + "\n")
		target[1].exists = true
	}
	code := w.commitProfileFiles(target, old, func() bool { return true }, webAtomicWrite)
	if code != "" {
		status := 500
		if code == "PROFILE_CONFLICT" {
			status = 412
		}
		if code == "PROFILE_STORE_UNAVAILABLE" {
			status = 503
		}
		webError(rw, status, code)
		return
	}
	changed := !webProfileEqual(old[:2], target[:2])
	// A no-op must still have passed CAS and readback in the shared helper.
	w.finishSelectionSave(rw, r, changed, `"`+shaHex(candidate)+`"`, consent)
}
