package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

func groupChoices(config string) ([]proxyGroup, error) {
	var d struct {
		Groups []proxyGroup `yaml:"proxy-groups"`
	}
	err := readYAML(config, &d)
	return d.Groups, err
}
func saveGroupChoice(config, group, choice string) error {
	// Reuse the existing config acquisition policy and limit, but reject final
	// symlinks: rename must not silently replace a link rather than its source.
	// One captured byte slice feeds every parser; no public-path re-read.
	captured, err := readSnapshotSource(config, snapshotConfigLimit, false)
	if err != nil {
		return err
	}
	var doc yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(captured))
	if err := decoder.Decode(&doc); err != nil {
		return err
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return errors.New("group choice requires a YAML mapping")
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return err
		}
		return errors.New("group choice requires a single YAML document")
	}
	nodes, err := loadNodesBytes(captured)
	if err != nil {
		return err
	}
	var typed struct {
		Groups []proxyGroup `yaml:"proxy-groups"`
	}
	// Decode also rejects repeated root and typed group mapping keys.
	if err := doc.Decode(&typed); err != nil {
		return err
	}
	groups := typed.Groups
	index := -1
	for i := range groups {
		if groups[i].Name == group {
			if index != -1 {
				return errors.New("duplicate group")
			}
			index = i
		}
	}
	if index == -1 {
		return errors.New("group not found")
	}
	previous := groups[index].Selected
	groups[index].Selected = choice
	if _, err := resolveGroup(group, nodes, groups); err != nil {
		return err
	}
	root := doc.Content[0]
	sequence := snapshotYAMLField(root, "proxy-groups")
	if sequence == nil || sequence.Kind != yaml.SequenceNode || len(sequence.Content) != len(groups) {
		return errors.New("group choice requires explicit proxy-groups")
	}
	target := sequence.Content[index]
	if target.Kind != yaml.MappingNode {
		return errors.New("group choice requires an explicit group mapping")
	}
	for i := 0; i < len(target.Content); i += 2 {
		if target.Content[i].Tag == "!!merge" {
			return errors.New("group choice does not support a merged target group")
		}
		// The typed decoder resolves alias keys, but the local AST lookup
		// deliberately recognizes explicit scalar keys only. Never append a
		// duplicate selected field when a key is indirect.
		if target.Content[i].Kind != yaml.ScalarNode {
			return errors.New("group choice requires explicit scalar group keys")
		}
	}
	selected := snapshotYAMLField(target, "selected")
	if selected != nil && selected.Kind != yaml.ScalarNode {
		return errors.New("group choice requires an explicit selected scalar")
	}
	// Editing a shared ancestor or leaf would change an unrelated alias too.
	// Walk Content only (not Alias pointers), so unrelated aliases remain valid.
	if groupChoiceSharedTarget(&doc, root, sequence, target, selected) {
		return errors.New("group choice target is shared by a YAML alias")
	}
	if selected != nil && previous == choice {
		return nil
	}
	if selected == nil {
		selected = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str"}
		target.Content = append(target.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "selected"}, selected)
	}
	selected.Tag, selected.Value = "!!str", choice
	b, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(config), ".group-choice-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	n, writeErr := f.Write(b)
	if writeErr != nil || n != len(b) {
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		return errors.Join(writeErr, f.Close())
	}
	if err := f.Sync(); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), config)
}
func groupChoiceSharedTarget(n *yaml.Node, targets ...*yaml.Node) bool {
	if n.Kind == yaml.AliasNode {
		for _, target := range targets {
			if target != nil && n.Alias == target {
				return true
			}
		}
	}
	for _, child := range n.Content {
		if groupChoiceSharedTarget(child, targets...) {
			return true
		}
	}
	return false
}

func pickOption(title string, labels []string, enabled []bool, current int, in *os.File, out io.Writer) (int, error) {
	if len(labels) == 0 {
		return -1, errors.New("empty menu")
	}
	if !term.IsTerminal(int(in.Fd())) {
		return -1, errors.New("terminal required")
	}
	state, err := term.MakeRaw(int(in.Fd()))
	if err != nil {
		return -1, err
	}
	defer term.Restore(int(in.Fd()), state)
	defer fmt.Fprint(out, "\x1b[?25h\r\n")
	cursor := current
	if cursor < 0 || cursor >= len(labels) {
		cursor = 0
	}
	fmt.Fprint(out, "\x1b[?25l")
	for {
		fmt.Fprintf(out, "\x1b[H\x1b[2J%s (↑/↓，回车/空格确认，q 取消)\r\n", title)
		for i, label := range labels {
			a, b := "  ", "  "
			if i == cursor {
				a = "> "
			}
			if i == current {
				b = "✓ "
			}
			fmt.Fprintf(out, "%s%s%s\r\n", a, b, label)
		}
		k, err := readMenuKey(in)
		if err != nil {
			return -1, err
		}
		switch k {
		case 'j':
			cursor = (cursor + 1) % len(labels)
		case 'k':
			cursor = (cursor + len(labels) - 1) % len(labels)
		case '\r', '\n', ' ':
			if enabled[cursor] {
				return cursor, nil
			}
		case 'q', 3:
			return -1, nil
		}
	}
}
func selectGroupMenu(config string, nodes []node, groups []proxyGroup, in *os.File, out io.Writer) error {
	labels := []string{}
	enabled := []bool{}
	for _, g := range groups {
		labels = append(labels, g.Name+" → "+g.Selected)
		enabled = append(enabled, true)
	}
	i, err := pickOption("选择策略组", labels, enabled, -1, in, out)
	if err != nil || i < 0 {
		return err
	}
	g := groups[i]
	labels = nil
	enabled = nil
	current := -1
	for j, name := range g.Proxies {
		ok := name == "DIRECT"
		if !ok {
			n, e := choose(nodes, name)
			ok = e == nil && selectable(n)
		}
		label := name
		if !ok {
			label += " [不支持或待补全]"
		}
		labels = append(labels, label)
		enabled = append(enabled, ok)
		if name == g.Selected {
			current = j
		}
	}
	j, err := pickOption("策略组 "+g.Name, labels, enabled, current, in, out)
	if err != nil || j < 0 {
		return err
	}
	if err := saveGroupChoice(config, g.Name, g.Proxies[j]); err != nil {
		return err
	}
	fmt.Fprintf(out, "已选中: %s → %s（下次启动生效）\n", g.Name, g.Proxies[j])
	return nil
}
