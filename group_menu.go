package main

import (
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
	var d map[string]any
	if err := readYAML(config, &d); err != nil {
		return err
	}
	groups, err := groupChoices(config)
	if err != nil {
		return err
	}
	nodes, err := loadNodes(config)
	if err != nil {
		return err
	}
	found := false
	for i := range groups {
		if groups[i].Name == group {
			groups[i].Selected = choice
			found = true
		}
	}
	if !found {
		return errors.New("group not found")
	}
	if _, err := resolveGroup(group, nodes, groups); err != nil {
		return err
	}
	d["proxy-groups"] = groups
	b, err := yaml.Marshal(d)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(config), ".group-choice-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), config)
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
