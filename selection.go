package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"
)

func selectedPath(config string) string { return config + ".selected" }

func selectable(n node) bool {
	return n.Type == "anytls" && n.Password != "" && n.Server != "" && !strings.ContainsAny(n.Server, " /\t\n") && n.Port > 0 && n.Port <= 65535
}

func selectedNode(config string, nodes []node) (string, error) {
	b, err := os.ReadFile(selectedPath(config))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	name := strings.TrimSuffix(string(b), "\n")
	n, err := choose(nodes, name)
	if err != nil {
		return "", fmt.Errorf("saved selection is stale: %w", err)
	}
	if !selectable(n) {
		return "", fmt.Errorf("saved selection %q is incomplete", name)
	}
	return name, nil
}

func saveSelection(config, name string, nodes []node) error {
	n, err := choose(nodes, name)
	if err != nil {
		return err
	}
	if !selectable(n) {
		return fmt.Errorf("node %q is incomplete (password or fixed IP missing)", name)
	}
	path := selectedPath(config)
	if st, err := os.Lstat(path); err == nil {
		if !st.Mode().IsRegular() {
			return errors.New("selection file is not regular")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".anytls-selection-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.WriteString(name + "\n"); err != nil {
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
	return os.Rename(f.Name(), path)
}

func printNodes(out io.Writer, nodes []node, current string) {
	for _, n := range nodes {
		marker := "  "
		if n.Name == current {
			marker = "* "
		}
		if selectable(n) {
			fmt.Fprintln(out, marker+n.Name+" (anytls, ready)")
		} else if n.Type == "anytls" {
			fmt.Fprintln(out, marker+n.Name+" (anytls, 待补全)")
		} else {
			fmt.Fprintln(out, marker+n.Name+" (unsupported: "+n.Type+")")
		}
	}
}

// readMenuKey consumes one terminal key, including the complete ANSI arrow sequence.
func readMenuKey(r io.Reader) (byte, error) {
	var one [1]byte
	if _, err := io.ReadFull(r, one[:]); err != nil {
		return 0, err
	}
	if one[0] != 27 {
		return one[0], nil
	}
	if _, err := io.ReadFull(r, one[:]); err != nil {
		return 0, err
	}
	if one[0] != '[' && one[0] != 'O' {
		return 0, nil
	}
	if _, err := io.ReadFull(r, one[:]); err != nil {
		return 0, err
	}
	if one[0] == 'A' {
		return 'k', nil
	}
	if one[0] == 'B' {
		return 'j', nil
	}
	return 0, nil
}

func selectMenu(config string, nodes []node, current string, in *os.File, out io.Writer) error {
	if !term.IsTerminal(int(in.Fd())) {
		return errors.New("select requires a terminal; use -node with check/run in scripts")
	}
	options := nodes
	if len(options) == 0 {
		return errors.New("no nodes in config")
	}
	index := 0
	for i, n := range options {
		if n.Name == current {
			index = i
		}
	}
	original, err := term.MakeRaw(int(in.Fd()))
	if err != nil {
		return err
	}
	defer term.Restore(int(in.Fd()), original)
	defer fmt.Fprint(out, "\x1b[?25h\x1b[0m\n")
	fmt.Fprint(out, "\x1b[?25l")
	for {
		fmt.Fprint(out, "\x1b[H\x1b[2J选择 AnyTLS 节点 (↑/↓ 移动，回车/空格选中，q 取消)\r\n")
		for i, n := range options {
			cursor := "  "
			if i == index {
				cursor = "> "
			}
			selected := "  "
			if n.Name == current {
				selected = "✓ "
			}
			status := ""
			if n.Type != "anytls" {
				status = " [不支持，不能选中]"
			} else if !selectable(n) {
				status = " [待补全，不能选中]"
			}
			fmt.Fprintf(out, "%s%s%s  %s:%d%s\r\n", cursor, selected, n.Name, n.Server, n.Port, status)
		}
		key, err := readMenuKey(in)
		if err != nil {
			return err
		}
		switch key {
		case 'j':
			index = (index + 1) % len(options)
		case 'k':
			index = (index + len(options) - 1) % len(options)
		case '\r', '\n', ' ':
			if !selectable(options[index]) {
				continue
			}
			if err := saveSelection(config, options[index].Name, nodes); err != nil {
				return err
			}
			fmt.Fprintf(out, "\x1b[H\x1b[2J已选中: %s\r\n", options[index].Name)
			return nil
		case 'q', 3:
			return nil
		}
	}
}
