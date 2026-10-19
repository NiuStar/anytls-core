package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSelectionRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	nodes := []node{{Name: "a", Type: "anytls", Server: "127.0.0.1", Port: 443, Password: "a"}, {Name: "b", Type: "anytls", Server: "127.0.0.2", Port: 444, Password: "b"}, {Name: "c", Type: "ss"}}
	s, err := selectedNode(p, nodes)
	if err != nil || s != "" {
		t.Fatalf("initial: %q %v", s, err)
	}
	if err := saveSelection(p, "b", nodes); err != nil {
		t.Fatal(err)
	}
	s, err = selectedNode(p, nodes)
	if err != nil || s != "b" {
		t.Fatalf("selected: %q %v", s, err)
	}
	info, err := os.Stat(selectedPath(p))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("permissions: %v %v", info, err)
	}
	var out bytes.Buffer
	printNodes(&out, nodes, s)
	if !strings.Contains(out.String(), "* b (anytls, ready)") || !strings.Contains(out.String(), "unsupported: ss") {
		t.Fatal(out.String())
	}
	if err := saveSelection(p, "c", nodes); err == nil {
		t.Fatal("unsupported node accepted")
	}
	if err := os.WriteFile(selectedPath(p), []byte("deleted\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := selectedNode(p, nodes); err == nil {
		t.Fatal("stale selected node accepted")
	}
}

func TestIncompleteNodeIsVisibleButNotSelectable(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	nodes := []node{{Name: "pending", Type: "anytls", Server: "127.0.0.1", Port: 443}, {Name: "ready", Type: "anytls", Server: "127.0.0.2", Port: 444, Password: "test"}}
	var out bytes.Buffer
	printNodes(&out, nodes, "ready")
	if !strings.Contains(out.String(), "pending (anytls, 待补全)") {
		t.Fatal(out.String())
	}
	if err := saveSelection(p, "pending", nodes); err == nil {
		t.Fatal("missing credential accepted")
	}
	if err := saveSelection(p, "ready", nodes); err != nil {
		t.Fatal(err)
	}
}

func TestArrowAndSelectionKeys(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want byte
	}{{"\x1b[A", 'k'}, {"\x1b[B", 'j'}, {"\x1bOA", 'k'}, {"\x1bOB", 'j'}, {" ", ' '}, {"\r", '\r'}} {
		got, err := readMenuKey(strings.NewReader(tc.in))
		if err != nil || got != tc.want {
			t.Fatalf("%q -> %q %v", tc.in, got, err)
		}
	}
}
