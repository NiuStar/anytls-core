package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

// These tests use only the released API so the same bytes can run on 0fed67f.
func groupSaveFixture(t *testing.T, source string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func groupSaveDocument(t *testing.T, b []byte) *yaml.Node {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return &doc
}

func groupSaveField(n *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// Ignore encoder layout, NOT tags, lexemes, ordering or comment attachment.
func groupSaveAST(n *yaml.Node) any {
	children := make([]any, len(n.Content))
	for i, child := range n.Content {
		children[i] = groupSaveAST(child)
	}
	return struct {
		Kind                                 yaml.Kind
		Tag, Value, Anchor, Head, Line, Foot string
		Children                             []any
	}{n.Kind, n.Tag, n.Value, n.Anchor, n.HeadComment, n.LineComment, n.FootComment, children}
}

func TestSaveGroupChoiceTargetedPreservesYAML(t *testing.T) {
	source := `# configuration head
x-root: {code: 00123, enabled: true}
x-anchor: &ordinary {opaque: 00123}
x-alias: *ordinary
proxies:
  - name: 00123 # numeric name
    type: anytls
    server: 203.0.113.1
    port: 443
    password: 00123 # numeric password
    x-node: {future: yes}
  - {name: true, type: anytls, password: true}
proxy-groups:
  - name: false
    type: select
    proxies: [DIRECT, 00123, true]
    selected: 00123 # selection comment
    x-group: {future: [z, a]}
  - {name: other, type: select, proxies: [true, DIRECT], selected: DIRECT, extra: 00123}
rules:
  - DOMAIN,example.org,true # first rule
  - MATCH,other
`
	p := groupSaveFixture(t, source)
	bootstrap := selectedPath(p)
	if err := os.WriteFile(bootstrap, []byte("00123\n"), 0600); err != nil {
		t.Fatal(err)
	}
	before := groupSaveDocument(t, []byte(source))
	groups := groupSaveField(before.Content[0], "proxy-groups")
	selected := groupSaveField(groups.Content[0], "selected")
	selected.Tag, selected.Value = "!!str", "true"
	if err := saveGroupChoice(p, "false", "true"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(groupSaveAST(before), groupSaveAST(groupSaveDocument(t, after))) {
		t.Fatal("non-target AST tag/value/order/comment attachment changed")
	}
	nodes, err := loadNodesBytes(after)
	if err != nil || len(nodes) != 2 || nodes[0].Name != "00123" || nodes[0].Password != "00123" || nodes[1].Name != "true" || nodes[1].Password != "true" {
		t.Fatalf("actual typed nodes changed: %#v, %v", nodes, err)
	}
	got, err := groupChoices(p)
	if err != nil || len(got) != 2 || got[0].Name != "false" || got[0].Selected != "true" || got[1].Selected != "DIRECT" {
		t.Fatalf("actual typed groups changed: %#v, %v", got, err)
	}
	b, err := os.ReadFile(bootstrap)
	if err != nil || string(b) != "00123\n" {
		t.Fatalf("bootstrap changed: %q, %v", b, err)
	}
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("replacement must retain private-write policy: %v, %v", st, err)
	}
}

func TestSaveGroupChoiceNoOpKeepsOriginal(t *testing.T) {
	p := groupSaveFixture(t, "# keep bytes\nproxy-groups: [{name: 00123, type: select, proxies: [DIRECT], selected: DIRECT}]\nx: &x {value: 00123}\ny: *x\n")
	before, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveGroupChoice(p, "00123", "DIRECT"); err != nil {
		t.Fatal(err)
	}
	groupSaveUnchanged(t, p, original, before)
}

func groupSaveUnchanged(t *testing.T, p string, original []byte, before os.FileInfo) {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, b) || !os.SameFile(before, after) || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("original bytes/inode/mode/mtime changed")
	}
	leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(p), ".group-choice-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v, %v", leftovers, err)
	}
}

func TestSaveGroupChoiceMissingSelected(t *testing.T) {
	p := groupSaveFixture(t, "proxy-groups: [{name: main, type: select, proxies: [DIRECT], x-field: 00123}]\n")
	original, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	want := groupSaveDocument(t, original)
	g := groupSaveField(want.Content[0], "proxy-groups").Content[0]
	g.Content = append(g.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "selected"}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "DIRECT"})
	if err := saveGroupChoice(p, "main", "DIRECT"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(groupSaveAST(want), groupSaveAST(groupSaveDocument(t, b))) {
		t.Fatal("missing selected insertion changed unrelated AST")
	}
}

func TestSaveGroupChoiceRejectsWithoutChangingOriginal(t *testing.T) {
	const valid = "proxy-groups: [{name: main, type: select, proxies: [DIRECT], selected: DIRECT}]\n"
	for _, tc := range []struct {
		name, source, group, choice string
	}{
		{"unlisted", valid, "main", "REJECT"},
		{"missing-group", valid, "absent", "DIRECT"},
		{"ss", "proxies: [{name: ss, type: ss}]\nproxy-groups: [{name: main, type: select, proxies: [ss], selected: ss}]\n", "main", "ss"},
		{"cycle", "proxy-groups: [{name: main, type: select, proxies: [main], selected: DIRECT}]\n", "main", "main"},
		{"unsupported-type", "proxy-groups: [{name: main, type: url-test, proxies: [DIRECT], selected: DIRECT}]\n", "main", "DIRECT"},
		{"invalid-actual-node", "proxies: [{name: broken, type: anytls, port: not-an-int}]\n" + valid, "main", "DIRECT"},
		{"duplicate-node-field", "proxies: [{name: a, name: b, type: anytls}]\n" + valid, "main", "DIRECT"},
		{"duplicate-root", valid + valid, "main", "DIRECT"},
		{"duplicate-group-selected", "proxy-groups: [{name: main, type: select, proxies: [DIRECT], selected: DIRECT, selected: REJECT}]\n", "main", "DIRECT"},
		{"duplicate-group-name", "proxy-groups: [{name: main, name: other, type: select, proxies: [DIRECT], selected: DIRECT}]\n", "main", "DIRECT"},
		{"duplicate-groups", "proxy-groups: [{name: main, type: select, proxies: [DIRECT], selected: DIRECT}, {name: main, type: select, proxies: [DIRECT], selected: DIRECT}]\n", "main", "DIRECT"},
		{"second-document", valid + "---\nx: second\n", "main", "DIRECT"},
		{"empty-second-document", valid + "---\n", "main", "DIRECT"},
		{"malformed-tail", valid + "---\n[\n", "main", "DIRECT"},
		{"sequence-root", "[DIRECT]\n", "main", "DIRECT"},
		{"empty", "", "main", "DIRECT"},
		{"group-alias-no-op", "x: &g {name: main, type: select, proxies: [DIRECT], selected: DIRECT}\nproxy-groups: [*g]\n", "main", "DIRECT"},
		{"sequence-alias", "x: &gs [{name: main, type: select, proxies: [DIRECT], selected: DIRECT}]\nproxy-groups: *gs\n", "main", "DIRECT"},
		{"root-merge", "x: &root {proxy-groups: [{name: main, type: select, proxies: [DIRECT], selected: DIRECT}]}\n<<: *root\n", "main", "DIRECT"},
		{"group-merge", "x: &g {name: main, type: select, proxies: [DIRECT], selected: DIRECT}\nproxy-groups: [{<<: *g}]\n", "main", "DIRECT"},
		{"selected-alias", "x: &s DIRECT\nproxy-groups: [{name: main, type: select, proxies: [DIRECT, REJECT], selected: *s}]\n", "main", "REJECT"},
		{"selected-shared-anchor", "proxy-groups: [{name: main, type: select, proxies: [DIRECT, REJECT], selected: &s DIRECT}]\nx: *s\n", "main", "REJECT"},
		{"group-shared-anchor", "proxy-groups: [&g {name: main, type: select, proxies: [DIRECT, REJECT], selected: DIRECT}]\nx: *g\n", "main", "REJECT"},
		{"sequence-shared-anchor", "proxy-groups: &gs [{name: main, type: select, proxies: [DIRECT, REJECT], selected: DIRECT}]\nx: *gs\n", "main", "REJECT"},
		{"root-shared-anchor", "&root\nproxy-groups: [{name: main, type: select, proxies: [DIRECT, REJECT], selected: DIRECT}]\nx: *root\n", "main", "REJECT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := groupSaveFixture(t, tc.source)
			before, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := saveGroupChoice(p, tc.group, tc.choice); err == nil {
				t.Fatal("unsafe or invalid selection accepted")
			}
			groupSaveUnchanged(t, p, []byte(tc.source), before)
		})
	}
}

func TestSaveGroupChoiceScalarNamesAndNoOp(t *testing.T) {
	for _, name := range []string{"00123", "true"} {
		t.Run(name, func(t *testing.T) {
			source := "proxies: [{name: " + name + ", type: anytls, password: 00123}]\nproxy-groups: [{name: main, type: select, proxies: [DIRECT, " + name + "], selected: " + name + "}]\n"
			p := groupSaveFixture(t, source)
			before, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := saveGroupChoice(p, "main", name); err != nil {
				t.Fatal(err)
			}
			groupSaveUnchanged(t, p, []byte(source), before)
			if err := saveGroupChoice(p, "main", "DIRECT"); err != nil {
				t.Fatal(err)
			}
			if err := saveGroupChoice(p, "main", name); err != nil {
				t.Fatal(err)
			}
			groups, err := groupChoices(p)
			if err != nil || len(groups) != 1 || groups[0].Selected != name {
				t.Fatalf("typed scalar selected mismatch: %#v, %v", groups, err)
			}
		})
	}
}

func TestSaveGroupChoiceUnsharedSelectedAnchor(t *testing.T) {
	p := groupSaveFixture(t, "proxy-groups: [{name: main, type: select, proxies: [DIRECT, REJECT], selected: &s DIRECT}]\n")
	if err := saveGroupChoice(p, "main", "REJECT"); err != nil {
		t.Fatal(err)
	}
	groups, err := groupChoices(p)
	if err != nil || len(groups) != 1 || groups[0].Selected != "REJECT" {
		t.Fatalf("unshared anchor save: %#v, %v", groups, err)
	}
}

func TestSaveGroupChoiceAliasedSelectedKey(t *testing.T) {
	const source = "x-key: &k selected\nproxy-groups:\n  - name: main\n    type: select\n    proxies: [DIRECT, REJECT]\n    *k : DIRECT\n"
	for _, choice := range []string{"DIRECT", "REJECT"} {
		t.Run(choice, func(t *testing.T) {
			p := groupSaveFixture(t, source)
			groups, err := groupChoices(p)
			if err != nil || len(groups) != 1 || groups[0].Selected != "DIRECT" {
				t.Fatalf("fixture must be accepted by actual typed loader: %v, %v", groups, err)
			}
			before, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := saveGroupChoice(p, "main", choice); err == nil {
				t.Fatal("aliased selected key accepted for modification")
			}
			groupSaveUnchanged(t, p, []byte(source), before)
		})
	}
}

func TestSaveGroupChoiceRejectsConfigSymlink(t *testing.T) {
	p := groupSaveFixture(t, "proxy-groups: [{name: main, type: select, proxies: [DIRECT, REJECT], selected: DIRECT}]\n")
	original, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(p), "link.yaml")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if err := saveGroupChoice(link, "main", "REJECT"); err == nil {
		t.Fatal("config symlink accepted")
	}
	st, err := os.Lstat(link)
	if err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink replaced: %v, %v", st, err)
	}
	groupSaveUnchanged(t, p, original, before)
}
