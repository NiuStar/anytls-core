package main

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Projection/parser-only fixtures: options are deterministic, request-local and
// do no file I/O or native checks. Real authenticated handler timing is separate.
func webRulesASTOptions(doc webRuleDoc) ([]string, []string) {
	targets := []string{"DIRECT", "REJECT"}
	for _, g := range doc.Groups {
		targets = append(targets, g.Name, g.Type, g.Selected)
		targets = append(targets, g.Proxies...)
	}
	sets := make([]string, 0, len(doc.Sets))
	for label, spec := range doc.Sets {
		sets = append(sets, fmt.Sprintf("%s:%s:%s:%t", label, spec.Path, spec.SHA256, spec.ResolveIP))
	}
	sort.Strings(sets)
	return targets, sets
}

func assertWebRulesASTError(t *testing.T, got, want error) {
	t.Helper()
	if (got == nil) != (want == nil) {
		t.Fatalf("error presence: got=%v want=%v", got, want)
	}
	if want == nil {
		return
	}
	// Compare category and exact text, never identity of separately allocated errors.
	if reflect.TypeOf(got) != reflect.TypeOf(want) || got.Error() != want.Error() {
		t.Fatalf("error: got=%T %v want=%T %v", got, got, want, want)
	}
	var gt, wt *yaml.TypeError
	if errors.As(got, &gt) != errors.As(want, &wt) || !reflect.DeepEqual(gt, wt) {
		t.Fatalf("typed YAML errors differ: got=%#v want=%#v", gt, wt)
	}
}

// Stable graph IDs compare fields and pointer relationships, not pointer values
// from distinct parses. Content and Alias edges share the same identity table;
// register before descent so recursive aliases terminate. Keep nil vs empty.
type webRulesASTNodeView struct {
	Kind               yaml.Kind
	Tag, Value, Anchor string
	Style              yaml.Style
	Line, Column       int
	Content            []int
	Alias              int
}
type webRulesASTGraph struct {
	Roots []int
	Nodes []webRulesASTNodeView
}

func webRulesASTGraphView(items []*yaml.Node) webRulesASTGraph {
	var graph webRulesASTGraph
	ids := map[*yaml.Node]int{}
	var visit func(*yaml.Node) int
	visit = func(n *yaml.Node) int {
		if n == nil {
			return 0
		}
		if id, ok := ids[n]; ok {
			return id
		}
		if len(ids) >= 4096 {
			panic("bounded AST test graph exceeded")
		}
		id := len(graph.Nodes) + 1
		ids[n] = id
		graph.Nodes = append(graph.Nodes, webRulesASTNodeView{})
		v := webRulesASTNodeView{Kind: n.Kind, Tag: n.Tag, Value: n.Value, Anchor: n.Anchor, Style: n.Style, Line: n.Line, Column: n.Column}
		if n.Content != nil {
			v.Content = make([]int, len(n.Content))
			for i, child := range n.Content {
				v.Content[i] = visit(child)
			}
		}
		v.Alias = visit(n.Alias)
		graph.Nodes[id-1] = v
		return id
	}
	if items != nil {
		graph.Roots = make([]int, len(items))
		for i, n := range items {
			graph.Roots[i] = visit(n)
		}
	}
	return graph
}

func TestWebRulesASTGraphComparison(t *testing.T) {
	makeGraph := func() []*yaml.Node {
		n := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "值", Anchor: "a", Style: yaml.DoubleQuotedStyle, Line: 2, Column: 3}
		a := &yaml.Node{Kind: yaml.AliasNode, Value: "a", Alias: n}
		root := &yaml.Node{Kind: yaml.SequenceNode, Content: []*yaml.Node{n, a, n}}
		n.Alias = root // Deliberate cycle exercises bounded traversal, not valid YAML.
		return []*yaml.Node{root}
	}
	want := webRulesASTGraphView(makeGraph())
	if !reflect.DeepEqual(want, webRulesASTGraphView(makeGraph())) {
		t.Fatal("independent pointer graphs differ")
	}
	for _, field := range []string{"Kind", "Tag", "Value", "Anchor", "Style", "Line", "Column", "Content", "Alias"} {
		t.Run(field, func(t *testing.T) {
			nodes := makeGraph()
			n := nodes[0].Content[0]
			switch field {
			case "Kind":
				n.Kind = yaml.MappingNode
			case "Tag":
				n.Tag = "!!int"
			case "Value":
				n.Value += "x"
			case "Anchor":
				n.Anchor = "b"
			case "Style":
				n.Style = yaml.SingleQuotedStyle
			case "Line":
				n.Line++
			case "Column":
				n.Column++
			case "Content":
				nodes[0].Content = nodes[0].Content[:2]
			case "Alias":
				copy := *n
				nodes[0].Content[1].Alias = &copy
			}
			if reflect.DeepEqual(want, webRulesASTGraphView(nodes)) {
				t.Fatal("graph comparison missed mutation")
			}
		})
	}
}

func TestWebRulesASTErrorComparison(t *testing.T) {
	assertWebRulesASTError(t, errors.New("RULE_EDIT_UNSUPPORTED"), errors.New("RULE_EDIT_UNSUPPORTED"))
	assertWebRulesASTError(t, &yaml.TypeError{Errors: []string{"line 1: duplicate key"}}, &yaml.TypeError{Errors: []string{"line 1: duplicate key"}})
}

func TestWebRulesASTEquivalence(t *testing.T) {
	block := "rules:\n  - DOMAIN,例子.example,DIRECT\n  - MATCH,DIRECT\n"
	cases := []struct{ name, raw string }{
		{"block", block},
		{"empty-input", ""},
		{"comment-only", "# comment\n"},
		{"missing-rules", "nodes: []\n"},
		{"empty-rules", "rules: []\n"},
		{"null-document", "null\n"},
		{"null-rules", "rules: null\n"},
		{"null-item", "rules:\n  - null\n  - MATCH,DIRECT\n"},
		{"scalar-document", "hello\n"},
		{"sequence-document", "- MATCH,DIRECT\n"},
		{"scalar-rules", "rules: MATCH,DIRECT\n"},
		{"mapping-item", "rules:\n  - {x: y}\n  - MATCH,DIRECT\n"},
		{"sequence-item", "rules:\n  - [x, y]\n  - MATCH,DIRECT\n"},
		{"numeric-item", "rules:\n  - 123\n  - MATCH,DIRECT\n"},
		{"bool-item", "rules:\n  - true\n  - MATCH,DIRECT\n"},
		{"explicit-string", "rules:\n  - !!str 123\n  - MATCH,DIRECT\n"},
		{"explicit-bad-int", "rules:\n  - !!int nope\n  - MATCH,DIRECT\n"},
		{"flow-rules", "rules: ['DOMAIN,x,DIRECT', 'MATCH,DIRECT']\n"},
		{"flow-top", "{rules: ['MATCH,DIRECT']}\n"},
		{"duplicate-rules", block + "rules:\n  - MATCH,REJECT\n"},
		{"duplicate-unknown", "x: 1\nx: 2\n" + block},
		{"duplicate-group-key", "proxy-groups:\n  - name: a\n    name: b\n" + block},
		{"duplicate-set-key", "rule-sets:\n  a: {path: a}\n  a: {path: b}\n" + block},
		{"complex-key", "? [a, b]\n: value\n" + block},
		{"unknown-fields", "unknown: {nested: [true, null, 42]}\n" + block},
		{"unrelated-anchor-alias", "x: &x {a: b}\ny: *x\n" + block},
		{"unrelated-recursive-alias", "x: &x [*x]\n" + block},
		{"sequence-anchor", "rules: &r\n  - MATCH,DIRECT\n"},
		{"sequence-alias", "x: &r\n  - MATCH,DIRECT\nrules: *r\n"},
		{"item-anchor", "rules:\n  - &r DOMAIN,x,DIRECT\n  - MATCH,DIRECT\n"},
		{"item-alias", "x: &r DOMAIN,x,DIRECT\nrules:\n  - *r\n  - MATCH,DIRECT\n"},
		{"undefined-alias", "rules: *missing\n"},
		{"top-merge", "base: &b {nodes: []}\n<<: *b\n" + block},
		{"merged-rules", "base: &b {rules: ['MATCH,DIRECT']}\n<<: *b\n"},
		{"quoted-key", "'rules':\n  - MATCH,DIRECT\n"},
		{"quoted-escapes", "rules:\n  - \"DOMAIN,\\u4f8b.example,DIRECT\"\n  - 'MATCH,DIRECT'\n"},
		{"escaped-newline", "rules:\n  - \"DOMAIN,x\\ny,DIRECT\"\n  - MATCH,DIRECT\n"},
		{"escaped-nul", "rules:\n  - \"DOMAIN,x\\0,DIRECT\"\n  - MATCH,DIRECT\n"},
		{"double-continuation", "rules:\n  - \"DOMAIN,x,\n    DIRECT\"\n  - MATCH,DIRECT\n"},
		{"single-continuation", "rules:\n  - 'DOMAIN,x,\n    DIRECT'\n  - MATCH,DIRECT\n"},
		{"plain-continuation", "rules:\n  - DOMAIN,x,\n    DIRECT\n  - MATCH,DIRECT\n"},
		{"folded", "rules:\n  - >-\n    DOMAIN,x,DIRECT\n  - MATCH,DIRECT\n"},
		{"literal", "rules:\n  - |-\n    DOMAIN,x,DIRECT\n  - MATCH,DIRECT\n"},
		{"comments", "# 顶部\nrules: # keep\n  - DOMAIN,x,DIRECT # item\n  # boundary\n  - MATCH,DIRECT # end\n"},
		{"crlf", strings.ReplaceAll(block, "\n", "\r\n")},
		{"no-final-newline", strings.TrimSuffix(block, "\n")},
		{"crlf-no-final-newline", strings.TrimSuffix(strings.ReplaceAll(block, "\n", "\r\n"), "\r\n")},
		{"unicode-bom", "\ufeff" + block},
		{"unindented", "rules:\n- DOMAIN,x,DIRECT\n- MATCH,DIRECT\n"},
		{"tab-after-dash", "rules:\n  -\tDOMAIN,x,DIRECT\n  -\tMATCH,DIRECT\n"},
		{"missing-match", "rules:\n  - DOMAIN,x,DIRECT\n"},
		{"match-not-last", "rules:\n  - MATCH,DIRECT\n  - DOMAIN,x,DIRECT\n"},
		{"duplicate-match", "rules:\n  - MATCH,DIRECT\n  - MATCH,REJECT\n"},
		{"match-extra-parts", "rules:\n  - MATCH,DIRECT,extra\n"},
		{"match-whitespace", "rules:\n  - ' MATCH , DIRECT '\n"},
		{"multi-document", block + "---\nrules: [broken]\n"},
		{"invalid-second-document", block + "---\nrules: [\n"},
		{"explicit-document", "---\n" + block + "...\n"},
		{"invalid-syntax", "rules: [\n"},
		{"invalid-indent", "rules:\n \t- MATCH,DIRECT\n"},
		{"invalid-utf8", string([]byte{0xff})},
		{"typed-options", "proxy-groups:\n  - {name: 组, type: select, proxies: [DIRECT, REJECT], selected: REJECT}\nrule-sets:\n  z: {path: z.json, sha256: abc, resolve-ip: true}\n  a: {path: a.json, sha256: def}\n" + block},
		{"invalid-groups", "proxy-groups: wrong\n" + block},
		{"invalid-sets", "rule-sets: wrong\n" + block},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(tc.raw)
			original := bytes.Clone(raw)
			gotNodes, gotErr := webRuleLayout(raw)
			wantNodes, wantErr := oldWebRulesASTLayout(raw)
			assertWebRulesASTError(t, gotErr, wantErr)
			if !reflect.DeepEqual(webRulesASTGraphView(gotNodes), webRulesASTGraphView(wantNodes)) {
				t.Fatal("complete layout node graph differs")
			}
			for _, list := range []bool{true, false} {
				t.Run(fmt.Sprintf("list=%t", list), func(t *testing.T) {
					gotCalls, wantCalls := 0, 0
					var gotDoc, wantDoc webRuleDoc
					got, ge := webRulesProjection(raw, list, func(doc webRuleDoc) ([]string, []string) { gotCalls++; gotDoc = doc; return webRulesASTOptions(doc) })
					want, we := oldWebRulesASTProjection(raw, list, func(doc webRuleDoc) ([]string, []string) { wantCalls++; wantDoc = doc; return webRulesASTOptions(doc) })
					assertWebRulesASTError(t, ge, we)
					if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(gotDoc, wantDoc) {
						t.Fatalf("complete projection/doc mismatch: got=%#v want=%#v", got, want)
					}
					expectedCalls := 0
					if we == nil && !list {
						expectedCalls = 1
					}
					if gotCalls != expectedCalls || wantCalls != expectedCalls {
						t.Fatalf("options order/count got=%d old=%d want=%d", gotCalls, wantCalls, expectedCalls)
					}
					if ge == nil && got["etag"] != `"`+shaHex(original)+`"` {
						t.Fatal("ETag did not bind original bytes")
					}
					if !bytes.Equal(raw, original) {
						t.Fatal("projection mutated source bytes")
					}
				})
			}
		})
	}
}

func webRulesASTFixture(n int) []byte {
	var s strings.Builder
	s.WriteString("nodes: []\nproxy-groups:\n  - {name: choice, type: select, proxies: [DIRECT, REJECT], selected: DIRECT}\nrule-sets:\n  synthetic: {path: not-read.json, sha256: fixture-only, resolve-ip: true}\nrules:\n")
	for i := 0; i < n-1; i++ {
		fmt.Fprintf(&s, "  - DOMAIN,host-%05d.example,DIRECT\n", i)
	}
	s.WriteString("  - MATCH,DIRECT\n")
	return []byte(s.String())
}

var webRulesASTBenchmarkSink map[string]any

// Run a wrapper-built test binary with -test.run=^$ -test.bench=BenchmarkWebRulesAST
// -test.benchtime=1x -test.count=5. Compare old/current WITHIN each mode/scale.
// This intentionally excludes handler, disk, native SDK and network latency.
func BenchmarkWebRulesAST(b *testing.B) {
	for _, n := range []int{10, 1000, 10000} {
		raw := webRulesASTFixture(n)
		for _, mode := range []struct {
			name string
			list bool
		}{{"list", true}, {"full", false}} {
			for _, impl := range []struct {
				name string
				run  func([]byte, bool, func(webRuleDoc) ([]string, []string)) (map[string]any, error)
			}{{"old", oldWebRulesASTProjection}, {"current", webRulesProjection}} {
				b.Run(fmt.Sprintf("rules=%d/%s/%s", n, mode.name, impl.name), func(b *testing.B) {
					want, err := oldWebRulesASTProjection(raw, mode.list, webRulesASTOptions)
					if err != nil {
						b.Fatal(err)
					}
					got, err := impl.run(raw, mode.list, webRulesASTOptions)
					if err != nil || !reflect.DeepEqual(got, want) {
						b.Fatalf("fixture projection mismatch: %v", err)
					}
					b.Logf("fixture_sha256=%s bytes=%d rules=%d labels=1 mode=%s implementation=%s options=deterministic-no-io", shaHex(raw), len(raw), n, mode.name, impl.name)
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						result, err := impl.run(raw, mode.list, webRulesASTOptions)
						if err != nil {
							b.Fatal(err)
						}
						webRulesASTBenchmarkSink = result
					}
				})
			}
		}
	}
}
