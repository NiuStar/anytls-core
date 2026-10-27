package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

func errorProjection(err error) []string {
	if err == nil {
		return nil
	}
	result := []string{fmt.Sprintf("%T: %s", err, err.Error())}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			result = append(result, errorProjection(child)...)
		}
	} else {
		result = append(result, errorProjection(errors.Unwrap(err))...)
	}
	return result
}

func assertOriginalDecode(t *testing.T, content []byte) {
	t.Helper()
	before := bytes.Clone(content)
	_, want, wantErr := originalOptions(context.Background(), content)
	_, got, gotErr := decodeOptions(context.Background(), content)
	if !reflect.DeepEqual(errorProjection(gotErr), errorProjection(wantErr)) {
		t.Fatalf("error text/type/chain differs: got=%v want=%v", errorProjection(gotErr), errorProjection(wantErr))
	}
	var gotSyntax, wantSyntax *json.SyntaxError
	if errors.As(gotErr, &gotSyntax) != errors.As(wantErr, &wantSyntax) || !reflect.DeepEqual(gotSyntax, wantSyntax) {
		t.Fatal("extended syntax cause or offset differs")
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("complete typed options differ")
	}
	if !bytes.Equal(content, before) {
		t.Fatal("caller bytes modified")
	}
}

func TestRouteRulePreallocationOracle(t *testing.T) {
	rule := `{"domain":["one.fixture.invalid","two.fixture.invalid"],"outbound":"direct"}`
	cases := []string{
		`{}`, `null`, `[]`, `1`, `"scalar"`, `true`, ``, `{`,
		`{} {}`, `{} true`, "{\n\"route\": {\n\"rules\": [}\n}",
		`{"route":null}`, `{"route":{}}`, `{"route":{"rules":null}}`, `{"route":{"rules":[]}}`,
		`{"route":{"rules":1}}`, `{"route":{"rules":{}}}`, `{"route":{"rules":"scalar"}}`,
		`{"route":{"rules":[null]}}`, `{"route":{"rules":[true]}}`, `{"route":{"rules":[[]]}}`,
		`{"route":{"rules":[` + rule + `]}}`,
		`{"Route":{"Rules":[` + rule + `]}}`, `{"ROUTE":{"RULES":[` + rule + `]}}`,
		`{"route":{"rules":[` + rule + `]},"route":null}`,
		`{"route":null,"route":{"rules":[` + rule + `]}}`,
		`{"route":{"rules":[` + rule + `]},"ROUTE":{"final":"direct"}}`,
		`{"route":{"rules":[` + rule + `],"rules":null}}`,
		`{"route":{"rules":[` + rule + `],"rules":[]}}`,
		`{"route":{"rules":[],"rules":[` + rule + `]}}`,
		`{"route":{"rules":[` + rule + `],"Rules":[{"domain":"scalar.fixture.invalid","outbound":"direct"}]}}`,
		`{"route":{"rules":[{"domain":null,"outbound":"direct"}]}}`,
		`{"route":{"rules":[{"domain":"scalar.fixture.invalid","outbound":"direct"}]}}`,
		`{"route":{"rules":[{"domain":[1],"outbound":"direct"}]}}`,
		`{"route":{"rules":[{"type":"unknown","outbound":"direct"}]}}`,
		`{"route":{"rules":[{"domain":["a"],"unknown":true,"outbound":"direct"}]}}`,
		`{"route":{"rules":[{"type":"logical","mode":"or","rules":[` + rule + `],"outbound":"direct"}]}}`,
		`{"route":{"rules":[{"type":"logical","mode":"or","rules":[{"domain":"a","action":"reject"}],"outbound":"direct"}]}}`,
		`{"route":{"rules":[{"action":"sniff"},{"action":"resolve","server":"local"},{"action":"hijack-dns"},{"action":"reject"}]}}`,
		`{"route":{"rules":[{"action":"route-options","override_port":80},{"action":"route","outbound":"direct"}]}}`,
		`{"route":{"unknown":true,"rules":[` + rule + `]}}`,
		`{"unknown":true,"route":{"rules":[` + rule + `]}}`,
		`{"route":{"rules":[null,null,null]}}`, `{"ro\u0075te":{"rul\u0065s":[` + rule + `]}}`,
		`{"route":{"rules":[` + rule + `],"rules":null,"rules":[` + rule + `]}}`,
		`{"route":{"rules":[{"domain":"first","domain":"second","outbound":"direct"}]}}`,
		`{"route":{"rules":[{"domain":"a","action":"route","action":"reject","outbound":"direct"}]}}`,
		`{"route":{"rules":[{"type":"logical","mode":"or","rules":[{"type":"logical","mode":"and","rules":[{"domain":"a","action":"reject"}]}],"outbound":"direct"}]}}`,
		`{"route":{"rules":[` + rule + `]},"outbounds":[{"type":"direct","tag":"same"},{"type":"direct","tag":"same"}]}`,
		`{"route":{"rules":[` + rule + `]},"outbounds":[{"type":"socks","server":"127.0.0.1","server_port":9}]}`,
		`{"log":{"level":"invalid"},"route":{"rules":[` + rule + `]}}`,
		`{"log":{"disabled":true,"level":"invalid"},"route":{"rules":[` + rule + `]}}`,
		`{"outbounds":[{"type":"anytls","tag":"tls","server":"127.0.0.1","server_port":9,"password":"synthetic","tls":{"enabled":true,"server_name":"fixture.invalid","utls":{"enabled":true,"fingerprint":"chrome"}}}],"route":{"rules":[` + rule + `]}}`,
	}
	for i, content := range cases {
		t.Run(fmt.Sprintf("case-%02d", i), func(t *testing.T) { assertOriginalDecode(t, []byte(content)) })
	}
	assertOriginalDecode(t, orderedRuleJSON(1000))
	// Deterministic structural mutations exercise syntax decoration, duplicate
	// fields, type dispatch, escaped keys and trailing bytes against the oracle.
	seed := orderedRuleJSON(4)
	for i := 0; i < len(seed); i += 7 {
		for _, replacement := range []byte{'{', ']', '"', '\n', 0xff} {
			content := bytes.Clone(seed)
			content[i] = replacement
			assertOriginalDecode(t, content)
		}
	}
}

func TestRouteRulePreallocationComments(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
	}{
		{"leading-line", "// leading\n{}"},
		{"inline-block", "{/* inner */ \"route\":{\"rules\":[{\"action\":\"reject\"}]}}"},
		{"trailing-line", "{\"route\":{\"rules\":[{\"action\":\"reject\"}]}} // trailing\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := []byte(tc.content)
			_, want, err := originalOptions(context.Background(), content)
			if err != nil || want.CommentsSet == nil {
				t.Fatal("oracle must accept input and retain comment metadata")
			}
			assertOriginalDecode(t, content) // Includes the full CommentsSet, not just acceptance.
		})
	}
}

func TestRouteRulePreallocationFreshConcurrent(t *testing.T) {
	type key struct{}
	parent, cancel := context.WithTimeout(context.WithValue(context.Background(), key{}, "kept"), time.Minute)
	defer cancel()
	parent = Context(parent)
	parentRegistry := service.RegistryFromContext(parent)
	content := orderedRuleJSON(12)
	before := bytes.Clone(content)
	var wg sync.WaitGroup
	registries := make(chan service.Registry, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, first, err := decodeOptions(parent, content)
			if err != nil {
				t.Error(err)
				return
			}
			registries <- service.RegistryFromContext(ctx)
			deadline, ok := ctx.Deadline()
			wantDeadline, _ := parent.Deadline()
			if ctx.Value(key{}) != "kept" || !ok || !deadline.Equal(wantDeadline) || ctx.Done() != parent.Done() {
				t.Error("parent context not preserved")
			}
			first.Route.Rules[0] = option.Rule{}
			_, second, err := decodeOptions(parent, content)
			if err != nil || reflect.DeepEqual(first.Route.Rules[0], second.Route.Rules[0]) {
				t.Error("per-call options shared or decode failed")
			}
		}()
	}
	wg.Wait()
	close(registries)
	seen := map[service.Registry]bool{parentRegistry: true}
	for registry := range registries {
		if seen[registry] {
			t.Fatal("shared registry")
		}
		seen[registry] = true
	}
	if !bytes.Equal(content, before) {
		t.Fatal("shared caller bytes modified")
	}
	cancel()
	ctx, _, _ := decodeOptions(parent, content)
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("cancellation lost")
	}
}

func TestRouteRulePreallocationHintBound(t *testing.T) {
	for _, content := range [][]byte{
		[]byte(`{"route":{"rules":[{"unknown":true},` + strings.Repeat(`null,`, 998) + `null]}}`),
		[]byte(`{"route":{"rules":[` + strings.Repeat(`{},`, 999) + `{}],"rules":null}}`),
		[]byte(`{"route":{"rules":[` + strings.Repeat(`{},`, 999) + `{}]},"route":null}`),
		[]byte(`{"route":{"rules":[{"type":"logical","mode":"or","rules":[` + strings.Repeat(`null,`, 999) + `null]}]}}`),
	} {
		count := routeRuleCapacityHint(content)
		if count*int(unsafe.Sizeof(option.Rule{})) > len(content)*32 {
			t.Fatal("speculative union allocation exceeds actual-byte bound")
		}
		assertOriginalDecode(t, content)
	}
}
