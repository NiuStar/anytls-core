package main

import (
	"bytes"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Test-only padding shared with the Darwin large-config startup fixture.
// Trailing YAML whitespace preserves file size and configuration semantics,
// not the original bytes or the parser's comment nodes.
func startupConfigPadding(raw []byte, size int) []byte {
	raw = append(raw, bytes.Repeat([]byte(" "), size-len(raw)-1)...)
	return append(raw, '\n')
}

func TestStartupConfigPaddingEquivalence(t *testing.T) {
	_, _, config, _, _, _ := lifecycleFixture(t)
	base, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	// Keep this recurring oracle small; the Darwin test retains both large sizes.
	for _, size := range []int{len(base) + 2, 8193} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			comment := append(bytes.Clone(base), []byte("#"+strings.Repeat("x", size-len(base)-2)+"\n")...)
			input := bytes.Clone(base)
			spaces := startupConfigPadding(input, size)
			if !bytes.Equal(input, base) {
				t.Fatal("padding mutated source business bytes")
			}
			if len(comment) != size || len(spaces) != size || !bytes.Equal(spaces[:len(base)], base) || spaces[size-1] != '\n' || bytes.Count(spaces[len(base):size-1], []byte(" ")) != size-len(base)-1 {
				t.Fatal("padding changed fixture bytes or size")
			}
			var wantYAML any
			var wantCompiled map[string]any
			var wantIPs []string
			var wantInsecure bool
			for i, raw := range [][]byte{comment, spaces} {
				var decoded any
				if err := yaml.Unmarshal(raw, &decoded); err != nil {
					t.Fatal(err)
				}
				// Check the full syntax value before the compiler can reject a
				// missing final rule; no business field is normalized or omitted.
				if i == 1 && !reflect.DeepEqual(wantYAML, decoded) {
					t.Fatal("padding changed decoded YAML, compiled configuration or outbounds")
				}
				if err := os.WriteFile(config, raw, 0600); err != nil {
					t.Fatal(err)
				}
				captured, err := captureServiceConfig(config)
				if err != nil {
					t.Fatal(err)
				}
				compiled, err := captured.compile(true)
				if err != nil {
					t.Fatal(err)
				}
				ips, insecure, err := serviceOutbounds(config, true)
				if err != nil {
					t.Fatal(err)
				}
				if i == 0 {
					wantYAML, wantCompiled, wantIPs, wantInsecure = decoded, compiled, ips, insecure
				} else if !reflect.DeepEqual(wantYAML, decoded) || !reflect.DeepEqual(wantCompiled, compiled) || !reflect.DeepEqual(wantIPs, ips) || wantInsecure != insecure {
					t.Fatal("padding changed decoded YAML, compiled configuration or outbounds")
				}
			}
		})
	}
}
