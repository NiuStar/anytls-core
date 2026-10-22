package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestConfigSizeLimit32MiB(t *testing.T) {
	if snapshotConfigLimit != 32<<20 {
		t.Fatal("configuration limit must be 32 MiB")
	}
	input := []byte("nodes: []\n#" + strings.Repeat("x", (4<<20)+1) + "\n")
	out, report, err := webConvertConfiguration(context.Background(), input, false, nil)
	if err != nil || !bytes.Equal(out, input) || len(report.Skipped) != 0 {
		t.Fatal("native configuration above 4 MiB was not preserved", err)
	}
	tooLarge := bytes.Repeat([]byte(" "), (32<<20)+1)
	if _, _, err := conversionParse(tooLarge); !errors.Is(err, errWebConversionTooLarge) {
		t.Fatal("32 MiB + 1 must be rejected as too large", err)
	}
}

func TestConfigLargeProviderPreservesEveryRule(t *testing.T) {
	const count = 50000
	domain := strings.Repeat("a", 40) + "." + strings.Repeat("b", 40) + ".example"
	payload := []byte("payload:\n" + strings.Repeat("  - "+domain+"\n", count))
	input := "proxies: [{name: test, type: anytls, server: 192.0.2.1, port: 443, password: test}]\nrule-providers: {p: {type: http, url: 'https://example.com/rules', behavior: domain}}\nrules: ['RULE-SET,p,DIRECT','MATCH,DIRECT']\n"
	out, report, err := webConvertConfiguration(context.Background(), []byte(input), true, func(context.Context, string) ([]byte, error) { return payload, nil })
	if err != nil || len(out) <= 4<<20 || len(report.Skipped) != 0 || len(report.Issues) != 0 {
		t.Fatal("large expanded configuration rejected or dropped content", len(out), err)
	}
	var decoded struct {
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Rules) != count+1 {
		t.Fatal("rule count changed", len(decoded.Rules))
	}
	for i, rule := range decoded.Rules[:count] {
		if rule != "DOMAIN,"+domain+",DIRECT" {
			t.Fatal("rule changed", i)
		}
	}
	if decoded.Rules[count] != "MATCH,DIRECT" {
		t.Fatal("final rule changed")
	}
}

// Stream the worst-case six-byte JSON escape without allocating the envelope.
type configEscapesReader struct {
	remaining int64
	offset    int64
}

func (r *configEscapesReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}
	const escape = `\u0020`
	for i := 0; i < n; i++ {
		p[i] = escape[(r.offset+int64(i))%6]
	}
	r.remaining -= int64(n)
	r.offset += int64(n)
	return n, nil
}

func TestConfigJSONEscapingEnvelopeAndControlBudget(t *testing.T) {
	body := io.MultiReader(strings.NewReader(`{"yaml":"`), &configEscapesReader{remaining: 6 * (32 << 20)}, strings.NewReader(`"}`))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/import/preview", body)
	r.Header.Set("Content-Type", "application/json")
	var in struct {
		YAML string `json:"yaml"`
	}
	if err := webDecode(httptest.NewRecorder(), r, &in); err != nil || len(in.YAML) != 32<<20 {
		t.Fatal("32 MiB worst-case JSON envelope unreachable", err, len(in.YAML))
	}
	in.YAML = ""
	for _, tc := range []struct {
		method, path string
		accept       bool
	}{
		{http.MethodPut, "/api/v1/config", true},
		{http.MethodPost, "/api/v1/login", false},
		{http.MethodPost, "/api/v1/import/commit", false},
		{http.MethodPost, "/api/v1/config", false},
	} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{"yaml":"`+strings.Repeat("x", 16<<10)+`"}`))
		r.Header.Set("Content-Type", "application/json")
		err := webDecode(httptest.NewRecorder(), r, &in)
		if (err == nil) != tc.accept {
			t.Fatal(tc.path, "incorrect request budget", err)
		}
	}
}

func TestConversionWriterSizeAndCancellationDistinct(t *testing.T) {
	w := &conversionWriter{ctx: context.Background()}
	w.data.Grow(32 << 20)
	if n, err := w.Write(bytes.Repeat([]byte("x"), 32<<20)); err != nil || n != 32<<20 {
		t.Fatal(n, err)
	}
	if _, err := w.Write([]byte("x")); !errors.Is(err, errWebConversionTooLarge) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w = &conversionWriter{ctx: ctx}
	if _, err := w.Write([]byte("x")); !errors.Is(err, context.Canceled) || errors.Is(err, errWebConversionTooLarge) {
		t.Fatal(err)
	}
	// YAML's encoder wraps writer errors, so conversionMarshal must retain the cause.
	n := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Style: yaml.DoubleQuotedStyle, Value: strings.Repeat("x", (32<<20)-1)}
	if _, err := conversionMarshal(context.Background(), n); !errors.Is(err, errWebConversionTooLarge) {
		t.Fatal("marshal size error lost", err)
	}
	if _, err := conversionMarshal(ctx, n); !errors.Is(err, context.Canceled) {
		t.Fatal("marshal cancellation lost", err)
	}
	if webConversionErrorCode(errWebConversionTooLarge) != "CONFIG_CONVERSION_TOO_LARGE" || webConversionErrorCode(context.Canceled) == "CONFIG_CONVERSION_TOO_LARGE" {
		t.Fatal("size and cancellation HTTP errors conflated")
	}
}
