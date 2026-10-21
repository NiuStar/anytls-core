package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
)

func conversionBomb() string {
	s := "a0: &a0 [x]\n"
	for i := 1; i <= 10; i++ {
		s += fmt.Sprintf("a%d: &a%d [%s]\n", i, i, strings.TrimSuffix(strings.Repeat(fmt.Sprintf("*a%d,", i-1), 8), ","))
	}
	return s + "nodes: []\n"
}
func TestConversionReviewExpansionAndCancel(t *testing.T) {
	if _, _, e := webConvertConfiguration(context.Background(), []byte(conversionBomb()), false, nil); e == nil {
		t.Fatal("exponential alias accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, e := webConvertConfiguration(ctx, []byte(clashExportFixture), false, nil); e == nil {
		t.Fatal("cancel ignored")
	}
	valid := strings.Replace(clashExportFixture, "password: '00123'", "password: '"+strings.Repeat("a", 100000)+"'", 1)
	if _, _, e := webConvertConfiguration(context.Background(), []byte(valid), false, nil); e != nil {
		t.Fatal("ordinary large alias rejected", e)
	}
}
func TestConversionReviewRemoteProviderCA(t *testing.T) {
	source := "proxy-providers: {p: {type: http, url: 'https://example.com/p'}}\nproxy-groups: [{name: g, type: select, use: [p]}]\nrules: ['MATCH,g']\n"
	fetch := func(context.Context, string) ([]byte, error) {
		return []byte("proxies: [{name: n, type: anytls, server: 1.1.1.1, port: 443, password: p, ca: /private/SECRET}]"), nil
	}
	_, r, e := webConvertConfiguration(context.Background(), []byte(source), false, fetch)
	if e != nil || len(r.Issues) == 0 || strings.Contains(strings.Join(r.Issues, ""), "SECRET") {
		t.Fatal(r, e)
	}
}
func TestConversionReviewCurrentWarningsAndBomb(t *testing.T) {
	w, p := webFixture(t)
	c, _ := webLogin(t, w, p)
	candidate := strings.Replace(clashExportFixture, "type: select", "type: url-test", 1) + "mixed-port: 7890\n"
	_ = os.WriteFile(w.configPath, []byte(candidate), 0600)
	rec := webRequest(w, http.MethodGet, "/api/v1/config/export", "", c, "")
	var out struct {
		Conversion webConversionReport `json:"conversion"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 200 || len(out.Conversion.Warnings) < 2 {
		t.Fatal(rec.Code, "warnings missing")
	}
	_ = os.WriteFile(w.configPath, []byte(conversionBomb()), 0600)
	rec = webRequest(w, http.MethodGet, "/api/v1/config/export", "", c, "")
	if rec.Code != 422 {
		t.Fatal(rec.Code)
	}
}
