package main

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestSubscriptionRequestsClashRepresentation(t *testing.T) {
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
	}
	rt := func(r *http.Request, tr *http.Transport) (*http.Response, error) {
		if !strings.Contains(strings.ToLower(r.UserAgent()), "clash") {
			t.Fatal("subscription does not negotiate Clash format")
		}
		if !strings.Contains(r.Header.Get("Accept"), "yaml") {
			t.Fatal("YAML Accept missing")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(clashExportFixture))}, nil
	}
	if _, e := webImportFetchWith(context.Background(), "https://subscription.example/private", lookup, rt); e != nil {
		t.Fatal(e)
	}
}
func TestSubscriptionResponseCategoriesNoPayloadLeaks(t *testing.T) {
	for _, tc := range []struct{ input, code string }{{"<!DOCTYPE html><html>SECRET</html>", "SUBSCRIPTION_HTML_RESPONSE"}, {"anytls://SECRET@host:443", "SUBSCRIPTION_URI_RESPONSE"}, {base64.StdEncoding.EncodeToString([]byte("ss://SECRET@host:443")), "SUBSCRIPTION_BASE64_RESPONSE"}, {base64.RawURLEncoding.EncodeToString([]byte("anytls://SECRET@host:443")), "SUBSCRIPTION_BASE64_RESPONSE"}, {clashExportFixture, ""}, {"not-yaml-config", ""}} {
		if got := webSubscriptionResponseCode([]byte(tc.input)); got != tc.code {
			t.Fatal(got, tc.code)
		}
	}
}
func TestSubscriptionPreviewCategorizedErrorsNoWrites(t *testing.T) {
	for _, tc := range []struct{ input, code string }{{"<html>SECRET</html>", "SUBSCRIPTION_HTML_RESPONSE"}, {"anytls://SECRET@host:443", "SUBSCRIPTION_URI_RESPONSE"}, {base64.StdEncoding.EncodeToString([]byte("ss://SECRET@host:443")), "SUBSCRIPTION_BASE64_RESPONSE"}} {
		w, password := webFixture(t)
		c, csrf := webLogin(t, w, password)
		w.importFetch = func(context.Context, string) ([]byte, error) { return []byte(tc.input), nil }
		rec := importRequest(t, w, c, csrf, "import/preview", map[string]any{"url": "https://subscription.example/private?token=SECRET"}, "")
		if rec.Code != 422 || !strings.Contains(rec.Body.String(), tc.code) || strings.Contains(rec.Body.String(), "SECRET") || w.importPending != nil {
			t.Fatal(rec.Code, rec.Body.String())
		}
	}
}
