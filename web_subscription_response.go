package main

import (
	"bytes"
	"encoding/base64"
	"strings"
)

// Identify response categories without returning response text, addresses or
// credentials. Only use at the top-level subscription, not provider payloads.
func webSubscriptionResponseCode(data []byte) string {
	b := bytes.TrimSpace(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))
	lower := strings.ToLower(string(b))
	if strings.HasPrefix(lower, "<!doctype html") || strings.HasPrefix(lower, "<html") || strings.HasPrefix(lower, "<head") || strings.HasPrefix(lower, "<body") {
		return "SUBSCRIPTION_HTML_RESPONSE"
	}
	if webSubscriptionURI(b) {
		return "SUBSCRIPTION_URI_RESPONSE"
	}
	compact := strings.Join(strings.Fields(string(b)), "")
	// A normal YAML document is not base64; only label a decoded URI list.
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err := enc.DecodeString(compact)
		if err == nil && webSubscriptionURI(bytes.TrimSpace(decoded)) {
			return "SUBSCRIPTION_BASE64_RESPONSE"
		}
	}
	return ""
}
func webSubscriptionURI(b []byte) bool {
	s := strings.ToLower(string(bytes.TrimSpace(b)))
	for _, prefix := range []string{"anytls://", "ss://", "ssr://", "vmess://", "vless://", "trojan://", "hysteria://", "hysteria2://", "hy2://", "tuic://"} {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}
