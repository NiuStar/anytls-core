package main

import (
	"bytes"
	"context"
	"encoding/json"
	cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestWebListenValidator(t *testing.T) {
	for _, h := range []string{"0.0.0.0", "127.0.0.1", "127.0.0.2", "10.0.0.1", "172.16.0.1", "192.168.5.2", "8.8.8.8", "169.254.1.1", "100.64.0.1", "172.32.0.1"} {
		if webValidateListen(h) != nil {
			t.Fatal(h)
		}
	}
	for _, h := range []string{"", "localhost", "::1", "::ffff:192.168.5.2", "192.168.005.2", "192.168.5.2:18089", "192.168.5.2%en0", "192.168.5.999", "127.1", "2130706433", "192.168.5.2/24", " 0.0.0.0"} {
		if webValidateListen(h) == nil {
			t.Fatal(h)
		}
	}
	_, assigned, _ := net.ParseCIDR("192.168.5.2/24")
	assigned.IP = net.ParseIP("192.168.5.2")
	if webListenAssigned("192.168.5.2", []net.Addr{assigned}) != nil || webListenAssigned("192.168.5.3", []net.Addr{assigned}) == nil {
		t.Fatal("assignment validation")
	}
	if webListenAssigned("0.0.0.0", nil) != nil || webListenAssigned("8.8.8.8", nil) == nil {
		t.Fatal("wildcard skips assignment; explicit address does not")
	}
	_, public, _ := net.ParseCIDR("8.8.8.8/24")
	public.IP = net.ParseIP("8.8.8.8")
	if webListenAssigned("8.8.8.8", []net.Addr{public}) != nil {
		t.Fatal("assigned public IPv4 rejected")
	}
}
func TestWebLANServeHTTP(t *testing.T) {
	w, password := webFixture(t)
	before, _ := os.ReadFile(w.passwordPath)
	w.listenHost = "192.168.5.2"
	request := func(method, path string, body []byte, cookie *http.Cookie, csrf string, change func(*http.Request)) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://192.168.5.2:18089"+path, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://"+r.Host)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		if change != nil {
			change(r)
		}
		rec := httptest.NewRecorder()
		w.ServeHTTP(rec, r)
		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("CORS enabled")
		}
		return rec
	}
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": password})
	login := request("POST", "/api/v1/login", body, nil, "", nil)
	if login.Code != 200 {
		t.Fatal(login.Code, login.Body.String())
	}
	cookie := login.Result().Cookies()[0]
	var result struct {
		CSRF string `json:"csrf"`
	}
	json.Unmarshal(login.Body.Bytes(), &result)
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || result.CSRF == "" {
		t.Fatal("session flags")
	}
	status := request("GET", "/api/v1/status", nil, cookie, "", nil)
	if status.Code != 200 || !bytes.Contains(status.Body.Bytes(), []byte(`"transport":"network-http"`)) {
		t.Fatal(status.Code, status.Body.String())
	}
	for _, tc := range []struct {
		name   string
		change func(*http.Request)
	}{
		{"missing origin", func(r *http.Request) { r.Header.Del("Origin") }},
		{"foreign origin", func(r *http.Request) { r.Header.Set("Origin", "http://evil:18089") }},
		{"duplicate origin", func(r *http.Request) { r.Header.Add("Origin", "http://"+r.Host) }},
		{"wildcard host", func(r *http.Request) { r.Host = "0.0.0.0:18089" }},
		{"loopback host", func(r *http.Request) { r.Host = "localhost:18089" }},
		{"wrong port", func(r *http.Request) { r.Host = "192.168.5.2:18090" }},
		{"forwarded host", func(r *http.Request) { r.Host = "evil:18089"; r.Header.Set("X-Forwarded-Host", "192.168.5.2:18089") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if r := request("POST", "/api/v1/login", body, nil, "", tc.change); r.Code != 403 {
				t.Fatal(r.Code)
			}
		})
	}
	if request("GET", "/api/v1/status", nil, nil, "", nil).Code != 401 {
		t.Fatal("anonymous accepted")
	}
	if request("POST", "/api/v1/logout", []byte(`{}`), cookie, "", nil).Code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	if request("OPTIONS", "/api/v1/login", nil, nil, "", nil).Code != 405 {
		t.Fatal("preflight accepted")
	}
	identity, _ := controlHelperConfigIdentity(w.configPath)
	calls := 0
	w.recordsRequest = func(context.Context, cr.PageRequest) (cr.PageResponse, error) {
		calls++
		return recordsTestPage(identity), nil
	}
	for _, site := range []string{"", "same-origin"} {
		r := request("GET", "/api/v1/connections", nil, cookie, "", func(r *http.Request) {
			r.Header.Set("X-AnyTLS-Origin", "http://"+r.Host)
			if site != "" {
				r.Header.Set("Sec-Fetch-Site", site)
			}
		})
		if r.Code != 200 {
			t.Fatal("positive records", site, r.Code, r.Body.String())
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*http.Request)
	}{
		{"no app header", func(r *http.Request) { r.Header.Del("X-AnyTLS-Origin") }},
		{"foreign app", func(r *http.Request) { r.Header.Set("X-AnyTLS-Origin", "http://localhost:18089") }},
		{"duplicate app", func(r *http.Request) { r.Header.Add("X-AnyTLS-Origin", "http://"+r.Host) }},
		{"cross-site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
		{"same-site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") }},
		{"empty site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "") }},
		{"duplicate site", func(r *http.Request) {
			r.Header.Add("Sec-Fetch-Site", "same-origin")
			r.Header.Add("Sec-Fetch-Site", "same-origin")
		}},
		{"bad origin", func(r *http.Request) { r.Header.Set("Origin", "http://evil:18089") }},
	} {
		t.Run("records/"+tc.name, func(t *testing.T) {
			r := request("GET", "/api/v1/connections", nil, cookie, "", func(r *http.Request) { r.Header.Set("X-AnyTLS-Origin", "http://"+r.Host); tc.change(r) })
			if r.Code != 403 {
				t.Fatal(r.Code)
			}
		})
	}
	if calls != 2 {
		t.Fatal("rejections reached backend", calls)
	}
	if request("POST", "/api/v1/logout", []byte(`{}`), cookie, result.CSRF, nil).Code != 200 || request("GET", "/api/v1/status", nil, cookie, "", nil).Code != 401 {
		t.Fatal("logout session revocation")
	}
	after, _ := os.ReadFile(w.passwordPath)
	if !bytes.Equal(before, after) {
		t.Fatal("password changed")
	}
}
